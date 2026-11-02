import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { escapeRegExp } from "./agent-dir.ts";
import { isWithin } from "./paths.ts";
import { BASH_MAX_MATCH_LEN, inOrder, joinContinuations, type Tripwire, tripwireHit } from "./shell.ts";
import { anyCommandIn, gitSubcommandIndex, mayExpand, wordBasename } from "./shell-words.ts";

// ============================================================================
// Command rules: the user's cc-safety-net-shaped rules over command words (ADR-0013)
// ============================================================================

/** What a command rule does when it matches. */
export type CommandRuleAction = "deny" | "ask";

/** One loaded command rule. `path` holds the subcommand or `command_path` words in order, `args` the
 *  block or any-of words, `exclude` the words that clear a match. */
export interface CommandRule {
	/** The audit id: `user-command:<rulebook>/<name>`, `user-command:<name>` or `project-command:<name>`. */
	readonly id: string;
	readonly name: string;
	readonly command: string;
	readonly path: readonly string[];
	readonly args: readonly string[];
	readonly exclude: readonly string[];
	readonly action: CommandRuleAction;
	readonly reason: string;
	readonly tripwire: Tripwire;
}

/** Where a list of rules comes from, which names their ids and fixes their shape. */
export interface RuleSource {
	readonly prefix: "user-command" | "project-command";
	/** The rulebook name, or null for inline rules. */
	readonly book: string | null;
	/** The shape a rulebook declares; null lets each inline rule's own fields decide. */
	readonly version: 1 | 2 | null;
}

/** cc-safety-net's validation limits (`src/core/policy/rulebook-limits.ts`, 2.7.1), and a token length cap of our own
 *  that keeps each generated tripwire small. */
export const COMMAND_RULE_LIMITS = Object.freeze({ maxRules: 1_024, maxArgsPerList: 1_024, maxTotalArgs: 16_384, maxTokenLength: 1_024 });
const NAME_PATTERN = /^[a-zA-Z][a-zA-Z0-9_-]{0,63}$/;
const COMMAND_PATTERN = /^[a-zA-Z][a-zA-Z0-9_-]*$/;
const MAX_REASON_LENGTH = 256;

const V1_FIELDS = new Set(["name", "command", "subcommand", "block_args", "reason", "intent", "action"]);
const V2_FIELDS = new Set(["name", "command", "match", "reason", "intent", "action"]);
const MATCH_FIELDS = new Set(["command_path", "any_args", "exclude_args"]);

/** A shared count of the argument words loaded so far, capped at `maxTotalArgs` across every source. */
export interface ArgBudget {
	remaining: number;
}

export function newArgBudget(): ArgBudget {
	return { remaining: COMMAND_RULE_LIMITS.maxTotalArgs };
}

/** Returns the valid rules of a raw list and an error naming each skipped one. Fails closed toward the user:
 *  every skipped rule is named, and the caller degrades the policy for it (ADR-0010). */
export function parseCommandRules(raw: unknown, source: RuleSource, budget: ArgBudget): { rules: CommandRule[]; errors: string[] } {
	const where = source.book === null ? "commandRules" : `rulebook ${source.book}`;
	if (!Array.isArray(raw)) return { rules: [], errors: [`${where}: rules must be an array`] };
	if (raw.length > COMMAND_RULE_LIMITS.maxRules) {
		return { rules: [], errors: [`${where}: more than ${COMMAND_RULE_LIMITS.maxRules} rules — none loaded`] };
	}
	const rules: CommandRule[] = [];
	const errors: string[] = [];
	const names = new Set<string>();
	raw.forEach((entry, index) => {
		const parsed = parseRule(entry, source, budget);
		const label = `${where}[${index}]`;
		if (typeof parsed === "string") errors.push(`${label}: ${parsed} — rule skipped`);
		else if (names.has(parsed.name.toLowerCase())) errors.push(`${label}: duplicate rule name ${parsed.name} — rule skipped`);
		else {
			names.add(parsed.name.toLowerCase());
			rules.push(parsed);
		}
	});
	return { rules, errors };
}

/** Returns one rule, or why it is invalid. */
function parseRule(entry: unknown, source: RuleSource, budget: ArgBudget): CommandRule | string {
	if (!isRecord(entry)) return "must be an object";
	const v2 = source.version === null ? entry.match !== undefined : source.version === 2;
	const unknown = Object.keys(entry).find((k) => !(v2 ? V2_FIELDS : V1_FIELDS).has(k));
	if (unknown !== undefined) return `unknown field ${unknown}`;
	const { name, command, reason, intent, action } = entry;
	if (typeof name !== "string" || !NAME_PATTERN.test(name)) return "name must match [a-zA-Z][a-zA-Z0-9_-]{0,63}";
	if (typeof command !== "string" || !COMMAND_PATTERN.test(command)) return "command must be a bare command name";
	if (typeof reason !== "string" || reason === "" || reason.length > MAX_REASON_LENGTH) {
		return `reason must be a non-empty string of at most ${MAX_REASON_LENGTH} characters`;
	}
	if (intent !== undefined && typeof intent !== "string") return "intent must be a string";
	if (action !== undefined && action !== "deny" && action !== "ask") return 'action must be "deny" or "ask"';
	const words = v2 ? v2Words(entry.match, budget) : v1Words(entry, budget);
	if (typeof words === "string") return words;
	const id = `${source.prefix}:${source.book === null ? "" : `${source.book}/`}${name}`;
	const cmd = command.toLowerCase();
	return { id, name, command: cmd, ...words, action: action ?? "deny", reason, tripwire: ruleTripwire(cmd, words.path, words.args) };
}

type RuleWords = Pick<CommandRule, "path" | "args" | "exclude">;

/** The words of a version 1 rule: an optional `subcommand` and the required `block_args`. */
function v1Words(entry: Record<string, unknown>, budget: ArgBudget): RuleWords | string {
	const { subcommand } = entry;
	if (subcommand !== undefined && (typeof subcommand !== "string" || !COMMAND_PATTERN.test(subcommand))) {
		return "subcommand must be a bare word";
	}
	const args = tokenList(entry.block_args, "block_args", budget);
	if (typeof args === "string") return args;
	return { path: subcommand === undefined ? [] : [subcommand], args, exclude: [] };
}

/** The words of a version 2 rule's `match`: the required `command_path` and the optional `any_args` and
 *  `exclude_args`. */
function v2Words(match: unknown, budget: ArgBudget): RuleWords | string {
	if (!isRecord(match)) return "match must be an object";
	const unknown = Object.keys(match).find((k) => !MATCH_FIELDS.has(k));
	if (unknown !== undefined) return `unknown field match.${unknown}`;
	const path = tokenList(match.command_path, "match.command_path", budget);
	if (typeof path === "string") return path;
	const args = match.any_args === undefined ? [] : tokenList(match.any_args, "match.any_args", budget);
	if (typeof args === "string") return args;
	const exclude = match.exclude_args === undefined ? [] : tokenList(match.exclude_args, "match.exclude_args", budget);
	if (typeof exclude === "string") return exclude;
	return { path, args, exclude };
}

/** Returns a non-empty list of non-empty words within the caps, charged to the budget, or why it is not one. */
function tokenList(value: unknown, field: string, budget: ArgBudget): string[] | string {
	if (!Array.isArray(value) || value.length === 0) return `${field} must be a non-empty array of words`;
	if (!value.every((t) => typeof t === "string" && t.length > 0 && t.length <= COMMAND_RULE_LIMITS.maxTokenLength)) {
		return `${field} must hold non-empty strings of at most ${COMMAND_RULE_LIMITS.maxTokenLength} characters`;
	}
	if (value.length > COMMAND_RULE_LIMITS.maxArgsPerList || value.length > budget.remaining) return `${field} is over the word cap`;
	budget.remaining -= value.length;
	return value as string[]; // every element was checked to be a string above
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** One rulebook fixture: a command and whether the book blocks it, and by which rule. */
export interface RulebookFixture {
	readonly command: string;
	readonly expect: "blocked" | "allowed";
	readonly rule?: string;
}

/** A parsed rulebook: its name, its valid rules, its fixtures, and an error for each skipped part. */
export interface LoadedRulebook {
	readonly book: string | null;
	readonly rules: CommandRule[];
	readonly tests: RulebookFixture[];
	readonly errors: string[];
}

/** Parses a cc-safety-net `rulebook.json` text. Only `rulebook_version`, `name`, `rules` and `tests` are read;
 *  other top-level fields (`allowed_commands`, `version`, `author` …) are ignored. A book whose header is
 *  invalid loads no rule. */
export function parseRulebook(text: string, prefix: RuleSource["prefix"], budget: ArgBudget): LoadedRulebook {
	let raw: unknown;
	try {
		raw = JSON.parse(text);
	} catch (err) {
		return { book: null, rules: [], tests: [], errors: [`rulebook parse failed: ${err instanceof Error ? err.message : String(err)}`] };
	}
	if (!isRecord(raw)) return { book: null, rules: [], tests: [], errors: ["rulebook must be an object"] };
	const { name, rulebook_version: version } = raw;
	if (typeof name !== "string" || !NAME_PATTERN.test(name))
		return { book: null, rules: [], tests: [], errors: ["rulebook name is invalid"] };
	if (version !== 1 && version !== 2)
		return { book: name, rules: [], tests: [], errors: [`rulebook ${name}: rulebook_version must be 1 or 2`] };
	const { rules, errors } = parseCommandRules(raw.rules, { prefix, book: name, version }, budget);
	return { book: name, rules, tests: fixtures(raw.tests), errors };
}

/** The raw command-rule keys of a loaded config. */
export interface CommandRuleInput {
	/** The user's inline `commandRules`. */
	readonly inline: unknown;
	/** The user's `commandRuleFiles`. */
	readonly files: unknown;
	/** A trusted project's inline `commandRules`, which only add rules (ADR-0006). */
	readonly project: unknown;
	readonly agentDir: string;
}

/** The one directory rule files load from; self-protection denies agent writes to it. */
export function commandRulesDir(agentDir: string): string {
	return path.join(agentDir, "config", "pi-verdict-rules");
}

/** Loads every command rule in order: the user's rule files, the user's inline rules, then the project's.
 *  Returns an error naming each skipped file or rule, which the caller reports and degrades the policy for
 *  (ADR-0010). A rule file outside `commandRulesDir`, symlinks followed, is skipped. */
export function loadCommandRules(input: CommandRuleInput): { set: CommandRuleSet; errors: string[] } {
	const budget = newArgBudget();
	const rules: CommandRule[] = [];
	const errors: string[] = [];
	if (input.files !== undefined) {
		if (!Array.isArray(input.files)) errors.push("commandRuleFiles must be an array of file names");
		else
			for (const file of input.files) {
				const loaded = loadRuleFile(file, input.agentDir, budget);
				rules.push(...loaded.rules);
				errors.push(...loaded.errors);
			}
	}
	for (const [raw, prefix] of [
		[input.inline, "user-command"],
		[input.project, "project-command"],
	] as const) {
		if (raw === undefined) continue;
		const parsed = parseCommandRules(raw, { prefix, book: null, version: null }, budget);
		rules.push(...parsed.rules);
		errors.push(...parsed.errors.map((e) => (prefix === "project-command" ? `project ${e}` : e)));
	}
	return { set: commandRuleSet(rules), errors };
}

/** Reads one `commandRuleFiles` entry, a name or path resolved inside `commandRulesDir` with symlinks
 *  followed, or says why it was skipped. */
export function readRuleFile(file: unknown, agentDir: string): { text: string } | { error: string } {
	if (typeof file !== "string" || file === "") return { error: `commandRuleFiles: ${JSON.stringify(file)} is not a file name` };
	const dir = commandRulesDir(agentDir);
	const spelled = file === "~" || file.startsWith("~/") ? path.join(os.homedir(), file.slice(1)) : file;
	let real: string;
	let realDir: string;
	try {
		real = fs.realpathSync(path.resolve(dir, spelled));
		realDir = fs.realpathSync(dir);
	} catch {
		return { error: `commandRuleFiles: ${file} cannot be read — skipped` };
	}
	if (!isWithin(real, realDir) || real === realDir) return { error: `commandRuleFiles: ${file} is outside ${dir} — skipped` };
	try {
		return { text: fs.readFileSync(real, "utf8") };
	} catch (err) {
		return { error: `commandRuleFiles: ${file} cannot be read (${err instanceof Error ? err.message : String(err)}) — skipped` };
	}
}

/** Loads one `commandRuleFiles` entry. */
function loadRuleFile(file: unknown, agentDir: string, budget: ArgBudget): { rules: CommandRule[]; errors: string[] } {
	const read = readRuleFile(file, agentDir);
	if ("error" in read) return { rules: [], errors: [read.error] };
	const book = parseRulebook(read.text, "user-command", budget);
	return { rules: book.rules, errors: book.errors.map((e) => `commandRuleFiles: ${String(file)}: ${e}`) };
}

/** The well-formed fixtures of a rulebook's `tests`; a malformed one is dropped, since fixtures never gate. */
function fixtures(raw: unknown): RulebookFixture[] {
	if (!Array.isArray(raw)) return [];
	return raw.flatMap((t): RulebookFixture[] => {
		if (!isRecord(t) || typeof t.command !== "string" || (t.expect !== "blocked" && t.expect !== "allowed")) return [];
		return [{ command: t.command, expect: t.expect, ...(typeof t.rule === "string" ? { rule: t.rule } : {}) }];
	});
}

// ---- matching ----------------------------------------------------------------------

/** Characters that end a shell word: whitespace, a quote, an operator, a parenthesis or a redirection. */
const BOUNDARY = "[\\s'\"`;&|()<>]";

/** Builds a rule's tripwire: the command name as a word, possibly path-qualified or with `.exe`, then each path
 *  word, then any argument word, a single-letter option also inside a short bundle (`-Am` holds `-A`). It only
 *  has to never miss; the word view decides. */
function ruleTripwire(command: string, path: readonly string[], args: readonly string[]): Tripwire {
	const end = `(?=$|${BOUNDARY})`;
	const word = (body: string): RegExp => new RegExp(`(?:^|${BOUNDARY})(?:${body})${end}`, "i");
	const parts = [
		new RegExp(`(?:^|${BOUNDARY}|[/\\\\])${escapeRegExp(command)}(?:\\.exe)?${end}`, "i"),
		...path.map((w) => word(escapeRegExp(w))),
	];
	if (args.length > 0) parts.push(word(args.map(argPattern).join("|")));
	return inOrder(...parts);
}

/** A single-letter option also matches inside a bundle. The letter is found by a lookahead, so the bundle is
 *  read once per `-` and the search stays linear in the text. */
function argPattern(arg: string): string {
	return /^-[A-Za-z0-9]$/.test(arg) ? `-(?=[A-Za-z0-9]*${escapeRegExp(arg[1])})[A-Za-z0-9]+` : escapeRegExp(arg);
}

/** The command name a word runs: its basename, lower case, with `.exe` dropped. */
function commandName(word: string): string {
	return wordBasename(word)
		.toLowerCase()
		.replace(/\.exe$/, "");
}

/** Global options that take a value, per command, as cc-safety-net reads them (2.7.1); git's are read by
 *  `gitSubcommandIndex`. */
const OPTIONS_WITH_VALUE: Readonly<Record<string, ReadonlySet<string>>> = {
	docker: new Set(["-c", "-H", "-l", "--config", "--context", "--host", "--log-level", "--tlscacert", "--tlscert", "--tlskey"]),
	aws: new Set([
		"--ca-bundle",
		"--cli-binary-format",
		"--cli-connect-timeout",
		"--cli-error-format",
		"--cli-read-timeout",
		"--color",
		"--endpoint-url",
		"--output",
		"--profile",
		"--query",
		"--region",
	]),
	gcloud: new Set([
		"--access-token-file",
		"--account",
		"--billing-project",
		"--configuration",
		"--flags-file",
		"--flatten",
		"--format",
		"--impersonate-service-account",
		"--project",
		"--trace-token",
		"--verbosity",
	]),
	az: new Set(["-o", "--output", "--query", "--subscription"]),
};

/**
 * True when the words after a command start with the rule's path words in order. Fails closed: an option the
 * table does not know may take the next word as its value, so after one the remaining path words are searched
 * in order anywhere; so is a word that may expand. For git, the subcommand is read past git's global options.
 */
function pathMatches(seg: readonly string[], at: number, rule: CommandRule): boolean {
	if (rule.path.length === 0) return true;
	const sub = rule.command === "git" ? gitSubcommandIndex(seg, at) : at + 1;
	if (sub === -1) return false;
	const from = sub ?? at + 1;
	const withValue = OPTIONS_WITH_VALUE[rule.command] ?? new Set<string>();
	let k = 0;
	let loose = sub === undefined;
	for (let i = from; i < seg.length && k < rule.path.length; i++) {
		const word = seg[i];
		if (word.startsWith("-") && word.length > 1) {
			if (word.includes("=")) continue;
			if (withValue.has(word)) i++;
			else loose = true;
			continue;
		}
		if (word === rule.path[k]) k++;
		else if (mayExpand(word)) loose = true;
		else if (!loose) return false;
	}
	return k === rule.path.length;
}

/** True when a word equals one of the argument words, or is a short bundle holding a single-letter one. */
function argMatches(word: string, args: readonly string[]): boolean {
	if (args.includes(word)) return true;
	if (!/^-[A-Za-z0-9]{2,}$/.test(word)) return false;
	return args.some((arg) => /^-[A-Za-z0-9]$/.test(arg) && word.includes(arg[1]));
}

/** True when the command a segment runs at `at` matches the rule. */
function runsAt(seg: readonly string[], at: number, rule: CommandRule): boolean {
	const args = seg.slice(at + 1);
	if (rule.exclude.length > 0 && args.some((w) => rule.exclude.includes(w))) return false;
	if (!pathMatches(seg, at, rule)) return false;
	return rule.args.length === 0 || args.some((w) => argMatches(w, rule.args));
}

/** True when a segment runs the rule's command at a word position the segment does not hold inert. */
function segmentRuns(seg: readonly string[], inert: ReadonlySet<number>, rule: CommandRule): boolean {
	return seg.some((word, at) => !inert.has(at) && commandName(word) === rule.command && runsAt(seg, at, rule));
}

/** The longest text the word view reads for command rules; one segment's word scan grows with the square of
 *  how often it names a ruled command. */
const WORD_READ_LIMIT = 8 * BASH_MAX_MATCH_LEN;

/** The loaded command rules, indexed by command name. */
export interface CommandRuleSet {
	readonly rules: readonly CommandRule[];
	readonly byCommand: ReadonlyMap<string, readonly CommandRule[]>;
}

export const NO_COMMAND_RULES: CommandRuleSet = { rules: [], byCommand: new Map() };

/** Indexes rules by command name, keeping their order. */
export function commandRuleSet(rules: readonly CommandRule[]): CommandRuleSet {
	const byCommand = new Map<string, CommandRule[]>();
	for (const rule of rules) byCommand.set(rule.command, [...(byCommand.get(rule.command) ?? []), rule]);
	return { rules, byCommand };
}

/**
 * Returns every rule that matches a command, in rule order. A rule matches at any word position of a segment,
 * so a wrapper (`sudo`, `env`, `xargs`, `ssh host …`) is looked through; inside an `sh -c` script; or in a word
 * holding its text outside a known inert position. An unsound reading keeps every tripwire hit (ADR-0007).
 * The whole text is read, not only the floor's capped prefix, so a rule past the cap still decides. Only the
 * rules whose command name and tripwire occur in the text are tested, and they share one reading of it.
 */
export function matchingCommandRules(text: string, set: CommandRuleSet): CommandRule[] {
	if (set.rules.length === 0) return [];
	const raw = text.toLowerCase();
	const joined = joinContinuations(raw);
	const named = (command: string): boolean => raw.includes(command) || joined.includes(command);
	const candidates = [...set.byCommand]
		.filter(([command]) => named(command))
		.flatMap(([, rules]) => rules)
		.filter((rule) => tripwireHit(text, rule.tripwire, Number.POSITIVE_INFINITY));
	if (candidates.length === 0) return [];
	// Fails closed: past the read limit the tripwire hits decide, which keeps the cost linear.
	if (text.length > WORD_READ_LIMIT) return candidates.sort((a, b) => set.rules.indexOf(a) - set.rules.indexOf(b));
	const hits = new Set<CommandRule>();
	const mark = (test: (rule: CommandRule) => boolean): false => {
		for (const rule of candidates) if (!hits.has(rule) && test(rule)) hits.add(rule);
		return false; // read on: every candidate gets the whole text
	};
	const unsound = anyCommandIn(text, {
		runs: (seg, inert) => mark((rule) => segmentRuns(seg, inert, rule)),
		mentions: (word) => mark((rule) => tripwireHit(word, rule.tripwire, Number.POSITIVE_INFINITY)),
	});
	return set.rules.filter((rule) => hits.has(rule) || (unsound && candidates.includes(rule)));
}
