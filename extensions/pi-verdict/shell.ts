// ============================================================================
// Rule layer: bash
// ============================================================================

import {
	ASSIGNMENT,
	anyCommandIn,
	firstOperandIs,
	type GitInvocation,
	ghRunsIn,
	gitRunsIn,
	hasUnsoundWord,
	isShellOperator,
	MIN_LONG_PREFIX,
	mentionsAny,
	shellWords,
	wordBasename,
} from "./shell-words.ts";

/** Whether one command segment's words run a rule's dangerous command. */
type SegmentMatcher = (seg: readonly string[]) => boolean;

/** Patterns that match one after another, at any distance, each with the `g` flag. */
export type Tripwire = readonly RegExp[];

/** A tripwire from its parts in order. Searching part by part keeps the cost linear in the text,
 *  where one regex with lazy `[\s\S]*?` gaps backtracks for seconds on a long repeated command. */
export function inOrder(...parts: RegExp[]): Tripwire {
	return parts.map((part) => new RegExp(part.source, `${part.flags}g`));
}

/** Whether every part of the tripwire matches, each after the end of the previous one. Each part but
 *  the last is a fixed word, so its earliest match also ends earliest. */
function tripwireMatches(text: string, tripwire: Tripwire): boolean {
	let from = 0;
	for (const part of tripwire) {
		part.lastIndex = from;
		const match = part.exec(text);
		if (match === null) return false;
		from = match.index + match[0].length;
	}
	return true;
}

/** A bash floor rule; any hit denies. A `raw` rule matches the full command string, pipelines and
 *  compound commands included. A `words` rule is decided by a raw-text tripwire that the shell-word
 *  view may clear when no command runs it (ADR-0007). */
type BashDangerRule =
	| { readonly kind: "raw"; readonly id: string; readonly reason: string; readonly pattern: RegExp }
	| { readonly kind: "words"; readonly id: string; readonly reason: string; readonly tripwire: Tripwire; readonly runs: SegmentMatcher }
	| { readonly kind: "delete"; readonly id: string; readonly reason: string; readonly tripwire: Tripwire };

/** One target the floor denies, a recursive delete's or a secret read's: the id of the rule it hit, why, and the
 *  target's forms, which a scoped `floorOverrides` entry must hold; with none, only an unscoped entry lifts it
 *  (ADR-0013, ADR-0014). */
export interface FloorHit {
	readonly rule: string;
	readonly reason: string;
	readonly forms: readonly string[];
}

/** A recursive `rm` the word view found at command position: its segment and the index of the `rm` word. */
export interface DeleteCommand {
	readonly seg: readonly string[];
	readonly at: number;
}

/** Grades the recursive deletes of a command by their targets, returning a hit per denied target, worst first;
 *  none clears the floor's tripwire. Bound to the call's directories by the rule layer. */
export type DeleteGrader = (deletes: readonly DeleteCommand[], command: string) => readonly FloorHit[];

/** Returns a hit for each secret file a command reads (ADR-0014). Bound to the call's directories by the rule
 *  layer. */
export type SecretReadGrader = (command: string) => readonly FloorHit[];

/** The graders the rule layer binds to a call's directories; without them the floor uses its tripwires alone. */
export interface ShellGraders {
	readonly deletes?: DeleteGrader;
	readonly reads?: SecretReadGrader;
}

/** The shortest `--recursive` abbreviation: GNU `rm` reads `--r` as unique among its long options. */
const RM_LONG_PREFIX = 3;

/** True when the words after an `rm` hold a recursive option before `--`: a short bundle with `r` or `R`, or
 *  `--recursive` abbreviated to at least `RM_LONG_PREFIX` characters. */
export function rmIsRecursive(args: readonly string[]): boolean {
	for (const word of args) {
		if (word === "--") return false;
		if (word.startsWith("--")) {
			if (word.length >= RM_LONG_PREFIX && "--recursive".startsWith(word)) return true;
		} else if (word.startsWith("-") && /[rR]/.test(word.slice(1))) return true;
	}
	return false;
}

/** The recursive deletes in a command, or null when the word view cannot show where each one runs: an `rm`
 *  with a recursive option in argument position (`xargs rm -r`, `find … -exec rm -r`, `command rm -r`), a
 *  word holding the tripwire's text outside a known inert position, or an unsound parse (ADR-0007). A
 *  `git rm` removes only tracked files of its repository, so it is no file-system delete. */
function deleteCommands(command: string, tripwire: Tripwire): DeleteCommand[] | null {
	const found: DeleteCommand[] = [];
	const runs = (seg: readonly string[]): boolean => {
		const at = seg.findIndex((word) => !ASSIGNMENT.test(word));
		if (at === -1) return false;
		const name = wordBasename(seg[at]);
		if (name === "rm") {
			if (rmIsRecursive(seg.slice(at + 1))) found.push({ seg, at });
			return false;
		}
		return name !== "git" && seg.some((word, k) => k > at && wordBasename(word) === "rm") && rmIsRecursive(seg.slice(at + 1));
	};
	return anyCommandIn(command, { runs, mentions: (word) => tripwireHit(word, tripwire) }) ? null : found;
}

/** A word that makes `git push` a force push. `--force-with-lease[=ref]` is the only escaping
 *  `--force-*` spelling; every other `--force-*` form is denied rather than handed to the classifier.
 *  Short flags are accepted in a bundle (`-f`, `-fu`, `-uf`, `-4f`), but not after an `o`, which takes
 *  the rest of the bundle as its value (`-of`). */
export function isForceFlag(word: string): boolean {
	const t = word.toLowerCase();
	if (/^-[a-np-z0-9]*f[a-z0-9]*$/.test(t)) return true;
	if (/^--force-with-lease(?:=|$)/.test(t)) return false;
	if (t === "--force-if-includes") return false; // no-op without a lease (git documents it)
	if (/^\+./.test(t)) return true; // a `+` refspec forces the update
	return /^--force(?![-\w])/.test(t) || t.startsWith("--force-");
}

/** `git push` options whose value is the next word, so a `+word` there is not a refspec. */
const PUSH_OPTIONS_WITH_VALUE = new Set(["--push-option", "--receive-pack", "--exec", "--repo"]);

/** Whether the words after `git push` force the update. Options may follow arguments, as git's
 *  option parser allows, until `--`; a short bundle ending in `o` (`-o`, `-uo`) takes the next word. */
function pushArgsForce(args: readonly string[]): boolean {
	for (let k = 0; k < args.length; k++) {
		const word = args[k].toLowerCase();
		if (word === "--") return args.slice(k + 1).some((arg) => arg.startsWith("+") && arg.length > 1);
		if (isForceFlag(word)) return true;
		if (PUSH_OPTIONS_WITH_VALUE.has(word) || /^-[a-np-z0-9]*o$/.test(word)) k++;
	}
	return false;
}

/** `git <subcommand>` whose arguments pass `argsHit`. An unreadable global option keeps the deny when
 *  any later word contains the subcommand's name (`git $X stash clear`). */
function gitCommand(subcommand: string, argsHit: (args: readonly string[]) => boolean): SegmentMatcher {
	const invocation: GitInvocation = { subcommand, argsHit, mayBeSubcommand: mentionsAny([subcommand]) };
	return (seg) => gitRunsIn(seg, invocation);
}

/** `gh <group> <action>` for one of `actions`. */
function ghCommand(group: string, actions: readonly string[]): SegmentMatcher {
	return (seg) => ghRunsIn(seg, { group, actions });
}

/**
 * The force-push rule. Its tripwire is anchored on a `push` word with a fully flexible body (so
 * `git --git-dir=X push …` and `-c/-C` gaps need no special handling), terminated by a bare `--force`,
 * another `--force-*` form (only `--force-with-lease` is exempt), a bundled short `f` flag (`-f`,
 * `-fu`, `-uf`, `-4f`, and `-f>/dev/null`) or a `+` refspec word. Quoted content does not break it:
 * `git push origin 'a&b' --force` names a legal refname. After an unreadable global option or
 * subcommand, any later word containing `push` keeps the deny, since `{push,}` or `push$X` may expand
 * to it.
 */
const GIT_PUSH_FORCE_RULE: BashDangerRule = {
	kind: "words",
	id: "git-push-force",
	reason: "git push --force",
	tripwire: inOrder(/\bpush\b/i, /--force(?![-\w])|--force-(?!with-lease)|\s-[a-zA-Z0-9]*f[a-zA-Z0-9]*\b|\s\+/i),
	runs: gitCommand("push", pushArgsForce),
};

/** Matches an `rm` word, then a short option bundle with `r`, quoted or not, or `--recursive` cut anywhere
 *  after `--r`, as a whole word. */
const RM_RECURSIVE_TRIPWIRE: Tripwire = inOrder(/\brm\b/i, /\s['"]?-[a-zA-Z]*r|--r(?:e(?:c(?:u(?:r(?:s(?:i(?:ve?)?)?)?)?)?)?)?(?![\w-])/i);

const BASH_DANGER_RULES: readonly BashDangerRule[] = [
	// Graded by target in the word view (ADR-0013); the tripwire alone decides a Python cell's shell lines.
	{ kind: "delete", id: "rm-recursive", tripwire: RM_RECURSIVE_TRIPWIRE, reason: "recursive delete (rm -r)" },
	{
		kind: "raw",
		id: "rm-root",
		pattern: /\brm\s+(-[a-zA-Z]*\s+)*(--recursive\s+)?(\/|\/etc|\/usr|\/var|~|\$HOME)(?:\s|$)/i,
		reason: "delete root/system/home directory",
	},
	{ kind: "raw", id: "sudo", pattern: /\bsudo\b/i, reason: "privilege escalation (sudo)" },
	{
		kind: "raw",
		id: "chmod-777",
		pattern: /\bchmod\b[^;|&]*(777|a\+rwx|ugo\+rwx|ugo=rwx|[ug]\+s)\b/i,
		reason: "permission weakening (chmod 777/setuid)",
	},
	{
		kind: "raw",
		id: "raw-device",
		pattern: /(>\s*\/dev\/(sd|hd|nvme|mmcblk|vd|xvd|r?disk[0-9])|of=\/dev\/(sd|hd|nvme|mmcblk|vd|xvd|r?disk[0-9])|\bmkfs\.)/i,
		reason: "raw device write/format",
	},
	GIT_PUSH_FORCE_RULE,
	// Each git tripwire allows any gap between `git` and its subcommand, so `git -C dir …` and
	// `git -c k=v …` reach the word view.
	{
		kind: "words",
		id: "git-reset-hard",
		tripwire: inOrder(/\bgit\b/i, /\breset\b/i, /--hard\b/i),
		runs: gitCommand("reset", (args) => args.some((arg) => arg.toLowerCase() === "--hard")),
		reason: "git reset --hard",
	},
	// Pattern from eugeniughelbur/jev-engineering@82655a6d policy.json (MIT, Copyright (c) 2026 Eugeniu Ghelbur).
	{
		kind: "words",
		id: "git-stash-clear",
		tripwire: inOrder(/\bgit\b/i, /\bstash\b/i, /\bclear\b/i),
		runs: gitCommand("stash", (args) => firstOperandIs(args, ["clear"])),
		reason: "git stash clear (drops all stashes)",
	},
	{
		kind: "words",
		id: "git-clean-force",
		tripwire: inOrder(/\bgit\b/i, /\bclean\b/i, /\s['"]?-[a-zA-Z]*f|--force/i),
		runs: gitCommand("clean", (args) => args.some((arg) => /^-[a-z]*f|^--force/i.test(arg))),
		reason: "git clean -f",
	},
	// Any `.` argument discards changes, `git checkout HEAD -- .` included.
	{
		kind: "words",
		id: "git-checkout-dot",
		tripwire: inOrder(/\bgit\b/i, /\bcheckout\b/i, /[\s'"]\.(?=[\s'"`;|&)]|$)/i),
		runs: gitCommand("checkout", (args) => args.includes(".")),
		reason: "git checkout . (discard working tree)",
	},
	{
		kind: "words",
		id: "git-restore",
		tripwire: inOrder(/\bgit\b/i, /\brestore\b/i),
		runs: gitCommand("restore", () => true),
		reason: "git restore (discard changes)",
	},
	// `raw-device`, `remote-exec`, `env-exfil` and `fork-bomb` stay raw-text only: their meaning spans a
	// pipe, a redirection or a function definition, which the word view splits or drops, so it cannot
	// show that such a hit is harmless (ADR-0007).
	{
		kind: "raw",
		id: "remote-exec",
		pattern: /\b(curl|wget)\b[^;|&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b/i,
		reason: "remote code execution (curl|sh)",
	},
	// Matches the environment or the shell history piped into a network tool: one pipe or `|&` (not the
	// `||` operator), on the same logical line (a backslash-newline continues it), to a bare or
	// path-qualified tool name. Trivially evaded (`env > f; curl -T f …`); it only removes the one-line
	// spelling from the classifier's judgement.
	// Pattern from eugeniughelbur/jev-engineering@82655a6d policy.json (MIT, Copyright (c) 2026 Eugeniu Ghelbur).
	{
		kind: "raw",
		id: "env-exfil",
		pattern: /\b(env|printenv|history)\b(?:[^;&\n]|\\\n)*(?<!\|)\|&?\s*(?:[\w./-]*\/)?(curl|wget|nc|ncat)\b/i,
		reason: "environment or history piped to a network tool",
	},
	{
		kind: "words",
		id: "gh-repo",
		tripwire: inOrder(/\bgh\b/i, /\brepo\b/i, /\b(?:create|delete|rename|archive)\b/i),
		runs: ghCommand("repo", ["create", "delete", "rename", "archive"]),
		reason: "GitHub repository-level change",
	},
	{
		kind: "words",
		id: "gh-release",
		tripwire: inOrder(/\bgh\b/i, /\brelease\b/i, /\b(?:create|delete|edit)\b/i),
		runs: ghCommand("release", ["create", "delete", "edit"]),
		reason: "GitHub release change",
	},
	{ kind: "raw", id: "fork-bomb", pattern: /:\(\)\s*\{/, reason: "fork bomb" },
];

/** The ids a graded recursive delete can deny under besides `rm-root` (ADR-0013). */
export const DELETE_RULE_IDS = ["rm-git", "rm-unreadable-target", "rm-outside-project"] as const;

/** The id of every bash floor rule, as `floorOverrides` and the audit name it. */
export const BASH_FLOOR_RULE_IDS: readonly string[] = [...BASH_DANGER_RULES.map((rule) => rule.id), ...DELETE_RULE_IDS];

/**
 * Whether a raw-text tripwire matches the command. A tripwire over-approximates its rule and only
 * has to never miss; the word view clears a false trip (ADR-0007). A backslash-newline may split a
 * word in the raw text, so the tripwire also tests the spelling with unescaped continuations removed
 * (an escaped `\\` pair is left alone: the shell splits there, and both views still hit that input).
 * The floor reads the first `BASH_MAX_MATCH_LEN` characters; a caller whose tripwire stays linear may
 * pass a larger `cap`.
 */
export function tripwireHit(command: string, tripwire: Tripwire, cap: number = BASH_MAX_MATCH_LEN): boolean {
	const capped = command.length > cap ? command.slice(0, cap) : command;
	if (tripwireMatches(capped, tripwire)) return true;
	const joined = joinContinuations(capped);
	return joined !== capped && tripwireMatches(joined, tripwire);
}

/** The text with every unescaped backslash-newline removed, as the shell joins a continued line. */
export function joinContinuations(text: string): string {
	return text.replace(/(?<!\\)\\\r?\n/g, "");
}

/** How a `words` rule reads text: through the word view, or on its tripwire alone. */
type FloorView = "words" | "raw-text";

/** Whether a rule hits the command. A `words` rule needs its tripwire to match; in the `words` view
 *  the word view must also find a command that runs it, a word holding its text outside a known
 *  inert position, or a construct it cannot read soundly. */
function ruleHits(rule: BashDangerRule, command: string, view: FloorView): boolean {
	switch (rule.kind) {
		case "raw":
			return rule.pattern.test(command);
		case "words":
			return (
				tripwireHit(command, rule.tripwire) &&
				(view === "raw-text" || anyCommandIn(command, { runs: rule.runs, mentions: (word) => tripwireHit(word, rule.tripwire) }))
			);
		case "delete":
			// Without a delete grader the tripwire decides; `deleteHits` grades the targets when one is bound.
			return tripwireHit(command, rule.tripwire);
		default: {
			const unknown: never = rule;
			return unknown;
		}
	}
}

/** `git push` with a force flag, decided as every `words` rule is (ADR-0007): a legal refname may
 *  contain a shell separator (`git push origin 'a&b' --force`), and text the shell never runs as a
 *  command (`git commit -m '… git push --force …'`) is not a force push. */
export function gitPushForce(command: string): boolean {
	return ruleHits(GIT_PUSH_FORCE_RULE, command, "words");
}

/** git flags that turn a read-shaped invocation into a write: `--output`/`-o` write a
 *  file, `--exec`/`--ext-diff`/`--textconv` run a program, `--git-dir`/`--work-tree` retarget the
 *  repository. Matched as bare or attached (`--output=…`, `-o…`). The reads outside the work tree and
 *  the configuration that runs a program (`-c`, `--config-env`) are refused by `allowOperandsAdmit`. */
const GIT_WRITE_FLAGS = ["--output", "-o", "--exec", "--ext-diff", "--textconv", "--git-dir", "--work-tree"];

/** The options with which a command runs another program or writes a file. A write option's value
 *  would be graded as a read, so the option itself refuses the allow. `words` match a whole word
 *  (find's actions); `long` names match bare, with `=value`, or abbreviated to a unique prefix as getopt
 *  allows; `short` letters match inside a short-option bundle, and for tar also in its old-style first
 *  word (`tar xIf`). */
interface SideEffectOptions {
	readonly words?: readonly string[];
	readonly long?: readonly string[];
	readonly short?: RegExp;
	readonly oldStyle?: boolean;
}

const FD_PROGRAM: SideEffectOptions = { long: ["--exec", "--exec-batch"], short: /[xX]/ };
const TAR_PROGRAM: SideEffectOptions = {
	long: [
		"--to-command",
		"--use-compress-program",
		"--checkpoint-action",
		"--info-script",
		"--new-volume-script",
		"--rsh-command",
		"--rmt-command",
	],
	short: /[IF]/,
	oldStyle: true,
};

const SIDE_EFFECT_OPTIONS: Readonly<Record<string, SideEffectOptions>> = {
	find: { words: ["-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls"] },
	fd: FD_PROGRAM,
	fdfind: FD_PROGRAM,
	rg: { long: ["--pre"] },
	tar: TAR_PROGRAM,
	bsdtar: TAR_PROGRAM,
	gtar: TAR_PROGRAM,
	// zip's `-TT` is one two-letter option, so it matches only spelled out.
	zip: { long: ["--unzip-command"], short: /TT/ },
	rsync: { long: ["--rsh", "--rsync-path"], short: /e/ },
	sort: { long: ["--output", "--compress-program"], short: /o/ },
};

/** True when `word` is one of the command's side-effect options. Over-approximates: an option's value
 *  that looks like one also counts, which only sends the call to the classifier. */
function hasSideEffect(word: string, first: boolean, options: SideEffectOptions): boolean {
	if (options.words?.includes(word)) return true;
	if (word.startsWith("--")) {
		const name = word.split("=")[0];
		return name.length >= MIN_LONG_PREFIX && (options.long ?? []).some((full) => full.startsWith(name));
	}
	if (options.short === undefined) return false;
	if (word.startsWith("-")) return options.short.test(word.slice(1));
	return first && options.oldStyle === true && /^[A-Za-z]+$/.test(word) && options.short.test(word);
}

/**
 * Whether a user `allow` regex may admit this command (ADR-0008). The allow layer tests
 * raw command text, so a regex anchored on the first word (`^ls\b`) would otherwise admit a whole
 * compound command — `ls\nbash /tmp/evil.sh`, `ls & npm install …`, `ls $(…)` — with no model
 * judgment, and a read-shaped `git log --output=<path>` would admit a write. An allow is granted
 * only for ONE simple command: false (allow skipped → the call reaches the classifier) on an
 * operator or newline, an unsound parse, a redirection other than to `/dev/null`, a re-parser in
 * command position (`xargs`, `find … -exec`), an option that runs a program (`fd -x`, `rg --pre`,
 * `tar -I`) or writes a file (`find -fprint`, `sort -o`), or a `git` invocation carrying a write flag. It checks the shape only;
 * `allowOperandsAdmit` grades what the operands touch.
 *
 * The narrowing direction is the safe one: a rejected allow never denies, it only defers to the
 * classifier. Redirect targets are not graded here; the classifier judges them (ADR-0008).
 */
export function allowAdmits(command: string): boolean {
	if (!command.trim()) return false;
	// A redirection other than to /dev/null, checked on the raw text because the scanner drops `<`/`>`.
	const stripped = command.replace(/\d?&?>>?\s*\/dev\/null/g, "").replace(/<\s*\/dev\/null/g, "");
	if (/[<>]/.test(stripped)) return false;
	// POSIX sh reads `&>` as a background `&` and then a redirection, so a word after it may run as
	// a second command; only the shell-word view reads it as one redirection.
	if (command.includes("&>")) return false;
	// A recursive delete may drop uncommitted work that only the classifier, with the session's context, can
	// judge (ADR-0013). Checked on the raw text, so one inside an `sh -c` script counts too.
	if (tripwireHit(command, RM_RECURSIVE_TRIPWIRE)) return false;
	const words = shellWords(command);
	if (hasUnsoundWord(words)) return false;
	// An operator or newline means more than one simple command.
	for (const w of words) {
		if (isShellOperator(w) || w === "\n") return false;
	}
	// A re-parser, or an option that runs a program, runs words the scanner never paired; a write
	// option's target would be graded as a read.
	for (let i = 0; i < words.length; i++) {
		const base = wordBasename(words[i]);
		if (base === "xargs") return false;
		const effects = SIDE_EFFECT_OPTIONS[base];
		if (effects && words.slice(i + 1).some((w, k) => hasSideEffect(w, k === 0, effects))) return false;
	}
	if (words.length > 0 && wordBasename(words[0]) === "git") {
		for (const w of words) {
			for (const flag of GIT_WRITE_FLAGS) {
				if (w === flag || w.startsWith(`${flag}=`) || (flag === "-o" && w.startsWith("-o") && w.length > 2)) return false;
			}
		}
	}
	return true;
}

type RuleVerdict = "allow" | "deny" | "gray" | "ask";
export interface RuleResult {
	verdict: RuleVerdict;
	reason?: string;
	/** UI-only plaintext (e.g. the matched protected path). Never reaches the agent
	 *  context: block reasons and notifications travel back to the model, so only the
	 *  local confirm dialog may show it (ADR-0002 story: zero path plaintext leaves the machine). */
	detail?: string;
	/** Set only by selfProtectCheck: this deny is not exempted by autoDeny:false. */
	selfProtect?: true;
	/** Named only on verdict:"ask": which rule-layer ask this is. Every producer names its own
	 *  source; an unset value maps to "protected-path". */
	askSource?: "protected-path" | "rule";
	/** A short id of the rule that decided, kept in the audit: the rule-verdict record of an allow or deny,
	 *  the full record of an ask. It never holds a path or other text from the call. */
	rule?: string;
	/** The floor rules a `floorOverrides` entry lifted for this call (ADR-0013), for the audit. */
	overridden?: readonly string[];
	/** A floor deny an override softened to an ask; the rule layer raises it after the protected-path asks. */
	carriedAsk?: { readonly rule: string; readonly reason: string };
}

/** Cap the danger-regex matching input: the prefix-consuming character
 *  classes plus nested alternations can backtrack quadratically on very long
 *  separator-free strings. Beyond the cap, rule matching is lost and the call
 *  falls to the classifier (fail-closed direction). */
export const BASH_MAX_MATCH_LEN = 8192;

/** Returns what a `floorOverrides` entry does to a floor rule for the call being graded, or null when no
 *  entry applies and the rule stays on (ADR-0013). `forms` are a delete target's forms, which a scoped entry
 *  must hold; without them the scope is checked against the call's directories. */
export type FloorLift = (id: string, forms?: readonly string[]) => "off" | "ask" | null;

const NO_LIFT: FloorLift = () => null;

/** The floor rules an override lifted while one call was graded: the first softened to an ask, and the ids
 *  of all of them for the audit. */
export class LiftedRules {
	private ask: RuleResult["carriedAsk"];
	private readonly ids: string[] = [];

	add(rule: string, reason: string, action: "off" | "ask"): void {
		this.ids.push(rule);
		if (action === "ask" && this.ask === undefined) this.ask = { rule, reason };
	}

	/** Returns the grade with the lifted rules attached; a grade with none passes unchanged. */
	onto(grade: RuleResult): RuleResult {
		if (this.ids.length === 0) return grade;
		return { ...grade, overridden: this.ids, ...(this.ask ? { carriedAsk: this.ask } : {}) };
	}
}

/** Grades a bash command: a floor deny, or gray for the user rules and the classifier. A recursive `rm` is
 *  graded by its targets when `graders.deletes` is bound, else denied on its tripwire; a secret file the
 *  command reads denies when `graders.reads` is bound. */
export function classifyBash(command: string, floorOn: boolean, lift: FloorLift = NO_LIFT, graders: ShellGraders = {}): RuleResult {
	return classifyShellText(command, floorOn, "words", lift, graders);
}

/** Grades the shell lines of a Python cell on raw text only: Python decides how their strings are
 *  quoted and joined, so the shell-word view cannot show that a tripwire hit is harmless (ADR-0007). */
export function classifyPyShellLines(lines: string, floorOn: boolean, lift: FloorLift = NO_LIFT): RuleResult {
	return classifyShellText(lines, floorOn, "raw-text", lift);
}

/** The floor's hits for one rule: a single hit under the rule's own id, or for a graded delete a hit per
 *  denied target. */
function ruleDenials(rule: BashDangerRule, command: string, view: FloorView, deletes: DeleteGrader | undefined): readonly FloorHit[] {
	if (!ruleHits(rule, command, view)) return [];
	const own: FloorHit = { rule: rule.id, reason: `rule ${rule.id}: ${rule.reason}`, forms: [] };
	if (rule.kind !== "delete" || view === "raw-text" || deletes === undefined) return [own];
	const found = deleteCommands(command, rule.tripwire);
	// Fails closed: a delete the word view cannot place has no target to grade, so the tripwire's own deny
	// stands, which no override lifts.
	return found === null ? [own] : deletes(found, command);
}

function classifyShellText(command: string, floorOn: boolean, view: FloorView, lift: FloorLift, graders: ShellGraders = {}): RuleResult {
	const lifted = new LiftedRules();
	if (floorOn) {
		const capped = command.length > BASH_MAX_MATCH_LEN ? command.slice(0, BASH_MAX_MATCH_LEN) : command;
		for (const rule of BASH_DANGER_RULES) {
			for (const hit of ruleDenials(rule, capped, view, graders.deletes)) {
				// A delete is scoped by its targets alone, so one with no readable target lifts only unscoped.
				const action = lift(hit.rule, rule.kind === "delete" ? hit.forms : undefined);
				if (action === null) return { verdict: "deny", reason: hit.reason, rule: hit.rule };
				lifted.add(hit.rule, hit.reason, action);
			}
		}
		// Not past the cap: a word cut there (`.env.example` cut to `.env`) would deny falsely (ADR-0014).
		const reads = graders.reads !== undefined && command.length <= BASH_MAX_MATCH_LEN ? graders.reads(command) : [];
		for (const hit of reads) {
			// A secret read is scoped by its file's forms, so one graded by name only lifts only unscoped.
			const action = lift(hit.rule, hit.forms);
			if (action === null) return { verdict: "deny", reason: hit.reason, rule: hit.rule };
			lifted.add(hit.rule, hit.reason, action);
		}
	}
	if (!command.trim()) return { verdict: "allow", reason: "empty command", rule: "empty-command" };
	// No built-in allowlist: every command the floor passes goes to user rules and the classifier.
	return lifted.onto({ verdict: "gray", reason: "no built-in allowlist" });
}

/** Direct shell APIs in py cell text: omp injects `__omp_shell` into the cell
 *  namespace, and subprocess/os.system stay importable — a model can shell out without a `!`
 *  line. A tripwire, not a parser: the whole line is pushed and the danger rules (regexes over
 *  text) do the matching. */
const PY_SHELL_API = /(^|[^\w.])(__omp_shell\s*\(|subprocess\.(?:Popen|run|call|check_call|check_output)\s*\(|os\.system\s*\()/;

/** Returns the lines of a Python `eval` cell that run a shell command, so the bash floor can check them:
 *  a `!` line (also `name = !cmd`), every line after `%%bash`, and a direct shell call (`subprocess.*`,
 *  `os.system(`, `__omp_shell(`). A plain line scan, so a `!` inside a string also counts; that only adds
 *  scrutiny. Mirrors omp's py cell transform (18.6.1). JS cells get no extraction (ADR-0009). */
export function pyEvalShellLines(code: string): string[] {
	const lines = code.split("\n");
	const out: string[] = [];
	for (let i = 0; i < lines.length; i++) {
		const stripped = lines[i].replace(/^[ \t]*/, "");
		if (/^%%bash(?:\s|$)/.test(stripped)) {
			out.push(...lines.slice(i + 1));
			break;
		}
		if (stripped.startsWith("!")) {
			out.push(stripped.slice(1).trim());
			continue;
		}
		const assign = /^[ \t]*[A-Za-z_][A-Za-z_0-9.[\], ]*?\s*=\s*(.+)$/.exec(lines[i]);
		const rhs = assign?.[1].trim();
		if (rhs?.startsWith("!")) out.push(rhs.slice(1).trim());
		else if (PY_SHELL_API.test(stripped)) out.push(stripped);
	}
	return out;
}
