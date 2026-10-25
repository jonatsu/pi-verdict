// ============================================================================
// Rule layer: bash
// ============================================================================

import {
	anyCommandIn,
	firstOperandIs,
	type GitInvocation,
	ghRunsIn,
	gitRunsIn,
	hasUnsoundWord,
	isShellOperator,
	mentionsAny,
	shellWords,
	wordBasename,
} from "./shell-words.ts";

/** Whether one command segment's words run a rule's dangerous command. */
type SegmentMatcher = (seg: readonly string[]) => boolean;

/** Patterns that match one after another, at any distance, each with the `g` flag. */
type Tripwire = readonly RegExp[];

/** A tripwire from its parts in order. Searching part by part keeps the cost linear in the text,
 *  where one regex with lazy `[\s\S]*?` gaps backtracks for seconds on a long repeated command. */
function inOrder(...parts: RegExp[]): Tripwire {
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
	| { readonly kind: "words"; readonly id: string; readonly reason: string; readonly tripwire: Tripwire; readonly runs: SegmentMatcher };

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
 * `git push origin 'a&b' --force` names a legal refname. An unreadable global option hides a later
 * word only when it is exactly `push`.
 */
const GIT_PUSH_FORCE_RULE: BashDangerRule = {
	kind: "words",
	id: "git-push-force",
	reason: "git push --force",
	tripwire: inOrder(/\bpush\b/i, /--force(?![-\w])|--force-(?!with-lease)|\s-[a-zA-Z0-9]*f[a-zA-Z0-9]*\b|\s\+/i),
	runs: (seg) => gitRunsIn(seg, { subcommand: "push", argsHit: pushArgsForce, mayBeSubcommand: (word) => word.toLowerCase() === "push" }),
};

const BASH_DANGER_RULES: readonly BashDangerRule[] = [
	{
		kind: "raw",
		id: "rm-recursive",
		pattern: /\brm\b[^;|&]*(\s-(?:[a-zA-Z]*r[a-zA-Z]*f?|[a-zA-Z]*f[a-zA-Z]*r)\b|--recursive)/i,
		reason: "recursive delete (rm -r)",
	},
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

/**
 * Whether a raw-text tripwire matches the command. A tripwire over-approximates its rule and only
 * has to never miss; the word view clears a false trip (ADR-0007). A backslash-newline may split a
 * word in the raw text, so the tripwire also tests the spelling with unescaped continuations removed
 * (an escaped `\\` pair is left alone: the shell splits there, and both views still hit that input).
 */
function tripwireHit(command: string, tripwire: Tripwire): boolean {
	const capped = command.length > BASH_MAX_MATCH_LEN ? command.slice(0, BASH_MAX_MATCH_LEN) : command;
	if (tripwireMatches(capped, tripwire)) return true;
	const joined = capped.replace(/(?<!\\)\\\r?\n/g, "");
	return joined !== capped && tripwireMatches(joined, tripwire);
}

/** Whether a rule hits the command. A `words` rule hits when its tripwire matches and the word view
 *  finds a command that runs it or cannot read the command soundly. */
function ruleHits(rule: BashDangerRule, command: string): boolean {
	switch (rule.kind) {
		case "raw":
			return rule.pattern.test(command);
		case "words":
			return tripwireHit(command, rule.tripwire) && anyCommandIn(shellWords(command), rule.runs);
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
	return ruleHits(GIT_PUSH_FORCE_RULE, command);
}

/** git flags that turn a read-shaped invocation into a write: `--output`/`-o` write a
 *  file, `--exec`/`--ext-diff`/`--textconv` run a program, `--git-dir`/`--work-tree` retarget the
 *  repository. Matched as bare or attached (`--output=…`, `-o…`). The reads outside the work tree and
 *  the configuration that runs a program (`-c`, `--config-env`) are refused by `allowOperandsAdmit`. */
const GIT_WRITE_FLAGS = ["--output", "-o", "--exec", "--ext-diff", "--textconv", "--git-dir", "--work-tree"];

/** The options with which a command runs another program. `words` match a whole word (find's
 *  actions); `long` names match bare, with `=value`, or abbreviated to a unique prefix as getopt
 *  allows; `short` letters match inside a short-option bundle, and for tar also in its old-style first
 *  word (`tar xIf`). */
interface ProgramOptions {
	readonly words?: readonly string[];
	readonly long?: readonly string[];
	readonly short?: RegExp;
	readonly oldStyle?: boolean;
}

const FD_PROGRAM: ProgramOptions = { long: ["--exec", "--exec-batch"], short: /[xX]/ };
const TAR_PROGRAM: ProgramOptions = {
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

const PROGRAM_OPTIONS: Readonly<Record<string, ProgramOptions>> = {
	find: { words: ["-exec", "-execdir", "-ok", "-okdir"] },
	fd: FD_PROGRAM,
	fdfind: FD_PROGRAM,
	rg: { long: ["--pre"] },
	tar: TAR_PROGRAM,
	bsdtar: TAR_PROGRAM,
	gtar: TAR_PROGRAM,
	// zip's `-TT` is one two-letter option, so it matches only spelled out.
	zip: { long: ["--unzip-command"], short: /TT/ },
	rsync: { long: ["--rsh", "--rsync-path"], short: /e/ },
};

/** The shortest long-option prefix read as an abbreviation. */
const MIN_LONG_PREFIX = 5;

/** True when `word` is one of the command's program options. Over-approximates: an option's value
 *  that looks like one also counts, which only sends the call to the classifier. */
function runsProgram(word: string, first: boolean, options: ProgramOptions): boolean {
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
 * command position (`xargs`, `find … -exec`) or an option that runs a program (`fd -x`, `rg --pre`,
 * `tar -I`), or a `git` invocation carrying a write flag. It checks the shape only;
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
	const words = shellWords(command);
	if (hasUnsoundWord(words)) return false;
	// An operator or newline means more than one simple command.
	for (const w of words) {
		if (isShellOperator(w) || w === "\n") return false;
	}
	// A re-parser, or an option that runs a program, runs words the scanner never paired.
	for (let i = 0; i < words.length; i++) {
		const base = wordBasename(words[i]);
		if (base === "xargs") return false;
		const executor = PROGRAM_OPTIONS[base];
		if (executor && words.slice(i + 1).some((w, k) => runsProgram(w, k === 0, executor))) return false;
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
}

/** Cap the danger-regex matching input: the prefix-consuming character
 *  classes plus nested alternations can backtrack quadratically on very long
 *  separator-free strings. Beyond the cap, rule matching is lost and the call
 *  falls to the classifier (fail-closed direction). */
export const BASH_MAX_MATCH_LEN = 8192;

export function classifyBash(command: string, floorOn: boolean): RuleResult {
	if (floorOn) {
		const capped = command.length > BASH_MAX_MATCH_LEN ? command.slice(0, BASH_MAX_MATCH_LEN) : command;
		for (const rule of BASH_DANGER_RULES) {
			if (ruleHits(rule, capped)) return { verdict: "deny", reason: `rule ${rule.id}: ${rule.reason}` };
		}
	}
	if (!command.trim()) return { verdict: "allow", reason: "empty command" };
	// No built-in allowlist: every command the floor passes goes to user rules and the classifier.
	return { verdict: "gray", reason: "no built-in allowlist" };
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
