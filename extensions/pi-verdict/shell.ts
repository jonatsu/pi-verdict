// ============================================================================
// Rule layer: bash
// ============================================================================

import {
	anyCommandIn,
	type GitInvocation,
	gitRunsIn,
	hasUnsoundWord,
	isShellOperator,
	mayExpand,
	shellWords,
	wordBasename,
} from "./shell-words.ts";

/** Dangerous commands; any hit denies. A `pattern` matches the full command string, pipelines and
 *  compound commands included. A `check` pairs a raw-text tripwire with a shell-word view that clears
 *  quoted text the shell never runs as the command (ADR-0007). */
type BashDangerRule = { id: string; reason: string; pattern?: RegExp; check?: (command: string) => boolean };
const BASH_DANGER_RULES: BashDangerRule[] = [
	{
		id: "rm-recursive",
		pattern: /\brm\b[^;|&]*(\s-(?:[a-zA-Z]*r[a-zA-Z]*f?|[a-zA-Z]*f[a-zA-Z]*r)\b|--recursive)/i,
		reason: "recursive delete (rm -r)",
	},
	{
		id: "rm-root",
		pattern: /\brm\s+(-[a-zA-Z]*\s+)*(--recursive\s+)?(\/|\/etc|\/usr|\/var|~|\$HOME)(?:\s|$)/i,
		reason: "delete root/system/home directory",
	},
	{ id: "sudo", pattern: /\bsudo\b/i, reason: "privilege escalation (sudo)" },
	{
		id: "chmod-777",
		pattern: /\bchmod\b[^;|&]*(777|a\+rwx|ugo\+rwx|ugo=rwx|[ug]\+s)\b/i,
		reason: "permission weakening (chmod 777/setuid)",
	},
	{
		id: "raw-device",
		pattern: /(>\s*\/dev\/(sd|hd|nvme|mmcblk|vd|xvd|r?disk[0-9])|of=\/dev\/(sd|hd|nvme|mmcblk|vd|xvd|r?disk[0-9])|\bmkfs\.)/i,
		reason: "raw device write/format",
	},
	// Fork fix: `git-push-force` is checked on a shell-word view, not a regex over the raw string.
	// A regex cannot tell an argument from a command: `git push origin 'a&b' --force` (a legal refname
	// containing `&`) evaded a `[^;|&]*` class, while `git commit -m '… git push --force …'` was denied
	// although the quoted text is only an argument. `gitPushForce` splits the command into words and
	// operators, so quoted separators do not split a command and a quoted argument is not re-read as
	// one — except a shell's own `-c` string (`sh -c 'git push --force …'`), which IS a command and is
	// recursed into. `--force-with-lease[=ref]` is the only escaping `--force-*` spelling; every other
	// `--force-*` form stays denied (explicit is better than an unbounded lookahead).
	{ id: "git-push-force", reason: "git push --force", check: gitPushForce },
	// Each tripwire allows any gap between `git` and its subcommand, so `git -C dir …` and `git -c k=v …`
	// reach the word view; `gitRule` decides which `git` really runs the subcommand.
	{
		id: "git-reset-hard",
		check: gitRule(/\bgit\b[\s\S]*?\breset\b[\s\S]*?--hard\b/i, "reset", (args) => args.some((arg) => arg.toLowerCase() === "--hard")),
		reason: "git reset --hard",
	},
	// Pattern from eugeniughelbur/jev-engineering@82655a6d policy.json (MIT, Copyright (c) 2026 Eugeniu Ghelbur).
	{
		id: "git-stash-clear",
		check: gitRule(/\bgit\b[\s\S]*?\bstash\b[\s\S]*?\bclear\b/i, "stash", (args) => firstOperandIs(args, ["clear"])),
		reason: "git stash clear (drops all stashes)",
	},
	{
		id: "git-clean-force",
		check: gitRule(/\bgit\b[\s\S]*?\bclean\b[\s\S]*?(?:\s['"]?-[a-zA-Z]*f|--force)/i, "clean", (args) =>
			args.some((arg) => /^-[a-z]*f|^--force/i.test(arg)),
		),
		reason: "git clean -f",
	},
	{
		// Any `.` argument discards changes, `git checkout -- .` and `git checkout HEAD -- .` included.
		id: "git-checkout-dot",
		check: gitRule(/\bgit\b[\s\S]*?\bcheckout\b[\s\S]*?[\s'"]\.(?=[\s'"`;|&)]|$)/i, "checkout", (args) => args.includes(".")),
		reason: "git checkout . (discard working tree)",
	},
	{ id: "git-restore", check: gitRule(/\bgit\b[\s\S]*?\brestore\b/i, "restore", () => true), reason: "git restore (discard changes)" },
	// `raw-device`, `remote-exec`, `env-exfil` and `fork-bomb` stay raw-text only: their meaning spans a
	// pipe, a redirection or a function definition, which the word view splits or drops, so it cannot
	// show that such a hit is harmless (ADR-0007).
	{ id: "remote-exec", pattern: /\b(curl|wget)\b[^;|&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b/i, reason: "remote code execution (curl|sh)" },
	// Matches the environment or the shell history piped into a network tool: one pipe or `|&` (not the
	// `||` operator), on the same logical line (a backslash-newline continues it), to a bare or
	// path-qualified tool name. Trivially evaded (`env > f; curl -T f …`); it only removes the one-line
	// spelling from the classifier's judgement.
	// Pattern from eugeniughelbur/jev-engineering@82655a6d policy.json (MIT, Copyright (c) 2026 Eugeniu Ghelbur).
	{
		id: "env-exfil",
		pattern: /\b(env|printenv|history)\b(?:[^;&\n]|\\\n)*(?<!\|)\|&?\s*(?:[\w./-]*\/)?(curl|wget|nc|ncat)\b/i,
		reason: "environment or history piped to a network tool",
	},
	{
		id: "gh-repo",
		check: ghRule(/\bgh\b[\s\S]*?\brepo\b[\s\S]*?\b(?:create|delete|rename|archive)\b/i, "repo", ["create", "delete", "rename", "archive"]),
		reason: "GitHub repository-level change",
	},
	{
		id: "gh-release",
		check: ghRule(/\bgh\b[\s\S]*?\brelease\b[\s\S]*?\b(?:create|delete|edit)\b/i, "release", ["create", "delete", "edit"]),
		reason: "GitHub release change",
	},
	{ id: "fork-bomb", pattern: /:\(\)\s*\{/, reason: "fork bomb" },
];

/** A floor check that the raw-text `tripwire` decides and the word view may clear: true when the
 *  tripwire hits and some command, or an unsound parse, satisfies `segmentHit` (ADR-0007). */
function wordRule(tripwire: RegExp, segmentHit: (seg: readonly string[]) => boolean): (command: string) => boolean {
	return (command) => tripwireHit(command, tripwire) && anyCommandIn(shellWords(command), segmentHit);
}

/** A floor check for `git <subcommand>` whose arguments pass `argsHit`. An unreadable global option
 *  keeps the deny when any later word contains the subcommand's name (`git $X stash clear`). */
function gitRule(tripwire: RegExp, subcommand: string, argsHit: (args: readonly string[]) => boolean): (command: string) => boolean {
	const invocation: GitInvocation = { subcommand, argsHit, mayBeSubcommand: (word) => word.toLowerCase().includes(subcommand) };
	return wordRule(tripwire, (seg) => gitRunsIn(seg, invocation));
}

/** Whether the first word after the options is one of `names`, or may expand to one. */
function firstOperandIs(args: readonly string[], names: readonly string[]): boolean {
	const operand = args.find((arg) => !arg.startsWith("-"));
	return operand !== undefined && (names.includes(operand.toLowerCase()) || mayExpand(operand));
}

/** gh options that take the next word as their value, compared case-folded (`-R`). */
const GH_OPTIONS_WITH_VALUE = new Set(["-r", "--repo"]);

/** Index of the action word in `seg` from `from` on, read past `--repo` and its value; -1 when none
 *  follows. Fails closed: another option may take a value, so it returns `undefined`. */
function ghActionIndex(seg: readonly string[], from: number): number | undefined {
	for (let k = from; k < seg.length; k++) {
		const word = seg[k].toLowerCase();
		if (!word.startsWith("-")) return k;
		if (GH_OPTIONS_WITH_VALUE.has(word)) k++;
		else if (!word.startsWith("--repo=") && !/^-r./.test(word)) return undefined;
	}
	return -1;
}

/** A floor check for `gh <group> <action>`. Fails closed: when a word before the group or the action
 *  cannot be read, a later word that contains the group or an action name keeps the deny. */
function ghRule(tripwire: RegExp, group: string, actions: readonly string[]): (command: string) => boolean {
	const mentions = (names: readonly string[]) => (word: string) => names.some((name) => word.toLowerCase().includes(name));
	return wordRule(tripwire, (seg) => {
		for (let i = 0; i + 1 < seg.length; i++) {
			if (wordBasename(seg[i]) !== "gh") continue;
			const first = seg[i + 1].toLowerCase();
			if (first.startsWith("-") || mayExpand(first)) {
				if (seg.slice(i + 1).some(mentions([group]))) return true;
				continue;
			}
			if (first !== group) continue;
			const action = ghActionIndex(seg, i + 2);
			if (action === undefined) {
				if (seg.slice(i + 2).some(mentions(actions))) return true;
			} else if (action !== -1 && firstOperandIs([seg[action]], actions)) {
				return true;
			}
		}
		return false;
	});
}

/** A word that makes `git push` a force push. `--force-with-lease[=ref]` is the only escaping
 *  `--force-*` spelling; every other `--force-*` form is denied rather than handed to the
 *  classifier (an audit boundary: the unbounded lookahead `--force(?![-\w])` exempted unknown
 *  spellings). Short flags are accepted in a bundle (`-f`, `-fu`, `-uf`, `-4f`), but not after an `o`,
 *  which takes the rest of the bundle as its value (`-of`). */
export function isForceFlag(word: string): boolean {
	const t = word.toLowerCase();
	if (/^-[a-np-z0-9]*f[a-z0-9]*$/.test(t)) return true;
	if (/^--force-with-lease(?:=|$)/.test(t)) return false;
	if (t === "--force-if-includes") return false; // no-op without a lease (git documents it)
	if (/^\+./.test(t)) return true; // a `+` refspec forces the update (F24)
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

/**
 * Whether a raw-text tripwire matches the command. A tripwire over-approximates its rule and only
 * has to never miss; the word view clears a false trip (ADR-0007). A backslash-newline may split a
 * word in the raw text, so the tripwire also tests the spelling with unescaped continuations removed
 * (an escaped `\\` pair is left alone: the shell splits there, and both views still hit that input).
 */
function tripwireHit(command: string, pattern: RegExp): boolean {
	const capped = command.length > BASH_MAX_MATCH_LEN ? command.slice(0, BASH_MAX_MATCH_LEN) : command;
	if (pattern.test(capped)) return true;
	const joined = capped.replace(/(?<!\\)\\\r?\n/g, "");
	return joined !== capped && pattern.test(joined);
}

/**
 * Force-push tripwire. Anchored on a `push` word with a fully flexible body (so
 * `git --git-dir=X push …` and `-c/-C` gaps need no special handling), terminated by any of: a bare
 * `--force`; another `--force-*` form (only `--force-with-lease` is exempt); a bundled short `f` flag
 * (`-f`, `-fu`, `-uf`, `-4f`, and `-f>/dev/null`); or a `+` refspec word. Quoted content does not
 * break it (the `a&b` refname is a genuine force push).
 */
const PUSH_FORCE_TRIPWIRE = /\bpush\b[\s\S]*?(?:--force(?![-\w])|--force-(?!with-lease)|\s-[a-zA-Z0-9]*f[a-zA-Z0-9]*\b|\s\+)/i;

/** The `git push` invocation with a force flag; an unreadable global option hides a later `push` word. */
const GIT_PUSH_FORCE: GitInvocation = {
	subcommand: "push",
	argsHit: pushArgsForce,
	mayBeSubcommand: (word) => word.toLowerCase() === "push",
};

/**
 * `git push` with a force flag. The raw-text tripwire decides every hit (the monotonicity rule:
 * a floor change may never turn a raw-text hit into a non-hit on an unsound parse); the tokenised
 * word view may only CLEAR a hit when its parse is sound, and CONFIRM one. Two review findings
 * motivate the word view over a bare regex: a legal refname may contain a shell separator
 * (`git push origin 'a&b' --force`), and text the shell never runs as a command
 * (`git commit -m '… git push --force …'`) must not be denied.
 */
export function gitPushForce(command: string): boolean {
	if (!tripwireHit(command, PUSH_FORCE_TRIPWIRE)) return false;
	return anyCommandIn(shellWords(command), (seg) => gitRunsIn(seg, GIT_PUSH_FORCE));
}

/** git flags that turn a read-shaped invocation into a write (audit V7): `--output`/`-o` write a
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
 * Whether a user `allow` regex may admit this command (audit F2, ADR-0008). The allow layer tests
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
 * classifier. Redirect TARGETS are not graded here (they ride the classifier); deterministic target
 * grading is deferred with the host-adapter round (recorded in ADR-0008).
 */
export function allowAdmits(command: string): boolean {
	if (!command.trim()) return false;
	// (c) redirection other than to /dev/null — checked on the raw text: the scanner drops `<`/`>`.
	const stripped = command.replace(/\d?&?>>?\s*\/dev\/null/g, "").replace(/<\s*\/dev\/null/g, "");
	if (/[<>]/.test(stripped)) return false;
	// POSIX sh reads `&>` as a background `&` and then a redirection, so a word after it may run as
	// a second command; only the shell-word view reads it as one redirection.
	if (command.includes("&>")) return false;
	const words = shellWords(command);
	// (b) an unsound parse: the scanner could not resolve a construct faithfully.
	if (hasUnsoundWord(words)) return false;
	// (a) any operator or newline: more than one simple command.
	for (const w of words) {
		if (isShellOperator(w) || w === "\n") return false;
	}
	// (d) a re-parser in command position, or an option that runs a program: either runs words the
	// scanner never paired.
	for (let i = 0; i < words.length; i++) {
		const base = wordBasename(words[i]);
		if (base === "xargs") return false;
		const executor = PROGRAM_OPTIONS[base];
		if (executor && words.slice(i + 1).some((w, k) => runsProgram(w, k === 0, executor))) return false;
	}
	// (e) a git invocation carrying a write flag (V7).
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
	/** Named only on verdict:"ask": which rule-layer ask this is (ask-source seam). Every
	 *  producer names its own source; an unset value maps to "protected-path" so older call
	 *  sites this seam does not yet know about keep today's label (Claude-review R2-9). */
	askSource?: "protected-path" | "rule";
}

/** Cap the danger-regex matching input (#25): the prefix-consuming character
 *  classes plus nested alternations can backtrack quadratically on very long
 *  separator-free strings. Beyond the cap, rule matching is lost and the call
 *  falls to the classifier (fail-closed direction). */
export const BASH_MAX_MATCH_LEN = 8192;

export function classifyBash(command: string, floorOn: boolean): RuleResult {
	if (floorOn) {
		const capped = command.length > BASH_MAX_MATCH_LEN ? command.slice(0, BASH_MAX_MATCH_LEN) : command;
		for (const rule of BASH_DANGER_RULES) {
			const hit = rule.check ? rule.check(capped) : rule.pattern!.test(capped);
			if (hit) return { verdict: "deny", reason: `rule ${rule.id}: ${rule.reason}` };
		}
	}
	if (!command.trim()) return { verdict: "allow", reason: "empty command" };
	// No built-in allowlist (#12): all non-dangerous commands go to user rules and the classifier.
	return { verdict: "gray", reason: "no built-in allowlist" };
}

/** Direct shell APIs in py cell text: omp injects `__omp_shell` into the cell
 *  namespace, and subprocess/os.system stay importable — a model can shell out without a `!`
 *  line. A tripwire, not a parser: the whole line is pushed and the danger rules (regexes over
 *  text) do the matching. */
const PY_SHELL_API = /(^|[^\w.])(__omp_shell\s*\(|subprocess\.(?:Popen|run|call|check_call|check_output)\s*\(|os\.system\s*\()/;

/** Extracts the shell-executing lines of an omp `eval {language:"py"}` cell (item 4, F13):
 *  the bash floor applies to these, never to the whole code text. Self-contained per
 *  constraint 3 (own constants/parser, no host import) and verified 2026-10-05 against the
 *  oh-my-pi v18.6.1 source (`coding-agent/src/eval/py/runner.py`'s `transform_cell`, the
 *  `_LINE_MAGICS`/`_CELL_MAGICS` registries) — **not** the plan draft's `%sh`/`%%sh`: that
 *  version has no such magic, line or cell (`_LINE_MAGICS` has no "sh" entry; `_CELL_MAGICS`
 *  registers only "bash" as shell-executing — `capture`/`timeit`/`writefile` parse their body
 *  as plain Python with no re-transform, so they cannot nest a nested `!`/`%%bash`). Three forms:
 *  a line starting with `!` (optionally `name = !cmd`) is a one-line shell-out, the text after
 *  `!` the command; a `%%bash` line is a cell magic — every line from the next one to the end
 *  of the cell is bash script text verbatim (cell magics consume the remainder of the cell); a
 *  direct shell-API call (`__omp_shell(`, `subprocess.*`, `os.system(`), whole
 *  line pushed. js cells get no equivalent extraction — recorded residual (ADR-0009 Phase 3
 *  amendment): their code text still feeds user `deny`/`denyPaths`/`.omp` and the classifier.
 *  A plain line scan, not the real tokenizer (which is string/comment-aware via Python's own
 *  `tokenize` module) — a `!`/`%%bash` spelling inside a string literal or comment is a false
 *  positive here, the safe direction (more scrutiny, not less); this is a tripwire over a
 *  cooperating-but-untrusted model's code, not a sandbox proof (ADR-0001 caveat, ADR-0007
 *  precedent: a raw-text tripwire decides every hit). Backslash line-continuation folding
 *  (`_fold_continuations` in the real source) is not reproduced — a continued `!`-line is
 *  scanned line by line instead, which only widens what counts as a candidate shell line. */
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
