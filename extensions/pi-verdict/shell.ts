// ============================================================================
// Rule layer: bash
// ============================================================================

/** Dangerous patterns: match the full command string (including pipelines and compound commands); any match denies (from research report §4.3).
 *  `git-push-force` is a `check` instead of a `pattern`: a regex over the raw string cannot tell an
 *  argument from a command (see `gitPushForce` below), so it evaluates a shell-word view instead. */
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
		pattern: /(>\s*\/dev\/(sd|hd|nvme|mmcblk|vd|xvd)|of=\/dev\/(sd|hd|nvme|mmcblk|vd|xvd)|\bmkfs\.)/i,
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
	{ id: "git-reset-hard", pattern: /\bgit\s+reset\s+--hard\b/i, reason: "git reset --hard" },
	{ id: "git-clean-force", pattern: /\bgit\s+clean\b[^;|&]*(\s-[a-zA-Z]*f|--force)/i, reason: "git clean -f" },
	{ id: "git-checkout-dot", pattern: /\bgit\s+checkout\s+(--\s+)?\.(?:\s|$)/i, reason: "git checkout . (discard working tree)" },
	{ id: "git-restore", pattern: /\bgit\s+restore\b/i, reason: "git restore (discard changes)" },
	{ id: "remote-exec", pattern: /\b(curl|wget)\b[^;|&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b/i, reason: "remote code execution (curl|sh)" },
	{ id: "gh-repo", pattern: /\bgh\s+repo\s+(create|delete|rename|archive)\b/i, reason: "GitHub repository-level change" },
	{ id: "gh-release", pattern: /\bgh\s+release\s+(create|delete|edit)\b/i, reason: "GitHub release change" },
	{ id: "fork-bomb", pattern: /:\(\)\s*\{/, reason: "fork bomb" },
];

// ---- git-push-force: shell-word view (fork; 2026-10-04 path-layer review, items 1–2) ----

/** Basename of a command word under both separator conventions (`/usr/bin/git`, `C:\bin\git`). */
function wordBasename(w: string): string {
	const i = Math.max(w.lastIndexOf("/"), w.lastIndexOf("\\"));
	return (i === -1 ? w : w.slice(i + 1)).toLowerCase();
}

const SHELL_NAMES: Record<string, true> = { sh: true, bash: true, zsh: true, dash: true, ksh: true, ash: true };

/**
 * Sentinel word for a construct the scanner cannot resolve faithfully (a command substitution it
 * does not re-parse, a re-parser like `eval`, a here-document, …). It cannot occur in natural
 * output, so `gitPushInWords` treats its presence as a hit: the raw-text tripwire already
 * decided the deny, and an unsound parse may only clear when it is sound (the monotonicity rule).
 */
const UNSOUND = "\u0000unsound\u0000";

/** Command operators: split words and end a command segment. */
const SHELL_OPERATORS: Record<string, true> = { ";": true, ";;": true, "&": true, "&&": true, "|": true, "||": true, "(": true, ")": true };

/**
 * Split a shell command into words at unquoted whitespace and operators, quoting removed
 * (`'a&b'` is one word `a&b`; `$(git …)` yields an operator `(` before the inner words).
 * Deliberately not a shell parser: no glob, process-substitution or brace-expansion modelling, and
 * an unterminated quote consumes the rest of the string. Linear, single pass (bounding is not
 * needed — unlike the danger regexes, it cannot backtrack).
 *
 * A construct the scanner cannot resolve faithfully emits the `UNSOUND` sentinel word instead of a
 * misleading parse. The sound path stays faithful: an unquoted backslash-newline is a line
 * continuation (consumed, appends nothing), a redirection (`>`, `>>`, `<`, `>&`, `<&`, `&>`, `&>>`,
 * `>|`, `<>`, with its fd digits and target word) is dropped without ending a segment, and unquoted
 * `(`/`)` remain plain operators. `gitPushInWords` treats a sentinel as a hit, so the deny only ever
 * stands (the monotonicity rule).
 */
export function shellWords(command: string): string[] {
	const words: string[] = [];
	let cur = "";
	let inWord = false;
	// The next word is a redirection target: the shell opens it, it is not an argument.
	let redirectTarget = false;
	const flush = () => {
		if (inWord) {
			if (redirectTarget) redirectTarget = false;
			else words.push(cur);
			cur = "";
			inWord = false;
		}
	};
	const redirection = (length: number, takesFd: boolean) => {
		if (takesFd && inWord && /^\d+$/.test(cur)) {
			cur = ""; // `2>&1`: the digits name a file descriptor, not an argument
			inWord = false;
		} else {
			flush();
		}
		redirectTarget = true;
		i += length;
	};
	const unsound = () => {
		flush();
		words.push(UNSOUND);
	};
	let i = 0;
	const n = command.length;
	while (i < n) {
		const ch = command[i];
		if (ch === "'") {
			const end = command.indexOf("'", i + 1);
			if (end === -1) {
				unsound(); // unterminated single quote: the rest is not a sound parse
				return words;
			}
			cur += command.slice(i + 1, end);
			inWord = true;
			i = end + 1;
			continue;
		}
		if (ch === "`") {
			unsound(); // backtick command substitution: not re-parsed
			const end = command.indexOf("`", i + 1);
			i = end === -1 ? n : end + 1;
			continue;
		}
		if (ch === '"') {
			i++;
			let closed = false;
			while (i < n) {
				const c = command[i];
				if (c === '"') {
					closed = true;
					i++;
					break;
				}
				if (c === "\\" && i + 1 < n) {
					const nx = command[i + 1];
					if (nx === "\n" || nx === "\r") {
						// line continuation inside double quotes: append nothing
						i += nx === "\r" && command[i + 2] === "\n" ? 3 : 2;
						continue;
					}
					if ('\\"$`'.includes(nx)) {
						cur += nx;
						i += 2;
						continue;
					}
				}
				if (c === "$" && command[i + 1] === "(") {
					unsound(); // command substitution inside double quotes: not re-parsed
					i += 2;
					continue;
				}
				cur += c;
				i++;
			}
			if (!closed) unsound(); // unterminated double quote
			inWord = true;
			continue;
		}
		if (ch === "\\" && i + 1 < n) {
			const nx = command[i + 1];
			if (nx === "\n" || nx === "\r") {
				// unquoted line continuation: consume, append nothing, do NOT end the word
				i += nx === "\r" && command[i + 2] === "\n" ? 3 : 2;
				continue;
			}
			cur += nx;
			inWord = true;
			i += 2;
			continue;
		}
		if (ch === "<" || ch === ">") {
			const next = command[i + 1];
			if (ch === "<" && next === "<") {
				flush();
				unsound(); // here-document: body not re-parsed
				i += 2;
				continue;
			}
			// The `&` of `>&`/`<&` and the `|` of `>|` belong to the redirection, not a command operator.
			const twoChar = ch === ">" ? next === ">" || next === "&" || next === "|" : next === "&" || next === ">";
			redirection(twoChar ? 2 : 1, true);
			continue;
		}
		if (ch === "&" && command[i + 1] === ">") {
			redirection(command[i + 2] === ">" ? 3 : 2, false); // `&>`/`&>>`: stdout and stderr, not a background `&`
			continue;
		}
		if (ch === " " || ch === "\t" || ch === "\r") {
			flush();
			i++;
			continue;
		}
		if (ch === "\n" || SHELL_OPERATORS[ch] === true) {
			flush();
			redirectTarget = false;
			const two = ch + (command[i + 1] ?? "");
			if (two === "&&" || two === "||" || two === ";;") {
				words.push(two);
				i += 2;
			} else {
				words.push(ch);
				i++;
			}
			continue;
		}
		cur += ch;
		inWord = true;
		i++;
	}
	flush();
	markReparsers(words);
	return words;
}

/** `eval` and `env`'s split-string forms re-parse their arguments, which the scanner does not
 *  follow: mark such a segment unsound so the tripwire's deny stands. Post-pass, linear. */
function markReparsers(words: string[]): void {
	let segStart = 0;
	for (let i = 0; i <= words.length; i++) {
		const atEnd = i === words.length;
		if (!atEnd && SHELL_OPERATORS[words[i]] !== true) continue;
		const first = words[segStart];
		if (first !== undefined) {
			const base = wordBasename(first);
			if (base === "eval") {
				words[segStart] = UNSOUND;
			} else if (base === "env" && envSplitsString(words.slice(segStart + 1, i))) {
				words[segStart] = UNSOUND;
			}
		}
		segStart = i + 1;
	}
}

/** env options that take the next word as their argument (GNU coreutils and uutils). */
const ENV_SHORT_WITH_ARG = "uCaf";
const ENV_LONG_WITH_ARG = ["unset", "chdir", "argv0", "file"];

/** Whether env's options, scanned left to right as env parses them, include a split-string form
 *  (`-S`, a bundle reaching `S`, `-S…`, `--split-string[=…]` or a prefix of it). An option that
 *  takes an argument consumes it, so `env -u HOME -S '…'` is found and `env -u -S cmd` is not.
 *  A lowercase `s` also counts: env rejects it, so reading it as a split string only adds a deny. */
function envSplitsString(args: readonly string[]): boolean {
	for (let j = 0; j < args.length; j++) {
		const word = args[j];
		if (word === "--" || word === "-" || !word.startsWith("-")) return false;
		if (word.startsWith("--")) {
			const eq = word.indexOf("=");
			const name = (eq === -1 ? word.slice(2) : word.slice(2, eq)).toLowerCase();
			if ("split-string".startsWith(name)) return true;
			if (eq === -1 && ENV_LONG_WITH_ARG.some((option) => option.startsWith(name))) j++;
			continue;
		}
		for (let k = 1; k < word.length; k++) {
			const c = word[k];
			if (c === "S" || c === "s") return true;
			if (ENV_SHORT_WITH_ARG.includes(c)) {
				if (k === word.length - 1) j++; // the argument is the next word, not attached
				break;
			}
		}
	}
	return false;
}

/** A word that makes `git push` a force push. `--force-with-lease[=ref]` is the only escaping
 *  `--force-*` spelling; every other `--force-*` form is denied rather than handed to the
 *  classifier (an audit boundary: the unbounded lookahead `--force(?![-\w])` exempted unknown
 *  spellings). Short flags are accepted in a bundle (`-f`, `-fu`, `-uf`), but not after an `o`,
 *  which takes the rest of the bundle as its value (`-of`). */
export function isForceFlag(word: string): boolean {
	const t = word.toLowerCase();
	if (/^-[a-np-z]*f[a-z]*$/.test(t)) return true;
	if (/^--force-with-lease(?:=|$)/.test(t)) return false;
	if (t === "--force-if-includes") return false; // no-op without a lease (git documents it)
	if (/^\+./.test(t)) return true; // a `+` refspec forces the update (F24)
	return /^--force(?![-\w])/.test(t) || t.startsWith("--force-");
}

/** git's global options that take the next word as their value (or an attached `=value`). */
const GIT_GLOBAL_WITH_VALUE = new Set(["-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config-env", "--attr-source"]);
/** git's global options that take no separate value. */
const GIT_GLOBAL_FLAGS = new Set([
	"-p",
	"--paginate",
	"--no-pager",
	"--bare",
	"--no-replace-objects",
	"--no-lazy-fetch",
	"--no-optional-locks",
	"--no-advice",
	"--literal-pathspecs",
	"--glob-pathspecs",
	"--noglob-pathspecs",
	"--icase-pathspecs",
	"--exec-path",
	"--list-cmds",
	"--html-path",
	"--man-path",
	"--info-path",
	"-v",
	"--version",
	"-h",
	"--help",
]);

/** Index of the subcommand word for the `git` at `seg[at]`, read past git's global options
 *  (compared case-folded, so `-C` and `-c`, `-P` and `-p` share an entry); -1 when none follows.
 *  Fails closed: an option it does not model returns `undefined`, since it may take a value. */
function gitSubcommandIndex(seg: readonly string[], at: number): number | undefined {
	for (let k = at + 1; k < seg.length; k++) {
		const word = seg[k].toLowerCase();
		if (!word.startsWith("-")) return k;
		const eq = word.startsWith("--") ? word.indexOf("=") : -1;
		const name = eq === -1 ? word : word.slice(0, eq);
		if (GIT_GLOBAL_WITH_VALUE.has(name)) {
			if (eq === -1) k++;
		} else if (!GIT_GLOBAL_FLAGS.has(name)) {
			return undefined;
		}
	}
	return -1;
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

function commandSegments(words: string[]): string[][] {
	const segs: string[][] = [];
	let cur: string[] = [];
	for (const w of words) {
		if (SHELL_OPERATORS[w] === true) {
			if (cur.length) segs.push(cur);
			cur = [];
		} else {
			cur.push(w);
		}
	}
	if (cur.length) segs.push(cur);
	return segs;
}

const GIT_PUSH_RECURSION_DEPTH = 3;

/**
 * Raw-text tripwire: a coarse net that over-approximates a force push. Anchored on a `push`
 * word with a fully flexible body (so `git --git-dir=X push …` and `-c/-C` gaps need no special
 * handling), terminated by any of: a bare `--force`; another `--force-*` form (the invented
 * spelling included — only `--force-with-lease` is exempt); a bundled short `f` flag (`-f`, `-fu`,
 * `-uf`, and `-f>/dev/null`); or a `+` refspec word. Quoted content does not break it (the `a&b`
 * refname is a genuine force push). The tokenised word view owns pairing precision — this only
 * has to never MISS; a false trip is cleared by the word view.
 *
 * Continuation tolerance: a backslash-newline may split a flag in the raw text, so the tripwire
 * also tests the spelling with UNESCAPED continuations removed (an escaped `\\` pair is left
 * alone — the shell splits there, and both views still hit that input).
 */
function tripwireHit(command: string): boolean {
	const capped = command.length > BASH_MAX_MATCH_LEN ? command.slice(0, BASH_MAX_MATCH_LEN) : command;
	const pattern = /\bpush\b[\s\S]*?(?:--force(?![-\w])|--force-(?!with-lease)|\s-[a-zA-Z]*f[a-zA-Z]*\b|\s\+)/i;
	if (pattern.test(capped)) return true;
	const joined = capped.replace(/(?<!\\)\\\r?\n/g, "");
	return joined !== capped && pattern.test(joined);
}

/**
 * `git push` with a force flag. The raw-text tripwire decides every hit (the monotonicity rule:
 * a floor change may never turn a raw-text hit into a non-hit on an unsound parse); the tokenised
 * word view may only CLEAR a hit when its parse is sound, and CONFIRM one. Two review findings
 * motivate the word view over a bare regex: a legal refname may contain a shell separator
 * (`git push origin 'a&b' --force`), and text the shell never runs as a command
 * (`git commit -m '… git push --force …'`) must not be denied.
 */
export function gitPushForce(command: string): boolean {
	if (!tripwireHit(command)) return false;
	return gitPushInWords(shellWords(command), 0);
}

function gitPushInWords(words: string[], depth: number): boolean {
	if (words.includes(UNSOUND)) return true; // unsound parse: the tripwire's deny stands
	for (const seg of commandSegments(words)) {
		for (let i = 0; i + 1 < seg.length; i++) {
			if (wordBasename(seg[i]) !== "git") continue;
			const sub = gitSubcommandIndex(seg, i);
			if (sub === undefined) return true; // an unmodelled git option may hide the subcommand: unsound
			if (sub !== -1 && seg[sub].toLowerCase() === "push" && pushArgsForce(seg.slice(sub + 1))) return true;
		}
		for (let i = 0; i < seg.length; i++) {
			if (SHELL_NAMES[wordBasename(seg[i])] !== true) continue;
			// Scan the shell's options; `-o`/`-O`/`+o`/`--rcfile`/`--init-file` consume the next word.
			// A dash-word the scan does not model is unsound (deny stands) rather than silently skipped
			// (covers `bash -o pipefail -c …`, `sh -O extglob -c …`, `bash --rcfile x -c …`).
			let hasReparseOption = false;
			let unknownOption = false;
			for (let j = i + 1; j < seg.length; j++) {
				const opt = seg[j].toLowerCase();
				if (!opt.startsWith("-") && !opt.startsWith("+")) break; // options ended
				if (opt === "-o" || opt === "-O" || opt === "+o" || opt === "--rcfile" || opt === "--init-file") {
					j++; // consumes its argument
					continue;
				}
				if (/^-[a-z]*c[a-z]*$/.test(opt)) {
					hasReparseOption = true;
					break;
				}
				unknownOption = true;
			}
			if (unknownOption) return true; // unmodelled shell option: unsound
			if (!hasReparseOption) continue;
			if (depth >= GIT_PUSH_RECURSION_DEPTH) return true; // recursion cap: unsound
			for (let j = i + 1; j < seg.length; j++) {
				const opt = seg[j].toLowerCase();
				if (!opt.startsWith("-")) break;
				if (/^-[a-z]*c[a-z]*$/.test(opt) && seg[j + 1] !== undefined) {
					const template = seg[j + 1];
					// A `-c` template that references positionals forwards data the scanner cannot see.
					if (/\$\{[0-9]+\}|\$[0-9]+|\$@|\$\*/.test(template)) return true;
					if (gitPushInWords(shellWords(template), depth + 1)) return true;
					break;
				}
				if (opt === "-o" || opt === "-O" || opt === "+o" || opt === "--rcfile" || opt === "--init-file") j++;
			}
		}
	}
	return false;
}

/** git flags that turn a read-shaped invocation into a write (audit V7): `--output`/`-o` write a
 *  file, `--exec`/`--ext-diff`/`--textconv` run a program, `--git-dir`/`--work-tree` retarget the
 *  repository. Matched as bare or attached (`--output=…`, `-o…`). */
const GIT_WRITE_FLAGS = ["--output", "-o", "--exec", "--ext-diff", "--textconv", "--git-dir", "--work-tree"];

/**
 * Whether a user `allow` regex may admit this command (audit F2, ADR-0008). The allow layer tests
 * raw command text, so a regex anchored on the first word (`^ls\b`) would otherwise admit a whole
 * compound command — `ls\nbash /tmp/evil.sh`, `ls & npm install …`, `ls $(…)` — with no model
 * judgment, and a read-shaped `git log --output=<path>` would admit a write. An allow is granted
 * only for ONE simple command: false (allow skipped → the call reaches the classifier) on an
 * operator or newline, an unsound parse, a redirection other than to `/dev/null`, a re-parser in
 * command position (`xargs`, `find … -exec`), or a `git` invocation carrying a write flag.
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
	if (words.includes(UNSOUND)) return false;
	// (a) any operator or newline: more than one simple command.
	for (const w of words) {
		if (SHELL_OPERATORS[w] === true || w === "\n") return false;
	}
	// (d) a re-parser in command position: it runs words the scanner never paired.
	for (let i = 0; i < words.length; i++) {
		const base = wordBasename(words[i]);
		if (base === "xargs") return false;
		if (base === "find") {
			for (let j = i + 1; j < words.length; j++) {
				if (words[j] === "-exec" || words[j] === "-execdir") return false;
			}
		}
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
