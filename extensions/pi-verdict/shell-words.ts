// ============================================================================
// Shell-word view: tokenizer, command segments, git and shell invocations
// ============================================================================

/** Basename of a command word under both separator conventions (`/usr/bin/git`, `C:\bin\git`). */
export function wordBasename(w: string): string {
	const i = Math.max(w.lastIndexOf("/"), w.lastIndexOf("\\"));
	return (i === -1 ? w : w.slice(i + 1)).toLowerCase();
}

const SHELL_NAMES: ReadonlySet<string> = new Set(["sh", "bash", "zsh", "dash", "ksh", "ash"]);

/**
 * Sentinel word for a construct the scanner cannot resolve faithfully (a command substitution it
 * does not re-parse, a re-parser like `eval`, a here-document, …). It cannot occur in natural
 * output, so `anyCommandIn` treats its presence as a hit: the raw-text tripwire already decided
 * the deny, and an unsound parse may only clear when it is sound (ADR-0007).
 */
const UNSOUND = "\u0000unsound\u0000";

/** Whether the scanner marked any construct in `words` as one it could not resolve faithfully. */
export function hasUnsoundWord(words: readonly string[]): boolean {
	return words.includes(UNSOUND);
}

/** Command operators: split words and end a command segment. */
const SHELL_OPERATORS: ReadonlySet<string> = new Set([";", ";;", "&", "&&", "|", "||", "(", ")"]);

/** Whether a scanned word is a command operator. */
export function isShellOperator(word: string): boolean {
	return SHELL_OPERATORS.has(word);
}

/** Length of a backslash-newline line continuation starting at `i` (`\` then LF, CR or CRLF), 0 when there is none. */
function continuationLength(command: string, i: number): number {
	if (command[i] !== "\\") return 0;
	const nx = command[i + 1];
	if (nx === "\r") return command[i + 2] === "\n" ? 3 : 2;
	return nx === "\n" ? 2 : 0;
}

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
 * `(`/`)` remain plain operators. `anyCommandIn` treats a sentinel as a hit, so the deny only ever
 * stands (ADR-0007).
 */
export function shellWords(command: string): string[] {
	const words: string[] = [];
	const n = command.length;
	let i = 0;
	let cur = "";
	let inWord = false;
	// The next word is a redirection target: the shell opens it, it is not an argument.
	let redirectTarget = false;
	// The current word holds a quoted or escaped character, so it cannot be a redirection's fd prefix.
	let curQuoted = false;
	const flush = () => {
		if (inWord) {
			if (redirectTarget) redirectTarget = false;
			else words.push(cur);
			cur = "";
			inWord = false;
		}
		curQuoted = false;
	};
	const redirection = (length: number, takesFd: boolean) => {
		if (takesFd && inWord && !curQuoted && /^(?:\d+|\{[A-Za-z_][A-Za-z0-9_]*\})$/.test(cur)) {
			cur = ""; // `2>&1`, `{fd}>x`: an unquoted fd number or bash fd variable, not an argument
			inWord = false;
			curQuoted = false;
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
	while (i < n) {
		const ch = command[i];
		if (ch === "#" && !inWord) {
			// An unquoted `#` that starts a word starts a comment to the end of the line, as in bash
			// (`a#b` is one word), so a quote inside the comment opens nothing.
			const end = command.indexOf("\n", i);
			i = end === -1 ? n : end;
			continue;
		}
		if (ch === "$" && command[i + 1] === "'") {
			// `$'…'` reads backslash escapes (`$'\''` is one quote), which this scanner does not model.
			unsound();
			return words;
		}
		if (ch === "'") {
			const end = command.indexOf("'", i + 1);
			if (end === -1) {
				unsound(); // unterminated single quote: the rest is not a sound parse
				return words;
			}
			cur += command.slice(i + 1, end);
			inWord = true;
			curQuoted = true;
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
				const continuation = continuationLength(command, i);
				if (continuation > 0) {
					i += continuation; // a line continuation inside double quotes appends nothing
					continue;
				}
				if (c === "\\" && i + 1 < n && '\\"$`'.includes(command[i + 1])) {
					cur += command[i + 1];
					i += 2;
					continue;
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
			curQuoted = true;
			continue;
		}
		if (ch === "\\" && i + 1 < n) {
			const continuation = continuationLength(command, i);
			if (continuation > 0) {
				i += continuation; // an unquoted line continuation appends nothing and does not end the word
				continue;
			}
			cur += command[i + 1];
			inWord = true;
			curQuoted = true;
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
		if (ch === "\n" || SHELL_OPERATORS.has(ch)) {
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
		if (!atEnd && !SHELL_OPERATORS.has(words[i])) continue;
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

/** Whether a word holds an expansion or a glob, so the shell may turn it into no word or several. */
export function mayExpand(word: string): boolean {
	return /[$*?[{]/.test(word);
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
 *  Fails closed: an option it does not model returns `undefined`, since it may take a value, and so
 *  does a word holding an expansion or glob, which can expand to no word or to several. */
export function gitSubcommandIndex(seg: readonly string[], at: number): number | undefined {
	for (let k = at + 1; k < seg.length; k++) {
		const word = seg[k].toLowerCase();
		if (mayExpand(word)) return undefined;
		if (!word.startsWith("-")) return k;
		const eq = word.startsWith("--") ? word.indexOf("=") : -1;
		const name = eq === -1 ? word : word.slice(0, eq);
		if (GIT_GLOBAL_WITH_VALUE.has(name)) {
			if (eq === -1) k++;
			if (k < seg.length && mayExpand(seg[k])) return undefined;
		} else if (!GIT_GLOBAL_FLAGS.has(name)) {
			return undefined;
		}
	}
	return -1;
}

/** A `git` subcommand and the test its arguments must pass for a rule to hit. */
export interface GitInvocation {
	/** The subcommand, lower case. */
	readonly subcommand: string;
	/** Whether the words after the subcommand make the call a hit. */
	readonly argsHit: (args: readonly string[]) => boolean;
	/** Whether a word after an unreadable global option could be the subcommand. */
	readonly mayBeSubcommand: (word: string) => boolean;
}

/** Whether a command segment runs `git` with the invocation's subcommand and hitting arguments.
 *  Fails closed: when git's global options cannot be read, any later word that may be the
 *  subcommand counts as a hit. */
export function gitRunsIn(seg: readonly string[], invocation: GitInvocation): boolean {
	for (let i = 0; i + 1 < seg.length; i++) {
		if (wordBasename(seg[i]) !== "git") continue;
		const sub = gitSubcommandIndex(seg, i);
		if (sub === undefined) {
			if (seg.slice(i + 1).some(invocation.mayBeSubcommand)) return true;
			continue;
		}
		if (sub !== -1 && seg[sub].toLowerCase() === invocation.subcommand && invocation.argsHit(seg.slice(sub + 1))) return true;
	}
	return false;
}

/** A predicate that is true for a word containing any of `names`, compared case-folded. */
export function mentionsAny(names: readonly string[]): (word: string) => boolean {
	return (word) => {
		const folded = word.toLowerCase();
		return names.some((name) => folded.includes(name));
	};
}

/** Whether the first word after the options is one of `names`, or may expand to one. */
export function firstOperandIs(args: readonly string[], names: readonly string[]): boolean {
	const operand = args.find((arg) => !arg.startsWith("-"));
	return operand !== undefined && (names.includes(operand.toLowerCase()) || mayExpand(operand));
}

/** A `gh <group> <action>` command, names lower case. */
export interface GhInvocation {
	readonly group: string;
	readonly actions: readonly string[];
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

/** Whether a command segment runs `gh` with the invocation's group and one of its actions. Fails
 *  closed: when a word before the group or the action cannot be read, a later word that contains the
 *  group or an action name counts as a hit. */
export function ghRunsIn(seg: readonly string[], invocation: GhInvocation): boolean {
	for (let i = 0; i + 1 < seg.length; i++) {
		if (wordBasename(seg[i]) !== "gh") continue;
		const first = seg[i + 1].toLowerCase();
		if (first.startsWith("-") || mayExpand(first)) {
			if (seg.slice(i + 1).some(mentionsAny([invocation.group]))) return true;
			continue;
		}
		if (first !== invocation.group) continue;
		const action = ghActionIndex(seg, i + 2);
		if (action === undefined) {
			if (seg.slice(i + 2).some(mentionsAny(invocation.actions))) return true;
		} else if (action !== -1 && firstOperandIs([seg[action]], invocation.actions)) {
			return true;
		}
	}
	return false;
}

/** Split words into simple commands at every operator and unquoted newline. */
function commandSegments(words: readonly string[]): string[][] {
	const segs: string[][] = [];
	let cur: string[] = [];
	for (const w of words) {
		if (SHELL_OPERATORS.has(w) || w === "\n") {
			if (cur.length) segs.push(cur);
			cur = [];
		} else {
			cur.push(w);
		}
	}
	if (cur.length) segs.push(cur);
	return segs;
}

/** Shell options that take the next word as their argument, compared case-folded (`-o`/`-O`, `+o`/`+O`). */
const SHELL_OPTIONS_WITH_ARG = new Set(["-o", "+o", "--rcfile", "--init-file"]);

/** What a shell word's options say about the script it runs; `at` is the script word's index. */
type ShellScript = { kind: "none" } | { kind: "unsound" } | { kind: "script"; text: string | undefined; at: number };

/**
 * Read the options after the shell at `seg[at]`. A `-c` bundle makes the next word a script the shell
 * runs (`text` is undefined when no word follows). Fails closed: an option this scan does not model
 * may take a value, so it is unsound (`bash --norc -c …`), and so is a script that references
 * positionals, since it forwards data the scanner cannot see.
 */
function shellScriptAt(seg: readonly string[], at: number): ShellScript {
	for (let j = at + 1; j < seg.length; j++) {
		const opt = seg[j].toLowerCase();
		if (!opt.startsWith("-") && !opt.startsWith("+")) return { kind: "none" };
		if (SHELL_OPTIONS_WITH_ARG.has(opt)) {
			j++;
			continue;
		}
		if (!/^-[a-z]*c[a-z]*$/.test(opt)) return { kind: "unsound" };
		const text = seg[j + 1];
		if (text === undefined) return { kind: "script", text: undefined, at: j + 1 };
		if (/\$\{[0-9]+\}|\$[0-9]+|\$@|\$\*/.test(text)) return { kind: "unsound" };
		return { kind: "script", text, at: j + 1 };
	}
	return { kind: "none" };
}

/** An option whose value is text the program never runs: its long name, which also takes `=value`,
 *  and its short letter, case-sensitive, which takes the next word or the rest of its bundle. */
interface TextOptions {
	readonly long: readonly string[];
	readonly short: string;
}

const GIT_MESSAGE_OPTIONS: TextOptions = { long: ["--message", "--file"], short: "mF" };
const GREP_PATTERN_OPTIONS: TextOptions = { long: ["--regexp"], short: "e" };
const GH_TEXT_OPTIONS: TextOptions = { long: ["--body", "--title"], short: "bt" };

/** Programs that only search text: their pattern is never run. */
const SEARCH_PROGRAMS: ReadonlySet<string> = new Set(["grep", "egrep", "fgrep", "rg", "ag"]);
/** Options with which a search program runs another program, so none of its words is inert. */
const SEARCH_RUNS_PROGRAM = ["--pre", "--hostname-bin", "--pager"];

/** Mark the values of `options` among `seg[from…]`, up to a `--`, as inert. Returns whether a
 *  pattern option was found. */
function markOptionValues(seg: readonly string[], from: number, options: TextOptions, inert: Set<number>): boolean {
	let found = false;
	for (let k = from; k < seg.length; k++) {
		const word = seg[k];
		if (word === "--") break;
		if (options.long.includes(word)) {
			inert.add(k + 1);
			found = true;
			k++;
		} else if (options.long.some((name) => word.startsWith(`${name}=`))) {
			inert.add(k);
			found = true;
		} else if (/^-[A-Za-z0-9]/.test(word)) {
			const letter = [...word.slice(1)].findIndex((c) => options.short.includes(c));
			if (letter === -1) continue;
			found = true;
			if (letter === word.length - 2) {
				inert.add(k + 1);
				k++;
			} else {
				inert.add(k);
			}
		}
	}
	return found;
}

/** Index of the first word from `from` on that is neither an option nor an option's value. */
function firstOperandIndex(seg: readonly string[], from: number, inert: ReadonlySet<number>): number {
	for (let k = from; k < seg.length; k++) {
		if (seg[k] === "--") return k + 1;
		if (!seg[k].startsWith("-") && !inert.has(k)) return k;
	}
	return -1;
}

/** A shell variable assignment before the command word (`X=1 cmd`). */
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;

/**
 * Indexes of the words in one simple command that the program only prints, searches for or records,
 * never runs: any argument of `echo` or `printf` (not `printf -v`, which sets a variable), the
 * message and message-file values of `git commit` and `git tag`, a search program's pattern, and a
 * `gh` title or body. Every other position may be run by its program (`ssh h '…'`, `watch '…'`,
 * `git rebase -x '…'`, `python3 -c '…'`), so a word there keeps a tripwire's deny (ADR-0007).
 */
function inertWordIndexes(seg: readonly string[]): ReadonlySet<number> {
	const inert = new Set<number>();
	const at = seg.findIndex((word) => !ASSIGNMENT.test(word));
	if (at === -1) return inert;
	const name = wordBasename(seg[at]);
	if (name === "echo" || (name === "printf" && !seg[at + 1]?.startsWith("-v"))) {
		for (let k = at + 1; k < seg.length; k++) inert.add(k);
	} else if (SEARCH_PROGRAMS.has(name)) {
		if (seg.some((word) => SEARCH_RUNS_PROGRAM.some((option) => word.startsWith(option)))) return inert;
		if (!markOptionValues(seg, at + 1, GREP_PATTERN_OPTIONS, inert)) {
			const pattern = firstOperandIndex(seg, at + 1, inert);
			if (pattern !== -1) inert.add(pattern);
		}
	} else if (name === "git") {
		const sub = gitSubcommandIndex(seg, at);
		if (sub !== undefined && sub !== -1 && ["commit", "tag"].includes(seg[sub])) markOptionValues(seg, sub + 1, GIT_MESSAGE_OPTIONS, inert);
	} else if (name === "gh") {
		markOptionValues(seg, at + 1, GH_TEXT_OPTIONS, inert);
	}
	return inert;
}

/** Text filters that only print or count what they read, never run it. */
const PIPE_FILTERS: ReadonlySet<string> = new Set([
	"grep",
	"egrep",
	"fgrep",
	"head",
	"tail",
	"wc",
	"sort",
	"uniq",
	"cut",
	"tr",
	"nl",
	"column",
	"cat",
	"less",
	"more",
]);

/** Whether some pipe anywhere in the words feeds a command that may run its input. Every pipe counts,
 *  since a brace group or an `if` body pipes every command inside it (`{ true; echo '…'; } | sh`); only a
 *  known text filter is safe, and `|&` scans as `|` then `&`. */
function pipeMayRun(words: readonly string[]): boolean {
	return words.some((word, k) => {
		if (word !== "|") return false;
		let at = k + 1;
		if (words[at] === "&") at++;
		while (words[at] !== undefined && ASSIGNMENT.test(words[at])) at++;
		const consumer = words[at];
		return consumer === undefined || isShellOperator(consumer) || !PIPE_FILTERS.has(wordBasename(consumer));
	});
}

/** Whether the text holds a construct that can run a command's output: a pipe into anything but a
 *  text filter, a redirection other than to `/dev/null` or a descriptor (`echo '…' > f; sh f`), and a
 *  process or command substitution (`bash <(echo '…')`, `$(echo '…')`). */
function outputMayRun(text: string, words: readonly string[]): boolean {
	const stripped = text.replace(/\d?&?>>?\s*\/dev\/null/g, "").replace(/\d?[<>]&\d/g, "");
	return /[<>]/.test(stripped) || pipeMayRun(words) || words.includes("(") || words.includes(")");
}

/** Whether an `eval` or a split-string `env` sits anywhere in the command, behind a keyword or a
 *  wrapper too (`time eval …`, `nice env -S …`): both join their arguments into a new command line,
 *  which the scanner does not follow. `markReparsers` checks only the first word, which serves the
 *  allow check; the floor needs every position. */
function reparsesWords(seg: readonly string[]): boolean {
	return seg.some((word, k) => {
		const base = wordBasename(word);
		return base === "eval" || (base === "env" && envSplitsString(seg.slice(k + 1)));
	});
}

/** What a floor rule's word view looks for. */
export interface CommandMatcher {
	/** Whether one simple command runs the rule's dangerous command. */
	readonly runs: (seg: readonly string[]) => boolean;
	/** Whether one word holds the rule's dangerous text. */
	readonly mentions: (word: string) => boolean;
}

const SHELL_RECURSION_DEPTH = 3;

/**
 * Whether the shell may run the matcher's dangerous command anywhere in `text`: a simple command runs
 * it, a shell's `-c` script does (recursed into up to `SHELL_RECURSION_DEPTH` levels), or a word that
 * holds its text sits anywhere but a known inert position. Fails closed: an unsound parse, an
 * unmodelled shell option, a script that forwards positionals or a script past the depth cap is a
 * hit, so a raw-text tripwire's deny stands (ADR-0007).
 */
export function anyCommandIn(text: string, matcher: CommandMatcher, depth = 0): boolean {
	const words = shellWords(text);
	if (words.includes(UNSOUND)) return true;
	const inertAllowed = !outputMayRun(text, words);
	for (const seg of commandSegments(words)) {
		if (reparsesWords(seg)) return true;
		if (matcher.runs(seg)) return true;
		const judged = new Set(inertAllowed ? inertWordIndexes(seg) : []);
		for (let i = 0; i < seg.length; i++) {
			if (!SHELL_NAMES.has(wordBasename(seg[i]))) continue;
			const script = shellScriptAt(seg, i);
			if (script.kind === "unsound") return true;
			if (script.kind === "none") continue;
			if (depth >= SHELL_RECURSION_DEPTH) return true;
			if (script.text === undefined) continue;
			if (anyCommandIn(script.text, matcher, depth + 1)) return true;
			judged.add(script.at);
		}
		if (seg.some((word, k) => !judged.has(k) && matcher.mentions(word))) return true;
	}
	return false;
}
