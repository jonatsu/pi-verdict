import { BASH_MAX_MATCH_LEN } from "./shell.ts";
import { gitSubcommandIndex, hasUnsoundWord, isShellOperator, shellWords, withoutSubstitutionMarks, wordBasename } from "./shell-words.ts";

// ============================================================================
// Session shell state: which user allows an earlier command may have voided (ADR-0008)
//
// omp runs every bash call of an agent session in one persistent shell, so a variable, function or alias
// one call sets changes what a later call runs: `export GIT_EXTERNAL_DIFF=…` turns an allowed `git diff`
// into a program run, and `PATH` or a function can redirect any command. The rule layer cannot see that
// shell, so it records, per session, which of the constructs below each command may have run.
// ============================================================================

/** What a construct makes the rule layer unable to vouch for. */
type Voids =
	/** Every command: the construct can redirect any command word. */
	| { readonly kind: "every-allow" }
	/** Every operand spelled through the home directory or split by the shell. */
	| { readonly kind: "home-operands" }
	/** The named commands, matched by the basename of any word, so `env git diff` counts. */
	| { readonly kind: "commands"; readonly names: readonly string[] };

const EVERY_ALLOW: readonly Voids[] = [{ kind: "every-allow" }];
const HOME_OPERANDS: Voids = { kind: "home-operands" };
const commands = (...names: string[]): Voids => ({ kind: "commands", names });

/** A construct a command may run, what it voids, and the substrings that stand for it when the command
 *  cannot be read word by word. */
type Row =
	/** Setting one of these variables, or one starting with `prefix`. */
	| { readonly kind: "variable"; readonly names: readonly string[]; readonly prefix?: string; readonly voids: readonly Voids[] }
	/** Running one of these commands, when `applies` (if any) holds for its arguments. */
	| {
			readonly kind: "command";
			readonly names: readonly string[];
			readonly applies?: (args: readonly string[]) => boolean;
			readonly voids: readonly Voids[];
			readonly fallback: readonly string[];
	  }
	/** Defining a shell function, which shadows any command of its name. */
	| { readonly kind: "function"; readonly voids: readonly Voids[]; readonly fallback: readonly string[] };

/**
 * Each construct and what it voids. The table over-matches on purpose: a false match sends later allowed
 * commands of the session to the classifier, one model call each. `CDPATH` voids nothing, since every
 * operand the gate grades resolves from the call's own cwd.
 */
const ROWS: readonly Row[] = [
	{
		kind: "variable",
		names: ["PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "BASH_ENV", "ENV", "PS4", "PROMPT_COMMAND"],
		voids: EVERY_ALLOW,
	},
	{ kind: "variable", names: ["HOME"], voids: [HOME_OPERANDS, commands("git")] },
	{ kind: "variable", names: ["IFS"], voids: [HOME_OPERANDS] },
	// A moved global gitconfig can set `core.fsmonitor`; `GIT_*` covers `GIT_EXTERNAL_DIFF`, `GIT_DIR` and the rest.
	{ kind: "variable", names: ["XDG_CONFIG_HOME"], prefix: "GIT_", voids: [commands("git")] },
	{ kind: "variable", names: ["RIPGREP_CONFIG_PATH"], voids: [commands("rg")] },
	{ kind: "variable", names: ["TAR_OPTIONS"], voids: [commands("tar", "gtar", "bsdtar")] },
	{ kind: "variable", names: ["ZIPOPT", "ZIP"], voids: [commands("zip")] },
	{ kind: "variable", names: ["RSYNC_RSH"], voids: [commands("rsync")] },
	{ kind: "variable", names: ["LESSOPEN", "LESSCLOSE"], voids: [commands("less")] },
	{ kind: "variable", names: ["GREP_OPTIONS"], voids: [commands("grep", "egrep", "fgrep", "rgrep")] },
	{
		kind: "command",
		names: ["alias", "enable", "source", ".", "eval", "trap", "function"],
		voids: EVERY_ALLOW,
		fallback: ["alias", "enable", "source", "eval", "trap", "function"],
	},
	{ kind: "command", names: ["hash"], applies: (args) => args.some((w) => /^-[A-Za-z]*p/.test(w)), voids: EVERY_ALLOW, fallback: ["hash"] },
	{ kind: "command", names: ["shopt"], applies: (args) => args.includes("expand_aliases"), voids: EVERY_ALLOW, fallback: ["shopt"] },
	// A repository config can set `core.fsmonitor`, `core.pager`, `diff.external` or a hooks path.
	{ kind: "command", names: ["git"], applies: gitConfigWrites, voids: [commands("git")], fallback: ["config"] },
	{ kind: "function", voids: EVERY_ALLOW, fallback: ["()"] },
];

/** The `git config` forms that only read. */
const GIT_CONFIG_READS: ReadonlySet<string> = new Set([
	"--get",
	"--get-all",
	"--get-regexp",
	"--list",
	"-l",
	"--show-origin",
	"--show-scope",
]);

/** True when git's arguments run `git config` in a form that may write. Fails closed: when git's global
 *  options cannot be read, any later `config` word counts. */
function gitConfigWrites(args: readonly string[]): boolean {
	const sub = gitSubcommandIndex(args, -1);
	if (sub === undefined) return args.some((w) => w.toLowerCase() === "config");
	if (sub === -1 || args[sub].toLowerCase() !== "config") return false;
	const rest = args.slice(sub + 1);
	return !(rest[0] === "get" || rest[0] === "list" || rest.some((w) => GIT_CONFIG_READS.has(w)));
}

/** Words that may precede the command word of a simple command without being it. */
const PREFIX_WORDS: ReadonlySet<string> = new Set(["{", "}", "!", "if", "then", "elif", "else", "do", "while", "until", "time"]);
/** Commands that run the next word as the command (`env` and `nice` also take options first). */
const WRAPPERS: ReadonlySet<string> = new Set(["command", "builtin", "exec", "env", "nice"]);
/** Builtins that declare, read into or unset the variables named in their arguments. */
const DECLARING: ReadonlySet<string> = new Set([
	"export",
	"declare",
	"typeset",
	"readonly",
	"local",
	"read",
	"mapfile",
	"readarray",
	"unset",
]);
/** Matches an assignment word, capturing the variable name. */
const ASSIGNMENT = /^([A-Za-z_][A-Za-z0-9_]*)\+?=/;
/** Matches a declared name, bare or assigned, capturing it. */
const DECLARED = /^([A-Za-z_][A-Za-z0-9_]*)(?:\+?=|$)/;
/** Matches the `${X:=…}` and `${X=…}` default expansions, which assign when `X` is unset. */
const DEFAULTED = /\$\{([A-Za-z_][A-Za-z0-9_]*):?=/g;

/** The rows a command fired: `persistent` changes the session's shell, `current` this call alone as well. */
interface Fired {
	persistent: number;
	current: number;
}

/** Returns the bit of the variable row that names `name`, or 0. */
function variableBit(name: string): number {
	for (let i = 0; i < ROWS.length; i++) {
		const row = ROWS[i];
		if (row.kind === "variable" && (row.names.includes(name) || (row.prefix !== undefined && name.startsWith(row.prefix)))) return 1 << i;
	}
	return 0;
}

/** Returns the bits of the command rows that a command word and its arguments fire. */
function commandBits(word: string, args: readonly string[]): number {
	let bits = 0;
	for (let i = 0; i < ROWS.length; i++) {
		const row = ROWS[i];
		if (row.kind !== "command") continue;
		const name = row.names.includes(word) ? word : wordBasename(word);
		if (row.names.includes(name) && (row.applies === undefined || row.applies(args))) bits |= 1 << i;
	}
	return bits;
}

const FUNCTION_BIT = 1 << ROWS.findIndex((row) => row.kind === "function");

/** Records the rows one simple command fires. A leading assignment persists only when no command word
 *  follows it; with one, it changes that command alone. */
function scanSimpleCommand(seg: readonly string[], fired: Fired): void {
	let at = 0;
	let prefixBits = 0;
	for (; at < seg.length; at++) {
		const word = seg[at];
		const assigned = ASSIGNMENT.exec(word);
		if (assigned) prefixBits |= variableBit(assigned[1]);
		else if (!PREFIX_WORDS.has(word)) break;
	}
	// A wrapper's options and assignments belong to it, so the wrapped command word follows them.
	while (at < seg.length && WRAPPERS.has(wordBasename(seg[at]))) {
		at++;
		for (; at < seg.length && (seg[at].startsWith("-") || ASSIGNMENT.test(seg[at])); at++) {
			const assigned = ASSIGNMENT.exec(seg[at]);
			if (assigned) prefixBits |= variableBit(assigned[1]);
		}
	}
	if (at >= seg.length) {
		fired.persistent |= prefixBits;
		return;
	}
	fired.current |= prefixBits;
	const word = seg[at];
	const args = seg.slice(at + 1);
	if (word.endsWith("()")) fired.persistent |= FUNCTION_BIT;
	// The tokenizer puts its unsound mark in place of an `eval` it will not re-read.
	fired.persistent |= commandBits(hasUnsoundWord([word]) ? "eval" : word, args);
	fired.persistent |= declaredBits(word, args);
}

/** Returns the bits of the variables a declaring builtin, `for` or `printf -v` names in its arguments. */
function declaredBits(word: string, args: readonly string[]): number {
	let names: readonly string[] = [];
	if (DECLARING.has(word)) names = args.filter((a) => !a.startsWith("-"));
	else if (word === "for") names = args.slice(0, 1);
	else if (word === "printf") {
		const v = args.findIndex((a) => a.startsWith("-v"));
		if (v !== -1) names = [args[v] === "-v" ? (args[v + 1] ?? "") : args[v].slice(2)];
	}
	let bits = 0;
	for (const name of names) {
		const declared = DECLARED.exec(name);
		if (declared) bits |= variableBit(declared[1]);
	}
	return bits;
}

/** Returns the rows that one command text fires, read word by word. */
function scanWords(words: readonly string[]): Fired {
	const fired: Fired = { persistent: 0, current: 0 };
	let start = 0;
	for (let i = 0; i <= words.length; i++) {
		const word = words[i];
		// The tokenizer emits a line break as its own word, which ends a simple command like an operator.
		if (word !== undefined && word !== "\n" && !isShellOperator(word)) {
			if (word.includes("${")) for (const m of word.matchAll(DEFAULTED)) fired.persistent |= variableBit(m[1]);
			continue;
		}
		// `name ( )`: the tokenizer reads both parentheses as operators.
		if (word === "(" && i - start === 1 && words[i + 1] === ")" && !words[start].endsWith("$")) fired.persistent |= FUNCTION_BIT;
		scanSimpleCommand(words.slice(start, i), fired);
		start = i + 1;
	}
	fired.current |= fired.persistent;
	return fired;
}

/** Returns the rows whose names occur anywhere in a text; over-matches, never backtracks. */
function scanSubstrings(text: string): number {
	let bits = 0;
	ROWS.forEach((row, i) => {
		const watched = row.kind === "variable" ? [...row.names, ...(row.prefix === undefined ? [] : [row.prefix])] : row.fallback;
		if (watched.some((s) => text.includes(s))) bits |= 1 << i;
	});
	return bits;
}

/** Matches a here-document operator (`<<` or `<<-`, not a `<<<` here-string), capturing the dash and the
 *  delimiter word, bare, backslashed or quoted. Bounded, so it cannot backtrack across a long line. */
const HERE_DOC = /(?<!<)<<(?!<)(-?)[ \t]*(?:'([^'\n]{1,64})'|"([^"\n]{1,64})"|\\?([^\s;&|<>()'"]{1,64}))/g;

/**
 * Returns a command with the bodies of its here-documents removed, for the shell-state scan only: a body
 * is the input of one command and cannot change the session's shell, while a lone quote in it would mislead
 * the tokenizer. A body ends at its delimiter line, with leading tabs allowed after `<<-`. A body whose
 * delimiter line never comes is kept, so a quoted `<<X` cannot hide the lines after it.
 */
function withoutHereDocBodies(command: string): string {
	if (!command.includes("<<")) return command;
	const lines = command.split("\n").map((line) => line.replace(/\r$/, ""));
	// Line numbers of each possible delimiter line, so finding a body's end needs no scan ahead.
	const exact = new Map<string, number[]>();
	const tabbed = new Map<string, number[]>();
	lines.forEach((line, i) => {
		for (const [index, key] of [
			[exact, line],
			[tabbed, line.replace(/^\t+/, "")],
		] as const) {
			const at = index.get(key);
			if (at === undefined) index.set(key, [i]);
			else at.push(i);
		}
	});
	// Lookups only move forward through the lines, so a cursor per list keeps the pass linear.
	const cursors = new Map<number[], number>();
	const firstFrom = (index: Map<string, number[]>, key: string, from: number): number => {
		const at = index.get(key);
		if (at === undefined) return -1;
		let c = cursors.get(at) ?? 0;
		while (c < at.length && at[c] < from) c++;
		cursors.set(at, c);
		return c < at.length ? at[c] : -1;
	};
	const kept: string[] = [];
	for (let i = 0; i < lines.length; ) {
		kept.push(lines[i]);
		let next = i + 1;
		for (const m of lines[i].matchAll(HERE_DOC)) {
			const end = firstFrom(m[1] === "-" ? tabbed : exact, m[2] ?? m[3] ?? m[4] ?? "", next);
			if (end === -1) break;
			next = end + 1;
		}
		i = next;
	}
	return kept.join("\n");
}

/** Returns the rows a command fires. A command over `BASH_MAX_MATCH_LEN`, or one the tokenizer stopped
 *  reading early (`$'…'`, an unterminated quote), takes the substring scan, which over-matches. */
function scan(command: string): Fired {
	if (command.length > BASH_MAX_MATCH_LEN) {
		const bits = scanSubstrings(command);
		return { persistent: bits, current: bits };
	}
	const text = withoutHereDocBodies(command);
	// A substitution's commands are read between its `(` and `)` operators, so its mark adds nothing here.
	const words = withoutSubstitutionMarks(shellWords(text));
	const fired = scanWords(words);
	if (words.length > 0 && hasUnsoundWord(words.slice(-1))) {
		const bits = scanSubstrings(text);
		fired.persistent |= bits;
		fired.current |= bits;
	}
	return fired;
}

/** What the session's shell state voids for the user allows of this call. */
export interface ShellState {
	/** No user allow may admit a command. */
	readonly everyAllow: boolean;
	/** No user allow may admit a home-relative operand. */
	readonly homeOperands: boolean;
	/** No user allow may admit a command with a word of one of these basenames. */
	readonly commands: ReadonlySet<string>;
}

/** The state that voids every allow, for a session the gate cannot read. */
const FAIL_CLOSED: ShellState = { everyAllow: true, homeOperands: true, commands: new Set() };

/** Returns what a set of fired rows voids. */
function stateOf(bits: number): ShellState {
	let everyAllow = false;
	let homeOperands = false;
	const voided = new Set<string>();
	ROWS.forEach((row, i) => {
		if ((bits & (1 << i)) === 0) return;
		for (const v of row.voids) {
			switch (v.kind) {
				case "every-allow":
					everyAllow = true;
					break;
				case "home-operands":
					homeOperands = true;
					break;
				case "commands":
					for (const name of v.names) voided.add(name);
					break;
				default: {
					const unreachable: never = v;
					throw new Error(`unknown shell-state void ${String(unreachable)}`);
				}
			}
		}
	});
	return { everyAllow, homeOperands, commands: voided };
}

/** Returns what one command, run on its own, voids for its own user allows. */
export function shellStateOf(command: string): ShellState {
	return stateOf(scan(command).current);
}

/** The part of the host session the record reads: its id and its past entries. */
export interface SessionSource {
	getSessionId(): string;
	getBranch(): readonly unknown[];
	/** Every entry of the session, off-branch ones included; pi and omp both provide it. */
	getEntries?(): readonly unknown[];
}

/** One session's record: the rows its commands fired, and whether the past entries were read in. */
interface SessionRecord {
	bits: number;
	seeded: boolean;
}

/**
 * The shell state of each session one gate instance serves, kept as the rows its commands fired. The
 * record only grows: a rewind or a move in the session tree hides an entry, not what it did to the shell.
 */
export class ShellStateLedger {
	private readonly sessions = new Map<string, SessionRecord>();

	clear(): void {
		this.sessions.clear();
	}

	/**
	 * Records a tool call's command in its session's record, and returns what that call's user allows
	 * must leave out: the record plus what an assignment prefix changes for this command alone. Call it
	 * for every tool call, before its verdict and whatever the verdict. The first call of a session reads
	 * the session's past entries in once. Fails closed: while neither `getEntries` nor `getBranch` can
	 * be read, every allow is voided.
	 */
	observe(host: SessionSource, input: Readonly<Record<string, unknown>>): ShellState {
		const record = this.recordFor(host);
		const fired = typeof input.command === "string" ? scan(input.command) : { persistent: 0, current: 0 };
		record.bits |= fired.persistent;
		if (!record.seeded) {
			const seed = seedBits(host);
			if (seed === null) return FAIL_CLOSED;
			record.bits |= seed;
			record.seeded = true;
		}
		return stateOf(record.bits | fired.current);
	}

	private recordFor(host: SessionSource): SessionRecord {
		const key = sessionKey(host);
		let record = this.sessions.get(key);
		if (record === undefined) {
			record = { bits: 0, seeded: false };
			this.sessions.set(key, record);
		}
		return record;
	}
}

/** Returns the host's session id, or one shared key when the host cannot name it. */
function sessionKey(host: SessionSource): string {
	try {
		return typeof host.getSessionId === "function" ? String(host.getSessionId()) : "";
	} catch {
		return "";
	}
}

/** Returns the rows the commands of the session's past tool calls fired, each command scanned on its own;
 *  null when the host hands over neither every entry nor the branch. */
function seedBits(host: SessionSource): number | null {
	for (const read of [host.getEntries, host.getBranch]) {
		try {
			if (typeof read !== "function") continue;
			const entries: unknown = read.call(host);
			if (!Array.isArray(entries)) continue;
			let bits = 0;
			for (const entry of entries) for (const command of toolCallCommands(entry)) bits |= scan(command).persistent;
			return bits;
		} catch {
			// An unreadable source falls through to the next one, and past the last to the fail-closed null.
		}
	}
	return null;
}

/** Returns the string `command` argument of every tool call in one assistant message entry. */
function toolCallCommands(entry: unknown): string[] {
	const message = field(entry, "type") === "message" ? field(entry, "message") : undefined;
	const content = field(message, "role") === "assistant" ? field(message, "content") : undefined;
	if (!Array.isArray(content)) return [];
	return content.flatMap((block: unknown) => {
		const command = field(block, "type") === "toolCall" ? field(field(block, "arguments"), "command") : undefined;
		return typeof command === "string" ? [command] : [];
	});
}

/** Returns a property of an object value, or undefined for anything else. */
function field(value: unknown, key: string): unknown {
	// Safe: any non-null object can be indexed by a string key, and the value stays unknown.
	return typeof value === "object" && value !== null ? (value as Record<string, unknown>)[key] : undefined;
}
