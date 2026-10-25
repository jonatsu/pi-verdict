import * as fs from "node:fs";
import * as os from "node:os";
import { escapeRegExp } from "./agent-dir.ts";
import { classifyPath } from "./floor.ts";
import { gitStaysInProject } from "./git-reach.ts";
import { shellWords, wordBasename } from "./shell.ts";

// ============================================================================
// Rule layer: the operands a user `allow` rule may admit (ADR-0008)
// ============================================================================

/** Operands graded per command; a command with more is refused, so the cost of one admission stays bounded. */
export const MAX_GRADED_OPERANDS = 64;

/** Matches a leading shell variable assignment (`NAME=value`, `NAME+=value`). */
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*\+?=/;
/** Matches `$HOME` or `${HOME}`, not the prefix of a longer variable name such as `$HOMEBREW`. */
const HOME_VARIABLE = /\$\{HOME\}|\$HOME(?![A-Za-z0-9_])/g;
/** Matches a brace expansion: a `{` whose closing `}` follows a `,` or a `..`. */
const BRACE_EXPANSION = /\{[^}]*(?:,|\.\.)[^}]*\}/;
/** Matches a glob metacharacter. */
const GLOB_CHARS = /[*?[]/;
/** Matches an option word that holds an expansion: a `$`, a `~` or a glob metacharacter. */
const OPTION_EXPANSION = /[$~*?[]/;

/** An operand after shell expansion: the paths the shell passes for it. */
interface Expanded {
	readonly paths: readonly string[];
	/** The operand names a path through the home directory, which a reassigned `HOME` moves. */
	readonly homeRelative: boolean;
}

/** What the operand grading reads besides the command. */
export interface OperandContext {
	/** The directory the command runs in, which its relative operands resolve from. */
	readonly commandCwd: string;
	/** The session cwd. The gate grades it as the project, which a git call must stay inside. */
	readonly sessionCwd: string;
	/** True when the session may have reassigned `HOME`; read only for a home-relative operand. */
	readonly homeReassigned: () => boolean;
	readonly shell: "bash" | "powershell";
}

/**
 * Returns whether every operand of a simple command, read as a path, is one the floor lets a file tool
 * read without asking (ADR-0008). Call it only after `allowAdmits` has accepted the command's shape.
 * Fails closed toward the classifier, never toward a deny: an operand that is a secret or system path,
 * one holding an expansion the gate cannot resolve, a home-relative operand after `HOME` was reassigned,
 * or more than `MAX_GRADED_OPERANDS` graded paths (a glob's matches each count) each refuse the admission,
 * and so does any backslash in a PowerShell command.
 * The floor grades here even with `builtinDenyFloor` off, because a refused admission only reaches the
 * classifier.
 */
export function allowOperandsAdmit(command: string, where: OperandContext): boolean {
	const { commandCwd, sessionCwd, homeReassigned, shell } = where;
	// The word view reads a backslash as bash's escape, while PowerShell keeps it as a path separator.
	if (shell === "powershell" && command.includes("\\")) return false;
	const words = shellWords(command);
	const at = words.findIndex((word) => !ASSIGNMENT.test(word));
	const operands = operandWords(words, at);
	if (operands === null) return false;
	let graded = 0;
	for (const word of operands) {
		const expanded = expandOperand(word, commandCwd);
		if (expanded === null) return false;
		if (expanded.homeRelative && homeReassigned()) return false;
		graded += expanded.paths.length;
		if (graded > MAX_GRADED_OPERANDS) return false;
		if (!expanded.paths.every((p) => readsAsAllowed(p, commandCwd))) return false;
	}
	const operandPaths = (word: string) => expandOperand(word, commandCwd)?.paths ?? null;
	return at === -1 || wordBasename(words[at]) !== "git" || gitStaysInProject(words, at, commandCwd, sessionCwd, operandPaths);
}

/** True when the floor lets a file tool read `target` without asking. The floor is always on here, even
 *  with `builtinDenyFloor` off: a refused admission only reaches the classifier. */
function readsAsAllowed(target: string, commandCwd: string): boolean {
	return classifyPath(target, commandCwd, /* isWrite */ false, /* floorOn */ true).verdict === "allow";
}

/**
 * Returns every text a command may read as a path, given the index of its command word (-1 for none), or
 * null when an option word holds an expansion. Collected: the value of each leading assignment; each later
 * word that is not an option, and also its value after an `=` (`if=~/x`: bash expands a tilde there); the
 * value of a `--name=value` option; the text from the first `/` of a short option with an attached value
 * (`-f/path`); and every word after `--`. An option word holding `$`, `~` or a glob character is refused,
 * since its attached value cannot be told from its letters. Over-extraction is the safe direction: a text
 * that is no path grades as an in-project file.
 */
function operandWords(words: readonly string[], at: number): string[] | null {
	const assignments = at === -1 ? words : words.slice(0, at);
	const operands = assignments.map(valueAfterEquals);
	let optionsEnded = false;
	for (const word of at === -1 ? [] : words.slice(at + 1)) {
		const isOption = !optionsEnded && word.startsWith("-");
		if (isOption && word === "--") {
			optionsEnded = true;
			continue;
		}
		if (isOption && OPTION_EXPANSION.test(word)) return null;
		if (!isOption) operands.push(word);
		if (word.includes("=")) operands.push(valueAfterEquals(word));
		if (isOption && !word.startsWith("--") && word.includes("/")) operands.push(word.slice(word.indexOf("/")));
	}
	return operands;
}

/** Returns the text after the first `=`. */
function valueAfterEquals(word: string): string {
	return word.slice(word.indexOf("=") + 1);
}

/**
 * Expands an operand the way bash would where the result is exact: a leading `~` or `~/`, `$HOME` and
 * `${HOME}`, quoted or not (the word view has lost the quotes, so a single-quoted `'$HOME'` is expanded
 * too, which only refuses more). Returns null for any other expansion, which the gate cannot resolve: a
 * variable (the agent's shell persists exports between calls and does not share the gate's environment),
 * `~user`, a brace expansion, or a glob. A glob with no `/` that does not start with `.` expands to the
 * cwd entries it matches (`cwdGlobMatches`), each of which is graded.
 */
function expandOperand(word: string, commandCwd: string): Expanded | null {
	const home = os.homedir();
	const viaTilde = word === "~" || word.startsWith("~/");
	if (!viaTilde && word.startsWith("~")) return null;
	const replaced = word.replace(HOME_VARIABLE, () => home);
	const text = viaTilde ? home + replaced.slice(1) : replaced;
	const homeRelative = viaTilde || replaced !== word;
	if (text.includes("$") || BRACE_EXPANSION.test(text)) return null;
	if (!GLOB_CHARS.test(text)) return { paths: [text], homeRelative };
	if (text.includes("/") || text.startsWith(".")) return null;
	const matches = cwdGlobMatches(text, commandCwd);
	return matches === null ? null : { paths: matches, homeRelative };
}

/**
 * Returns the names of the cwd entries a one-segment glob matches, or null when it matches none (bash would
 * pass the pattern itself), when the cwd cannot be read, or when the pattern holds a bracket form the gate
 * does not model. Hidden entries count and the match ignores case: the agent's shell replays the user's
 * `shopt` settings, so `dotglob`, `GLOBIGNORE` or `nocaseglob` may be on, and the gate grades a superset of
 * what any of them can match.
 */
function cwdGlobMatches(pattern: string, commandCwd: string): string[] | null {
	const re = globRegExp(pattern);
	if (re === null) return null;
	let names: string[];
	try {
		names = fs.readdirSync(commandCwd);
	} catch {
		return null;
	}
	const matches = names.filter((name) => re.test(name));
	return matches.length === 0 ? null : matches;
}

/** Returns a glob pattern as an anchored regex: `*`, `?` and a bracket expression (`[abc]`, `[a-z]`,
 *  `[!x]`, `[^x]`). Null for an unterminated bracket or a character class such as `[[:alpha:]]`. */
function globRegExp(pattern: string): RegExp | null {
	let source = "";
	for (let i = 0; i < pattern.length; i++) {
		const c = pattern[i];
		if (c === "*") source += ".*";
		else if (c === "?") source += ".";
		else if (c !== "[") source += escapeRegExp(c);
		else {
			const negated = pattern[i + 1] === "!" || pattern[i + 1] === "^";
			const start = i + (negated ? 2 : 1);
			// A `]` right after the opening bracket is a member, not the end.
			const close = pattern.indexOf("]", start + 1);
			if (close === -1) return null;
			const members = pattern.slice(start, close);
			if (/\[[:=.]/.test(members)) return null;
			source += `[${negated ? "^" : ""}${members.replace(/[\\\]^[]/g, "\\$&")}]`;
			i = close;
		}
	}
	try {
		return new RegExp(`^${source}$`, "is");
	} catch {
		return null;
	}
}
