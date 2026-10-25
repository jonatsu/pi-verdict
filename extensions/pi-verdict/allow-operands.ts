import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { escapeRegExp } from "./agent-dir.ts";
import { classifyPath } from "./floor.ts";
import { baseForms, isWithin } from "./paths.ts";
import { gitSubcommandIndex, shellWords, wordBasename } from "./shell.ts";

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

/**
 * Returns whether every operand of a simple command, read as a path, is one the floor lets a file tool
 * read without asking (ADR-0008). Call it only after `allowAdmits` has accepted the command's shape.
 * Fails closed toward the classifier, never toward a deny: an operand that is a secret or system path,
 * one holding an expansion the gate cannot resolve, a home-relative operand after `HOME` was reassigned,
 * or more than `MAX_GRADED_OPERANDS` graded paths (a glob's matches each count) each refuse the admission.
 * The floor grades here even with `builtinDenyFloor` off, because a refused admission only reaches the
 * classifier.
 */
export function allowOperandsAdmit(command: string, cwd: string, homeReassigned: () => boolean): boolean {
	const words = shellWords(command);
	const at = words.findIndex((word) => !ASSIGNMENT.test(word));
	const operands = operandWords(words, at);
	if (operands === null) return false;
	let graded = 0;
	for (const word of operands) {
		const expanded = expandOperand(word, cwd);
		if (expanded === null) return false;
		if (expanded.homeRelative && homeReassigned()) return false;
		graded += expanded.paths.length;
		if (graded > MAX_GRADED_OPERANDS) return false;
		if (expanded.paths.some((p) => classifyPath(p, cwd, false, true).verdict !== "allow")) return false;
	}
	return at === -1 || wordBasename(words[at]) !== "git" || gitStaysInProject(words, at, cwd);
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
		if (optionsEnded || !word.startsWith("-")) {
			operands.push(word);
			if (word.includes("=")) operands.push(valueAfterEquals(word));
		} else if (word === "--") {
			optionsEnded = true;
		} else if (OPTION_EXPANSION.test(word)) {
			return null;
		} else if (word.startsWith("--")) {
			if (word.includes("=")) operands.push(valueAfterEquals(word));
		} else {
			if (word.includes("=")) operands.push(valueAfterEquals(word));
			if (word.includes("/")) operands.push(word.slice(word.indexOf("/")));
		}
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
 * visible cwd entries it matches (`cwdGlobMatches`), each of which is graded.
 */
function expandOperand(word: string, cwd: string): Expanded | null {
	const home = os.homedir();
	const viaTilde = word === "~" || word.startsWith("~/");
	if (!viaTilde && word.startsWith("~")) return null;
	const replaced = word.replace(HOME_VARIABLE, () => home);
	const text = viaTilde ? home + replaced.slice(1) : replaced;
	const homeRelative = viaTilde || replaced !== word;
	if (text.includes("$") || BRACE_EXPANSION.test(text)) return null;
	if (!GLOB_CHARS.test(text)) return { paths: [text], homeRelative };
	if (text.includes("/") || text.startsWith(".")) return null;
	const matches = cwdGlobMatches(text, cwd);
	return matches === null ? null : { paths: matches, homeRelative };
}

/**
 * Returns the names of the visible cwd entries a one-segment glob matches, or null when it matches none
 * (bash would pass the pattern itself), when the cwd cannot be read, or when the pattern holds a bracket
 * form the gate does not model. Matched case-insensitively, a superset of bash's default, so a shell set
 * to `nocaseglob` matches nothing the gate did not grade.
 */
function cwdGlobMatches(pattern: string, cwd: string): string[] | null {
	const re = globRegExp(pattern);
	if (re === null) return null;
	let names: string[];
	try {
		names = fs.readdirSync(cwd);
	} catch {
		return null;
	}
	const matches = names.filter((name) => !name.startsWith(".") && re.test(name));
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

/** git subcommands that read any file named outside the work tree, with or without `--no-index`. */
const GIT_NO_INDEX_SUBCOMMANDS: ReadonlySet<string> = new Set(["diff", "grep"]);

/**
 * Returns whether the git invocation whose `git` word is `words[at]` stays inside the project. Its global
 * options are read by `gitSubcommandIndex`, so an option it does not model refuses the admission (fails
 * closed). `gitRunsInProject` judges the global options and `gitReadsStayInProject` the operands of
 * `diff` and `grep`.
 */
function gitStaysInProject(words: readonly string[], at: number, cwd: string): boolean {
	const sub = gitSubcommandIndex(words, at);
	if (sub === undefined) return false;
	const base = gitRunsInProject(words.slice(at + 1, sub === -1 ? words.length : sub), cwd);
	if (base === null) return false;
	return sub === -1 || !GIT_NO_INDEX_SUBCOMMANDS.has(words[sub]) || gitReadsStayInProject(words.slice(sub + 1), base, cwd);
}

/** Returns the directory git runs in after its global options, or null when an option injects
 *  configuration that can run a program (`injectsGitConfig`) or a `-C` names a directory outside the cwd. */
function gitRunsInProject(globals: readonly string[], cwd: string): string | null {
	let base = path.resolve(cwd);
	for (let k = 0; k < globals.length; k++) {
		if (injectsGitConfig(globals[k])) return null;
		if (globals[k] !== "-C") continue;
		const dir = expandOperand(globals[k + 1] ?? "", cwd);
		k++;
		if (dir === null || dir.paths.length !== 1) return null;
		base = path.resolve(base, dir.paths[0]);
		if (!insideProject(base, cwd)) return null;
	}
	return base;
}

/** Returns whether a `diff` or `grep` stays in the project: no `--no-index`, and every operand inside the
 *  cwd once resolved from `base`, since git implies `--no-index` for a path outside the work tree and then
 *  reads any file. */
function gitReadsStayInProject(args: readonly string[], base: string, cwd: string): boolean {
	let optionsEnded = false;
	for (const word of args) {
		if (!optionsEnded && word === "--") {
			optionsEnded = true;
		} else if (!optionsEnded && word.startsWith("-")) {
			if (isNoIndexFlag(word)) return false;
		} else {
			const operand = expandOperand(word, cwd);
			if (operand === null || !operand.paths.every((p) => insideProject(path.resolve(base, p), cwd))) return false;
		}
	}
	return true;
}

/** True for a global option that sets git configuration (`-c`, `--config-env`), each key of which may name
 *  a program git runs, or that moves the directory git loads its subcommand programs from (`--exec-path=`). */
function injectsGitConfig(word: string): boolean {
	return word.startsWith("-c") || word === "--config-env" || word.startsWith("--config-env=") || word.startsWith("--exec-path=");
}

/** True for `--no-index` or an abbreviation of it, which git's option parser accepts for `grep`. */
function isNoIndexFlag(word: string): boolean {
	return word.length >= "--no-i".length && "--no-index".startsWith(word);
}

/** True when every form of `target`, lexical and real, lies inside the cwd in one of its forms. */
function insideProject(target: string, cwd: string): boolean {
	const cwdForms = baseForms(path.resolve(cwd));
	return baseForms(target).every((form) => cwdForms.some((c) => isWithin(form, c)));
}
