import * as os from "node:os";
import * as path from "node:path";
import { classifyPath } from "./floor.ts";
import { baseForms, isWithin } from "./paths.ts";
import { shellWords, wordBasename } from "./shell.ts";

// ============================================================================
// Rule layer: the operands a user `allow` rule may admit (ADR-0008)
// ============================================================================

/** Operands graded per command; a command with more is refused, so the cost of one admission stays bounded. */
export const MAX_GRADED_OPERANDS = 64;

/** A leading shell variable assignment (`NAME=value`, `NAME+=value`); its value is an operand too. */
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*\+?=/;

/** An operand after shell expansion, or null when the gate cannot know what the shell would pass. */
interface Expanded {
	readonly path: string;
	/** The operand names a path through the home directory, which a reassigned `HOME` moves. */
	readonly homeRelative: boolean;
}

/**
 * Returns whether every operand of a simple command, read as a path, is one the floor lets a file tool
 * read without asking (ADR-0008). Call it only after `allowAdmits` has accepted the command's shape.
 * Fails closed toward the classifier, never toward a deny: an operand that is a secret or system path,
 * one holding an expansion the gate cannot resolve, a home-relative operand after `HOME` was reassigned,
 * or more than `MAX_GRADED_OPERANDS` operands each refuse the admission. The floor grades here even with
 * `builtinDenyFloor` off, because a refused admission only reaches the classifier.
 */
export function allowOperandsAdmit(command: string, cwd: string, homeReassigned: () => boolean): boolean {
	const words = shellWords(command);
	const operands = operandWords(words);
	if (operands.length > MAX_GRADED_OPERANDS) return false;
	for (const word of operands) {
		const expanded = expandOperand(word, cwd);
		if (expanded === null) return false;
		if (expanded.homeRelative && homeReassigned()) return false;
		if (classifyPath(expanded.path, cwd, false, true).verdict !== "allow") return false;
	}
	const at = commandIndex(words);
	return at === -1 || wordBasename(words[at]) !== "git" || gitStaysInProject(words.slice(at + 1), cwd);
}

/** Index of the command word, the first word that is not a leading assignment; -1 when there is none. */
function commandIndex(words: readonly string[]): number {
	return words.findIndex((word) => !ASSIGNMENT.test(word));
}

/** Returns every word a command may read as a path: each word after the command word that is not an
 *  option, the `=`-attached value of an option or assignment, and every word after `--`. Over-extraction
 *  is the safe direction: a word that is no path grades as an in-project file. */
function operandWords(words: readonly string[]): string[] {
	const operands: string[] = [];
	let commandSeen = false;
	let optionsEnded = false;
	for (const word of words) {
		if (!commandSeen) {
			if (ASSIGNMENT.test(word)) {
				operands.push(word.slice(word.indexOf("=") + 1));
				continue;
			}
			commandSeen = true;
			continue;
		}
		if (optionsEnded || !word.startsWith("-")) {
			operands.push(word);
		} else if (word === "--") {
			optionsEnded = true;
		} else if (word.includes("=")) {
			operands.push(word.slice(word.indexOf("=") + 1));
		}
	}
	return operands;
}

/** `$HOME` or `${HOME}`, not the prefix of a longer variable name such as `$HOMEBREW`. */
const HOME_VARIABLE = /\$\{HOME\}|\$HOME(?![A-Za-z0-9_])/g;
/** A brace expansion: a `{` whose closing `}` follows a `,` or a `..`. */
const BRACE_EXPANSION = /\{[^}]*(?:,|\.\.)[^}]*\}/;
const GLOB_CHARS = /[*?[]/;

/**
 * Expands an operand the way bash would where the result is exact: a leading `~` or `~/`, `$HOME` and
 * `${HOME}`, quoted or not (the word view has lost the quotes, so a single-quoted `'$HOME'` is expanded
 * too, which only refuses more). Returns null for any other expansion, which the gate cannot resolve: a
 * variable (the agent's shell persists exports between calls and does not share the gate's environment),
 * `~user`, a brace expansion, or a glob. A glob with no `/` that does not start with `.` matches only
 * visible entries of the cwd, so it grades as the cwd itself.
 */
function expandOperand(word: string, cwd: string): Expanded | null {
	const home = os.homedir();
	let homeRelative = false;
	let text = word.replace(HOME_VARIABLE, () => {
		homeRelative = true;
		return home;
	});
	if (text === "~" || text.startsWith("~/")) {
		text = home + text.slice(1);
		homeRelative = true;
	} else if (text.startsWith("~")) {
		return null;
	}
	if (text.includes("$") || BRACE_EXPANSION.test(text)) return null;
	if (GLOB_CHARS.test(text)) {
		if (text.includes("/") || text.startsWith(".")) return null;
		return { path: cwd, homeRelative };
	}
	return { path: text, homeRelative };
}

/** git global options whose value is the next word. `-C` is handled on its own, and `-c` and
 *  `--config-env` refuse the admission before their value matters. */
const GIT_GLOBAL_WITH_VALUE: ReadonlySet<string> = new Set(["--git-dir", "--work-tree", "--namespace", "--super-prefix", "--attr-source"]);
/** git subcommands that read any file named outside the work tree, with or without `--no-index`. */
const GIT_NO_INDEX_SUBCOMMANDS: ReadonlySet<string> = new Set(["diff", "grep"]);

/**
 * Returns whether a git invocation stays inside the project, given the words after `git`. Refuses
 * configuration a global option injects (`-c`, `--config-env`, `--exec-path=`), each of which can run a
 * program; a `-C` that leaves the cwd; and, for `diff` and `grep`, `--no-index` or any operand outside
 * the cwd, since git then reads arbitrary files and implies `--no-index` itself. Operands after a `-C`
 * resolve from its directory, as git resolves them.
 */
function gitStaysInProject(args: readonly string[], cwd: string): boolean {
	let base = path.resolve(cwd);
	let k = 0;
	for (; k < args.length && args[k].startsWith("-"); k++) {
		const word = args[k];
		if (injectsGitConfig(word)) return false;
		if (word === "-C") {
			const dir = args[k + 1] === undefined ? null : expandOperand(args[k + 1], cwd);
			if (dir === null) return false;
			base = path.resolve(base, dir.path);
			if (!insideProject(base, cwd)) return false;
			k++;
		} else if (word.startsWith("-C")) {
			return false;
		} else if (GIT_GLOBAL_WITH_VALUE.has(word)) {
			k++;
		}
	}
	if (k >= args.length || !GIT_NO_INDEX_SUBCOMMANDS.has(args[k])) return true;
	let optionsEnded = false;
	for (const word of args.slice(k + 1)) {
		if (!optionsEnded && word === "--") {
			optionsEnded = true;
			continue;
		}
		if (!optionsEnded && word.startsWith("-")) {
			if (isNoIndexFlag(word)) return false;
			continue;
		}
		const operand = expandOperand(word, cwd);
		if (operand === null || !insideProject(path.resolve(base, operand.path), cwd)) return false;
	}
	return true;
}

/** True for a global option that sets git configuration or the directory git runs its commands from. */
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

/** Matches text that may assign `HOME`: a plain or `+=` assignment, a `${HOME:=…}` default, a declaring
 *  builtin (`export`, `declare`, `typeset`, `readonly`, `local`, `read`, `unset`) naming it, `for HOME`
 *  and `printf -v HOME`. Over-matching only refuses home-relative admissions. */
const HOME_ASSIGNMENT =
	/(?<![\w$])HOME\s*\+?=|\$\{HOME:?=|\b(?:export|declare|typeset|readonly|local|read|unset)\b[^\n;&|]*(?<![\w${])HOME\b|\bfor\s+HOME\b|-v\s*HOME\b/;

/** Returns whether a command text may assign `HOME`, after which `~` names a directory the gate does
 *  not know for the rest of the agent's shell session. */
export function assignsHome(command: string): boolean {
	return HOME_ASSIGNMENT.test(command);
}
