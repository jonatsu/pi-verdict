import * as os from "node:os";
import { classifyPath } from "./floor.ts";
import { shellWords } from "./shell.ts";

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
	const operands = operandWords(shellWords(command));
	if (operands.length > MAX_GRADED_OPERANDS) return false;
	for (const word of operands) {
		const expanded = expandOperand(word, cwd);
		if (expanded === null) return false;
		if (expanded.homeRelative && homeReassigned()) return false;
		if (classifyPath(expanded.path, cwd, false, true).verdict !== "allow") return false;
	}
	return true;
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
	let path = word.replace(HOME_VARIABLE, () => {
		homeRelative = true;
		return home;
	});
	if (path === "~" || path.startsWith("~/")) {
		path = home + path.slice(1);
		homeRelative = true;
	} else if (path.startsWith("~")) {
		return null;
	}
	if (path.includes("$") || BRACE_EXPANSION.test(path)) return null;
	if (GLOB_CHARS.test(path)) {
		if (path.includes("/") || path.startsWith(".")) return null;
		return { path: cwd, homeRelative };
	}
	return { path, homeRelative };
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
