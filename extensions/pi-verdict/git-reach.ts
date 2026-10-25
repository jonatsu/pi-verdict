import * as path from "node:path";
import { baseForms, isWithin } from "./paths.ts";
import { gitSubcommandIndex } from "./shell-words.ts";

// ============================================================================
// Git reach: whether a git call a user `allow` rule matched stays inside the project (ADR-0008)
// ============================================================================

/** Returns the paths the shell passes for one operand word, relative to the command cwd, or null when the
 *  gate cannot know them. */
export type OperandPaths = (word: string) => readonly string[] | null;

/** git subcommands that read any file named outside the work tree, with or without `--no-index`. */
const GIT_NO_INDEX_SUBCOMMANDS: ReadonlySet<string> = new Set(["diff", "grep"]);

/**
 * Returns whether the git invocation whose `git` word is `words[at]` stays inside the project. Its global
 * options are read by `gitSubcommandIndex`, so an option it does not model refuses the admission (fails
 * closed). `gitRunsInProject` judges the directory git runs in and its global options, and
 * `gitReadsStayInProject` the operands of `diff` and `grep`. The project is graded as `sessionCwd`;
 * `commandCwd` is where the command runs, which a `bash` call may move. `operandPaths` expands an operand
 * word as the allow-operand grading does.
 */
export function gitStaysInProject(
	words: readonly string[],
	at: number,
	commandCwd: string,
	sessionCwd: string,
	operandPaths: OperandPaths,
): boolean {
	const sub = gitSubcommandIndex(words, at);
	if (sub === undefined) return false;
	const base = gitRunsInProject(words.slice(at + 1, sub === -1 ? words.length : sub), commandCwd, sessionCwd, operandPaths);
	if (base === null) return false;
	if (sub === -1 || !GIT_NO_INDEX_SUBCOMMANDS.has(words[sub])) return true;
	return gitReadsStayInProject(words.slice(sub + 1), base, sessionCwd, operandPaths);
}

/** Returns the directory git runs in after its global options, or null when that directory, the command's
 *  cwd moved by each `-C`, lies outside the project, or when an option injects configuration that can run a
 *  program (`injectsGitConfig`). Outside the project git may run with no repository, which implies
 *  `--no-index`. */
function gitRunsInProject(globals: readonly string[], commandCwd: string, sessionCwd: string, operandPaths: OperandPaths): string | null {
	let base = path.resolve(commandCwd);
	if (!insideProject(base, sessionCwd)) return null;
	for (let k = 0; k < globals.length; k++) {
		if (injectsGitConfig(globals[k])) return null;
		if (globals[k] !== "-C") continue;
		const dir = operandPaths(globals[k + 1] ?? "");
		k++;
		if (dir === null || dir.length !== 1) return null;
		base = path.resolve(base, dir[0]);
		if (!insideProject(base, sessionCwd)) return null;
	}
	return base;
}

/** Returns whether a `diff` or `grep` stays in the project: no `--no-index`, and every operand, resolved
 *  from `base` (a glob's matches are names in the command cwd), inside the project, since git implies
 *  `--no-index` for a path outside the work tree and then reads any file. */
function gitReadsStayInProject(args: readonly string[], base: string, sessionCwd: string, operandPaths: OperandPaths): boolean {
	let optionsEnded = false;
	for (const word of args) {
		if (!optionsEnded && word === "--") {
			optionsEnded = true;
		} else if (!optionsEnded && word.startsWith("-")) {
			if (isNoIndexFlag(word)) return false;
		} else {
			const paths = operandPaths(word);
			if (paths === null || !paths.every((p) => insideProject(path.resolve(base, p), sessionCwd))) return false;
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

/** True when every form of `target`, lexical and real, lies inside the session cwd in one of its forms. */
function insideProject(target: string, sessionCwd: string): boolean {
	const sessionForms = baseForms(path.resolve(sessionCwd));
	return baseForms(target).every((form) => sessionForms.some((s) => isWithin(form, s)));
}
