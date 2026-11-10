import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { expandOperand, MAX_GRADED_OPERANDS } from "./allow-operands.ts";
import { baseForms, fold, isWithin } from "./paths.ts";
import type { DeleteCommand, DeleteGrader, FloorHit } from "./shell.ts";
import { ASSIGNMENT, anyCommandIn, mayExpand, shellWords } from "./shell-words.ts";

// ============================================================================
// Rule layer: recursive deletes graded by target (ADR-0013)
// ============================================================================

/** The directories a recursive delete's call names: the project is the session cwd, and relative operands
 *  resolve from the command cwd. */
export interface DeleteContext {
	readonly sessionCwd: string;
	readonly commandCwd: string;
	/** False when the gate cannot resolve the command cwd; every relative operand is then unreadable. */
	readonly commandCwdExact: boolean;
	/** True when a command of the session may have reassigned `HOME`, so `~` and `$HOME` name an unknown directory. */
	readonly homeReassigned: boolean;
	/** True when a command of the session may have moved where a `cd` lands (`CDPATH`, a function or alias). */
	readonly workingDirectoryUnknown: boolean;
}

const GLOB_CHARS = /[*?[]/;
const DIRECTORY_CHANGE = /\b(?:cd|pushd|popd)\b/g;
const DIRECTORY_COMMANDS: ReadonlySet<string> = new Set(["cd", "pushd", "popd"]);
/** Matches a `..` that follows a named component (`build/../x`): the kernel resolves it from wherever that
 *  component leads, which may be a symlink, so the text cannot place the target. */
const INTERIOR_PARENT = /(?:^|\/)(?!\.\.(?:\/|$))[^/]+\/\.\.(?:\/|$)/;
/** Matches a command that is one leading `rm`, alone or followed in sequence by other commands, with nothing
 *  that runs before or beside it: no substitution, pipe, background `&` or redirection. */
const SOLE_LEADING_RM = /^\s*rm\s[^;&|\n`$<>()]*(?:&&|\|\||;|$)/;
/** Matches a `cd` target that bash looks up in `CDPATH` first: any not starting with `/`, `~`, or a `.` or `..` component. */
const CDPATH_SEARCHED = /^(?!\/|~|\.\.?(?:\/|$))/;
const SYSTEM_DIRECTORIES = ["/System", "/Library"];

const REASONS = {
	"rm-root": "recursive delete of the root, a top-level or system directory, or the home directory",
	"rm-git": "recursive delete of git metadata or of the project that holds it",
	"rm-unreadable-target": "recursive delete of a target the gate cannot read",
	"rm-outside-project": "recursive delete outside the project and the temp directories",
} as const;

type DeleteRule = keyof typeof REASONS;

/** A hit whose rule is one of the graded delete rules. */
type GradedHit = FloorHit & { readonly rule: DeleteRule };

const SEVERITY: readonly DeleteRule[] = ["rm-root", "rm-git", "rm-unreadable-target", "rm-outside-project"];

/** What grading one command reads, computed once for it. */
interface Grading {
	/** The directory relative operands resolve from; null when it is unknown. */
	readonly cwd: string | null;
	/** The real path of `cwd`, where a relative `..` climbs from; null when unknown. */
	readonly realCwd: string | null;
	readonly base: string;
	readonly homes: readonly string[];
	readonly project: readonly string[];
	readonly projectGit: boolean;
	/** The bases a target must sit strictly inside: the project, unless it is root-class, and the temp directories. */
	readonly inside: readonly string[];
	/** True when the command runs more than one command, so a missing path may exist by the time `rm` runs. */
	readonly compound: boolean;
	readonly homeReassigned: boolean;
	/** Paths graded so far; past `MAX_GRADED_OPERANDS` the command is unreadable, so its cost stays bounded. */
	graded: number;
}

/** Returns the grader that decides a command's recursive deletes for one call, worst hit first. A target
 *  strictly inside the project or a temp directory yields no hit, so the classifier judges it. */
export function deleteGrader(ctx: DeleteContext): DeleteGrader {
	return (deletes, command) => {
		const g = grading(command, ctx, deletes.length);
		const hits: GradedHit[] = [];
		for (const word of deletes.flatMap(operandWords)) {
			hits.push(...gradeOperand(word, g));
			if (g.graded > MAX_GRADED_OPERANDS) return [hit("rm-unreadable-target", [])];
		}
		return hits.sort((a, b) => SEVERITY.indexOf(a.rule) - SEVERITY.indexOf(b.rule));
	};
}

function grading(command: string, ctx: DeleteContext, deleteCount: number): Grading {
	const homes = baseForms(os.homedir());
	const project = baseForms(path.resolve(ctx.sessionCwd));
	const temps = ["/tmp", "/var/tmp", os.tmpdir()]
		.flatMap((t) => baseForms(path.resolve(t)))
		.filter((b) => !homes.some((home) => isWithin(home, b)));
	const cwd = commandWorkingDirectory(command, ctx);
	return {
		cwd,
		realCwd: cwd === null ? null : realpathOrNull(cwd),
		base: cwd ?? ctx.commandCwd,
		homes,
		project,
		projectGit: fs.existsSync(path.join(ctx.sessionCwd, ".git")),
		inside: [...(project.some((p) => rootClass(p, homes)) ? [] : project), ...temps],
		// A lone leading rm runs before every other command, so none can move a path it follows.
		compound: deleteCount !== 1 || !SOLE_LEADING_RM.test(command),
		homeReassigned: ctx.homeReassigned,
		graded: 0,
	};
}

/** Returns the directory relative operands resolve from, or null when it is unknown: an inexact command cwd,
 *  a session whose shell may have moved where a `cd` lands, `cd -`, a `cd` target bash would look up in a
 *  set `CDPATH`, or a directory change other than one leading `cd X &&`, which is moved into the working
 *  directory as omp does (`src/tools/bash.ts`, 18.13.0). A change counts on the raw text, so one inside an
 *  `sh -c` script counts, and by word value there too, so a quoted or escaped `c''d` counts; a word holding `cd`
 *  only makes the operands unreadable. */
export function commandWorkingDirectory(command: string, ctx: DeleteContext): string | null {
	if (!ctx.commandCwdExact || ctx.workingDirectoryUnknown) return null;
	const words = shellWords(command);
	let cwd = ctx.commandCwd;
	let allowedChanges = 0;
	if (words[0] === "cd" && words[1] !== undefined && words[2] === "&&") {
		if (words[1] === "-" || (process.env.CDPATH && CDPATH_SEARCHED.test(words[1]))) return null;
		const target = expandOperand(words[1], cwd);
		if (target === null || target.paths.length !== 1 || (target.homeRelative && ctx.homeReassigned)) return null;
		cwd = path.resolve(cwd, target.paths[0]);
		allowedChanges = 1;
	}
	const rawChanges = (command.match(DIRECTORY_CHANGE) ?? []).length;
	return Math.max(rawChanges, wordChanges(command)) > allowedChanges ? null : cwd;
}

/** Counts the `cd`, `pushd` and `popd` words a command runs, in every segment and inside every `sh -c` script,
 *  so a quoted or escaped `c''d` counts; an unsound reading counts as unbounded. */
function wordChanges(command: string): number {
	let changes = 0;
	const unsound = anyCommandIn(command, {
		runs: (seg) => {
			const name = seg.find((w) => !ASSIGNMENT.test(w));
			// A command name built from an expansion (`${D}d`) may be a cd.
			changes += name !== undefined && mayExpand(name) ? Number.POSITIVE_INFINITY : seg.filter((w) => DIRECTORY_COMMANDS.has(w)).length;
			return false; // read on: every segment counts
		},
		mentions: () => false,
	});
	return unsound ? Number.POSITIVE_INFINITY : changes;
}

/** The operand words of one `rm`: every word after it that is not an option, and every word after `--`. */
function operandWords(d: DeleteCommand): string[] {
	const operands: string[] = [];
	let optionsEnded = false;
	for (const word of d.seg.slice(d.at + 1)) {
		if (!optionsEnded && word === "--") optionsEnded = true;
		else if (optionsEnded || !word.startsWith("-")) operands.push(word);
	}
	return operands;
}

/** Grades one operand word: a hit for each denied path it expands to. */
function gradeOperand(word: string, g: Grading): GradedHit[] {
	const root = globRoot(word, g);
	if (root !== null) return [hit("rm-root", [root])];
	const expanded = expandOperand(word, g.base, true);
	if (expanded === null || (expanded.homeRelative && g.homeReassigned)) return [hit("rm-unreadable-target", [])];
	g.graded += expanded.paths.length;
	if (g.graded > MAX_GRADED_OPERANDS) return [];
	const hits: GradedHit[] = [];
	for (const p of expanded.paths) {
		if (!path.isAbsolute(p) && g.cwd === null) return [hit("rm-unreadable-target", [])];
		const followsLeaf = /\/\.?$/.test(p);
		const forms = targetForms(path.isAbsolute(p) ? p : `${g.cwd}/${p}`, followsLeaf);
		// A relative `..` climbs from the real working directory, which `path.resolve` and `realpath` both skip.
		if (!path.isAbsolute(p) && g.realCwd !== null) forms.push(path.resolve(g.realCwd, p));
		const rule = targetRule(forms, g);
		// A worse grade stands; only a target that would pass or fall outside is held unreadable.
		const unplaced = INTERIOR_PARENT.test(p.replace(/\/+/g, "/")) || (g.compound && followsDirectory(p, followsLeaf, g));
		if ((rule === null || rule === "rm-outside-project") && unplaced) hits.push(hit("rm-unreadable-target", []));
		else if (rule !== null) hits.push(hit(rule, forms));
	}
	return hits;
}

/** True when a delete target is reached through a directory below the one it is graded from: a trailing `/`,
 *  a relative path with more than one component, or an absolute path whose parent is not the project or a temp
 *  directory itself. Another command of the call could swap such a directory for a symlink after grading. */
function followsDirectory(p: string, followsLeaf: boolean, g: Grading): boolean {
	if (followsLeaf) return true;
	if (!path.isAbsolute(p)) return path.normalize(p).includes("/");
	const parent = fold(path.dirname(path.resolve(p)));
	return !g.inside.some((b) => fold(b) === parent);
}

function hit(rule: DeleteRule, forms: readonly string[]): GradedHit {
	return { rule, reason: `rule ${rule}: ${REASONS[rule]}`, forms };
}

/** Returns the directory a glob operand expands in when that directory is root-class (`/*`, `~/*`, `~/.*`),
 *  else null. */
function globRoot(word: string, g: Grading): string | null {
	const glob = word.search(GLOB_CHARS);
	if (glob === -1) return null;
	const dir = word.slice(0, word.lastIndexOf("/", glob) + 1) || ".";
	const expanded = expandOperand(dir, g.base);
	if (expanded === null || expanded.paths.length !== 1) return null;
	const resolved = path.resolve(g.base, expanded.paths[0]);
	return rootClass(resolved, g.homes) ? resolved : null;
}

/** The forms one delete target is graded in: its lexical path, its name under the real path of its parent
 *  directory, and, for an operand ending in `/` or `/.` (which rm follows into a symlinked directory), its own
 *  real path. The leaf itself is not resolved: deleting a symlink removes only the link. */
function targetForms(joined: string, followsLeaf: boolean): string[] {
	const forms = [path.resolve(joined)];
	const parentReal = realpathOrNull(path.dirname(joined));
	if (parentReal !== null) forms.push(path.resolve(parentReal, path.basename(joined)));
	const own = followsLeaf ? realpathOrNull(joined) : null;
	if (own !== null) forms.push(own);
	return [...new Set(forms)];
}

function realpathOrNull(p: string): string | null {
	try {
		return fs.realpathSync(p);
	} catch {
		return null;
	}
}

/** Returns the rule the worst form of a target hits, or null when every form sits strictly inside the
 *  project or a temp directory. */
function targetRule(forms: readonly string[], g: Grading): DeleteRule | null {
	if (forms.some((f) => rootClass(f, g.homes))) return "rm-root";
	const holdsProject = (f: string): boolean => g.projectGit && g.project.some((p) => isWithin(p, f));
	if (forms.some((f) => /(^|\/)\.git(\/|$)/i.test(fold(f)) || holdsProject(f))) return "rm-git";
	return forms.every((f) => g.inside.some((b) => isWithin(f, b) && fold(f) !== fold(b))) ? null : "rm-outside-project";
}

/** True for `/`, a directory one level below it (`/etc`, `/usr`, `/tmp` itself), `/System`, `/Library`, a
 *  directory directly under `/private`, and the home directory or an ancestor of it. */
function rootClass(p: string, homes: readonly string[]): boolean {
	const dir = path.dirname(p);
	if (p === "/" || dir === "/" || fold(dir) === fold("/private")) return true;
	if (SYSTEM_DIRECTORIES.some((s) => fold(s) === fold(p))) return true;
	return homes.some((home) => isWithin(home, p));
}
