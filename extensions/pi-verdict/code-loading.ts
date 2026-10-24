import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { isCommandTool, toolAccess } from "./access.ts";
import { agentDirPath } from "./agent-dir.ts";
import { callPathCandidates, denyPathForms } from "./deny-paths.ts";
import { baseForms, fold } from "./paths.ts";

// ============================================================================
// Code-loading ask (ADR-0011): a write where omp or pi loads code at the start of a
// later session asks a human. The set is a point-in-time reading of omp 18.12.6 and
// pi 0.84.3; ADR-0011 holds the table and its accepted residuals.
// ============================================================================

/** The location class a hit names in the ask's reason. */
export type CodeLoadKind =
	| "agent directory code"
	| "agent directory launcher file"
	| "agent directory config file"
	| "plugin install root"
	| "project code directory"
	| "project launcher file"
	| "project config file"
	| "working-directory launcher file";

export interface CodeLoadHit {
	path: string;
	kind: CodeLoadKind;
}

/** Entry names below one root, by location class. A name ending in `.*` matches any extension.
 *  The general config files (`config.yml`, `settings.json`) hold launch keys among unrelated
 *  settings, so they stay in their own list and a later change can grade them apart. */
interface LocationTable {
	dirs: readonly string[];
	launchers: readonly string[];
	configs: readonly string[];
	dirKind: CodeLoadKind;
	launcherKind: CodeLoadKind;
	configKind: CodeLoadKind;
}

const OMP_AGENT: LocationTable = {
	dirs: ["extensions", "hooks", "tools", "commands"],
	launchers: ["mcp.json", ".mcp.json", "models.yml", "lsp.*", ".lsp.*", "dap.*"],
	configs: ["config.yml", "settings.json"],
	dirKind: "agent directory code",
	launcherKind: "agent directory launcher file",
	configKind: "agent directory config file",
};

const PI_AGENT: LocationTable = {
	dirs: ["extensions", "npm", "git", "bin"],
	launchers: ["models.json", "trust.json"],
	configs: ["settings.json"],
	dirKind: "agent directory code",
	launcherKind: "agent directory launcher file",
	configKind: "agent directory config file",
};

/** The resolved agent directory may belong to either host, so it carries both hosts' entries. */
const ANY_AGENT: LocationTable = {
	...OMP_AGENT,
	dirs: [...new Set([...OMP_AGENT.dirs, ...PI_AGENT.dirs])],
	launchers: [...OMP_AGENT.launchers, ...PI_AGENT.launchers],
};

const OMP_PROJECT: LocationTable = {
	dirs: ["extensions", "hooks", "tools", "commands", "plugins"],
	launchers: ["mcp.json", ".mcp.json", "lsp.*", "dap.*"],
	configs: ["config.yml", "settings.json"],
	dirKind: "project code directory",
	launcherKind: "project launcher file",
	configKind: "project config file",
};

const PI_PROJECT: LocationTable = {
	dirs: ["extensions", "npm", "git"],
	launchers: [],
	configs: ["settings.json"],
	dirKind: "project code directory",
	launcherKind: "project launcher file",
	configKind: "project config file",
};

/** omp reads these generic names only directly in the working directory, so they match nowhere else. */
const CWD_LAUNCHERS: readonly string[] = ["mcp.json", ".mcp.json", "lsp.*", ".lsp.*", "dap.*"];

/** A bare working-directory launcher name as a word of a command or code text (`> mcp.json`,
 *  `open("lsp.json")`); the path tokenizer only extracts spellings that hold a separator. */
const CWD_LAUNCHER_WORD = /(?<![\w./\\-])(?:\.?mcp\.json|\.?lsp\.[\w-][\w.-]*|dap\.[\w-][\w.-]*)(?![\w.\\/-])/;

const nameMatches = (name: string, patterns: readonly string[]): boolean =>
	patterns.some((p) => (p.endsWith(".*") ? name.startsWith(p.slice(0, -1)) && name.length > p.length - 1 : name === p));

/** The class of `rel` (the segments below a root) in `table`: a listed directory or anything
 *  beneath it, or a listed file directly in the root. */
function classify(rel: readonly string[], table: LocationTable): CodeLoadKind | null {
	if (rel.length === 0 || rel[0] === "") return null;
	if (table.dirs.includes(rel[0])) return table.dirKind;
	if (rel.length !== 1) return null;
	if (nameMatches(rel[0], table.launchers)) return table.launcherKind;
	if (nameMatches(rel[0], table.configs)) return table.configKind;
	return null;
}

/** Path text with "/" separators, case-folded on case-insensitive filesystems. */
const comparable = (p: string): string => fold(path.sep === "\\" ? p.replace(/\\/g, "/") : p);

const under = (child: string, root: string): boolean => child === root || child.startsWith(`${root}/`);

/** The resolved agent directory in every spelling the gate grades: lexical and realpath. */
const agentRoots = (): string[] => baseForms(path.resolve(agentDirPath())).map(comparable);

/** omp's user plugin root, and the XDG one when `XDG_DATA_HOME` is an absolute path. */
function pluginRoots(): string[] {
	const roots = [path.join(os.homedir(), ".omp", "plugins")];
	const xdg = process.env.XDG_DATA_HOME;
	if (xdg && path.isAbsolute(xdg)) roots.push(path.join(xdg, "omp", "plugins"));
	return roots.flatMap((r) => baseForms(r)).map(comparable);
}

/** The agent-directory spellings that sit anywhere in a path: `.omp/agent`,
 *  `.omp/profiles/<name>/agent` and `.pi/agent`. Returns the segments below one, with its table. */
function segmentAgentRel(segs: readonly string[]): { rel: string[]; table: LocationTable } | null {
	for (let i = 0; i < segs.length; i++) {
		if (segs[i] === ".omp" && segs[i + 1] === "agent") return { rel: segs.slice(i + 2), table: OMP_AGENT };
		if (segs[i] === ".omp" && segs[i + 1] === "profiles" && segs[i + 2] && segs[i + 3] === "agent")
			return { rel: segs.slice(i + 4), table: OMP_AGENT };
		if (segs[i] === ".pi" && segs[i + 1] === "agent") return { rel: segs.slice(i + 2), table: PI_AGENT };
	}
	return null;
}

/** The location class of one absolute, comparable path form, or null when the host loads nothing there. */
function classifyForm(form: string, cwdForms: readonly string[]): CodeLoadKind | null {
	for (const root of agentRoots()) {
		if (form.startsWith(`${root}/`)) {
			const kind = classify(form.slice(root.length + 1).split("/"), ANY_AGENT);
			if (kind) return kind;
		}
	}
	if (pluginRoots().some((root) => under(form, root))) return "plugin install root";
	const segs = form.split("/");
	const agent = segmentAgentRel(segs);
	if (agent) {
		const kind = classify(agent.rel, agent.table);
		if (kind) return kind;
	}
	for (let i = 0; i < segs.length; i++) {
		const table = segs[i] === ".omp" ? OMP_PROJECT : segs[i] === ".pi" ? PI_PROJECT : null;
		const kind = table && classify(segs.slice(i + 1), table);
		if (kind) return kind;
	}
	const dir = path.posix.dirname(form);
	if (cwdForms.includes(dir) && nameMatches(path.posix.basename(form), CWD_LAUNCHERS)) return "working-directory launcher file";
	return null;
}

/** The first existing code-loading entry inside the subtree a mutating scope tool covers. The
 *  roots checked are the ones the gate can name without walking the tree: the agent
 *  directories, the plugin roots, and the `.omp` and `.pi` trees of the scope and of the cwd.
 *  Such a tool edits only files that exist, so a missing entry cannot be reached. */
function coveredEntry(scope: string, cwd: string): CodeLoadHit | null {
	const home = os.homedir();
	const roots: Array<{ root: string; table: LocationTable | "whole" }> = [
		...agentRoots().map((root) => ({ root, table: ANY_AGENT })),
		{ root: comparable(path.join(home, ".omp", "agent")), table: OMP_AGENT },
		{ root: comparable(path.join(home, ".pi", "agent")), table: PI_AGENT },
		...pluginRoots().map((root) => ({ root, table: "whole" as const })),
	];
	for (const base of [scope, comparable(path.resolve(cwd))]) {
		roots.push(
			{ root: `${base}/.omp`, table: OMP_PROJECT },
			{ root: `${base}/.omp/agent`, table: OMP_AGENT },
			{ root: `${base}/.pi`, table: PI_PROJECT },
			{ root: `${base}/.pi/agent`, table: PI_AGENT },
		);
	}
	const segs = scope.split("/");
	const last = segs[segs.length - 1];
	if (last === ".omp") roots.push({ root: scope, table: OMP_PROJECT }, { root: `${scope}/agent`, table: OMP_AGENT });
	if (last === ".pi") roots.push({ root: scope, table: PI_PROJECT }, { root: `${scope}/agent`, table: PI_AGENT });
	const agent = segmentAgentRel(segs);
	if (agent && agent.rel.length === 0) roots.push({ root: scope, table: agent.table });
	for (const { root, table } of roots) {
		if (!under(root, scope)) continue;
		let names: string[];
		try {
			names = fs.readdirSync(root);
		} catch {
			continue;
		}
		if (table === "whole") return { path: root, kind: "plugin install root" };
		for (const name of names) {
			const kind = classify([name], table);
			if (kind) return { path: `${root}/${name}`, kind };
		}
	}
	const cwd0 = comparable(path.resolve(cwd));
	if (under(cwd0, scope)) {
		try {
			const name = fs.readdirSync(cwd0).find((n) => nameMatches(n, CWD_LAUNCHERS));
			if (name) return { path: `${cwd0}/${name}`, kind: "working-directory launcher file" };
		} catch {
			/* an unreadable cwd holds nothing the scope tool could edit */
		}
	}
	return null;
}

/** Does the call write where the host loads code in a later session (ADR-0011)? Returns the first
 *  matched path and its location class, or null. A file tool counts its write targets only; a
 *  command, a code cell and a tool the adapter cannot classify count every target they name,
 *  because their direction is unknown. A mutating scope tool also hits when a location sits
 *  inside the subtree it edits. Every form the host can resolve a target to is compared. */
export function hitCodeLoadPath(toolName: string, input: Record<string, unknown>, cwd: string): CodeLoadHit | null {
	const access = toolAccess(toolName, input);
	const cwdForms = baseForms(path.resolve(cwd)).map(comparable);
	const subtree = access.scope && access.direction === "mutating";
	for (const candidate of callPathCandidates(toolName, input, cwd, "written")) {
		for (const form of denyPathForms(candidate, cwd)) {
			const kind = classifyForm(comparable(form), cwdForms);
			if (kind) return { path: form, kind };
			const covered = subtree ? coveredEntry(comparable(form), cwd) : null;
			if (covered) return covered;
		}
	}
	const text = isCommandTool(toolName) ? String(input.command ?? "") : access.kind === "code" ? access.command : null;
	const word = text === null ? null : CWD_LAUNCHER_WORD.exec(fold(text));
	if (word) return { path: path.join(cwd, word[0]), kind: "working-directory launcher file" };
	return null;
}
