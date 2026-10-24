import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { isCommandTool, toolAccess } from "./access.ts";
import { agentDirPath } from "./agent-dir.ts";
import { callPathCandidates, denyPathForms, expandPathSpelling } from "./deny-paths.ts";
import { baseForms, fold, rebuiltForms } from "./paths.ts";

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
	| "working-directory launcher file"
	| "home-directory launcher file"
	| "directory holding code-loading locations";

export interface CodeLoadHit {
	path: string;
	kind: CodeLoadKind;
}

/** Entry names directly below one root, by location class. The general config files
 *  (`config.yml`, `settings.json`) hold launch keys among unrelated settings, so they stay in
 *  their own list and a later change can grade them apart. */
interface LocationTable {
	dirs: readonly string[];
	launchers: readonly string[];
	configs: readonly string[];
	dirKind: CodeLoadKind;
	launcherKind: CodeLoadKind;
	configKind: CodeLoadKind;
}

/** The LSP and DAP config names omp reads: `{,.}{lsp,dap}.{json,yaml,yml}`; mirrors omp's config file sources (18.12.6). */
const LSP_DAP: readonly string[] = ["", "."].flatMap((dot) =>
	["lsp", "dap"].flatMap((name) => ["json", "yaml", "yml"].map((ext) => `${dot}${name}.${ext}`)),
);

const OMP_AGENT: LocationTable = {
	dirs: ["extensions", "hooks", "tools", "commands"],
	launchers: ["mcp.json", ".mcp.json", "models.yml", ...LSP_DAP],
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
	launchers: ["mcp.json", ".mcp.json", ...LSP_DAP],
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
const CWD: LocationTable = {
	dirs: [],
	launchers: ["mcp.json", ".mcp.json", ...LSP_DAP],
	configs: [],
	dirKind: "working-directory launcher file",
	launcherKind: "working-directory launcher file",
	configKind: "working-directory launcher file",
};

/** omp reads the LSP and DAP config in the home directory from any working directory. */
const HOME: LocationTable = { ...CWD, launchers: LSP_DAP, launcherKind: "home-directory launcher file" };

/** A bare working-directory launcher name as a word of a command or code text (`> mcp.json`,
 *  `open(".dap.json")`); the path tokenizer only extracts spellings that hold a separator. */
const CWD_LAUNCHER_WORD = /(?<![\w./\\-])\.?(?:mcp\.json|(?:lsp|dap)\.(?:json|ya?ml))(?![\w.\\/-])/;

const PARENT: CodeLoadKind = "directory holding code-loading locations";

/** Linux's `PATH_MAX`; `kernelWalk` stops at the same length. */
const MAX_REBUILT_PATH = 4096;

/** The class of `rel` (the segments below a root) in `table`: a listed directory or anything
 *  beneath it, or a listed file directly in the root. */
function classify(rel: readonly string[], table: LocationTable): CodeLoadKind | null {
	if (rel.length === 0 || rel[0] === "") return null;
	if (table.dirs.includes(rel[0])) return table.dirKind;
	if (rel.length !== 1) return null;
	if (table.launchers.includes(rel[0])) return table.launcherKind;
	if (table.configs.includes(rel[0])) return table.configKind;
	return null;
}

/** Path text with "/" separators, case-folded on case-insensitive filesystems. */
const comparable = (p: string): string => fold(path.sep === "\\" ? p.replace(/\\/g, "/") : p);

const withSlash = (root: string): string => (root.endsWith("/") ? root : `${root}/`);
const strictlyUnder = (child: string, root: string): boolean => child !== root && child.startsWith(withSlash(root));
const under = (child: string, root: string): boolean => child === root || strictlyUnder(child, root);
const join = (root: string, name: string): string => `${withSlash(root)}${name}`;
const relSegments = (child: string, root: string): string[] => child.slice(withSlash(root).length).split("/");

/** The roots one call is graded against, computed once per call: the resolved agent directory,
 *  omp's data roots (`~/.omp`, and `$XDG_DATA_HOME/omp` when that variable is absolute), the
 *  home directory and the working directory, each in its lexical and realpath form. */
interface Roots {
	agent: string[];
	ompData: string[];
	home: string[];
	cwd: string[];
}

function rootsFor(cwd: string): Roots {
	const forms = (p: string): string[] => baseForms(path.resolve(p)).map(comparable);
	const xdg = process.env.XDG_DATA_HOME;
	const ompData = [path.join(os.homedir(), ".omp"), ...(xdg && path.isAbsolute(xdg) ? [path.join(xdg, "omp")] : [])];
	return { agent: forms(agentDirPath()), ompData: ompData.flatMap(forms), home: forms(os.homedir()), cwd: forms(cwd) };
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

/** The class of a path below an omp data root: a plugin root, or a profile's plugin root. The
 *  data root itself, its `profiles` directory and a profile directory hold such roots. */
function classifyOmpData(rel: readonly string[]): CodeLoadKind | null {
	if (rel[0] === "plugins") return "plugin install root";
	if (rel[0] !== "profiles") return null;
	if (rel.length <= 2) return PARENT;
	return rel[2] === "plugins" ? "plugin install root" : null;
}

/** The location class of one absolute, comparable path form, or null when the host loads nothing
 *  there. A directory that holds locations counts too: a command or an archive extraction aimed
 *  at it writes into them. */
function classifyForm(form: string, roots: Roots): CodeLoadKind | null {
	for (const root of roots.agent) {
		if (form === root) return PARENT;
		const kind = strictlyUnder(form, root) ? classify(relSegments(form, root), ANY_AGENT) : null;
		if (kind) return kind;
	}
	for (const root of roots.ompData) {
		if (form === root) return PARENT;
		const kind = strictlyUnder(form, root) ? classifyOmpData(relSegments(form, root)) : null;
		if (kind) return kind;
	}
	const segs = form.split("/");
	const last = segs[segs.length - 1];
	if (last === ".omp" || last === ".pi") return PARENT;
	const agent = segmentAgentRel(segs);
	if (agent) {
		if (agent.rel.length === 0) return PARENT;
		const kind = classify(agent.rel, agent.table);
		if (kind) return kind;
	}
	for (let i = 0; i < segs.length; i++) {
		if (segs[i] === ".omp" && segs[i + 1] === "profiles" && segs.length <= i + 3) return PARENT;
		const table = segs[i] === ".omp" ? OMP_PROJECT : segs[i] === ".pi" ? PI_PROJECT : null;
		const kind = table && classify(segs.slice(i + 1), table);
		if (kind) return kind;
	}
	const dir = path.posix.dirname(form);
	const name = path.posix.basename(form);
	if (roots.cwd.includes(dir)) {
		const kind = classify([name], CWD);
		if (kind) return kind;
	}
	if (roots.home.includes(dir)) return classify([name], HOME);
	return null;
}

const readdir = (dir: string): string[] => {
	try {
		return fs.readdirSync(dir);
	} catch {
		return [];
	}
};

/** The first existing code-loading entry inside the subtree a mutating scope tool covers. The
 *  roots checked are the ones the gate can name without walking the tree: the agent
 *  directories, the plugin roots, the home and working directories, and the `.omp` and `.pi`
 *  trees of the scope and of the cwd. Such a tool edits only files that exist, so a missing
 *  entry cannot be reached. */
function coveredEntry(scope: string, roots: Roots): CodeLoadHit | null {
	const home = comparable(os.homedir());
	const candidates: Array<{ root: string; table: LocationTable | "whole" }> = [
		...roots.agent.map((root) => ({ root, table: ANY_AGENT })),
		{ root: join(home, ".omp/agent"), table: OMP_AGENT },
		{ root: join(home, ".pi/agent"), table: PI_AGENT },
		...roots.home.map((root) => ({ root, table: HOME })),
		...roots.cwd.map((root) => ({ root, table: CWD })),
	];
	for (const data of roots.ompData) {
		candidates.push({ root: join(data, "plugins"), table: "whole" });
		const profiles = join(data, "profiles");
		if (!under(profiles, scope) && !under(scope, profiles)) continue;
		for (const name of readdir(profiles)) {
			candidates.push(
				{ root: join(profiles, `${name}/plugins`), table: "whole" },
				{ root: join(profiles, `${name}/agent`), table: OMP_AGENT },
			);
		}
	}
	for (const base of [scope, ...roots.cwd]) {
		candidates.push(
			{ root: join(base, ".omp"), table: OMP_PROJECT },
			{ root: join(base, ".omp/agent"), table: OMP_AGENT },
			{ root: join(base, ".pi"), table: PI_PROJECT },
			{ root: join(base, ".pi/agent"), table: PI_AGENT },
		);
	}
	const segs = scope.split("/");
	const last = segs[segs.length - 1];
	if (last === ".omp") candidates.push({ root: scope, table: OMP_PROJECT }, { root: join(scope, "agent"), table: OMP_AGENT });
	if (last === ".pi") candidates.push({ root: scope, table: PI_PROJECT }, { root: join(scope, "agent"), table: PI_AGENT });
	const agent = segmentAgentRel(segs);
	if (agent && agent.rel.length === 0) candidates.push({ root: scope, table: agent.table });
	for (const { root, table } of candidates) {
		if (!under(root, scope)) continue;
		if (table === "whole") {
			if (fs.existsSync(root)) return { path: root, kind: "plugin install root" };
			continue;
		}
		for (const name of readdir(root)) {
			const kind = classify([name], table);
			if (kind) return { path: join(root, name), kind };
		}
	}
	return null;
}

/** A command with `$PWD` and `$PI_CODING_AGENT_DIR` (bare or braced, with an adjoining double quote)
 *  spelled out, so the path tokenizer sees the directory they name. */
function expandCommandVariables(command: string, cwd: string): string {
	return command
		.replace(/"?\$(?:\{PWD\}|PWD\b)"?/g, () => cwd)
		.replace(/"?\$(?:\{PI_CODING_AGENT_DIR\}|PI_CODING_AGENT_DIR\b)"?/g, () => agentDirPath());
}

/** Does the call write where the host loads code in a later session (ADR-0011)? Returns the first
 *  matched path and its location class, or null. A file tool counts its write targets only; a
 *  command, a code cell and a tool the adapter cannot classify count every target they name,
 *  because their direction is unknown. A mutating scope tool also hits when a location sits
 *  inside the subtree it edits. Each target is compared in every form the host can resolve it
 *  to, including the form rebuilt from its nearest existing ancestor, so a new file under a
 *  symlinked directory is matched by where it lands. */
export function hitCodeLoadPath(toolName: string, input: Record<string, unknown>, cwd: string): CodeLoadHit | null {
	const roots = rootsFor(cwd);
	const access = toolAccess(toolName, input);
	const command = isCommandTool(toolName) ? expandCommandVariables(String(input.command ?? ""), cwd) : null;
	const graded = command === null ? input : { ...input, command };
	const subtree = access.scope && access.direction === "mutating";
	for (const candidate of callPathCandidates(toolName, graded, cwd, "written")) {
		if (!candidate) continue;
		const resolved = path.resolve(cwd, expandPathSpelling(candidate));
		// The rebuild walks one syscall per ancestor; a path past the kernel's limit cannot be opened.
		const rebuilt = resolved.length <= MAX_REBUILT_PATH ? rebuiltForms(resolved) : [];
		const forms = new Set([...denyPathForms(candidate, cwd), ...rebuilt]);
		for (const form of forms) {
			// A scope tool names the entry it would edit, which says more than the directory holding it.
			const covered = subtree ? coveredEntry(comparable(form), roots) : null;
			if (covered) return covered;
			const kind = classifyForm(comparable(form), roots);
			if (kind) return { path: form, kind };
		}
	}
	const text = command ?? (access.kind === "code" ? access.command : null);
	const word = text === null ? null : CWD_LAUNCHER_WORD.exec(fold(text));
	if (word) return { path: path.join(cwd, word[0]), kind: "working-directory launcher file" };
	return null;
}
