import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { baseForms } from "./paths.ts";

/** The location of this module (`import.meta.url` resolved; null = unresolvable), which stands in for the gate's
 *  entry file when self-protection and agent-dir anchoring read where the gate is installed. That holds only
 *  because this module sits directly in `extensions/pi-verdict/`, beside `index.ts`, so both share one install
 *  root and one protected directory prefix (pinned by the test `the anchor module sits in the gate directory`). */
export const OWN_FILE_PATH: string | null = (() => {
	try {
		return fileURLToPath(import.meta.url);
	} catch {
		return null;
	}
})();

/**
 * Resolve the agent directory the gate is anchored to (#35, dual-host):
 *   1. PI_CODING_AGENT_DIR — explicit user override, always wins.
 *   2. Self-anchoring from the extension's own installed path: a copy at
 *      <home>/<dot-dir>/(agent/)?(plugins/node_modules/<pkg>/)?extensions/…
 *      anchors to <home>/<dot-dir>/agent. Covers the pi forms
 *      (~/.pi/agent/extensions[/pkg]/…) and the two omp npm layouts:
 *      under the agent dir (~/.omp/agent/plugins/node_modules/<pkg>/…) and,
 *      since omp 18.1, next to it (~/.omp/plugins/node_modules/<pkg>/…) —
 *      omp keeps its config tree under <dot-dir>/agent in both layouts.
 *      Deliberately NO host-tree existence probing: on a dual-install machine
 *      running under pi, a present ~/.omp must not misroute the gate.
 *   3. Fallback: today's default (~/.pi/agent) — dev checkouts and any
 *      unanchored location.
 * Both the lexical and the realpath form of ownFile are tried (symlinked
 * agent trees, macOS firmlink homes).
 */
export function escapeRegExp(s: string): string {
	return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function resolveAgentDir(ownFile: string | null, home: string, envAgentDir: string | undefined): string {
	if (envAgentDir) return envAgentDir;
	if (ownFile) {
		// [pi-verdict local patch: Windows path-separator compat] fileURLToPath()
		// and os.homedir() return backslash-separated paths on Windows, but the
		// anchor regex is written with literal forward slashes — normalize both
		// sides before matching, or the anchor never matches on Windows and the
		// gate silently falls back to ~/.pi/agent (wrong host's config tree).
		const normalizedHome = home.replace(/\\/g, "/");
		const anchor = new RegExp(
			`^${escapeRegExp(normalizedHome)}(/(\\.[^/]+)/(?:agent/)?(?:plugins/node_modules/(?:@[^/]+/)?[^/]+/)?extensions/)`,
		);
		for (const f of baseForms(ownFile)) {
			const m = f.replace(/\\/g, "/").match(anchor);
			if (m) return path.join(home, m[2], "agent");
		}
	}
	return path.join(home, ".pi", "agent");
}

export function agentDirPath(): string {
	return resolveAgentDir(OWN_FILE_PATH, os.homedir(), process.env.PI_CODING_AGENT_DIR);
}

export function userConfigPath(): string {
	return path.join(agentDirPath(), "config", "pi-verdict.json");
}

/** [pi-verdict local patch: project overrides] project dir name mirrors the host tree: ~/.omp/agent → ".omp", ~/.pi/agent → ".pi" */
export function projectDotDir(agentDir: string): string {
	const d = path.basename(path.dirname(agentDir));
	return d.startsWith(".") ? d : ".pi";
}

export function samePath(a: string, b: string): boolean {
	const n = (p: string) => {
		const r = path.resolve(p);
		return process.platform === "win32" ? r.toLowerCase() : r;
	};
	return n(a) === n(b);
}

/** Nearest <dir>/<dotDir>/pi-verdict.json walking up from cwd. Stops (exclusive) at the home dir
 *  and at the agent tree's root parent, so the global tree is never mistaken for a project.
 *  Applied only when the project is trusted (see readTrustStore). */
export function findProjectConfig(cwd: string, agentDir: string): string | null {
	const dot = projectDotDir(agentDir);
	const stops = [os.homedir(), path.dirname(path.dirname(agentDir))];
	let dir = path.resolve(cwd);
	for (;;) {
		if (stops.some((s) => samePath(s, dir))) return null;
		const candidate = path.join(dir, dot, "pi-verdict.json");
		if (fs.existsSync(candidate)) return candidate;
		const parent = path.dirname(dir);
		if (parent === dir) return null;
		dir = parent;
	}
}
