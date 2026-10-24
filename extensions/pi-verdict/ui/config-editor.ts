import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { findProjectConfig, projectDotDir, samePath } from "../agent-dir.ts";
import { USER_CONFIG_TEMPLATE } from "../config.ts";

// ============================================================================
// Config editor helpers (/verdict)
// ============================================================================

export const EDITABLE_LIST_KEYS = ["allow", "deny", "denyPaths", "tools", "rules"] as const;
export type EditableListKey = (typeof EDITABLE_LIST_KEYS)[number];
export const LIST_KEY_DESC: Record<EditableListKey, string> = {
	allow: "regexes that auto-allow",
	deny: "regexes that auto-deny",
	denyPaths: "protected paths (always ask)",
	tools: "MCP/custom tool names that auto-allow",
	rules: "free-text classifier rules",
};
export const LIST_KEY_PLACEHOLDER: Record<EditableListKey, string> = {
	allow: "regex, e.g. ^git status\\b",
	deny: "regex, e.g. ^git push --force",
	denyPaths: "path, e.g. ~/.aws/",
	tools: "exact tool name, e.g. ask",
	rules: "free-text rule for the classifier",
};
export const GATE_OMP_DIR_DESC = "forced ask on any .omp directory access";
export const FOOTER_DESC = "footer status style";

/** Where a project config would be written for `cwd`: the existing one if discovered, else `<cwd>/<dotdir>/pi-verdict.json`.
 *  null when `findProjectConfig`'s stop rule (home dir / agent tree root) would never discover a file there. */
export function projectConfigTarget(cwd: string, agentDir: string): string | null {
	const found = findProjectConfig(cwd, agentDir);
	if (found) return found;
	if (samePath(cwd, os.homedir()) || samePath(cwd, path.dirname(path.dirname(agentDir)))) return null;
	return path.join(path.resolve(cwd), projectDotDir(agentDir), "pi-verdict.json");
}

/** Parse a config file into its top-level object. A missing file yields the first-run template (user) or `{}` (local). */
export function readConfigObject(file: string, kind: "user" | "local"): { raw: Record<string, unknown> } | { error: string } {
	if (!fs.existsSync(file)) return { raw: kind === "user" ? (JSON.parse(USER_CONFIG_TEMPLATE) as Record<string, unknown>) : {} };
	let parsed: unknown;
	try {
		parsed = JSON.parse(fs.readFileSync(file, "utf8"));
	} catch (e) {
		return { error: `${file} is not valid JSON (${e instanceof Error ? e.message : String(e)}) — fix it by hand` };
	}
	if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
		return { error: `${file}: top level must be a JSON object — fix it by hand` };
	}
	return { raw: parsed as Record<string, unknown> };
}

/** Write the config object back as pretty JSON; null on success, the error message otherwise */
export function writeConfigObject(file: string, raw: Record<string, unknown>): string | null {
	try {
		fs.mkdirSync(path.dirname(file), { recursive: true });
		fs.writeFileSync(file, JSON.stringify(raw, null, 2) + "\n");
		return null;
	} catch (e) {
		return e instanceof Error ? e.message : String(e);
	}
}

/** Validate and canonicalize a typed list entry; null = blank input (treated as cancel) */
export function normalizeEntry(key: EditableListKey, input: string): { value: string } | { error: string } | null {
	const text = input.replace(/[\r\n]+$/, ""); // editor dialogs may append a trailing newline
	if (text.trim() === "") return null;
	if (key !== "rules" && /[\r\n]/.test(text)) return { error: "must be a single line" };
	if (key === "allow" || key === "deny") {
		// verbatim: patterns like "rm " rely on their spaces
		try {
			new RegExp(text);
		} catch (e) {
			return { error: `invalid regex: ${e instanceof Error ? e.message : String(e)}` };
		}
		return { value: text };
	}
	return { value: text.trim() }; // matches loadUserRules trimming
}

/** Display form of a list entry; non-strings stay visible as JSON so they can be removed or fixed */
export function entryLabel(x: unknown): string {
	return typeof x === "string" ? x : JSON.stringify(x);
}
