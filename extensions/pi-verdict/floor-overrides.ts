import * as os from "node:os";
import * as path from "node:path";
import { baseForms, fold } from "./paths.ts";

// ============================================================================
// Floor overrides: the user's per-rule changes to the built-in floor (ADR-0013)
// ============================================================================

/** What an override does to its rule: skip it, or turn its deny into an ask. */
export type OverrideAction = "off" | "ask";

/** One parsed override. `scope` holds the base forms of its `paths`; null means everywhere. */
export interface FloorOverride {
	readonly action: OverrideAction;
	readonly scope: readonly string[] | null;
}

/** The parsed `floorOverrides` key, by rule id. */
export type FloorOverrides = ReadonlyMap<string, FloorOverride>;

export const NO_OVERRIDES: FloorOverrides = new Map();

/** Rules no override may change: the catastrophic deletes, the agent's own credential store, and the
 *  write whose kernel target is unknowable, which is a fail-closed mechanism rather than a policy.
 *  `rm-recursive` is the only rule that catches `rm -rf ~/` and `rm -rf /*`, which `rm-root` misses. */
export const NOT_OVERRIDABLE: ReadonlySet<string> = new Set(["rm-root", "rm-recursive", "rm-git", "S0:agent-db", "unresolved-symlink"]);

/** Returns the overrides a raw `floorOverrides` value declares, and a warning for each entry it ignores.
 *  Fails closed: a non-overridable id, a bad action and a bad scope path each leave that rule
 *  on, so a broken entry can only keep the gate as strict as it was. */
export function parseFloorOverrides(raw: unknown): { overrides: FloorOverrides; warnings: string[] } {
	const overrides = new Map<string, FloorOverride>();
	const warnings: string[] = [];
	if (raw === undefined) return { overrides, warnings };
	if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
		return { overrides, warnings: ["floorOverrides must be an object of rule id to override — ignored"] };
	}
	for (const [id, value] of Object.entries(raw)) {
		const parsed = NOT_OVERRIDABLE.has(id) ? "this rule cannot be overridden" : parseEntry(value);
		if (typeof parsed === "string") warnings.push(`floorOverrides.${id}: ${parsed} — the rule stays on`);
		else overrides.set(id, parsed);
	}
	return { overrides, warnings };
}

/** Returns the override an entry declares, or why it is ignored. */
function parseEntry(value: unknown): FloorOverride | string {
	if (value === "off" || value === "ask") return { action: value, scope: null };
	if (typeof value !== "object" || value === null || Array.isArray(value)) return 'expected "off", "ask" or { action, paths }';
	const entry = value as Record<string, unknown>; // a non-array object, read by key
	// A misspelled `paths` would otherwise read as no scope, widening the entry to everywhere.
	const unknownKey = Object.keys(entry).find((k) => k !== "action" && k !== "paths");
	if (unknownKey !== undefined) return `unknown key ${unknownKey} (expected action and paths)`;
	const { action, paths } = entry;
	if (action !== "off" && action !== "ask") return 'action must be "off" or "ask"';
	if (paths === undefined) return { action, scope: null };
	if (!Array.isArray(paths) || paths.length === 0 || !paths.every((p) => typeof p === "string" && p.length > 0)) {
		return "paths must be a non-empty list of paths";
	}
	const scope: string[] = [];
	for (const p of paths as string[]) {
		const homeRelative = p === "~" || p.startsWith("~/");
		if (!path.isAbsolute(p) && !homeRelative) return `scope path ${p} must be absolute or start with ~/`;
		const abs = path.resolve(homeRelative ? path.join(os.homedir(), p.slice(1)) : p);
		// Every form counts, since a scope path that is a symlink to home would admit home by its real form.
		const forms = baseForms(abs);
		if (forms.some(coversHome)) return `scope path ${p} covers the home directory`;
		scope.push(...forms);
	}
	return { action, scope };
}

/** True when a scope path is the home directory or one of its ancestors. */
function coversHome(abs: string): boolean {
	const home = fold(path.resolve(os.homedir()));
	const base = fold(abs);
	return home === base || home.startsWith(base.endsWith(path.sep) ? base : base + path.sep);
}

/** Returns the override that applies to rule `id` for a call graded in `forms`: one without a scope, or
 *  one whose scope holds every form. Null keeps the rule on. */
export function overrideFor(overrides: FloorOverrides, id: string, forms: readonly string[]): FloorOverride | null {
	const override = overrides.get(id);
	if (override === undefined) return null;
	if (override.scope === null) return override;
	const bases = override.scope.map(fold);
	const inside = (f: string): boolean => {
		const form = fold(f);
		return bases.some((b) => form === b || form.startsWith(b + path.sep));
	};
	return forms.length > 0 && forms.every(inside) ? override : null;
}

/** Returns the overrides whose id names a floor rule, and a warning for each that does not. The ids are
 *  checked after loading, because the rule tables live in modules the config loader does not import. */
export function knownOverrides(
	overrides: FloorOverrides,
	knownIds: ReadonlySet<string>,
): { overrides: FloorOverrides; warnings: string[] } {
	const known = new Map<string, FloorOverride>();
	const warnings: string[] = [];
	for (const [id, override] of overrides) {
		if (knownIds.has(id)) known.set(id, override);
		else warnings.push(`floorOverrides.${id}: unknown rule id — ignored`);
	}
	return { overrides: known, warnings };
}
