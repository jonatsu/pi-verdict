import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { agentDirPath, samePath } from "./agent-dir.ts";
import { baseForms } from "./paths.ts";

// ---- project trust (gate-owned; the host's own trust notion is not usable: omp always reports trusted) ----

export const TRUST_CHOICE = "Trust — apply this project's config (remembered)";
export const NOT_NOW_CHOICE = "Not now — ignore it this session";
export const NEVER_CHOICE = "Never — ignore it and don't ask again";

export function trustStorePath(): string {
	return path.join(agentDirPath(), "config", "pi-verdict-trust.json");
}

/** The directory that contains the project's dot dir */
export function projectRootOf(configPath: string): string {
	return path.dirname(path.dirname(configPath));
}

/** Exact-root match only, never subtrees */
export function rootIn(root: string, list: string[]): boolean {
	const rootForms = baseForms(root);
	return list.some((t) => baseForms(t).some((tf) => rootForms.some((rf) => samePath(tf, rf))));
}

interface TrustStore {
	trusted: string[];
	untrusted: string[];
	hashes: Record<string, string>;
	error: string | null;
}

/** sha256 of a file's bytes, or null when it cannot be read. */
function hashFile(p: string): string | null {
	try {
		return createHash("sha256").update(fs.readFileSync(p)).digest("hex");
	} catch {
		return null;
	}
}

export function readTrustStore(): TrustStore {
	const p = trustStorePath();
	if (!fs.existsSync(p)) return { trusted: [], untrusted: [], hashes: {}, error: null };
	let raw: unknown;
	try {
		raw = JSON.parse(fs.readFileSync(p, "utf8"));
	} catch (err) {
		return {
			trusted: [],
			untrusted: [],
			hashes: {},
			error: `trust file unreadable: ${err instanceof Error ? err.message : String(err)} (${p})`,
		};
	}
	if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
		return { trusted: [], untrusted: [], hashes: {}, error: `trust file unreadable: top level must be a JSON object (${p})` };
	}
	let error: string | null = null;
	const obj = raw as Record<string, unknown>; // narrowed above to a non-null, non-array object
	const list = (key: "trusted" | "untrusted"): string[] => {
		const v = obj[key];
		if (v === undefined) return [];
		if (!Array.isArray(v)) {
			error ??= `trust file ${key}: must be an array of paths (${p})`;
			return [];
		}
		return v.flatMap((x) => (typeof x === "string" && x.trim() ? [path.resolve(x.trim())] : []));
	};
	const hashes: Record<string, string> = {};
	const rawHashes = obj.hashes;
	if (rawHashes && typeof rawHashes === "object" && !Array.isArray(rawHashes)) {
		for (const [k, v] of Object.entries(rawHashes as Record<string, unknown>)) {
			if (typeof v === "string" && v) hashes[path.resolve(k)] = v;
		}
	}
	return { trusted: list("trusted"), untrusted: list("untrusted"), hashes, error };
}

/** Trust state for a project root whose override config sits at `configPath`.
 *  "trusted" requires both a recorded root and a content-hash match: the approved
 *  override must be byte-for-byte the one the user saw (TOCTOU guard — a later commit
 *  or PR to a trusted repo re-prompts instead of silently widening the gate). */
export function projectTrustState(root: string, configPath: string, store: TrustStore): "trusted" | "untrusted" | "undecided" {
	if (rootIn(root, store.untrusted)) return "untrusted";
	if (!rootIn(root, store.trusted)) return "undecided";
	const approved = store.hashes[path.resolve(root)];
	if (!approved) return "undecided"; // legacy entry without a hash — re-prompt once
	return hashFile(configPath) === approved ? "trusted" : "undecided";
}

/** Persist a trust decision for a project root (and, for "trusted", the approved
 *  override's content hash). Returns an error message, or null on success.
 *  A damaged file is never overwritten (the user may have hand-edited it). */
export function recordTrust(root: string, decision: "trusted" | "untrusted", configPath: string | null = null): string | null {
	const store = readTrustStore();
	if (store.error !== null) return store.error;
	const key = path.resolve(root);
	const trusted = store.trusted.filter((e) => !rootIn(root, [e]));
	const untrusted = store.untrusted.filter((e) => !rootIn(root, [e]));
	const hashes = { ...store.hashes };
	delete hashes[key];
	if (decision === "trusted") {
		trusted.push(key);
		const hash = configPath ? hashFile(configPath) : null;
		if (hash) hashes[key] = hash;
	} else {
		untrusted.push(key);
	}
	const p = trustStorePath();
	try {
		fs.mkdirSync(path.dirname(p), { recursive: true });
		fs.writeFileSync(p, JSON.stringify({ trusted, untrusted, hashes }, null, 2) + "\n");
	} catch (err) {
		return `could not write ${p}: ${err instanceof Error ? err.message : String(err)}`;
	}
	return null;
}
