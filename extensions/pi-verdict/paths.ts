import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

// ============================================================================
// Canonical forms: the only implementation of both tiers of dual-form matching (see the “dual-form matching” entry in CONTEXT.md).
// ============================================================================

/**
 * Base tier (ADR-0002): lexical absolute form + full-path realpath form (realpath resolves symlinks transitively;
 * on failure—target does not exist, glob token—downgrade to lexical form only). denyPaths and all
 * “base-side” dual-form sets (cwd base, agentDir, install root) use this tier.
 */
export function baseForms(p: string): string[] {
	const out = [p];
	try {
		const r = fs.realpathSync(p);
		if (r !== p) out.push(r);
	} catch {
		/* Does not exist: lexical form only */
	}
	return out;
}

/**
 * Ancestor-rebuilt tier (#20): beyond base forms, when the target does not exist, rebuild its real form stepwise
 * from the nearest existing ancestor's realpath—symlink aliases expose their real location even if the final
 * segment does not exist. Use this tier for decisions where accidental allows are costly (path-sensitivity floor);
 * denyPaths do not move up a tier (ADR-0002).
 */
export function rebuiltForms(abs: string): string[] {
	const out = new Set<string>([abs]);
	let dir = abs;
	const tail: string[] = [];
	for (;;) {
		try {
			const real = fs.realpathSync(dir);
			out.add(path.join(real, ...tail));
			return [...out];
		} catch {
			const parent = path.dirname(dir);
			if (parent === dir) return [...out];
			tail.unshift(path.basename(dir));
			dir = parent;
		}
	}
}

/** Splitter for walk tails and readlink targets: on POSIX a backslash is a legal filename
 *  character (path-layer review item 7), so only `/` separates components; win32 treats both. */
const SPLIT_PATH_SEPS = process.platform === "win32" ? /[\\/]+/ : /\/+/;

/** Symlink-expansion budget for kernelWalk: a chain deeper than this is unresolvable, not walked. */
const SYMLINK_HOP_BUDGET = 8;

/** Kernel-faithful walk of a spelling a host may open verbatim (path-layer review item 4; items 7–8):
 *  symlinked components are resolved as the path descends and `..` applies to the already-resolved
 *  parent, unlike path.resolve's lexical collapse. omp's file tools return an *absolute* input to the
 *  filesystem verbatim (`resolveToCwd`: `isAbsolute ? expanded : path.resolve(cwd, expanded)`), so
 *  `link/../x` (link -> /) opens `/x` while path.resolve names `<dir>/x` — the floor must see the
 *  spelling the kernel would. The walk runs when the spelling contains `..` (what makes lexical
 *  collapse diverge) OR when the leaf itself is a symlink: a dangling or looping leaf has no
 *  realpath, so only readlink sees the file a later kernel open/create would touch (item 8; a
 *  missing leaf fails the kernel call regardless — the lexical candidate is what the kernel sees).
 *  Per component: realpath success advances; on failure lstat decides — a symlink expands via
 *  readlink (`SYMLINK_HOP_BUDGET`; exceeding marks the spelling unresolved), an existing non-link
 *  or a missing final component keeps the lexical candidate. A looping or unreadable link target
 *  returns `resolved: null` with `unresolved: true` — writes must fail closed there
 *  (kernelUnresolved). Inherits `~` expansion and caps length so a content-sized argument is not
 *  walked as a path. */
export function kernelWalk(rawPath: string, cwd: string): { resolved: string | null; unresolved: boolean } {
	if (!rawPath || rawPath.length > 4096) return { resolved: null, unresolved: false };
	const expanded = rawPath.startsWith("~") ? os.homedir() + rawPath.slice(1) : rawPath;
	if (!expanded.includes("..")) {
		try {
			if (!fs.lstatSync(path.resolve(cwd, expanded)).isSymbolicLink()) return { resolved: null, unresolved: false };
		} catch {
			return { resolved: null, unresolved: false };
		}
	}
	const absolute = path.isAbsolute(expanded);
	const root = absolute ? path.parse(expanded).root : path.resolve(cwd);
	const tail = absolute ? expanded.slice(root.length) : expanded;
	let resolved = root;
	const parts = tail.split(SPLIT_PATH_SEPS);
	let hops = 0;
	while (parts.length > 0) {
		const part = parts.shift();
		if (part === undefined) break;
		if (part === "" || part === ".") continue;
		if (part === "..") {
			resolved = path.dirname(resolved);
			continue;
		}
		const candidate = path.join(resolved, part);
		try {
			resolved = fs.realpathSync(candidate);
			continue;
		} catch {
			/* Did not resolve — dangling link, loop, or missing component: lstat decides. */
		}
		let st: fs.Stats;
		try {
			st = fs.lstatSync(candidate);
		} catch {
			// Missing final component: the lexical candidate is what the kernel sees/creates.
			resolved = candidate;
			continue;
		}
		if (!st.isSymbolicLink()) {
			resolved = candidate;
			continue;
		}
		let target: string;
		try {
			target = fs.readlinkSync(candidate);
		} catch {
			return { resolved: null, unresolved: true };
		}
		hops++;
		if (hops > SYMLINK_HOP_BUDGET) return { resolved: null, unresolved: true };
		if (path.isAbsolute(target)) {
			resolved = path.parse(target).root;
			parts.unshift(...target.slice(path.parse(target).root.length).split(SPLIT_PATH_SEPS));
		} else {
			parts.unshift(...target.split(SPLIT_PATH_SEPS));
		}
	}
	return { resolved, unresolved: false };
}

/** Kernel-faithful forms (floor + self-protection tier, #20): the walk result passed through the
 *  ancestor-rebuild tier — a resolvable spelling contributes its rebuilt forms, a skipped or
 *  unresolvable walk contributes nothing. The self-protection helpers share this derivation;
 *  classifyPath consumes the walk result directly so one walk feeds forms + the fail-closed flag. */
export function kernelForms(rawPath: string, cwd: string): string[] {
	const { resolved } = kernelWalk(rawPath, cwd);
	return resolved === null ? [] : rebuiltForms(resolved);
}

/** Kernel-true spelling only — the base tier for `denyPathForms` and user-rule targets (item 10):
 *  no ancestor rebuild (ADR-0002's no-rebuild rule is unchanged), and gated on `..` so a plain
 *  path token pays no syscall walk. Null when the spelling has no `..` (those spellings stay
 *  base tier) or the walk is skipped/unresolvable. */
export function kernelPath(rawPath: string, cwd: string): string | null {
	if (!rawPath.includes("..")) return null;
	return kernelWalk(rawPath, cwd).resolved;
}

/** Case-insensitive filesystems (default macOS APFS, Windows) compare path strings
 *  case-folded; realpath already normalizes case whenever it resolves, this covers
 *  the lexical-only forms of nonexistent targets (#21). Linux stays case-sensitive.
 * Folded comparison is used only by denyPaths (S-rule comparison discipline lives in regex /i
 * —each keeps its own and is not unified by this module; see the “dual-form matching” entry). */
export const CASE_INSENSITIVE_FS = process.platform === "darwin" || process.platform === "win32";
export const fold = (s: string): string => (CASE_INSENSITIVE_FS ? s.toLowerCase() : s);

/** True when `child` is `base` or lies beneath it, compared case-folded on case-insensitive filesystems.
 *  A base that already ends in a separator, such as the filesystem root, contains every path under it. */
export function isWithin(child: string, base: string): boolean {
	const c = fold(child);
	const b = fold(base);
	return c === b || c.startsWith(b.endsWith(path.sep) ? b : b + path.sep);
}

/** Returns the part of `child` below `base` in `child`'s own spelling, or null when `child` is `base`
 *  itself or lies outside it; compared as `isWithin` compares. */
export function relativeBeneath(child: string, base: string): string | null {
	if (fold(child) === fold(base) || !isWithin(child, base)) return null;
	return child.slice(base.endsWith(path.sep) ? base.length : base.length + 1);
}
