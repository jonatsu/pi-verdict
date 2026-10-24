import * as os from "node:os";
import * as path from "node:path";
import { toolAccess } from "./access.ts";
import { bashPathTokens, commandForPathTokens, denyPathForms } from "./deny-paths.ts";
import { baseForms, CASE_INSENSITIVE_FS } from "./paths.ts";

// ============================================================================
// Protected-path redaction of model payloads (ADR-0002)
// ============================================================================

/** True when a tool call's arguments name a protected path; the caller then replaces the whole payload line
 *  with `PROTECTED_PATH_MARKER`. */
export type RedactorFn = (args: Record<string, unknown>) => boolean;

/** The fixed text a redacted payload line becomes: a neutral privacy marker, not an instruction to the model. */
export const PROTECTED_PATH_MARKER = "<protected-path>";

/** Returns a predicate that is true when a tool call names one of the `denyPaths` bases, anchored at `cwd`.
 *  It matches a call's extracted targets the way a `denyPaths` hit does, and any spelling of a base in its
 *  string values: absolute, cwd-relative, `~/`, `$HOME`, `${HOME}`, and the bare home-relative tail.
 *  It fails toward redaction, since an extra marker is harmless and a missed path leaks it to a model
 *  provider (ADR-0002); obfuscated spellings such as command substitution are the recorded residual.
 *  `strict` is the protected-path ask's form: spellings must sit on path-word boundaries and the bare
 *  tail is left out, because a false positive there blocks a legitimate call. */
export function redactorFor(
	cwd: string,
	bases: readonly string[],
	platform: RedactionPlatform = HOST_REDACTION_PLATFORM,
	strict = false,
): RedactorFn {
	const fold = (s: string): string => (platform.caseInsensitive ? s.toLowerCase() : s);
	const spellings = new Set<string>();
	const home = os.homedir();
	for (const base of bases) {
		for (const form of baseForms(base)) spellings.add(form);
		// `~/` and `$HOME`/`${HOME}` spellings of the same base, plus the home-relative tail
		// (e.g. `/.ssh/`) when the base sits under the user's home directory. The bare tail matches
		// the same directory name in any other tree, so the strict ask match leaves it out.
		const relativeToHome =
			home && (fold(base) === fold(home) || fold(base).startsWith(fold(home + path.sep))) ? base.slice(home.length) : null;
		if (relativeToHome !== null && relativeToHome !== "") {
			const prefixedForms = [`~${relativeToHome}`, `$HOME${relativeToHome}`, `{HOME}${relativeToHome}`];
			for (const form of strict ? prefixedForms : [relativeToHome, ...prefixedForms]) {
				spellings.add(form); // `{HOME}` + tail also matches inside a literal `${HOME}` spelling
				for (const resolved of denyPathForms(form, cwd)) spellings.add(resolved); // its cwd-resolved forms too
			}
		}
		// Prefix form without a trailing separator. A root base strips to "", which would match every string.
		const withoutSep = base.endsWith(path.sep) ? base.slice(0, -path.sep.length) : "";
		if (withoutSep) spellings.add(withoutSep);
		// The cwd-relative spelling of an in-cwd base, which a past call may use ("secrets/a.txt").
		const relToCwd = fold(base).startsWith(fold(cwd + path.sep)) ? path.relative(cwd, base) : null;
		if (relToCwd) spellings.add(relToCwd);
	}
	if (spellings.size === 0) return () => false;
	// A target hits when one of its `denyPathForms` equals a spelling or lies beneath it, as a `denyPaths`
	// hit does; a command is tokenized first, so every spelling the `denyPaths` layer catches redacts here.
	const hits = (text: string): boolean => {
		for (const form of denyPathForms(text, cwd)) {
			const folded = fold(form);
			for (const spelling of spellings) {
				const base = fold(spelling);
				if (folded === base || folded.startsWith(base.endsWith(path.sep) ? base : base + path.sep)) return true;
			}
		}
		return false;
	};
	return (args: Record<string, unknown>): boolean => {
		const access = toolAccess("", args); // name-agnostic: direction/unknown both key on payload shape only
		for (const target of [...access.gradedReads, ...access.gradedWrites]) if (hits(target)) return true;
		if (access.command !== null)
			for (const token of bashPathTokens(commandForPathTokens(access.command, platform.win32))) if (hits(token)) return true;
		// Over the string values themselves: the JSON text doubles every backslash, so a Windows spelling
		// would never match there. The JSON check stays for nesting deeper than inputStrings reads.
		if (mentionsSpelling(inputStrings(args), spellings, platform, strict)) return true;
		return mentionsSpelling([JSON.stringify(args)], spellings, platform, strict);
	};
}

/** What the platform changes about path comparison: Windows and macOS compare names without
 *  case, and Windows spells separators with a backslash. A parameter so each branch is testable
 *  on any host. */
export interface RedactionPlatform {
	caseInsensitive: boolean;
	win32: boolean;
}
/** The platform this process runs on. */
export const HOST_REDACTION_PLATFORM: RedactionPlatform = { caseInsensitive: CASE_INSENSITIVE_FS, win32: path.sep === "\\" };

/** A character that may precede a path word in a command or argument. */
const LEFT_BOUNDARY = /[\s/\\'"`=~$({;,|&:]/;
/** A character that may follow a path word in a command or argument. */
const RIGHT_BOUNDARY = /[\s/\\'"`;,|&)<>:]/;

/** True when any text contains any spelling, compared without case and across both separator styles where
 *  the platform does. `strict` also requires path-word boundaries, so `secrets` does not match inside
 *  `secrets-loader.test.ts`; the protected-path ask uses it because a match there is a hard ask. */
export function mentionsSpelling(
	texts: readonly string[],
	spellings: Iterable<string>,
	platform: RedactionPlatform,
	strict = false,
): boolean {
	const normalize = (s: string): string => {
		const separated = platform.win32 ? s.replace(/\\/g, "/") : s;
		return platform.caseInsensitive ? separated.toLowerCase() : separated;
	};
	const haystacks = texts.map(normalize);
	const found = (h: string, needle: string): boolean => {
		if (!strict) return h.includes(needle);
		const needsLeft = /^[\w.-]/.test(needle);
		for (let at = h.indexOf(needle); at >= 0; at = h.indexOf(needle, at + 1)) {
			const before = at === 0 ? "" : (h[at - 1] ?? "");
			const after = h[at + needle.length] ?? "";
			if ((!needsLeft || before === "" || LEFT_BOUNDARY.test(before)) && (after === "" || RIGHT_BOUNDARY.test(after))) return true;
		}
		return false;
	};
	for (const spelling of spellings) {
		const needle = normalize(spelling);
		if (needle && haystacks.some((h) => found(h, needle))) return true;
	}
	return false;
}

/** Returns every string value in a tool input, down to a fixed nesting depth: the candidates the redactor
 *  and the self-protection scan test for a protected path. */
export function inputStrings(value: unknown, out: string[] = [], depth = 0): string[] {
	if (depth > 6 || value === null || value === undefined) return out;
	if (typeof value === "string") out.push(value);
	else if (Array.isArray(value)) for (const v of value) inputStrings(v, out, depth + 1);
	else if (typeof value === "object") for (const v of Object.values(value)) inputStrings(v, out, depth + 1);
	return out;
}
