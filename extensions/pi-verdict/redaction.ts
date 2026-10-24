import * as os from "node:os";
import * as path from "node:path";
import { toolAccess } from "./access.ts";
import { bashPathTokens, commandForPathTokens, denyPathForms } from "./deny-paths.ts";
import { baseForms, CASE_INSENSITIVE_FS } from "./paths.ts";

// ============================================================================
// Protected-path redaction of model payloads (ADR-0002)
// ============================================================================

/** Transcript redaction predicate (item 6b, Phase 5): true when this tool call's arguments
 *  name a user-declared protected path — the caller then substitutes the whole line for the
 *  fixed `<protected-path>` marker (see redactorFor). */
export type RedactorFn = (args: Record<string, unknown>) => boolean;

/** The one fixed marker a redacted payload line becomes (plan item 6b) — a neutral
 *  privacy marker, never an injection framing. Named once so every substitution
 *  site in the pipeline and the presentation layer shares it. */
export const PROTECTED_PATH_MARKER = "<protected-path>";

/** Builds the redaction predicate from env.cwd and the session's anchored denyPaths bases
 *  (item 6b, Phase 5; Claude-review F10). Detection is deliberately conservative — two
 *  independent checks, either one redacts: (1) the structured adapter extraction
 *  (toolAccess → reads/writes, which covers a known tool's path/paths/patch text and an
 *  unknown tool's extracted targets too, F10), tested against the same dual-form set a
 *  denyPaths comparison uses (`denyPathForms`, anchored here once with `cwd`), and (2) the
 *  raw JSON of the arguments containing any base's spelling — absolute, `~/`, `$HOME`/`${HOME}`
 *  (the denyPaths tokeniser reads `$HOME`, `"$HOME"` and a braced `${HOME}` before a `/`, but no
 *  other expansion, so this raw check covers what the tokeniser cannot), or the home-relative tail (e.g. a
 *  `~/.ssh/` declaration's `.ssh/` tail), in both its literal and `cwd`-resolved spellings so
 *  a relative declaration still catches an absolute spelling of the same path. In transcript
 *  use (the default), over-redaction is harmless and under-redaction is a leak, so the
 *  conservative direction is wholesale. With `strict`, the raw spelling check also needs path-word
 *  boundaries and leaves out the bare home-relative tail (`~/`, `$HOME` and `${HOME}` spellings stay),
 *  because the verdict's protected-path ask uses that form and a false positive there blocks a
 *  legitimate call. A redacted line is dropped for the fixed marker `<protected-path>`, a neutral
 *  privacy marker, not an injection framing (PC-review F9). Detected only literally:
 *  obfuscated spellings (command substitution, base64, archiving — ADR-0002's documented
 *  holes) are NOT redacted here; the classifier's existence hint stays the backstop for those
 *  calls (recorded residual, ADR-0002 amendment — PC-review F5b). User-message lines are
 *  deliberately never redacted — the user's own disclosure in their own message is theirs
 *  (PC-review F5c). */
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
				spellings.add(form); // `{HOME}` + tail produces the literal ${HOME}… — F10's missed tokeniser form
				for (const resolved of denyPathForms(form, cwd)) spellings.add(resolved); // literal + cwd-resolved, both ways
			}
		}
		// Prefix form without a trailing separator. A root base strips to "", which would match every string.
		const withoutSep = base.endsWith(path.sep) ? base.slice(0, -path.sep.length) : "";
		if (withoutSep) spellings.add(withoutSep);
		// The cwd-relative spelling of an in-cwd base — a past call may spell the
		// same path relatively ("secrets/a.txt"), which neither the absolute form nor its
		// raw-JSON substring can catch.
		const relToCwd = fold(base).startsWith(fold(cwd + path.sep)) ? path.relative(cwd, base) : null;
		if (relToCwd) spellings.add(relToCwd);
	}
	if (spellings.size === 0) return () => false;
	// The structured half mirrors a real denyPaths hit: the candidate runs
	// through denyPathForms (cwd-resolved + kernel forms, same as hitDenyPaths) and matches a
	// spelling exactly or beneath it (single-directional: the leak direction; over-redaction is
	// the accepted side). Command/code payloads tokenize through bashPathTokens first, so an
	// alias/kernel spelling a denyPaths hit would catch is redacted here too.
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
export const HOST_REDACTION_PLATFORM: RedactionPlatform = { caseInsensitive: CASE_INSENSITIVE_FS, win32: path.sep === "\\" };

/** Characters that end or begin a path word in a command or argument. */
const LEFT_BOUNDARY = /[\s/\\'"`=~$({;,|&:]/;
const RIGHT_BOUNDARY = /[\s/\\'"`;,|&)<>:]/;

/** Does any text contain any spelling, comparing case-insensitively and across both separator
 *  styles where the platform does? Over-matching is the safe direction for transcript redaction.
 *  `strict` additionally requires the spelling to sit on path-word boundaries, so `secrets` does not
 *  match inside `secrets-loader.test.ts`; the verdict uses it, because a match there is a hard ask. */
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

/** Every string value in a tool input, recursively — the candidates the protected-path
 *  test runs over. A false positive on a legitimately-named path is visible and safe;
 *  a missed write is not. */
export function inputStrings(value: unknown, out: string[] = [], depth = 0): string[] {
	if (depth > 6 || value === null || value === undefined) return out;
	if (typeof value === "string") out.push(value);
	else if (Array.isArray(value)) for (const v of value) inputStrings(v, out, depth + 1);
	else if (typeof value === "object") for (const v of Object.values(value)) inputStrings(v, out, depth + 1);
	return out;
}
