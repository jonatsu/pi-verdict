import * as os from "node:os";
import * as path from "node:path";
import { commandText, isCommandTool, toolAccess } from "./access.ts";
import { expandHome } from "./floor.ts";
import { baseForms, isWithin, kernelPath } from "./paths.ts";

// ============================================================================
// denyPaths (ADR-0002): user-declared protected paths — deterministic ask
//
// A path-semantic declaration: unlike deny regexes (string patterns, the user
// owns the normalization assumptions), the tool owns normalization here —
// ~ / $HOME expansion, lexical resolve against cwd, realpath resolution of
// symlink indirection (failure — nonexistent target, glob token — degrades to
// the lexical form). Comparison is per path segment, both sides in dual form
// (lexical + realpath). Scope tools (grep/find/ls) are subtree-scoped and
// bidirectional (#48): an omitted path means the cwd, and a declaration that
// sits INSIDE the searched subtree hits as well. The extractor is an evidence producer, never an
// adjudicator: a hit routes to a terminal ask (the declaring user owns the
// exception); non-interactive sessions degrade to deny. External script
// contents are never read (unsound by construction, ADR-0002); the classifier
// only ever sees a fixed existence hint — zero path plaintext.
// ============================================================================

/** Path-like tokens in a shell command string: ~/…, $HOME/…, absolute /…, ./… / ../…, and word/word relative forms. URL path segments can match the absolute branch — harmless: resolution against denyPaths prefixes is what decides, false positives ask (safe direction).
 *
 * Exported as the SEMANTIC ORACLE for #32's linear tokenizer (bashPathTokens) — the
 * production path never runs this regex: its four alternatives backtrack
 * quadratically on long failure searches (a 200k separator-free run takes ~28s,
 * issue #32), and unlike the danger regexes (#25's 8192 cap) it cannot be capped —
 * truncation would let a protected-path spelling beyond the cap silently escape
 * the deterministic ask (ADR-0002's never-silently-passed contract). */
export const BASH_PATH_TOKENS = /(?:~|\$HOME)(?:\/[\w.@*-]+)*|\/(?:[\w.@*-]+\/)*[\w.@*-]*|\.{1,2}(?:\/[\w.@*-]+)+|[\w.-]+(?:\/[\w.-]+)+/g;

/** ASCII class membership for the tokenizer (JS \w is ASCII-only; non-ASCII code
 *  points simply fall outside the classes, matching the regex). */
const TOKEN_W2 = new Uint8Array(128); // [\w.@*-]
const TOKEN_W4 = new Uint8Array(128); // [\w.-]
for (let c = 0; c < 128; c++) {
	const ch = String.fromCharCode(c);
	if (/[a-zA-Z0-9_]/.test(ch) || ".@*-".includes(ch)) TOKEN_W2[c] = 1;
	if (/[a-zA-Z0-9_]/.test(ch) || ".-".includes(ch)) TOKEN_W4[c] = 1;
}

const isW2 = (s: string, i: number): boolean => i < s.length && s.charCodeAt(i) < 128 && TOKEN_W2[s.charCodeAt(i)] === 1;
const isW4 = (s: string, i: number): boolean => i < s.length && s.charCodeAt(i) < 128 && TOKEN_W4[s.charCodeAt(i)] === 1;

/** #32: linear tokenizer for BASH_PATH_TOKENS — one deterministic pass, provably
 *  O(n): each alternative parses greedily with at most a bounded (≤ 2) retry, and
 *  the scan position only advances. The regex oracle's matchAll semantics are
 *  reproduced exactly (alternation priority included; equivalence pinned by a
 *  fuzz test against the oracle). Derivation per alternative:
 *  - alt1 `(~|$HOME)(\/W2+)*`: the star never fails — prefix + maximal (/ + W2-run)
 *    repetitions; a bare ~ / $HOME is a legal zero-iteration match.
 *  - alt2 `\/(W2+\/)*W2*`: pairs stop at the first word-run not followed by a slash;
 *    the trailing star always succeeds, so the greedy parse is THE match (a lone
 *    "/" is a legal zero-pair, empty-tail match).
 *  - alt3 `\.{1,2}(\/W2+)+`: dots are tried greedily (2 then 1 — the regex's DFS
 *    order); the plus needs one '/'-then-W2 continuation, else the alternative fails.
 *  - alt4 `W4+(\/W4+)+`: the leading run is maximal [p, e); a continuation is viable
 *    ONLY at a '/' (a literal) immediately followed by a W4 char, and once viable
 *    the greedy inner always completes — so the DFS-first match takes the LARGEST
 *    viable '/' at or before e and extends greedily. This is exactly where the
 *    regex paid O(n) per start position on failure; the scan computes it in O(1)
 *    amortized. */
export function bashPathTokens(command: string): string[] {
	const s = command;
	const n = s.length;
	// Right-to-left precompute of maximal-run ends — the single pass that makes every
	// position O(1): runEndX[i] = first index >= i not in class X (i when s[i] itself
	// is out of class; n at the end of string).
	const runEnd2 = new Int32Array(n + 1);
	const runEnd4 = new Int32Array(n + 1);
	runEnd2[n] = n;
	runEnd4[n] = n;
	for (let i = n - 1; i >= 0; i--) {
		runEnd2[i] = isW2(s, i) ? runEnd2[i + 1] : i;
		runEnd4[i] = isW4(s, i) ? runEnd4[i + 1] : i;
	}
	const out: string[] = [];
	let p = 0;
	while (p < n) {
		const c = s[p];
		let m = 0; // match end (exclusive); 0 = no match at p
		if (c === "~" || s.startsWith("$HOME", p)) {
			// alt1: deterministic greedy (/ + W2-run) repetitions
			let q = c === "~" ? p + 1 : p + 5;
			for (;;) {
				if (s[q] === "/" && isW2(s, q + 1)) q = runEnd2[q + 1];
				else break;
			}
			m = q;
		} else if (c === "/") {
			// alt2: (W2-run + /) pairs while possible, then the trailing W2-run
			let q = p + 1;
			for (;;) {
				if (!isW2(s, q)) break; // empty tail — the match is the consumed prefix
				const r = runEnd2[q];
				if (s[r] !== "/") {
					q = r; // tail run consumes through r
					break;
				}
				q = r + 1; // pair complete — another may follow
			}
			m = q;
		} else if (c === ".") {
			// alt3: dots greedy 2 then 1; inner = maximal (/ + W2-run) repetitions, >= 1 required
			const innerEnd = (q: number): number | null => {
				if (s[q] !== "/" || !isW2(s, q + 1)) return null;
				let r = q;
				for (;;) {
					if (s[r] === "/" && isW2(s, r + 1)) r = runEnd2[r + 1];
					else break;
				}
				return r;
			};
			if (s[p + 1] === ".") m = innerEnd(p + 2) ?? 0;
			if (m === 0) m = innerEnd(p + 1) ?? 0;
		}
		if (m === 0 && isW4(s, p)) {
			// alt4: the maximal leading run is [p, e). '/' is not in W4, so the run
			// itself contains no slash and the ONLY viable continuation split is at e
			// — the O(1) step that replaces the regex's O(n)-per-position backtrack.
			const e = runEnd4[p];
			if (s[e] === "/" && isW4(s, e + 1)) {
				let q = e;
				for (;;) {
					if (s[q] === "/" && isW4(s, q + 1)) q = runEnd4[q + 1];
					else break;
				}
				m = q;
			}
		}
		if (m > p) {
			out.push(s.slice(p, m));
			p = m; // matchAll semantics: continue after the match
		} else {
			p++;
		}
	}
	return out;
}

/** A path spelling with a leading `~` or `$HOME` expanded, as denyPaths spellings accept them. User-rule
 *  targets stay raw strings, with no `$` expansion. */
export function expandPathSpelling(raw: string): string {
	return expandHome(raw.replace(/^\$HOME(?=\/|$)/, os.homedir()));
}

/** Normalized forms of one path for denyPaths comparison: base tier (ADR-0002) plus, for
 *  `..`-spellings, the kernel-true spelling the host would open (item 10, ADR-0002 amendment):
 *  omp's file tools return an absolute input verbatim, so `subLink/../secret` opens
 *  `<subLinkTarget>/../secret` while `path.resolve` names `<cwd>/secret` — the declaration and
 *  the candidate both gain the same tier through this one function, which is what keeps the
 *  comparison sound. Still no ancestor rebuild: a nonexistent target under a symlinked dir
 *  falls to the classifier + existence hint instead (pinned by a regression test). */
export function denyPathForms(raw: string, cwd: string): string[] {
	if (!raw) return [];
	const expanded = expandPathSpelling(raw);
	const forms = baseForms(path.resolve(cwd, expanded));
	const kernel = kernelPath(expanded, cwd);
	if (kernel !== null) for (const f of baseForms(kernel)) if (!forms.includes(f)) forms.push(f);
	return forms;
}

/** Normalize the configured denyPaths against one cwd (ADR-0002: anchored once per session, never re-derived) */
export const anchorDenyPaths = (paths: string[], cwd: string): string[] => paths.flatMap((b) => denyPathForms(b, cwd));

/** Which targets `callPathCandidates` returns: every target the call touches, or only those it may
 *  write. A command, a code cell and a tool the adapter cannot classify count as writing every
 *  target, because their direction is unknown. */
export type CandidateDirection = "touched" | "written";

/** Every path candidate a tool call exposes to path comparison, via the adapter
 *  (an unknown tool's shape-inferred fields are included here, unlike userRuleTargets).
 *  Scope tools with an omitted/empty path contribute the cwd: their search scope
 *  IS the cwd subtree (#48). A known observing call contributes nothing when only
 *  `written` targets are asked for. */
export function callPathCandidates(
	toolName: string,
	input: Record<string, unknown>,
	cwd: string,
	direction: CandidateDirection = "touched",
): string[] {
	if (isCommandTool(toolName)) {
		// win32: backslash-separated paths (`C:\proj\f`) are the native spelling; BASH_PATH_TOKENS is
		// "/"-only, so unify separators first (drive letter is skipped by the absolute-path branch;
		// a mis-read shell escape only yields extra candidates — false positives ask, the safe direction)
		const cmd = commandText(input);
		const tokens = bashPathTokens(commandForPathTokens(cmd, path.sep === "\\"));
		// A command that names the directory it runs in touches that directory (`resolveCommandCwd` resolved it into `cwd`).
		return typeof input.cwd === "string" && input.cwd !== "" ? [cwd, ...tokens] : tokens;
	}
	const access = toolAccess(toolName, input);
	if (access.direction === "mutating") return access.gradedWrites;
	if (access.direction === "observing") {
		if (direction === "written") return [];
		return access.gradedReads.length > 0 ? access.gradedReads : [cwd];
	}
	// unknown: whatever targets the payload yields still feed denyPaths — the surviving
	// BREAKING change (an unknown tool's extracted targets now hit this ask where today
	// nothing grades them; `userRuleTargets` stays known-tool-only, see R2-2 above).
	// kind "code" (eval, item 4): denyPaths extraction also runs over the code text via the
	// same path-token scan bash commands use — an eval cell is free-form text, not a shell
	// command line, but a path mention in it is exactly as real a signal.
	const codeTokens = access.kind === "code" && access.command !== null ? bashPathTokens(access.command) : [];
	return [...access.gradedReads, ...access.gradedWrites, ...codeTokens];
}

/** Does the call touch a user-declared protected path? `bases` are the denyPaths
 *  pre-normalized ONCE at session start (anchored to the session cwd) — mid-session
 *  symlink creation or cwd drift must not change what the declaration covers.
 *  Returns the matched base for the ask dialog (UI-only plaintext, see RuleResult.detail).
 *  Scope tools compare BIDIRECTIONALLY (#48): their search covers a subtree, so a
 *  hit fires when the target sits under a base (single-target direction) OR a base
 *  sits inside the searched subtree (cwd-inside-declaration, declaration-under-cwd).
 *  False positives ask — the safe direction. read/write/edit and bash tokens stay
 *  one-directional: single-target semantics. */
export function hitDenyPaths(toolName: string, input: Record<string, unknown>, cwd: string, bases: readonly string[]): string | null {
	if (bases.length === 0) return null;
	const subtree = toolAccess(toolName, input).scope;
	for (const candidate of callPathCandidates(toolName, input, cwd)) {
		for (const c of denyPathForms(candidate, cwd)) {
			for (const b of bases) {
				if (isWithin(c, b) || (subtree && isWithin(b, c))) return b;
			}
		}
	}
	return null;
}

/** `.omp` as a whole path segment (case-insensitive: case-folding filesystems; both separators: win32 forms) */
const OMP_DIR_SEGMENT = /(?:^|[\\/])\.omp(?:[\\/]|$)/i;
/** `.omp` as a shell word inside a raw command string (`cd .omp`, `ls ~/.omp/x`, `"$HOME/.omp"`): not preceded by a word/dot/dash char, not followed by one (`x.omp`, `.omp.bak`, `.ompx` do not match). False positives ask — the safe direction */
const OMP_DIR_IN_COMMAND = /(?<![\w.-])\.omp(?![\w.-])/;

/** Forced-gate detection (gateOmpDir): does the call target a path inside a `.omp` directory?
 *  Reuses the denyPaths candidate extraction and base-tier dual forms (lexical + realpath), so a
 *  symlink aliasing a `.omp` directory hits too. Scope tools (grep/find/ls) are checked on their
 *  own target only (omitted path → cwd): a recursive search from a project root that merely
 *  traverses a nested `.omp` is not a `.omp` access. Returns the matched form (UI-only detail). */
export function hitOmpDir(toolName: string, input: Record<string, unknown>, cwd: string): string | null {
	if (isCommandTool(toolName)) {
		const command = commandText(input);
		if (OMP_DIR_IN_COMMAND.test(command)) return ".omp referenced in the command";
	}
	// kind "code" (eval, item 4): the same word check runs directly over the code text —
	// callPathCandidates' token extraction alone could miss a bare ".omp" with no path
	// separator around it (e.g. `dest = ".omp"`), same rationale as the command branch above.
	const access = toolAccess(toolName, input);
	if (access.kind === "code" && access.command !== null && OMP_DIR_IN_COMMAND.test(access.command)) {
		return ".omp referenced in the code";
	}
	for (const candidate of callPathCandidates(toolName, input, cwd)) {
		for (const form of denyPathForms(candidate, cwd)) {
			if (OMP_DIR_SEGMENT.test(form)) return form;
		}
	}
	return null;
}

/** A `$HOME` or braced `${HOME}` expansion, with the quotes the shell joins around it, directly before
 *  a `/`: `"$HOME"/x`, `$HOME"/x"`, `${HOME}'/x'`, `"$HOME""/x"`. Braces may carry a default that
 *  expands to `$HOME` while it is set: `${HOME:-x}`, `${HOME-x}`, `${HOME:=x}`, `${HOME=x}`,
 *  `${HOME:?x}` and `${HOME?x}`. `${HOME:+x}` is left alone because it expands to `x`, and a
 *  single-quoted `'$HOME'` is literal in the shell (the lookbehind). The default text is capped so a
 *  command full of unterminated `${HOME-` cannot make the scan quadratic. */
const HOME_EXPANSION_BEFORE_SLASH = /(?<!')"?\$(?:HOME|\{HOME(?::?[-=?]([^}]{0,200}))?\})["']{0,3}(?=\/)/g;

/** `bashPathTokens` knows only "/" separators and the bare `$HOME` spelling. The result holds the
 *  command as written, a copy with each home expansion spelled `$HOME`, and each expansion's default
 *  word on a line of its own (the tokenizer would glue `:-` onto it), so the tokens of all three are
 *  candidates. A Windows command's backslashes are unified, as callPathCandidates does. A mis-read
 *  shell escape only adds candidates, which asks. */
export function commandForPathTokens(command: string, win32: boolean): string {
	const defaults: string[] = [];
	const canonical = command.replace(HOME_EXPANSION_BEFORE_SLASH, (_match, word: string | undefined) => {
		if (word) defaults.push(word);
		return "$HOME";
	});
	const all = canonical === command ? command : [command, canonical, ...defaults].join("\n");
	return win32 ? all.replace(/\\/g, "/") : all;
}
