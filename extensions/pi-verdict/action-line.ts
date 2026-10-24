import { toolAccess } from "./access.ts";
import { BASH_MAX_MATCH_LEN } from "./shell.ts";

// ============================================================================
// Action line: one tool call rendered as a transcript line
// ============================================================================

const MAX_ENTRY_CHARS = 1000;

/** Strip zero-width characters (the injection-defense half of `sanitize`, #22) — exposed
 *  separately so the action line (item 6a, Phase 4) can reuse it without `sanitize`'s length
 *  cap, which the action line is deliberately exempt from. */
function stripZeroWidth(text: string): string {
	// eslint-disable-next-line no-control-regex
	return text.replace(/[​-‍⁠﻿]/g, "");
}

/** Strip zero-width characters + cap length (head 60% + tail 40%), basic injection sanitization (inspired by ai-guard). */
export function sanitize(text: string): string {
	const cleaned = stripZeroWidth(text);
	if (cleaned.length <= MAX_ENTRY_CHARS) return cleaned;
	const head = Math.floor(MAX_ENTRY_CHARS * 0.6);
	const tail = MAX_ENTRY_CHARS - head;
	return `${cleaned.slice(0, head)}…[truncated]…${cleaned.slice(-tail)}`;
}

/** Line-break escaping only (the structural-defense half of `transcriptSafe`, #22) — exposed
 *  separately so the action line can reuse it without transcriptSafe's length cap. Covers \n,
 *  \r\n, lone \r and the Unicode separators U+2028/U+2029/U+0085, which models may render as
 *  breaks. */
function escapeLineBreaks(text: string): string {
	return text.replace(/[\r\n\u2028\u2029\u0085]/g, "\\n");
}

/** Transcript line body: sanitized (zero-width stripped, length-capped) with
 *  line breaks escaped in place — the transcript is line-structured ("User: …" /
 *  "tool: …"), and an embedded line break in a path, command, or message could
 *  otherwise forge a structural line (#22).
 *  Content is preserved, only the line structure is defended. */
export function transcriptSafe(text: string): string {
	return escapeLineBreaks(sanitize(text));
}

export function toolCallLine(name: string, args: Record<string, unknown>): string {
	if (typeof args.command === "string") return `${name}: ${transcriptSafe(args.command)}`;
	// Multi-target edit (ADR-0009): the transcript action line names the full target set
	// instead of silently showing only args.path (unset above one hashline header) or the
	// raw patch JSON.
	const access = toolAccess(name, args);
	const targets = access.direction === "mutating" ? access.writes : access.direction === "observing" ? access.reads : [];
	if (targets.length > 1) return `${name}: ${transcriptSafe(`${targets.length} targets: ${targets.join(", ")}`)}`;
	if (typeof args.path === "string") return `${name}: ${transcriptSafe(args.path)}`;
	return `${name}: ${transcriptSafe(JSON.stringify(args))}`;
}

/** The action line's own cap (item 6a, Phase 4; Claude-review F8): aligned with the floor's
 *  own reading horizon — the action under review is exempt from transcriptSafe's blanket
 *  1000-char MAX_ENTRY_CHARS cap that a historical line still gets. Toward this cap: the tool
 *  name, every adapter target, and the full command (bash/powershell) or code (eval) text.
 *  Verified safe against both jev transports: TypeSafe's documented 32k-token `state` budget
 *  (docs.typesafe.ai/models, 2026; ~128k chars) comfortably covers this plus every other
 *  transcript part even at their own caps — see ADR-0009 Phase 4 amendment. */
export const ACTION_LINE_MAX_CHARS = BASH_MAX_MATCH_LEN;
/** Gray (unrecognised-shape) tool argument JSON excerpt cap (Claude-review R2-12): separate
 *  from ACTION_LINE_MAX_CHARS — raw JSON.stringify(args) is not a target or command the floor
 *  or user rules read, so it never counts toward the action cap; it is still bounded (with an
 *  explicit marker) so a pathological payload cannot blow out the transcript. */
const GRAY_ARGS_CHARS = 2000;
/** Bounded write/edit content excerpt window (item 6a step 3, Phase 4): the write `content` or
 *  the edit patch text, behind an explicit `[excerpt: N of M chars]` marker — additional
 *  evidence for the classifier, never counted toward ACTION_LINE_MAX_CHARS (Claude-review F8:
 *  "first N chars inside the action cap" would contradict refuse-what-cannot-be-shown). */
const EXCERPT_CHARS = 2000;

/** A bounded, zero-width-stripped, line-break-escaped excerpt with an explicit,
 *  classifier-visible marker — never silently cut with no trace. */
function boundedExcerpt(text: string, maxChars: number): string {
	const safe = escapeLineBreaks(stripZeroWidth(text));
	const shown = safe.length > maxChars ? safe.slice(0, maxChars) : safe;
	return `[excerpt: ${shown.length} of ${safe.length} chars] ${shown}`;
}

/** The action line under review (item 6a, Phase 4; Claude-review F8): same shape as
 *  `toolCallLine` but exempt from its MAX_ENTRY_CHARS cap, with precise over-cap detection —
 *  `overCap: true` means the COUNTED portion alone (tool name + separator + every adapter
 *  target, or the full command/code) already exceeds ACTION_LINE_MAX_CHARS; `classifyByRules`
 *  turns this into a deterministic ask before the classifier ever runs, so `line` in that case
 *  is diagnostic only. A write/edit action appends a bounded content excerpt (EXCERPT_CHARS)
 *  that never counts toward the cap; a gray tool's raw JSON arguments are bounded separately
 *  too (GRAY_ARGS_CHARS), also uncounted — neither can ever trigger `overCap`. */
export function actionCallLine(name: string, args: Record<string, unknown>): { line: string; overCap: boolean } {
	// The cap counts RAW lengths — the floor reads the raw prefix (classifyBash
	// slices the raw command at BASH_MAX_MATCH_LEN), so zero-width padding must not shrink a
	// counted action below the horizon the floor never read. Display stays sanitized.
	if (typeof args.command === "string") {
		return {
			line: `${name}: ${escapeLineBreaks(stripZeroWidth(args.command))}`,
			overCap: `${name}: ${args.command}`.length > ACTION_LINE_MAX_CHARS,
		};
	}
	const access = toolAccess(name, args);
	if (access.kind === "code" && access.command !== null) {
		return {
			line: `${name}: ${escapeLineBreaks(stripZeroWidth(access.command))}`,
			overCap: `${name}: ${access.command}`.length > ACTION_LINE_MAX_CHARS,
		};
	}
	const targets = access.direction === "mutating" ? access.writes : access.direction === "observing" ? access.reads : [];
	let raw: string | null = null;
	if (targets.length > 1) raw = `${name}: ${targets.length} targets: ${targets.join(", ")}`;
	// A single extracted target (paths[]/patch text, no path field) counts too —
	// previously it fell to the gray-JSON branch where overCap is structurally false.
	else if (targets.length === 1) raw = `${name}: ${targets[0]}`;
	else if (typeof args.path === "string") raw = `${name}: ${args.path}`;
	if (raw !== null) {
		if (raw.length > ACTION_LINE_MAX_CHARS) return { line: escapeLineBreaks(stripZeroWidth(raw)), overCap: true };
		const counted = escapeLineBreaks(stripZeroWidth(raw));
		if (access.direction === "mutating") {
			const content =
				typeof args.content === "string"
					? args.content
					: typeof args.input === "string"
						? args.input
						: typeof args._input === "string"
							? args._input
							: null;
			if (content !== null) return { line: `${counted}\n${boundedExcerpt(content, EXCERPT_CHARS)}`, overCap: false };
		}
		return { line: counted, overCap: false };
	}
	// Gray (unrecognised-shape) tool: raw JSON, bounded separately, never counted toward the cap.
	return { line: `${name}: ${boundedExcerpt(JSON.stringify(args), GRAY_ARGS_CHARS)}`, overCap: false };
}
