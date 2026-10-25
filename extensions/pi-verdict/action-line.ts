import { toolAccess } from "./access.ts";
import { BASH_MAX_MATCH_LEN } from "./shell.ts";

// ============================================================================
// Action line: one tool call rendered as a transcript line
// ============================================================================

const MAX_ENTRY_CHARS = 1000;

/** Strips zero-width characters, which can hide injected text (#22). Separate from `sanitize` because the
 *  action line is exempt from its length cap. */
function stripZeroWidth(text: string): string {
	return text.replace(/[\u200B-\u200D\u2060\uFEFF]/g, "");
}

/** Returns the text without zero-width characters, capped at `MAX_ENTRY_CHARS` by keeping its head and tail
 *  around a `…[truncated]…` marker. */
export function sanitize(text: string): string {
	const cleaned = stripZeroWidth(text);
	if (cleaned.length <= MAX_ENTRY_CHARS) return cleaned;
	const head = Math.floor(MAX_ENTRY_CHARS * 0.6);
	const tail = MAX_ENTRY_CHARS - head;
	return `${cleaned.slice(0, head)}…[truncated]…${cleaned.slice(-tail)}`;
}

/** Escapes every line break a model may render as one: CR, LF and the Unicode separators U+2028, U+2029
 *  and U+0085 (#22). */
function escapeLineBreaks(text: string): string {
	return text.replace(/[\r\n\u2028\u2029\u0085]/g, "\\n");
}

/** Returns a transcript line body: sanitized, with line breaks escaped so embedded text cannot forge a
 *  `User:` or tool line in the line-structured transcript (#22). */
export function transcriptSafe(text: string): string {
	return escapeLineBreaks(sanitize(text));
}

/** Returns a past tool call as one capped transcript line: its command, its targets, its path, or its JSON. */
export function toolCallLine(name: string, args: Readonly<Record<string, unknown>>): string {
	if (typeof args.command === "string") return `${name}: ${transcriptSafe(args.command)}`;
	// A multi-target edit names its full target set, not only `args.path` or the raw patch (ADR-0009).
	const access = toolAccess(name, args);
	const targets = access.direction === "mutating" ? access.writes : access.direction === "observing" ? access.reads : [];
	if (targets.length > 1) return `${name}: ${transcriptSafe(`${targets.length} targets: ${targets.join(", ")}`)}`;
	if (typeof args.path === "string") return `${name}: ${transcriptSafe(args.path)}`;
	return `${name}: ${transcriptSafe(JSON.stringify(args))}`;
}

/** Cap on the counted part of the action under review (tool name, targets, full command or code). It equals
 *  the floor's reading horizon, so the model never judges text the floor did not read (ADR-0009). */
export const ACTION_LINE_MAX_CHARS = BASH_MAX_MATCH_LEN;
/** Excerpt cap for an unrecognised tool's raw JSON arguments. Neither rules nor floor read that JSON, so it
 *  never counts toward the action cap. */
const GRAY_ARGS_CHARS = 2000;
/** Excerpt cap for a write's content or an edit's patch text: extra evidence for the classifier, never
 *  counted toward the action cap. */
const EXCERPT_CHARS = 2000;
/** Separates a write's target from its content excerpt on the one action line. */
const CONTENT_SEPARATOR = "| content:";

/** Returns a sanitized excerpt behind a visible `[excerpt: N of M chars]` marker, so a cut is never silent. */
function boundedExcerpt(text: string, maxChars: number): string {
	const safe = escapeLineBreaks(stripZeroWidth(text));
	const shown = safe.length > maxChars ? safe.slice(0, maxChars) : safe;
	return `[excerpt: ${shown.length} of ${safe.length} chars] ${shown}`;
}

/** Returns the action under review as its transcript line, uncapped by `MAX_ENTRY_CHARS`. `overCap` is true
 *  when the counted part exceeds `ACTION_LINE_MAX_CHARS`; the rule layer then asks before any model runs.
 *  A content excerpt or an unrecognised tool's JSON is appended bounded and never sets `overCap`. */
export function actionCallLine(name: string, args: Readonly<Record<string, unknown>>): { line: string; overCap: boolean } {
	// The cap counts raw lengths, as the floor reads the raw text: zero-width padding cannot shrink an
	// action below the cap. Only the displayed line is sanitized.
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
	// A single target extracted from `paths` or patch text counts too, so it cannot dodge the cap as JSON.
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
			// The excerpt stays on the action line: the prompts read the transcript's last line as the action,
			// and the content is model-written text.
			if (content !== null) return { line: `${counted} ${CONTENT_SEPARATOR} ${boundedExcerpt(content, EXCERPT_CHARS)}`, overCap: false };
		}
		return { line: counted, overCap: false };
	}
	// An unrecognised tool shape: its raw JSON, bounded and uncounted.
	return { line: `${name}: ${boundedExcerpt(JSON.stringify(args), GRAY_ARGS_CHARS)}`, overCap: false };
}
