import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { COVERAGE_SIGNAL_FIELD_TYPE, COVERAGE_SIGNAL_FIELDS, SIDE_EFFECTING_TOOL_NAMES } from "./config.ts";
import { expandHome, toRuleForm } from "./floor.ts";
import { kernelPath } from "./paths.ts";
import { BASH_MAX_MATCH_LEN } from "./shell.ts";

// ============================================================================
// Host path spelling: the forms a path can take before the host opens it
//
// omp rewrites a path argument before it opens the file, so the spelling the model wrote is not
// always the path that is read. Every file or scope target is therefore graded in its raw form and
// in each form the host can resolve it to, and the worst grade wins. This is the one place that
// knows the host's rewrites; the floor, denyPaths, gateOmpDir, self-protection, user rules and the
// transcript redactor all read their targets through `hostPathForms` (ADR-0009 amendment).
// ============================================================================

/** URL schemes that omp's InternalUrlRouter registers (18.12.6). Only these are URLs to the host;
 *  any other `scheme://` text is an ordinary relative path. */
const HOST_INTERNAL_SCHEMES: ReadonlySet<string> = new Set([
	"skill",
	"rule",
	"memory",
	"agent",
	"history",
	"artifact",
	"local",
	"proc",
	"cfg",
	"ssh",
	"security",
	"vault",
	"issue",
	"pr",
	"mr",
	"mcp",
	"omp",
	"xd",
	"attachment",
	"conflict",
]);

export function isHostInternalUrl(target: string): boolean {
	const match = /^([a-z][a-z0-9+.-]*):\/\//i.exec(target);
	return match !== null && HOST_INTERNAL_SCHEMES.has(match[1].toLowerCase());
}

/** `@` is a shorthand only before the shapes the host recognizes; `@my-file.txt` stays literal. */
function stripHostAtPrefix(target: string): string {
	if (!target.startsWith("@")) return target;
	const rest = target.slice(1);
	const shorthand = rest.startsWith("/") || rest === "~" || rest.startsWith("~/") || path.win32.isAbsolute(rest) || isHostInternalUrl(rest);
	return shorthand ? rest : target;
}

const HOST_UNICODE_SPACES = /[\u00A0\u2000-\u200A\u202F\u205F\u3000]/g;

function hostFileUrlToPath(target: string): string {
	if (!target.toLowerCase().startsWith("file://")) return target;
	try {
		return fileURLToPath(target);
	} catch {
		return target;
	}
}

/** Strips the Win32 extended-length prefixes (`\\?\C:\x`, `\\?\UNC\server\share`) on every platform,
 *  because an extra form only widens what is graded. */
function stripExtendedLengthPrefix(target: string): string {
	const unc = /^\\\\[?][?]?\\UNC[\\/]([^\\/]+)[\\/](.+)$/i.exec(target);
	if (unc) return `\\\\${unc[1]}\\${unc[2]}`;
	const drive = /^\\\\[?][?]?\\([A-Za-z]:[\\/].*)$/.exec(target);
	return drive ? drive[1] : target;
}

function expandHostTilde(target: string, home: string): string {
	if (target === "~") return home;
	if (target.startsWith("~/") || target.startsWith("~\\")) return home + target.slice(1);
	// `~name` is `$HOME/name`: the host joins the remainder onto the home directory.
	if (target.startsWith("~")) return path.join(home, target.slice(1));
	return target;
}

/** The path the host opens for a model-written path argument; mirrors omp's expandPath (18.6.1).
 *  A stray leading `:` goes first, then the `@` shorthand, unicode spaces, a `file://` URL, a Win32
 *  extended-length prefix and the tilde. */
export function expandHostPath(target: string, home: string = os.homedir()): string {
	const colonless = /^:(?=[/\\~]|\.\.?[/\\]|[A-Za-z]:)/.test(target) ? target.slice(1) : target;
	const spaced = stripHostAtPrefix(colonless).replace(HOST_UNICODE_SPACES, " ");
	return expandHostTilde(stripExtendedLengthPrefix(hostFileUrlToPath(spaced)), home);
}

/** Longest target the host spellings are derived for: a longer one is an over-cap action that is
 *  asked about before any allow, so deriving forms for it would only cost time. */
const HOST_PATH_FORMS_MAX_CHARS = BASH_MAX_MATCH_LEN;

const SELECTOR_LINE_RANGE = String.raw`L?(\d+)(?:(\.\.|[-+])L?(\d+)?)?`;
const SELECTOR_RANGE_CHUNK = `${SELECTOR_LINE_RANGE}(?<=[\\d.-])`;
const SELECTOR_TAIL = String.raw`-\d+`;
// A comma list may mix ranges and tails (`1-12,-15`); a lone tail is a one-chunk list.
const SELECTOR_LIST_CHUNK = `(?:${SELECTOR_RANGE_CHUNK}|${SELECTOR_TAIL})`;
const SELECTOR_LIST = `${SELECTOR_LIST_CHUNK}(?:,${SELECTOR_LIST_CHUNK})*`;
const SELECTOR_RE = new RegExp(`^(?:${SELECTOR_LIST}|raw|conflicts|img)$`, "i");
const SELECTOR_RANGE_ONLY_RE = new RegExp(`^${SELECTOR_LIST}$`, "i");

/** Moves a list that repeats its selector colon after a comma (`a:1-30,:-30`) out of the base, so the
 *  base is the path in front of the whole list. */
function foldRepeatedListColons(base: string): string {
	let folded = base;
	while (folded.endsWith(",")) {
		const colon = folded.lastIndexOf(":");
		if (colon < 1 || !SELECTOR_RANGE_ONLY_RE.test(folded.slice(colon + 1, -1))) break;
		folded = folded.slice(0, colon);
	}
	return folded;
}

/** The path with a trailing read selector (a range and tail list such as `:1-12,-15`, `:raw`,
 *  `:conflicts`, `:img`, or one list plus `:raw`) removed, or null when the text carries none; mirrors
 *  omp's `splitPathAndSel` (18.12.6). `foldListColons: false` keeps a repeated list colon in the base
 *  (`a:1-30,:-30` peels only `:-30`), the split the host takes when that shorter path is a real file.
 *  The host opens the peeled path, so `.env:raw` reads `.env`. */
function peelHostSelector(target: string, foldListColons = true): string | null {
	const colon = target.lastIndexOf(":");
	if (colon <= 0) return null;
	const candidate = target.slice(colon + 1);
	if (!SELECTOR_RE.test(candidate)) return null;
	let base = target.slice(0, colon);
	let rawSuffix = false;
	if (/^raw$/i.test(candidate)) {
		const inner = base.lastIndexOf(":");
		if (inner > 0 && SELECTOR_RANGE_ONLY_RE.test(base.slice(inner + 1))) {
			base = base.slice(0, inner);
			rawSuffix = true;
		}
		if (!rawSuffix) return base;
	} else if (!SELECTOR_RANGE_ONLY_RE.test(candidate)) {
		return base;
	}
	if (foldListColons) base = foldRepeatedListColons(base);
	const inner = base.lastIndexOf(":");
	return !rawSuffix && inner > 0 && /^raw$/i.test(base.slice(inner + 1)) ? base.slice(0, inner) : base;
}

/** The tools whose path argument the host splits a read selector from. A tool the gate does not model
 *  is read both ways: an extra form only widens what is graded. */
function peelsHostSelector(toolName: string): boolean {
	return toolName === "read" || toolName === "grep" || !(OBSERVING_TOOL_NAMES.has(toolName) || MUTATING_TOOL_NAMES.has(toolName));
}

/** The tools whose path argument the host splits into a list of paths: every tool that reads or
 *  searches, including `ast_edit`. `write` and `edit` open one file. */
function splitsHostList(toolName: string): boolean {
	return toolName !== "write" && toolName !== "edit";
}

const normalizeHostPathEntry = (entry: string): string => {
	const trimmed = entry.trim();
	return trimmed.length > 1 && trimmed.startsWith('"') && trimmed.endsWith('"') ? trimmed.slice(1, -1) : trimmed;
};

/** Splits at every top-level separator; a backslash escapes the next character and a brace group is
 *  not split, as in omp's splitTopLevelDelimitedPath (18.6.1). */
function splitTopLevel(entry: string, isSeparator: (ch: string) => boolean): string[] {
	const parts: string[] = [];
	let braceDepth = 0;
	let start = 0;
	for (let i = 0; i < entry.length; i++) {
		const ch = entry[i];
		if (ch === "\\" && i + 1 < entry.length) {
			i++;
		} else if (ch === "{") {
			braceDepth++;
		} else if (ch === "}") {
			if (braceDepth > 0) braceDepth--;
		} else if (braceDepth === 0 && isSeparator(ch)) {
			parts.push(entry.slice(start, i));
			start = i + 1;
		}
	}
	parts.push(entry.slice(start));
	return parts;
}

const HOST_LIST_SEPARATORS: ReadonlyArray<(ch: string) => boolean> = [
	(ch) => ch === ";",
	(ch) => ch === ",",
	(ch) => /\s/.test(ch),
	(ch) => ch === ";" || ch === "," || /\s/.test(ch),
];

/** Every part omp's expandDelimitedPathEntries (18.6.1) can split one entry into. The host tries `;`,
 *  then `,`, then whitespace, then all three, and keeps the first split whose parts resolve; the gate
 *  cannot tell which one wins, so it grades the parts of every split. */
function hostPathListParts(entry: string): string[] {
	const parts = new Set<string>();
	for (const isSeparator of HOST_LIST_SEPARATORS) {
		const raw = splitTopLevel(entry, isSeparator);
		if (raw.length < 2) continue;
		for (const part of raw.map(normalizeHostPathEntry)) if (part.length > 0) parts.add(part);
	}
	return [...parts];
}

interface HostPathFormOptions {
	/** Also grade the path with a trailing read selector removed. */
	peelSelector?: boolean;
	/** Also grade each part of a `;`, `,` or whitespace separated list. */
	splitList?: boolean;
	/** Also grade the path with a `?q=` or `?query=` selector removed. */
	peelImageQuestion?: boolean;
	/** Also grade the path with shell escapes (`\ `, `\(`) removed. */
	unescapeShell?: boolean;
}

/** Every spelling of one target that the gate must grade: the raw text and the host's expansion of
 *  it, plus, as `how` asks, the parts of a delimited list and the paths without a trailing read
 *  selector. Deduplicated; an ordinary path yields itself alone. */
export function hostPathForms(target: string, how: HostPathFormOptions = {}): string[] {
	if (target.length > HOST_PATH_FORMS_MAX_CHARS) return [target];
	const whole = normalizeHostPathEntry(target);
	const entries = new Set([target, whole]);
	if (how.splitList) for (const part of hostPathListParts(whole)) entries.add(part);
	const forms = new Set<string>();
	for (const entry of entries) {
		const asked = how.peelImageQuestion ? peelImageQuestion(entry) : null;
		for (const variant of asked === null ? [entry] : [entry, asked]) {
			forms.add(variant);
			forms.add(expandHostPath(variant));
			if (!how.peelSelector) continue;
			for (const form of [variant, expandHostPath(variant)]) {
				for (const peeled of [peelHostSelector(form), peelHostSelector(form, false)]) {
					if (peeled === null) continue;
					forms.add(peeled);
					forms.add(expandHostPath(peeled));
				}
			}
		}
	}
	for (const form of [...forms]) {
		const alias = wslDriveAlias(form);
		if (alias !== null) forms.add(alias);
		if (how.unescapeShell) forms.add(unescapeShellPath(form));
	}
	return [...forms];
}

/** The path with a backslash before a space, quote, bracket or brace removed: omp's `read` retries a
 *  missing path in this form (tryShellEscapedPath, 18.6.1), so `~/Tax\ Returns/a.pdf` opens
 *  `~/Tax Returns/a.pdf`. */
function unescapeShellPath(target: string): string {
	return target.includes("\\") ? target.replace(/\\([ \t"'(){}[\]])/g, "$1") : target;
}

/** Under WSL omp opens a Windows drive path through the drive's mount (`C:\x` is `/mnt/c/x`), as
 *  its normalizeWindowsDriveAliasPath does (18.6.1); null elsewhere, where the text stays what it says. */
function wslDriveAlias(target: string): string | null {
	const wsl = process.platform === "linux" && Boolean(process.env.WSL_DISTRO_NAME || process.env.WSL_INTEROP);
	const match = wsl ? /^([A-Za-z]):[\\/](.*)$/.exec(path.win32.normalize(target.trim())) : null;
	return match === null ? null : path.posix.join("/mnt", match[1].toLowerCase(), ...match[2].split("\\").filter(Boolean));
}

/** The path with an image question or JSON filter (`?q=<text>` or `?query=<text>`) removed, or null when
 *  the text carries none; mirrors omp's splitImageQuestionTarget and parseJsonSelector (18.12.6). The
 *  host opens the file before the question, so `~/.netrc?q=x` reads `~/.netrc`. URLs keep their query.
 *  Grading peels `query` for every file, since an extra form only widens it; `jsonOnlyQuery` peels it
 *  only in front of a `.json`, `.jsonl` or `.ndjson` name, the files the host treats it as a filter for. */
function peelImageQuestion(target: string, jsonOnlyQuery = false): string | null {
	if (target.includes("://")) return null;
	const queryIndex = target.indexOf("?");
	if (queryIndex === -1) return null;
	const params = new URLSearchParams(target.slice(queryIndex + 1));
	const file = target.slice(0, queryIndex);
	const filter = params.get("query") && (!jsonOnlyQuery || /\.(?:jsonl?|ndjson)$/i.test(file));
	return params.get("q") || filter ? file : null;
}

/** A text the host opens as a filesystem path that is relative to the project. */
function isRelativeFilesystemPath(p: string): boolean {
	return p.length > 0 && !path.isAbsolute(p) && !path.win32.isAbsolute(p) && !/^[a-z][a-z0-9+.-]*:\/\//i.test(p);
}

/** Could omp's `read` open a different file than the one this entry names? When a relative path does
 *  not exist, the host looks for a unique workspace file that ends with the same path and reads that
 *  instead (a missing `id_ed25519` becomes `.ssh/id_ed25519` in a project that holds one), so the
 *  spelling says nothing about the file that is opened. Only the path the host would choose counts:
 *  a whole entry that exists, with or without a selector or an image question, is read as it is, and
 *  a `;`, `,` or whitespace list is read part by part only when the whole entry is missing. A project
 *  directory that does not exist holds nothing to relocate to. */
export function readMayRelocate(entry: string, cwd: string): boolean {
	if (!fs.existsSync(cwd)) return false;
	const missingRelative = (unit: string): boolean => {
		const chosen = hostReadPath(unit, cwd);
		return isRelativeFilesystemPath(chosen) && !fs.existsSync(path.resolve(cwd, chosen));
	};
	const whole = normalizeHostPathEntry(entry);
	if (fs.existsSync(path.resolve(cwd, hostReadPath(whole, cwd)))) return false;
	const parts = hostPathListParts(whole);
	return (parts.length > 0 ? parts : [whole]).some(missingRelative);
}

/** The path omp's `read` opens for one entry, in the host's order: the image question is cut, then a
 *  trailing selector is cut unless the whole text names an existing file (a list that repeats its colon
 *  keeps the shorter split when that one exists), then the path is expanded. */
export function hostReadPath(entry: string, cwd: string): string {
	const asked = peelImageQuestion(entry, true) ?? entry;
	const folded = peelHostSelector(asked);
	const unfolded = peelHostSelector(asked, false);
	const exists = (p: string): boolean => fs.existsSync(path.resolve(cwd, expandHostPath(p)));
	const peeled = folded !== null && folded !== unfolded && unfolded !== null && exists(unfolded) ? unfolded : folded;
	const literalExists = peeled !== null && exists(asked);
	const chosen = expandHostPath(peeled === null || literalExists ? asked : peeled);
	const unescaped = unescapeShellPath(chosen);
	return !fs.existsSync(path.resolve(cwd, chosen)) && fs.existsSync(path.resolve(cwd, unescaped)) ? unescaped : chosen;
}

// ============================================================================
// Tool-access adapter (ADR-0009): one host-agnostic model of what a tool call
// touches — built from the call's own payload alone (universal-plugin
// constraint 2). Closes item 1 (a multi-header omp `edit` graded on
// `input.path` alone, which omp leaves unset above one header) by generalizing
// every file-tool consumer (user rules, denyPaths, the built-in floor,
// self-protection) from "one path" to "every target the payload names".
// ============================================================================

/** Known observing (read-only) and mutating (write) tool names; "everything
 *  else" is `direction: "unknown"` — not "unrecognized by the gate" but "not a
 *  known file-access tool" (bash/powershell grade through the separate command
 *  channel unchanged; eval/task/MCP tools fall here too). Adding a file tool
 *  means adding its name to one of these two sets. */
export const OBSERVING_TOOL_NAMES: ReadonlySet<string> = new Set(["read", "grep", "find", "ls", "glob", "ast_grep"]);
export const MUTATING_TOOL_NAMES: ReadonlySet<string> = new Set(["write", "edit", "ast_edit"]);
/** Scope tools: `path`/`paths` accept a directory/glob and the search covers a
 *  SUBTREE — an omitted path means the workspace root/cwd (#48), and the
 *  denyPaths compare is bidirectional (hitDenyPaths/hitOmpDir). */
const SCOPE_TOOL_NAMES: ReadonlySet<string> = new Set(["grep", "find", "ls", "glob", "ast_grep", "ast_edit"]);

/** Scope tools whose `path`/`paths` may carry a glob. `ls` takes a directory only. */
const GLOB_PATH_TOOL_NAMES: ReadonlySet<string> = new Set(["grep", "find", "glob", "ast_grep", "ast_edit"]);
const GLOB_METACHARACTER = /[*?[{]/;

/** The part of a glob path before the first segment that holds a metacharacter, with its trailing
 *  separator; a path that starts with a glob segment grades as the cwd. The whole subtree below
 *  the prefix is what the call can reach, so grading the prefix is the most the gate can say
 *  without expanding the glob. */
function globLiteralPrefix(target: string): string {
	const at = target.search(GLOB_METACHARACTER);
	if (at < 0) return target;
	const separators = path.sep === "\\" ? ["/", "\\"] : ["/"];
	const cut = Math.max(...separators.map((sep) => target.lastIndexOf(sep, at)));
	return cut < 0 ? "." : target.slice(0, cut + 1);
}

export function isCommandTool(toolName: string): boolean {
	return toolName === "bash" || toolName === "powershell";
}

/** Returns a command tool's command line as text; a missing command is the empty string. A non-string
 *  command is coerced to text so it is still graded, which fails toward over-grading. */
export function commandText(input: Readonly<Record<string, unknown>>): string {
	return String(input.command ?? "");
}

/** Minimal local shape of what the coverage report needs from a host tool (zero-dependency
 *  constraint: not imported) — `ToolInfo.parameters` is a TypeBox `TSchema`, whose
 *  `.properties` carries each declared field's own schema for an object schema. */
export interface CoverageToolInfo {
	name: string;
	parameters?: { properties?: Record<string, { type?: unknown }> };
}

/** Schema-driven session_start coverage report (item 4, Phase 3; Claude-review F15: the
 *  adapter is payload-keyed and session_start has no payload to run it on, so this inspects
 *  each ACTIVE tool's declared schema instead). Only tools outside the user's `tools`
 *  allowlist and outside the adapter's known observing/mutating/command names are examined —
 *  everything else is already graded. `noFields`: a schema exposing none of
 *  COVERAGE_SIGNAL_FIELDS — the tool will stay gray/classifier-only forever. `untyped`: a
 *  schema field matching a signal name under a JSON-Schema `type` the adapter's
 *  string/string-array readers do not recognize (today silently treated as absent). A future
 *  host tool then surfaces here instead of a silent gap. */
export function toolCoverageReport(
	allTools: readonly CoverageToolInfo[],
	activeNames: ReadonlySet<string>,
	userTools: readonly string[],
): { noFields: string[]; untyped: Array<{ tool: string; field: string }> } {
	const userToolSet = new Set(userTools);
	const noFields: string[] = [];
	const untyped: Array<{ tool: string; field: string }> = [];
	for (const tool of allTools) {
		if (!activeNames.has(tool.name) || userToolSet.has(tool.name)) continue;
		if (OBSERVING_TOOL_NAMES.has(tool.name) || MUTATING_TOOL_NAMES.has(tool.name) || isCommandTool(tool.name)) continue;
		const properties = tool.parameters?.properties;
		if (!properties || typeof properties !== "object") {
			noFields.push(tool.name);
			continue;
		}
		let anyField = false;
		for (const field of COVERAGE_SIGNAL_FIELDS) {
			if (!Object.hasOwn(properties, field)) continue;
			anyField = true;
			if (properties[field]?.type !== COVERAGE_SIGNAL_FIELD_TYPE[field]) untyped.push({ tool: tool.name, field });
		}
		if (!anyField) noFields.push(tool.name);
	}
	return { noFields, untyped };
}

/** One-time session_start warning (item 4, Phase 3): a known side-effecting tool
 *  (persistent-memory writes) listed in the user's `tools` exact-name allowlist bypasses the
 *  classifier entirely for every call. The consumer's choice stays theirs — this just stops
 *  the gate being silent about it. */
export function sideEffectingToolsWarning(userTools: readonly string[]): string | null {
	const hit = userTools.filter((t) => SIDE_EFFECTING_TOOL_NAMES.has(t));
	if (hit.length === 0) return null;
	return `pi-verdict: tools lists side-effecting tool(s) ${hit.join(", ")} — calls bypass the classifier entirely (persistent-memory writes get no further scrutiny)`;
}

type ToolDirection = "observing" | "mutating" | "unknown";
type ToolAccessKind = "command" | "file" | "code" | null;

/** One pure, host-agnostic model of what a tool call touches. A function of the
 *  call's own payload only (constraint 2) — the one permitted exception is a
 *  version-targeted branch citing a specific documented host fact, never the
 *  development host's own state. `command` carries either the command text
 *  (`kind:"command"`) or the code text (`kind:"code"`) — a call is never both. */
export interface ToolAccess {
	direction: ToolDirection;
	kind: ToolAccessKind;
	reads: string[];
	writes: string[];
	command: string | null;
	/** A known mutating call (write/edit/ast_edit) whose payload names no target at
	 *  all — deterministic ask (headless → deny). Never true for an unknown tool:
	 *  the opaque ask exists to catch a file write whose target can't be found,
	 *  which a tool naming no file at all is not (narrowed 2026-10-05). */
	opaque: boolean;
	scope: boolean;
	/** `reads` and `writes` as the floor and the path layers must grade them. A glob-capable
	 *  tool's target also contributes its literal prefix (see globLiteralPrefix); every other target is unchanged. */
	gradedReads: string[];
	gradedWrites: string[];
	/** A glob-capable tool names a target with a glob metacharacter. The literal prefix cannot say
	 *  what such a target matches, so no rule layer may allow the call. */
	globbed: boolean;
}

/** Hashline header tag: `#` + exactly 4 hex digits, anchored at the end of the
 *  trimmed header body (verified against the installed omp 18.6.1 source —
 *  `extensibility/tool-event-input.ts`'s `extractHashlinePaths`/
 *  `normalizeHashlineHeaderPath` — and `edit/plan-mode-guard.d.ts`'s
 *  `unwrapHashlineHeaderPath` doc comment, which independently confirms the
 *  `[path]`/`[path#XXXX]` bracket shape the plan's original 18.5.1 citations
 *  inferred; self-contained per constraint 3 — no host import). */
const HASHLINE_TAG_RE = /#[0-9a-fA-F]{4}$/;

/** Strip a trailing hashline tag, then one layer of matching quotes, from a
 *  trimmed header body. `null` for an empty body (mirrors omp's
 *  `normalizeHashlineHeaderPath`). */
function stripHashlineTagAndQuotes(trimmedBody: string): string | null {
	if (!trimmedBody) return null;
	const tag = HASHLINE_TAG_RE.exec(trimmedBody);
	return unquoteHashlinePath(tag ? hostTrim(trimmedBody.slice(0, tag.index)) : trimmedBody);
}

/** One layer of matching quotes removed; null for an empty text. */
function unquoteHashlinePath(raw: string): string | null {
	if (raw.length < 2) return raw.length > 0 ? raw : null;
	const first = raw[0];
	const last = raw[raw.length - 1];
	if ((first === '"' || first === "'") && first === last) return raw.slice(1, -1);
	return raw;
}

/** A stand-in where the tag belongs (`#AUTO`, `#????`, `#0`, a bare `#`): one short word of no path
 *  characters at the end of a header body. omp parses such a header as the untagged path. */
const HASHLINE_PLACEHOLDER_TAG_RE = /#[^\s#./\\:[\]]{0,16}\s*$/;

/** The leading apply-patch noise omp drops from a header path (`*** Update File: `, `Add file:`, bare
 *  asterisks), so `[*** Update File: a.ts#1A2B]` edits `a.ts`. Matches the same text as omp's
 *  expression with the optional `file`/`to` word grouped with its trailing run, which keeps matching
 *  linear on a long run of punctuation. */
const HASHLINE_PATH_NOISE_RE = /^\*{0,3}\s*(?:(?:update|add|delete|move)[^A-Za-z0-9]*(?:(?:file|to)[^A-Za-z0-9]*)?:)?\s*\*{0,3}\s*/i;

/** Every path a trimmed header body can name: the body with a 4-hex tag stripped, which is also the
 *  raw spelling when no tag follows, the path in front of a trailing placeholder tag, and each of
 *  these without apply-patch noise. The host peels tag, quotes and noise in an order that depends on
 *  the shape, so the gate grades every order; a form the host would not pick only adds scrutiny.
 *  A well-formed header yields one path. Mirrors omp's `recover_header` (18.12.6). */
function hashlineHeaderPaths(trimmedBody: string): string[] {
	const forms = new Set<string>();
	const addTagForms = (body: string): void => {
		const tagless = stripHashlineTagAndQuotes(body);
		if (tagless) forms.add(tagless);
		const placeholder = HASHLINE_PLACEHOLDER_TAG_RE.exec(body);
		const untagged = placeholder ? unquoteHashlinePath(hostTrim(body.slice(0, placeholder.index))) : null;
		if (untagged) forms.add(untagged);
	};
	addTagForms(trimmedBody);
	addTagForms(trimmedBody.replace(HASHLINE_PATH_NOISE_RE, ""));
	for (const form of [...forms]) {
		const clean = form.replace(HASHLINE_PATH_NOISE_RE, "");
		if (clean) forms.add(clean);
	}
	return [...forms];
}

/** Whitespace as Rust's `trim` counts it, which omp's header parser uses: JavaScript's `\s` plus U+0085
 *  (NEL). Scanned by index, so trimming is linear. */
const isHostSpace = (ch: string | undefined): boolean => ch !== undefined && (ch === "\u0085" || /\s/.test(ch));

function hostTrimEnd(text: string): string {
	let end = text.length;
	while (end > 0 && isHostSpace(text[end - 1])) end--;
	return text.slice(0, end);
}

function hostTrim(text: string): string {
	let start = 0;
	while (start < text.length && isHostSpace(text[start])) start++;
	return hostTrimEnd(text.slice(start));
}

/** The patch envelope markers omp consumes around a hashline header. */
const HASHLINE_ENVELOPE_MARKERS = ["*** Begin Patch", "*** End Patch", "*** Abort"] as const;

/** The row with leading bracketed envelope markers removed, closed (`[*** Begin Patch] [a#1A2B]`) or
 *  unclosed (`[*** Begin Patch [a#1A2B]`), repeatedly; a row that is only markers comes back as the
 *  last bare marker, and a row without one is returned unchanged. Scans by index, so it runs in
 *  linear time. Mirrors omp's `unbracket_envelope_markers` (18.12.6). */
function unbracketEnvelopeMarkers(line: string): string {
	let at = 0;
	for (;;) {
		if (line[at] !== "[") return line.slice(at);
		let inner = at + 1;
		while (inner < line.length && isHostSpace(line[inner])) inner++;
		const marker = HASHLINE_ENVELOPE_MARKERS.find((m) => line.startsWith(m, inner));
		if (marker === undefined) return line.slice(at);
		let tail = inner + marker.length;
		while (tail < line.length && isHostSpace(line[tail])) tail++;
		if (line[tail] === "]") tail++;
		while (tail < line.length && isHostSpace(line[tail])) tail++;
		if (tail >= line.length) return marker;
		at = tail;
	}
}

/** Unwrap a hashline-wrapped `[path#TAG]` value (`write` may carry one) to the
 *  inner path; anything outside the strict bracket shape returns unchanged —
 *  same contract as omp's `unwrapHashlineHeaderPath` (18.12.6), which trims the end first. */
function unwrapHashlineHeaderPath(value: string): string {
	const trimmed = hostTrimEnd(value);
	if (!trimmed.startsWith("[") || !trimmed.endsWith("]")) return value;
	return stripHashlineTagAndQuotes(hostTrim(trimmed.slice(1, -1))) ?? value;
}

/** Parses hashline file headers (`[PATH]`/`[PATH#TAG]`, legacy `¶PATH`) and `MV
 *  DEST` op lines (hashline mode) plus apply-patch `*** Add/Update/Delete
 *  File:`/`*** Move to:` lines (apply_patch mode) from the SAME patch text — a
 *  payload is never pre-classified by mode name, so this recognizes whichever
 *  grammar the text actually carries. An unrecognized ("sloppy") payload yields
 *  no targets, which is what keeps it opaque. The move destination is a write
 *  and the source stays a target too (the move deletes it there). */
function parseHashlineTargets(text: string): string[] {
	const targets: string[] = [];
	const stripped = text.startsWith("\uFEFF") ? text.slice(1) : text;
	for (const raw of stripped.split("\n")) {
		// omp trims the line end before it reads a header, so `[path#TAG] ` is still a header.
		const line = hostTrimEnd(raw);
		// A header behind bracketed envelope markers is graded peeled and as written.
		const peeled = unbracketEnvelopeMarkers(line);
		let isHeader = false;
		for (const row of peeled === line ? [line] : [peeled, line]) {
			if (!row.startsWith("[") || !row.endsWith("]")) continue;
			targets.push(...hashlineHeaderPaths(hostTrim(row.slice(1, -1))));
			isHeader = true;
		}
		if (isHeader) continue;
		const legacy = line.trimStart();
		if (legacy.startsWith("¶")) {
			let i = 0;
			while (i < legacy.length && legacy[i] === "¶") i++;
			const body = stripHashlineTagAndQuotes(legacy.slice(i).trim());
			if (body) targets.push(body);
			continue;
		}
		const mv = /^MV\s+(.+)$/.exec(line.trim());
		if (mv?.[1].trim()) {
			targets.push(mv[1].trim());
			continue;
		}
		// omp trims both ends of an apply-patch hunk header, so an indented one is still a header.
		const hunk = hostTrim(raw);
		for (const prefix of ["*** Add File: ", "*** Update File: ", "*** Delete File: ", "*** Move to: "]) {
			if (hunk.startsWith(prefix) && hunk.slice(prefix.length).trim()) {
				targets.push(hunk.slice(prefix.length).trim());
				break;
			}
		}
	}
	return targets;
}

function readStringField(input: Record<string, unknown>, key: string): string | null {
	const v = input[key];
	return typeof v === "string" && v.length > 0 ? v : null;
}
function readStringArrayField(input: Record<string, unknown>, key: string): string[] {
	const v = input[key];
	return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && x.length > 0) : [];
}
/** Patch-mode `edits[].rename` values are also targets: the structured `patch`
 *  edit mode (`{path, edits:[{op?, diff?, rename?}]}`) can rename a file as part
 *  of one section's edit. */
function readPatchRenameTargets(input: Record<string, unknown>): string[] {
	if (!Array.isArray(input.edits)) return [];
	const out: string[] = [];
	for (const e of input.edits) {
		if (e && typeof e === "object" && !Array.isArray(e)) {
			const rename = (e as Record<string, unknown>).rename;
			if (typeof rename === "string" && rename) out.push(rename);
		}
	}
	return out;
}

/** code/command shape inference for a tool outside the known observing/mutating
 *  sets (constraint 2: payload shape, not the tool name). A shape-inferred
 *  `command` (e.g. `debug`'s DAP request) never enters `classifyBash` — every
 *  consumer of `kind`/`command` stays scoped to known tool names. */
function inferUnknownShape(input: Record<string, unknown>): { kind: ToolAccessKind; command: string | null } {
	const code = readStringField(input, "code");
	if (code !== null) return { kind: "code", command: code };
	const command = readStringField(input, "command");
	if (command !== null) return { kind: "command", command };
	return { kind: null, command: null };
}

/** `toolAccess(toolName, input): ToolAccess` — see the file banner above. */
export function toolAccess(toolName: string, input: Record<string, unknown>): ToolAccess {
	const scope = SCOPE_TOOL_NAMES.has(toolName);
	const rawPath = readStringField(input, "path") ?? readStringField(input, "_path");
	const unwrapped = rawPath !== null ? unwrapHashlineHeaderPath(rawPath) : null;
	const pathsField = readStringArrayField(input, "paths");
	const patchText = readStringField(input, "input") ?? readStringField(input, "_input");

	if (OBSERVING_TOOL_NAMES.has(toolName)) {
		const reads = new Set<string>();
		if (unwrapped !== null) reads.add(unwrapped);
		for (const p of pathsField) reads.add(p);
		return withGradedTargets(toolName, {
			direction: "observing",
			kind: "file",
			reads: [...reads],
			writes: [],
			command: null,
			opaque: false,
			scope,
		});
	}
	if (MUTATING_TOOL_NAMES.has(toolName)) {
		const writes = new Set<string>();
		if (unwrapped !== null) writes.add(unwrapped);
		for (const p of pathsField) writes.add(p);
		for (const t of readPatchRenameTargets(input)) writes.add(t);
		// A host-derived or model-supplied path/paths is added to the target set above (for
		// deny-side grading) but never makes a call non-opaque: when patch text is present,
		// opaqueness is grammar-driven — only what the grammar itself recognizes counts, so a
		// sloppy/unrecognized payload stays opaque even if path/paths also names something
		// (a spoofed paths value must not rescue an unparseable patch). When no patch text
		// exists at all (replace/patch-mode edit, write), path/paths/rename ARE authoritative.
		let opaque: boolean;
		if (patchText !== null) {
			const parsed = parseHashlineTargets(patchText);
			for (const t of parsed) writes.add(t);
			opaque = parsed.length === 0;
		} else {
			opaque = writes.size === 0;
		}
		return withGradedTargets(toolName, {
			direction: "mutating",
			kind: "file",
			reads: [],
			writes: [...writes],
			command: null,
			opaque,
			scope,
		});
	}
	// unknown: never opaque, never mutating-by-shape (2026-10-05 re-review) — whatever
	// targets the payload yields still feed the deny-side layers; otherwise gray, as today.
	const reads = new Set<string>();
	if (unwrapped !== null) reads.add(unwrapped);
	for (const p of pathsField) reads.add(p);
	const writes = new Set<string>();
	if (patchText !== null) for (const t of parseHashlineTargets(patchText)) writes.add(t);
	const { kind, command } = inferUnknownShape(input);
	return withGradedTargets(toolName, {
		direction: "unknown",
		kind,
		reads: [...reads],
		writes: [...writes],
		command,
		opaque: false,
		scope: false,
	});
}

/** omp's search tools turn every backslash in a path into a slash on every platform, so
 *  a path written with backslashes after a tilde opens the slash spelling even on POSIX. Only a URL of a
 *  scheme the host registers is left alone; any other `scheme://` text is an ordinary relative path. */
function hostSeparators(target: string): string {
	return isHostInternalUrl(target) ? target : target.replace(/\\/g, "/");
}

/** Every form of each target that the floor and the path layers grade (see hostPathForms). A
 *  glob-capable tool's forms also contribute their literal prefix, so the worst grade of the spelling
 *  and of the directory the glob walks wins: the spelling still matches a floor rule on its tail
 *  (`**` + `/*.pem`), the prefix covers the directory. */
function gradedForms(toolName: string, targets: string[]): string[] {
	const readSpellings = toolName !== "grep" && peelsHostSelector(toolName);
	const how = {
		peelSelector: peelsHostSelector(toolName),
		splitList: splitsHostList(toolName),
		peelImageQuestion: readSpellings,
		unescapeShell: readSpellings,
	};
	const forms = targets.flatMap((t) => hostPathForms(t, how));
	if (!GLOB_PATH_TOOL_NAMES.has(toolName)) return [...new Set(forms)];
	return [...new Set(forms.flatMap((f) => [f, hostSeparators(f), globLiteralPrefix(hostSeparators(f))]))];
}

function withGradedTargets(toolName: string, a: Omit<ToolAccess, "gradedReads" | "gradedWrites" | "globbed">): ToolAccess {
	const globbed =
		GLOB_PATH_TOOL_NAMES.has(toolName) &&
		[...a.reads, ...a.writes].flatMap((t) => hostPathForms(t)).some((t) => GLOB_METACHARACTER.test(t));
	return { ...a, gradedReads: gradedForms(toolName, a.reads), gradedWrites: gradedForms(toolName, a.writes), globbed };
}

/** Dialog-only suffix (ADR-0002: local plaintext, never a block reason) naming a multi-target
 *  edit's full target set — the matched denyPaths/gateOmpDir base alone does not say which of
 *  N targets in a multi-header edit it was. Empty for a single-target call (bit-for-bit
 *  unchanged `detail`). */
export function multiTargetDetailSuffix(access: ToolAccess): string {
	const all = access.direction === "mutating" ? access.writes : access.reads;
	return all.length > 1 ? ` (${all.length} targets: ${all.join(", ")})` : "";
}

/** Lexical + kernel-true forms of each target (item 10, plan-review F11,
 *  generalized to N targets): omp opens an absolute input verbatim, so a
 *  symlink-aliased target reaches a different file than path.resolve names
 *  when the raw spelling contains `..`. Deduped. */
function expandTargetForms(targets: string[], cwd: string): string[] {
	const forms = new Set<string>();
	for (const t of targets) {
		forms.add(toRuleForm(path.resolve(cwd, expandHome(t))));
		const kernel = kernelPath(t, cwd);
		if (kernel !== null) forms.add(toRuleForm(kernel));
	}
	return [...forms];
}

/** User-rule match targets: bash/powershell = the full command string; a known
 *  observing/mutating tool = every read/write target the adapter extracts (an
 *  unlisted tool's shape-inferred fields never reach user rules — Claude-review
 *  R2-2 — so a `deny`/`allow` regex can never key on an MCP tool's payload by
 *  accident). A pathless observing call's effective target is the cwd (#48); a
 *  pathless mutating call stays targetless here (opaque — nothing to match).
 *  Semantics unchanged: deny = ANY target matches; allow = EVERY target
 *  matches (F11). */
export function userRuleTargets(toolName: string, input: Record<string, unknown>, cwd: string): string[] {
	if (isCommandTool(toolName)) return [commandText(input)];
	const access = toolAccess(toolName, input);
	if (access.direction === "unknown") return [];
	const raw = access.direction === "mutating" ? access.gradedWrites : access.gradedReads.length > 0 ? access.gradedReads : [cwd];
	return expandTargetForms(raw, cwd);
}

// A string nested deeper than this is not collected: self-protection then sees only the targets
// `toolAccess` extracts, and the redactor still scans the arguments' JSON text.
const MAX_STRING_DEPTH = 6;

/** Returns every string value in a tool input, down to `MAX_STRING_DEPTH` levels of nesting: the candidates
 *  the redactor and the self-protection scan test for a protected path. */
export function collectStrings(value: unknown): string[] {
	const out: string[] = [];
	collectStringsInto(value, out, 0);
	return out;
}

function collectStringsInto(value: unknown, out: string[], depth: number): void {
	if (depth > MAX_STRING_DEPTH || value === null || value === undefined) return;
	if (typeof value === "string") out.push(value);
	else if (Array.isArray(value)) for (const v of value) collectStringsInto(v, out, depth + 1);
	else if (typeof value === "object") for (const v of Object.values(value)) collectStringsInto(v, out, depth + 1);
}
