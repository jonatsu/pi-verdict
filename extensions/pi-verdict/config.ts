import * as fs from "node:fs";
import * as path from "node:path";
import { agentDirPath, findProjectConfig, userConfigPath } from "./agent-dir.ts";
import { projectRootOf, projectTrustState, readTrustStore, rootIn } from "./trust.ts";

// ============================================================================
// User rules: allowlist/denylist (configurable; #12 audit response)
//
// Config: <agentDir>/config/pi-verdict.json (respects PI_CODING_AGENT_DIR override):
//   { "allow": ["^ls\\b", "^git (status|log|diff)\\b"], "deny": ["rm ", "^/etc/"], "tools": ["ask", "propose_commit"] }
// Match target: bash/powershell = full command string; read/write/edit/grep/find/ls = parsed absolute path;
// other tools (MCP/custom, e.g. ask/propose_commit/propose_changelog/todo) always go to the classifier by default—
// tools is the exact tool-name exception declaration for this group: a match directly allows, bypassing the classifier
// (not through the built-in floor / denyPaths, which do not cover this group anyway).
// Priority: built-in deny floor → user deny → user allow → gray; floor is on by default and can be disabled with builtinDenyFloor:false.
// Invalid regexes are skipped and reported (a config error does not disable the extension); takes effect next session.
// ============================================================================

// ============================================================================
// Master toggle shortcut (#15)
//
// Equivalent to the /automode command: one shared toggle entry point, with no extra rules from a different interaction surface
// (takes effect while running / no confirmation dialog / no persisted writeback—writeback would blur the “user-edited only” boundary).
// Silent feedback: the footer always shows the two auto-mode states and is the only feedback; no notify.
// Key: config's toggleShortcut field, default ctrl+shift+a (no conflicts with any pi default shortcut,
// two modifiers reduce accidental triggers, and avoid super, which depends on the Kitty protocol); null/empty string disables; takes effect next session.
// ============================================================================

/** Default toggle shortcut: free in the main editor context, memorable meaning (A for Auto), hard to trigger accidentally. */
const DEFAULT_TOGGLE_SHORTCUT = "ctrl+shift+a";

/** Key-name list (function and special keys; aligned with pi keybindings docs). */
const KEY_NAME_ALT =
	"f(?:[1-9]|1[0-2])|escape|esc|enter|return|tab|space|backspace|delete|insert|clear|home|end|pageup|pagedown|up|down|left|right";
const KEY_PRINTABLE = "[a-z0-9]|[-=`\\[\\];',./!@#$%^&*()_+|~{}:<>?]";
/**
 * Key-combination format validation: at least one modifier + any key, or a bare function/special key—
 * bare printable characters (e.g. “a”) are rejected because they hijack normal text input. The list is aligned with pi keybindings docs;
 * under the zero-dependency constraint, do not import pi's internal validation API; pi provides a fallback: conflicts with built-in keys are automatically skipped and reported.
 */
const KEY_COMBO_RE = new RegExp(`^(?:(?:ctrl|shift|alt|super)\\+)+(?:${KEY_NAME_ALT}|${KEY_PRINTABLE})$|^(?:${KEY_NAME_ALT})$`, "i");

/**
 * Parse toggleShortcut config: missing → default key; null/blank/wrong type → disabled;
 * invalid format → disabled + warning message (emitted via ctx at session_start, matching the skipped-regex pattern;
 * config errors do not fail silently, but also do not prevent the rest of the extension from working).
 */
function resolveToggleShortcut(raw: unknown): { key: string | null; warning: string | null } {
	if (raw === undefined) return { key: DEFAULT_TOGGLE_SHORTCUT, warning: null };
	if (raw === null) return { key: null, warning: null };
	if (typeof raw !== "string") {
		return {
			key: null,
			warning: `toggleShortcut must be a pi key combo string (e.g. "${DEFAULT_TOGGLE_SHORTCUT}"), or null/empty to disable — got ${JSON.stringify(raw)}`,
		};
	}
	const s = raw.trim();
	if (!s) return { key: null, warning: null };
	if (!KEY_COMBO_RE.test(s)) {
		return {
			key: null,
			warning: `toggleShortcut "${raw}" is not a valid pi key combo (modifier+key, e.g. "${DEFAULT_TOGGLE_SHORTCUT}") — shortcut not registered; fix config/pi-verdict.json`,
		};
	}
	return { key: s, warning: null };
}

export interface UserRules {
	allow: RegExp[];
	deny: RegExp[];
	/** User-declared protected paths (ADR-0002): plain paths, tool-owned normalization; hit → ask */
	denyPaths: string[];
	/** [tools allowlist] exact tool-name allowlist for the MCP/custom family (adapter direction "unknown", e.g. "ask", "propose_commit", "propose_changelog") — a case-sensitive exact match on the tool's registered name bypasses the classifier and returns allow directly. Does not touch the built-in floor or denyPaths (none of those cover this family either). Empty = unchanged default (always classifier). Config key: "tools". */
	tools: string[];
	/** Built-in deny floor switch (danger regexes + path-sensitivity deny), true by default; when off, relies on user rules and the classifier. */
	builtinDenyFloor: boolean;
	/** Forced gate on `.omp` directories: any file-tool path or bash token that resolves into a `.omp` path segment (lexical or realpath form) is a terminal ask (non-interactive → deny). Default false (fork decision: the self-protection layer carries the protection; ADR-0005); checked after the built-in floor and user deny, before denyPaths/user allow. Config key: "gateOmpDir". */
	gateOmpDir: boolean;
	/** [pi-verdict local patch: autoDeny] false → auto-review denies become interactive asks (headless still denies). Default true. */
	autoDeny: boolean;
	/** [pi-verdict local patch: rules] user-authored free-text rules appended to every classifier prompt (LLM + jev). Config key: "rules". */
	classifierRules: string[];
	/** Classifier model spec (provider/id); null = not configured (self-inspection inherits the session model). */
	classifierModel: string | null;
	/** EXPLAIN-GATE role model spec (provider/id[:thinking]) behind the dialog's "Explain" option; null = inherit the session model */
	explainGateModel: string | null;
	/** EXPLAIN-GATE role: replaces the built-in default explanation prompt; null = EXPLAIN_GATE_DEFAULT_PROMPT */
	explainGatePrompt: string | null;
	/** Master toggle shortcut key (#15); null = disabled; defaults to DEFAULT_TOGGLE_SHORTCUT. */
	toggleShortcut: string | null;
	/** Opt-in gray-zone adjudication audit (#54): per-session JSONL under <agentDir>/verdicts/ */
	audit: boolean;
	/** Allow visibility (#60): info notification on classifier allows; mechanical passes stay silent. Default off. */
	notifyAllows: boolean;
	/** #67: autonomy floor for the first layer — a jev verdict with confidence strictly
	 *  below this is demoted (cascaded to the fallback if configured, else asked of the
	 *  user; non-interactive degrades to deny). null = floor off. */
	classifierMinConfidence: number | null;
	/** #63/#67: second-layer model spec (provider/id[:thinking]); consulted on demotion
	 *  and fail-closed only. null = no second layer. */
	classifierFallbackModel: string | null;
	/** #67: does the second layer adjudicate cascaded calls ("enforce", default, matching
	 *  upstream 0.13) or only record its opinion while the human decides ("shadow")? */
	classifierFallbackMode: "shadow" | "enforce";
	/** Subagent gate mode (omp only): "off" = gate inert in subagents; "normal" = asks prompt on the root UI, unanswered within subagentAskTimeoutMs → resolved by the second model; "auto" = never prompt, resolved by the second model. Default "normal" (fork decision: "off" skipped the rule layer, floor and classifier inside every subagent; ADR-0006). */
	subagentGate: "off" | "normal" | "auto";
	/** normal-mode root-dialog deadline in ms, measured from enqueue (queue wait counts). Default 60000. */
	subagentAskTimeoutMs: number;
	/** Footer status style: "full" = Nerd Font powerline blocks, "compact" = plain one-line text, "off" = no status. Default "full". */
	footer: "full" | "compact" | "off";
}

const EMPTY_RULES: UserRules = {
	allow: [],
	deny: [],
	denyPaths: [],
	tools: [],
	builtinDenyFloor: true,
	gateOmpDir: false,
	classifierModel: null,
	explainGateModel: null,
	explainGatePrompt: null,
	toggleShortcut: DEFAULT_TOGGLE_SHORTCUT,
	audit: false,
	notifyAllows: false,
	footer: "full",
	classifierMinConfidence: null,
	classifierFallbackModel: null,
	classifierFallbackMode: "enforce",
	subagentGate: "normal",
	subagentAskTimeoutMs: 60_000,
	autoDeny: true,
	classifierRules: [],
};

/**
 * Starter `tools` allowlist written into the first-run config template (a pre-filled
 * user declaration, like the denyPaths starter list — existing configs are never
 * rewritten). Only tools outside the tool-access adapter's observing/mutating sets
 * (adapter direction "unknown") can be listed. Selection criterion: no filesystem/process/
 * network side effect of their own, or an effect already gated elsewhere.
 *  - ask:        prompts the user; the user is the gate
 *  - todo:       session task list (UI/session metadata only)
 *  - wait:       blocks on already-started background jobs
 *  - yield:      subagent result submission (hidden tool)
 *  - think:      private scratchpad (hidden tool)
 *  - checkpoint, rewind: in-memory session context only — message count + session-tree
 *                entry id, no file or git restore (R8: verified in omp's checkpoint tool)
 *  - recall, reflect:    read from the configured memory backend
 * Deliberately NOT listed: task (spawns a subagent — exempting it would be a fail-open
 * relative to the subagent gate; gate its calls instead), glob/ast_grep (path-scoped reads
 * the tool-access adapter grades like grep/find; exempting them would bypass denyPaths), lsp
 * (no declared path shape yet, but may gain one), web_search (query text leaves the machine),
 * retain/learn/memory_edit/manage_skill (persist content into future prompts),
 * eval/github/debug/ida/security_scan/ast_edit (execute code or mutate state).
 */
const DEFAULT_ALLOWED_TOOLS = ["ask", "todo", "wait", "yield", "think", "checkpoint", "rewind", "recall", "reflect"];

/** Side-effecting tools whose starter-template exclusion (above) is a silent default, not a
 *  stated warning (item 4, Phase 3): a user who lists one of these in `tools` gets a one-time
 *  session_start warning instead of a quiet classifier bypass for persistent-memory writes. */
export const SIDE_EFFECTING_TOOL_NAMES: ReadonlySet<string> = new Set(["learn", "memory_edit", "retain"]);

/** Session-start coverage report signal fields (Claude-review R2-14: kept in lockstep with the
 *  adapter's own mutation triggers — `toolAccess`'s `readStringField`/`readStringArrayField`
 *  calls read `path`, `_path`, `paths`, `input`, `_input`, `code`, `command`; `content` is an
 *  additional signal — omp's own `write = {path, content?}` — not itself extracted as a target).
 *  A schema exposing none of these will stay gray/classifier-only forever; one exposing a
 *  matching field name under an unrecognized JSON-Schema type is a field the adapter cannot
 *  read (it silently treats the field as absent). */
export const COVERAGE_SIGNAL_FIELDS = ["path", "_path", "paths", "input", "_input", "code", "command", "content"] as const;
/** Expected top-level JSON-Schema `type` keyword per signal field — `paths` is the only array. */
export const COVERAGE_SIGNAL_FIELD_TYPE: Record<(typeof COVERAGE_SIGNAL_FIELDS)[number], string> = {
	path: "string",
	_path: "string",
	paths: "array",
	input: "string",
	_input: "string",
	code: "string",
	command: "string",
	content: "string",
};

export const USER_CONFIG_TEMPLATE = `${JSON.stringify(
	{
		_hint:
			'pi-verdict user rules — full reference: https://github.com/jonatsu/pi-verdict/blob/main/docs/configuration.md. deny beats allow. denyPaths: protected paths, any touch asks for your confirmation (non-interactive degrades to deny); the pre-filled starter list is your declaration, edit or empty freely. builtinDenyFloor=false disables the built-in danger floor and the code-loading ask (writes where omp or pi loads code in later sessions ask for your confirmation) at your own risk. gateOmpDir (default false; the self-protection layer over the gate\'s own files stays on regardless): true makes any read/write touching a .omp directory ask for your confirmation (non-interactive degrades to deny); false disables it; also togglable via /verdict. tools (the legacy key ignoreTools is accepted as a deprecated alias): exact names of non-path, non-command tools (e.g. todo, ask) that skip the classifier and are allowed directly; the pre-filled starter list holds only tools without side effects of their own, edit or empty freely. classifierModel pins the classifier (provider/id, e.g. zai/glm-5.3-flash; empty = session model). classifierFallbackModel (optional) adds a second-layer classifier consulted only when the first layer fails closed or, with the jev classifier, reports a confidence below classifierMinConfidence (0-100; null = off); mode enforce (default) lets the second layer adjudicate, shadow only records its opinion while the human decides. toggleShortcut sets the master-switch toggle key (null or empty disables). Changes apply to new sessions. autoDeny=false turns every auto-review deny (danger floor, deny rules, classifier) into a confirmation prompt; non-interactive sessions still deny. rules: free-text rules for the classifier (e.g. "npm install is expected in this repo"); they take precedence over its default criteria. explainGateModel (provider/id[:thinking]; empty = session model) and explainGatePrompt (empty = built-in default) configure the EXPLAIN-GATE role behind the Explain option of the confirmation dialog; it is never offered for protected-path or .omp asks. subagentGate (omp only: normal default / off / auto; off makes the gate inert in subagents) routes asks raised inside subagents to the root UI (normal) or straight to the second model (auto); unanswered within subagentAskTimeoutMs (default 60000) an ask is resolved by classifierFallbackModel, and only its explicit allow permits the call — set omp\'s extensionHandlers.toolCallTimeoutMs to at least subagentAskTimeoutMs + 60000. footer: "full" (Nerd Font powerline blocks, default) | "compact" (plain text) | "off" (no footer status).',
		allow: ["^ls\\b"],
		deny: [],
		tools: DEFAULT_ALLOWED_TOOLS,
		denyPaths: ["~/.ssh/", "~/.profile", "~/.gnupg", "~/.mc", "~/.zshrc", "~/.bashrc"],
		builtinDenyFloor: true,
		gateOmpDir: false,
		autoDeny: true,
		classifierModel: null,
		explainGateModel: null,
		explainGatePrompt: null,
		toggleShortcut: DEFAULT_TOGGLE_SHORTCUT,
		audit: false,
		notifyAllows: false,
		footer: "full",
		classifierMinConfidence: null,
		classifierFallbackModel: null,
		classifierFallbackMode: "enforce",
		subagentGate: "normal",
		subagentAskTimeoutMs: 60000,
		rules: [],
	},
	null,
	2,
)}\n`;

export interface LoadedRules {
	rules: UserRules;
	skipped: string[];
	shortcutWarning: string | null;
	project: { path: string; trusted: boolean; applied: boolean } | null;
	/** item 6c (Phase 6): policyDegraded — set when the user's own declarations could not be
	 *  fully loaded: a config parse failure, a load exception, a trusted-project parse/shape
	 *  failure, or any skipped `deny`/`denyPaths` entry (Claude-review F11). While set, every
	 *  model-originated allow becomes an ask (see adjudicate) — see ADR-0010. */
	degraded: boolean;
}

const stringList = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);

/** A single string where `deny` or `denyPaths` expects a list has an unambiguous intent, so it
 *  becomes a one-element list and keeps its protection; the note names the key. Other wrong
 *  types are left for the loader's degrading checks. */
const coerceSingleStringLists = (obj: Record<string, unknown>, skipped: string[], where: string): void => {
	for (const key of ["deny", "denyPaths"]) {
		const v = obj[key];
		if (typeof v !== "string") continue;
		obj[key] = [v];
		skipped.push(`${key}: ${JSON.stringify(v)} is a string, not a list — treated as a one-element list (${where})`);
	}
};

/** Union of two deny-side lists that keeps type-invalid values (a non-array, a non-string entry)
 *  in the result, so the loader's own checks still see and report them after a project merge. */
const unionKeepingInvalid = (userVal: unknown, projVal: unknown): unknown[] => {
	const out: unknown[] = [];
	for (const v of [userVal, projVal]) {
		if (v === undefined || v === null) continue;
		if (Array.isArray(v)) out.push(...v);
		else out.push(v);
	}
	return [...new Set(out)];
};

/** subagentAskTimeoutMs feeds AbortSignal.timeout/setTimeout (below): a value above 2^31-1ms
 *  overflows those Node/Bun timers, which then fire almost immediately — acting like "auto"
 *  instead of waiting. The cap applies to the user's own value and to any project narrowing
 *  alike (F12). */
const SUBAGENT_ASK_TIMEOUT_MAX_MS = 2_147_483_647;
const validSubagentAskTimeoutMs = (v: unknown): number | null =>
	typeof v === "number" && Number.isInteger(v) && v >= 1 && v <= SUBAGENT_ASK_TIMEOUT_MAX_MS ? v : null;
const widenSkip = (key: string, v: unknown, pp: string): string =>
	`${key}: ${JSON.stringify(v)} would widen the gate — project override ignored (${pp})`;

/** Each overridable key's narrowing merge, given the user's own raw value and the project's
 *  raw value (ADR-0006, narrowed by R7; direction table). This table IS the overridability
 *  list — a key absent from it is not overridable per project at all (the loop below warns and
 *  ignores it) — so a new key cannot be added to the merge without choosing a narrowing
 *  direction. The gate's decision inputs stay user-only regardless: the classifier and
 *  EXPLAIN-GATE model specs (an egress channel), the free-text `rules` (injected into the
 *  classifier prompt with "takes precedence" wording), toggleShortcut, and the authority/
 *  egress keys `autoDeny`, `audit`, `classifierMinConfidence` and `classifierFallbackModel`.
 *  `footer` is user-only too: `footer:"off"` would hide the `subagent off` warning badge that
 *  exists to expose a widened state, so a project must not be able to silence it. The trust
 *  prompt names this set. */
type ProjectOverrideNarrow = (userVal: unknown, projVal: unknown, skipped: string[], pp: string) => unknown;
/** The shared shape of the scalar direction-table arms: an identical project
 *  value is a no-op with no note, an accepted value applies, anything else is a
 *  widening the skip channel names (plan Phase 1 step 2). */
const narrowScalar = (key: string, userVal: unknown, projVal: unknown, accept: unknown, skipped: string[], pp: string): unknown => {
	if (projVal === userVal) return userVal;
	if (projVal === accept) return projVal;
	skipped.push(widenSkip(key, projVal, pp));
	return userVal;
};
const PROJECT_OVERRIDE_DIRECTION: Record<string, ProjectOverrideNarrow> = {
	deny: (userVal, projVal) => unionKeepingInvalid(userVal, projVal),
	denyPaths: (userVal, projVal) => unionKeepingInvalid(userVal, projVal),
	allow: (userVal, projVal) => stringList(userVal).filter((x) => stringList(projVal).includes(x)),
	tools: (userVal, projVal) => stringList(userVal).filter((x) => stringList(projVal).includes(x)),
	ignoreTools: (userVal, projVal) => stringList(userVal).filter((x) => stringList(projVal).includes(x)),
	builtinDenyFloor: (userVal, projVal, skipped, pp) => narrowScalar("builtinDenyFloor", userVal, projVal, true, skipped, pp),
	gateOmpDir: (userVal, projVal, skipped, pp) => narrowScalar("gateOmpDir", userVal, projVal, true, skipped, pp),
	notifyAllows: (userVal, projVal, skipped, pp) => narrowScalar("notifyAllows", userVal, projVal, true, skipped, pp),
	classifierFallbackMode: (userVal, projVal, skipped, pp) =>
		narrowScalar("classifierFallbackMode", userVal, projVal, "shadow", skipped, pp),
	subagentGate: (userVal, projVal, skipped, pp) => narrowScalar("subagentGate", userVal, projVal, "normal", skipped, pp),
	subagentAskTimeoutMs: (userVal, projVal, skipped, pp) => {
		const userEff = validSubagentAskTimeoutMs(userVal) ?? 60_000;
		const projEff = validSubagentAskTimeoutMs(projVal);
		if (projEff === userEff) return userVal; // an equal effective value changes nothing — no note
		if (projEff !== null && projEff > userEff) return projEff;
		skipped.push(widenSkip("subagentAskTimeoutMs", projVal, pp));
		return userVal;
	},
};

/** Every key the user config may carry; anything else warns (R9) — a typo in `deny`
 *  or `denyPaths` would otherwise silently drop that protection. */
const KNOWN_USER_KEYS: Record<string, true> = {
	allow: true,
	deny: true,
	denyPaths: true,
	tools: true,
	ignoreTools: true,
	builtinDenyFloor: true,
	gateOmpDir: true,
	classifierModel: true,
	explainGateModel: true,
	explainGatePrompt: true,
	toggleShortcut: true,
	audit: true,
	notifyAllows: true,
	classifierFallbackModel: true,
	classifierFallbackConfidence: true,
	classifierMinConfidence: true,
	classifierFallbackMode: true,
	footer: true,
	subagentGate: true,
	subagentAskTimeoutMs: true,
	autoDeny: true,
	rules: true,
	_hint: true,
};

/**
 * Load user rules. On first run, create a commented template (only the ^ls\b example in allow is usable by default; the rest are explanatory placeholders);
 * if the config is missing/corrupt/has invalid fields, fall back to empty rules (safe default, does not fail); collect invalid regexes for reporting,
 * and collect invalid toggleShortcut warning text (emitted at session_start along with skipped regexes).
 */
export function loadUserRules(cwd: string | null = null, sessionTrustedRoot: string | null = null): LoadedRules {
	try {
		const p = userConfigPath();
		if (!fs.existsSync(p)) {
			try {
				fs.mkdirSync(path.dirname(p), { recursive: true });
				fs.writeFileSync(p, USER_CONFIG_TEMPLATE);
			} catch {
				/* Silently skip in read-only environments */
			}
			return { rules: EMPTY_RULES, skipped: [], shortcutWarning: null, project: null, degraded: false };
		}
		let raw: {
			allow?: unknown;
			deny?: unknown;
			denyPaths?: unknown;
			tools?: unknown;
			ignoreTools?: unknown;
			builtinDenyFloor?: unknown;
			gateOmpDir?: unknown;
			classifierModel?: unknown;
			explainGateModel?: unknown;
			explainGatePrompt?: unknown;
			toggleShortcut?: unknown;
			audit?: unknown;
			notifyAllows?: unknown;
			classifierFallbackModel?: unknown;
			classifierFallbackConfidence?: unknown;
			classifierMinConfidence?: unknown;
			classifierFallbackMode?: unknown;
			footer?: unknown;
			subagentGate?: unknown;
			subagentAskTimeoutMs?: unknown;
			autoDeny?: unknown;
			rules?: unknown;
		};
		try {
			raw = JSON.parse(fs.readFileSync(p, "utf8")) as typeof raw;
		} catch (err) {
			// Invalid config never silently disables the gate (#25): a parse failure
			// loads empty user rules (the floor stays on) and reports through the
			// session_start skip channel, same as invalid regexes
			return {
				rules: EMPTY_RULES,
				skipped: [`config parse failed: ${err instanceof Error ? err.message : String(err)} — user rules not loaded (${p})`],
				shortcutWarning: null,
				project: null,
				degraded: true, // item 6c: the user's own declarations are gone entirely (ADR-0010)
			};
		}
		const skipped: string[] = [];
		// item 6c (Phase 6): tracks the failure families that make policyDegraded true (ADR-0010)
		let degraded = false;
		// R9: an unrecognised user-config key is a typo that would silently drop a
		// protection — name it and the file, keep loading the rest.
		for (const k of Object.keys(raw as Record<string, unknown>)) {
			if (!Object.hasOwn(KNOWN_USER_KEYS, k)) skipped.push(`unknown key: ${k} — ignored (${p})`);
		}
		coerceSingleStringLists(raw as Record<string, unknown>, skipped, p);
		// [pi-verdict local patch: project overrides] merge the nearest trusted project's
		// config over the global raw object, narrowing only (ADR-0006/R7)
		const agentDir = agentDirPath();
		let project: LoadedRules["project"] = null;
		const pp = cwd === null ? null : findProjectConfig(cwd, agentDir);
		if (pp) {
			const root = projectRootOf(pp);
			const store = readTrustStore();
			if (store.error) skipped.push(store.error);
			// Hash-bound trust (ADR-0006): a stale override re-prompts instead of applying.
			const trusted =
				projectTrustState(root, pp, store) === "trusted" || (sessionTrustedRoot !== null && rootIn(root, [sessionTrustedRoot]));
			project = { path: pp, trusted, applied: false };
			let projRaw: unknown;
			// untrusted and undecided both mean "not applied" (file never parsed); the session_start prompt owns the user-facing notice
			if (trusted) {
				try {
					projRaw = JSON.parse(fs.readFileSync(pp, "utf8"));
				} catch (err) {
					degraded = true; // item 6c: a TRUSTED project override failed to load (ADR-0010)
					skipped.push(
						`project config parse failed: ${err instanceof Error ? err.message : String(err)} — project overrides not loaded (${pp})`,
					);
				}
			}
			if (projRaw !== undefined) {
				if (typeof projRaw !== "object" || projRaw === null || Array.isArray(projRaw)) {
					degraded = true; // item 6c: a TRUSTED project override's top level is not an object (ADR-0010)
					skipped.push(`project config ${pp}: top level must be a JSON object — project overrides not loaded`);
				} else {
					// Only the allowlisted keys merge (ADR-0006): the classifier/explain-gate
					// models are an egress channel and the free-text `rules` are injected into
					// the classifier prompt with "takes precedence" wording, so a project must
					// never steer either; toggleShortcut stays user-only too.
					// R7 — narrowing only, mechanically enforced: every key in
					// PROJECT_OVERRIDE_DIRECTION applies its own narrowing merge; a key absent
					// from the table is not overridable per project at all (handled below).
					coerceSingleStringLists(projRaw as Record<string, unknown>, skipped, pp);
					const merged = { ...raw } as Record<string, unknown>;
					for (const [k, v] of Object.entries(projRaw as Record<string, unknown>)) {
						const narrow = Object.hasOwn(PROJECT_OVERRIDE_DIRECTION, k) ? PROJECT_OVERRIDE_DIRECTION[k] : undefined;
						if (!narrow) {
							if (k !== "_hint") skipped.push(`${k}: not overridable per project — key ignored (${pp})`);
							continue;
						}
						merged[k] = narrow(merged[k], v, skipped, pp);
					}
					raw = merged as unknown as typeof raw;
					project = { path: pp, trusted: true, applied: true };
				}
			}
		}
		// item 6c (Phase 6): only a skipped DENY entry marks policy degraded — a skipped allow
		// entry cannot make the gate MORE permissive than it already is (it never granted
		// anything); a dropped deny silently removes a protection (Claude-review F11). The
		// deny call site below passes the marker; the allow call site does not.
		const compile = (key: string, list: unknown, onSkip?: () => void): RegExp[] => {
			if (list !== undefined && list !== null && !Array.isArray(list)) {
				onSkip?.();
				skipped.push(`${key}: ${JSON.stringify(list)} (must be an array of strings)`);
				return [];
			}
			return ((list ?? []) as unknown[]).flatMap((src) => {
				if (typeof src !== "string") {
					onSkip?.();
					skipped.push(`${key}: ${JSON.stringify(src)}`);
					return [];
				}
				try {
					return [new RegExp(src)];
				} catch {
					onSkip?.();
					skipped.push(src);
					return [];
				}
			});
		};
		// denyPaths entries are plain paths: only type-valid non-empty strings survive;
		// anything else is skipped into the one-shot warning channel (invalid config never disables the gate)
		if (raw.denyPaths !== undefined && raw.denyPaths !== null && !Array.isArray(raw.denyPaths)) {
			degraded = true;
			skipped.push(`denyPaths: ${JSON.stringify(raw.denyPaths)} (must be an array of strings)`);
		}
		const denyPaths = (Array.isArray(raw.denyPaths) ? raw.denyPaths : []).flatMap((x) => {
			if (typeof x !== "string" || !x.trim()) {
				if (x !== undefined && x !== null) {
					degraded = true; // item 6c: a dropped denyPaths entry silently removes a protection (ADR-0010)
					skipped.push(`denyPaths: ${JSON.stringify(x)}`);
				}
				return [];
			}
			return [x.trim()];
		});
		if (raw.rules !== undefined && raw.rules !== null && !Array.isArray(raw.rules))
			skipped.push(`rules: ${JSON.stringify(raw.rules)} (must be an array of strings)`);
		const classifierRules = (Array.isArray(raw.rules) ? raw.rules : []).flatMap((x) => {
			if (typeof x !== "string" || !x.trim()) {
				if (x !== undefined && x !== null) skipped.push(`rules: ${JSON.stringify(x)}`);
				return [];
			}
			return [x.trim()];
		});
		if (raw.tools !== undefined && raw.tools !== null && !Array.isArray(raw.tools))
			skipped.push(`tools: ${JSON.stringify(raw.tools)} (must be an array of strings)`);
		const namedTool = (key: string, list: unknown): string[] =>
			(Array.isArray(list) ? list : []).flatMap((x) => {
				if (typeof x !== "string" || !x.trim()) {
					if (x !== undefined && x !== null) skipped.push(`${key}: ${JSON.stringify(x)}`);
					return [];
				}
				return [x.trim()];
			});
		// [pi-verdict local patch: ignoreTools alias] the pre-0.17 key name for `tools`;
		// accepted so an unmigrated policy keeps its exemption instead of silently
		// losing it (0.12.1 read ignoreTools, the fork reads tools, neither warns).
		// The canonical key wins on a duplicate name; `tools` is the documented form.
		if (raw.ignoreTools !== undefined) skipped.push("ignoreTools: deprecated key name — use tools (accepted as an alias this session)");
		const tools = [...new Set([...namedTool("tools", raw.tools), ...namedTool("ignoreTools", raw.ignoreTools)])];
		const shortcut = resolveToggleShortcut(raw.toggleShortcut);
		// #63/#67: confidence-floor keys — invalid values skip into the one-shot warning channel
		if (raw.classifierFallbackConfidence !== undefined)
			skipped.push("classifierFallbackConfidence: renamed to classifierMinConfidence (0.11.0) — key ignored");
		const minConfRaw = raw.classifierMinConfidence;
		const minConfOk = typeof minConfRaw === "number" && Number.isFinite(minConfRaw) && minConfRaw >= 0 && minConfRaw <= 100;
		if (minConfRaw !== undefined && minConfRaw !== null && !minConfOk)
			skipped.push(`classifierMinConfidence: ${JSON.stringify(minConfRaw)}`);
		const fbModeRaw = raw.classifierFallbackMode;
		if (fbModeRaw !== undefined && fbModeRaw !== "shadow" && fbModeRaw !== "enforce")
			skipped.push(`classifierFallbackMode: ${JSON.stringify(fbModeRaw)}`);
		const footerRaw = raw.footer;
		const footerOk = footerRaw === "full" || footerRaw === "compact" || footerRaw === "off";
		if (footerRaw !== undefined && !footerOk) skipped.push(`footer: ${JSON.stringify(footerRaw)}`);
		const sgRaw = raw.subagentGate;
		const sgOk = sgRaw === "off" || sgRaw === "normal" || sgRaw === "auto";
		if (sgRaw !== undefined && !sgOk) skipped.push(`subagentGate: ${JSON.stringify(sgRaw)}`);
		const satRaw = raw.subagentAskTimeoutMs;
		const satValid = validSubagentAskTimeoutMs(satRaw);
		if (satRaw !== undefined && satValid === null) skipped.push(`subagentAskTimeoutMs: ${JSON.stringify(satRaw)}`);
		return {
			rules: {
				allow: compile("allow", raw.allow),
				deny: compile("deny", raw.deny, () => {
					degraded = true; // item 6c: a dropped deny regex silently removes a protection (ADR-0010)
				}),
				denyPaths,
				tools,
				builtinDenyFloor: raw.builtinDenyFloor !== false,
				gateOmpDir: raw.gateOmpDir === true,
				classifierModel: typeof raw.classifierModel === "string" && raw.classifierModel.trim() ? raw.classifierModel.trim() : null,
				explainGateModel: typeof raw.explainGateModel === "string" && raw.explainGateModel.trim() ? raw.explainGateModel.trim() : null,
				explainGatePrompt: typeof raw.explainGatePrompt === "string" && raw.explainGatePrompt.trim() ? raw.explainGatePrompt.trim() : null,
				toggleShortcut: shortcut.key,
				audit: raw.audit === true,
				notifyAllows: raw.notifyAllows === true,
				classifierFallbackModel:
					typeof raw.classifierFallbackModel === "string" && raw.classifierFallbackModel.trim() ? raw.classifierFallbackModel.trim() : null,
				classifierMinConfidence: minConfOk ? minConfRaw : null,
				classifierFallbackMode: fbModeRaw === "shadow" ? "shadow" : "enforce",
				footer: footerOk ? footerRaw : "full",
				subagentGate: sgOk ? sgRaw : "normal",
				subagentAskTimeoutMs: satValid ?? 60_000,
				autoDeny: raw.autoDeny !== false,
				classifierRules,
			},
			skipped,
			shortcutWarning: shortcut.warning,
			project,
			degraded,
		};
	} catch (err) {
		// An unexpected failure (not the JSON-parse path above) must not vanish: load
		// empty rules with the floor on and surface the error through the same channel.
		return {
			rules: EMPTY_RULES,
			skipped: [`config load failed: ${err instanceof Error ? err.message : String(err)} — user rules not loaded`],
			shortcutWarning: null,
			project: null,
			degraded: true, // item 6c: an unexpected load exception, same fail-direction change (ADR-0010)
		};
	}
}
