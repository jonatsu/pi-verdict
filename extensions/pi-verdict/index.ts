/**
 * Auto Mode Extension — PROTOTYPE (not production quality)
 *
 * Tool-call permission is adjudicated automatically by "rule layer + model classifier",
 * no per-call human approval. Semantically aligned with Claude Code Auto Mode but
 * inverted: pi defaults to allowing → this extension intercepts.
 *
 * Pipeline (tool_call hook):
 *   1. Rule layer (built-in deny floor + user declarations):
 *      - built-in floor: bash danger regexes + path sensitivity S0-S5 → hard deny
 *        (on by default; builtinDenyFloor:false turns the whole floor off, at your
 *        own risk)
 *      - user rules: allow/deny regexes in config/pi-verdict.json (deny wins over
 *        allow); no built-in allowlist (every "always allow" claim is the user's,
 *        #12/audit response)
 *      - denyPaths (ADR-0002): user-declared protected paths; path-semantic
 *        comparison with tool-owned normalization (~, $HOME, relative, .., symlink
 *        forms all resolve); a hit → terminal ask (non-interactive degrades to
 *        deny), after user deny, before user allow — a protected path is the user's
 *        exception to their own allow rules
 *   2. Gray zone → model classifier (defaults to "self-reflection": inherits the
 *      session provider/model)
 *      - input: CC-style condensed <transcript> (user message stream + tool call
 *        stream, no assistant narration or tool results), action under review
 *        pinned as the last line; when denyPaths are configured a fixed existence
 *        hint is appended to the system prompt (zero path plaintext)
 *      - output contract: <verdict>allow|ask|deny</verdict> prefix-anchored
 *   3. Three-state verdict: allow passes / deny blocks / ask goes to a human
 *      (ctx.ui.confirm)
 *
 * Structure: the pipeline is adjudicate() — a zero-UI module returning a Verdict
 * value object (source: rule|protected-path|classifier|fail-closed, plus a
 * `degraded` flag for ask→deny in non-interactive sessions); the tool_call
 * handler maps verdicts to UI (notify/confirm) by source (the degraded context is
 * implicit in the protected-path source's deny wording).
 *
 * fail-closed: classifier exception/timeout/contract violation → deny; in
 * non-interactive modes (no UI) ask → deny.
 *
 * Configuration:
 *   --auto-mode / --no-auto-mode   CLI flag, master switch (default on)
 *   ctrl+shift+a                   master-switch toggle shortcut (default; silent
 *                                   toggle, footer always visible as the only
 *                                   feedback; config toggleShortcut rebinds/null
 *                                   disables, new session applies)
 *   --auto-mode-model provider/id[:thinking]  classifier model + optional thinking
 *                                   suffix (pi-native --model syntax; default off
 *                                   = thinking explicitly disabled)
 *   PI_AUTO_MODE_MODEL             env-var form of the above
 *   --auto-mode-debug              notify on every verdict (incl. allows)
 *   PI_AUTO_MODE_DEBUG=1           env-var form of the above (kept for compat)
 *   <agentDir>/config/pi-verdict.json   user rules: { allow: [regex], deny: [regex],
 *                                   denyPaths: [path], builtinDenyFloor,
 *                                   classifierModel, explainGateModel,
 *                                   explainGatePrompt, toggleShortcut }
 *                                   match target: bash = full command string /
 *                                   file tools = absolute path; new session applies
 *
 * Known prototype simplifications (see README "Status & limitations"):
 *   - no built-in bash allowlist; danger detection is regex floor (no AST parsing)
 *     — unknown shapes go to the classifier
 *   - AGENTS.md not passed to the classifier as downweighted intent evidence
 *   - denyPaths bash extraction is token-level: command substitution, base64-
 *     embedded paths and external script contents produce no hit signal — those
 *     fall back to the classifier's existence-hint vigilance (ADR-0002)
 *
 * Design basis: research/claude-code-classifier-prompts.md,
 *               research/pi-model-call-and-ref-implementations.md
 */

import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { parseJevReason } from "../jev-adapter.ts";
import { type CoverageToolInfo, sideEffectingToolsWarning, toolCoverageReport } from "./access.ts";
import { actionCallLine, toolCallLine } from "./action-line.ts";
import {
	type AdjudicateEnv,
	type AllowVerdict,
	type AskVerdict,
	adjudicate,
	type DenyVerdict,
	resolveAskWithoutHuman,
	type Verdict,
	type VerdictSource,
} from "./adjudicate.ts";
import { agentDirPath, findProjectConfig, userConfigPath } from "./agent-dir.ts";
import type { AuditRecord } from "./audit.ts";
import { completionForHost } from "./completion.ts";
import type { UserRules } from "./config.ts";
import { declineDetail, type ExplainGateResult, explainGate } from "./explain.ts";
import { resolveClassifier, resolveExplainGate, resolveFallbackClassifier } from "./model-roles.ts";
import { PROTECTED_PATH_MARKER, type RedactorFn, redactorFor } from "./redaction.ts";
import { type AutoModeDeps, createRuntime, refreshStatus as refreshRuntimeStatus } from "./runtime.ts";
import type { FallbackStats, RulesLoadReport } from "./state.ts";
import {
	HOST_RETURN_MARGIN_MS,
	hostBudgetAdvice,
	hostBudgetExpiry,
	MIN_SUBAGENT_DIALOG_MS,
	STATUS_WIDGET_KEY,
	subagentAskWindow,
	subagentIdentity,
	subagentLabel,
	type UiContext,
	untilAborted,
} from "./subagent.ts";
import {
	NEVER_CHOICE,
	NOT_NOW_CHOICE,
	projectRootOf,
	projectTrustState,
	readTrustStore,
	recordTrust,
	TRUST_CHOICE,
	trustStorePath,
} from "./trust.ts";
import { runConfigEditor } from "./ui/config-editor.ts";
import { approveCodeMarkdown, confirmAsk, displaySafe } from "./ui/dialog.ts";

export { expandHostPath, hostPathForms, hostReadPath } from "./access.ts";
export { type AdjudicateEnv, adjudicate, resolveAskWithoutHuman, type Verdict, type VerdictSource } from "./adjudicate.ts";
export { resolveAgentDir } from "./agent-dir.ts";
export { AuditLog, type AuditRecord, type FallbackAudit } from "./audit.ts";
export { budgetedTimeoutMs } from "./classifier.ts";
export { bindCompletion, type CompatLoader, type CompletionFn } from "./completion.ts";
export { BASH_PATH_TOKENS, bashPathTokens } from "./deny-paths.ts";
export {
	declineDetail,
	EXPLAIN_GATE_DEFAULT_PROMPT,
	EXPLAIN_GATE_ROLE,
	type ExplainGateArgs,
	type ExplainGateResult,
	explainGate,
} from "./explain.ts";
export { computeTmpdirBases, setTmpdirBasesForTests, setXdgConfigRootsForTests } from "./floor.ts";
export type { PipelineHost } from "./model-call.ts";
export { mentionsSpelling, type RedactionPlatform, type RedactorFn, redactorFor } from "./redaction.ts";
export type { AutoModeDeps } from "./runtime.ts";
export { buildProtectedSet, isProtectedReadPath, isProtectedWritePath } from "./self-protection.ts";
export { allowAdmits, BASH_MAX_MATCH_LEN, gitPushForce, isForceFlag, shellWords } from "./shell.ts";
export { type RulesLoadReport, SessionState } from "./state.ts";
export { subagentIdentity } from "./subagent.ts";
export { type AskChoice, type AskDecision, approveCodeMarkdown, buildApproveDialog, displaySafe, renderJevBar } from "./ui/dialog.ts";
export { type FooterInfo, renderFooter } from "./ui/footer.ts";

/** UI of the top-level interactive session in this process. Module-level: extension factories
 *  are re-bound per subagent session but module variables are shared across sessions. */
let rootUi: UiContext | null = null;

// ============================================================================
// Extension body
// ============================================================================

/** presentVerdict's ask-dialog reason-line label, keyed by verdict source (presentation only;
 *  the protected-path branch renders its own dialog and never reads this map). */
const ASK_SOURCE_LABEL: Record<VerdictSource, string> = {
	rule: "Rule",
	"protected-path": "Protected path",
	classifier: "Classifier opinion",
	"fail-closed": "Fail-closed",
	"degraded-policy": "Policy degraded", // item 6c (Phase 6): names the state in the dialog's reason line
};

/** The tag of every block reason: a deny's verdict source, or the step that blocked an ask. */
type BlockTag = VerdictSource | "user-declined" | "subagent-auto" | "subagent-expired" | "subagent-cancelled";

type Notify = (msg: string, level: "info" | "warning" | "error") => void;

/** Agent-facing block reason (#53): the text must be self-sufficient — structural
 * error signaling does not reach several provider lanes, and verbatim rule/classifier
 * reasons can be empty or too terse for the acting model to recognize as a block.
 * While the policy is degraded every block names that state (ADR-0010). */
function blockReasonText(tag: BlockTag, detail: string, policyDegraded: boolean): string {
	const stated = policyDegraded
		? `${detail} [policy degraded: the user's own rules failed to load, so model-originated allows are withheld — ADR-0010]`
		: detail;
	const clean = stated.trim().replace(/\.+$/, "");
	return `[auto-mode ${tag} block] BLOCKED — this action did NOT run. Reason: ${clean || "(no further reason given)"}. Report the block to the user; never claim it succeeded or completed.`;
}

/** The `/automode` status line for the confidence cascade; shadow mode names what enforce would have done. */
function cascadeSummary(s: Readonly<FallbackStats>, mode: UserRules["classifierFallbackMode"]): string {
	if (s.triggered === 0) return "confidence cascade: not triggered this session";
	const enforced = mode === "enforce";
	return `confidence cascade (${mode}): triggered ${s.triggered} · agreed ${s.agreed} · ${enforced ? "overruled" : "would-overrule"} ${s.overruled} · ${enforced ? "rescued-allow" : "would-rescue-allow"} ${s.rescuedAllow} · errored ${s.errored}`;
}

export default function autoMode(pi: ExtensionAPI, deps: AutoModeDeps = {}) {
	pi.registerFlag("auto-mode", {
		description: "Enable Auto Mode (rules + model classifier gating for tool calls)",
		type: "boolean",
		default: true,
	});
	pi.registerFlag("auto-mode-model", {
		description: "Classifier model as provider/id[:thinking] (pi --model syntax; default: inherit session model)",
		type: "string",
	});
	pi.registerFlag("auto-mode-debug", { description: "Notify every verdict incl. allows", type: "boolean", default: false });

	const rt = createRuntime(pi, deps);
	const { state } = rt;
	const refreshStatus = (ctx: ExtensionContext): void => refreshRuntimeStatus(rt, ctx);

	/** One construction point for this session's redactor: the presentation and
	 *  handler sites build their per-call predicate through this helper instead of repeating
	 *  the redactorFor + anchored-bases idiom. (adjudicate and resolveAskWithoutHuman live
	 *  outside this closure and use `env.redact ?? …` — the handler publishes the session
	 *  redactor through AdjudicateEnv.redact below.) */
	const sessionRedactor = (cwd: string): RedactorFn => redactorFor(cwd, state.anchoredDenyPathBases(cwd));

	/** This session's block reason, naming the degraded-policy state while it holds. */
	const blockReason = (tag: BlockTag, detail: string): string => blockReasonText(tag, detail, state.policyDegraded);

	/** Verdict → UI (the extension's single presentation point): presentation keys on
	 *  source alone; protected-path wording carries the ask-degradation context. */
	async function presentVerdict(
		v: Verdict,
		call: { toolName: string; input: Record<string, unknown> },
		action: string,
		ui: UiContext,
		opts: { label: string | null; signal?: AbortSignal; ctx: ExtensionContext; deadlineAt?: number },
	): Promise<{ block: true; reason: string } | undefined | "aborted"> {
		const note = (msg: string, level: "info" | "warning" | "error"): void =>
			ui.notify(opts.label ? msg.replace(/^🛡️ /u, `🛡️ [${opts.label}] `) : msg, level);
		const titled = (t: string): string => (opts.label ? t.replace(/^🛡️ /u, `🛡️ [${opts.label}] `) : t);
		// Notifications carry no protected-path plaintext (ADR-0002): an action that names a protected
		// path becomes the fixed marker. Block reasons and the local dialog show the action unchanged.
		const displayAction = sessionRedactor(opts.ctx.cwd)(call.input) ? PROTECTED_PATH_MARKER : action;
		switch (v.verdict) {
			case "allow":
				presentAllow(v, displayAction, note);
				return undefined;
			case "deny":
				return presentDeny(v, displayAction, note);
			case "ask":
				return presentAsk(v, call, action, ui, opts, titled);
			default: {
				// A fixed message: the verdict may carry a protected path in `detail` (ADR-0002).
				const _unhandled: never = v;
				throw new Error("unhandled verdict");
			}
		}
	}

	/** Notifies an allow: a classifier allow with `notifyAllows` or debug, a mechanical one only with debug (#60). */
	function presentAllow(v: AllowVerdict, displayAction: string, note: Notify): void {
		if (rt.debug) {
			if (v.source === "rule") note(`🛡️ allow (rule): ${displayAction}`, "info");
			else note(`🛡️ allow (classifier): ${v.reason}\n  ${displayAction}`, "info");
		} else if (state.userRules.notifyAllows && v.source === "classifier") {
			note(`🛡️ allow (classifier): ${v.reason}\n  ${displayAction}`, "info");
		}
	}

	/** Notifies a deny and returns its block, tagged by the verdict's source. */
	function presentDeny(v: DenyVerdict, displayAction: string, note: Notify): { block: true; reason: string } {
		/** A headless ask reaches the agent as a block; saying so tells it a human could have allowed the call. */
		const headlessAsk = (): string => (v.degraded ? `ask degraded to block in non-interactive mode: ${v.reason}` : v.reason);
		switch (v.source) {
			case "degraded-policy":
				note(`🛡️ Auto Mode blocked (policy degraded, allow withheld): ${v.reason}\n  ${displayAction}`, "warning");
				return { block: true, reason: blockReason(v.source, v.reason) };
			case "protected-path":
				// No action line: notifications carry no protected-path plaintext (ADR-0002).
				note(`🛡️ Auto Mode blocked (non-interactive, protected-path ask→deny): ${v.reason}`, "warning");
				return { block: true, reason: blockReason(v.source, `ask degraded to block in non-interactive mode: ${v.reason}`) };
			case "fail-closed":
				note(`🛡️ Auto Mode blocked: ${v.reason}\n  ${displayAction}`, "warning");
				return { block: true, reason: blockReason(v.source, v.reason) };
			case "rule":
			case "classifier":
				note(`🛡️ Auto Mode blocked: ${v.reason}\n  ${displayAction}`, "warning");
				return { block: true, reason: blockReason(v.source, headlessAsk()) };
			default: {
				const unhandled: never = v.source;
				throw new Error(`unhandled verdict source: ${unhandled}`);
			}
		}
	}

	/** Puts an ask to the human; interactive only, since the pipeline turns a headless ask into a deny. */
	async function presentAsk(
		v: AskVerdict,
		call: { toolName: string; input: Record<string, unknown> },
		action: string,
		ui: UiContext,
		opts: { signal?: AbortSignal; ctx: ExtensionContext; deadlineAt?: number },
		titled: (title: string) => string,
	): Promise<{ block: true; reason: string } | undefined | "aborted"> {
		const note = (msg: string, level: "info" | "warning" | "error"): void => ui.notify(titled(msg), level);
		if (v.source === "protected-path") {
			// no EXPLAIN-GATE here: the protected path plaintext must not reach a model provider (ADR-0002)
			const d = await confirmAsk(
				ui,
				{
					title: titled("🛡️ Auto Mode: protected path"),
					toolName: call.toolName,
					input: call.input,
					action,
					reasonLine: v.reason,
					detail: v.detail ?? "(see pi-verdict.json)",
					question: "Allow this access?",
					jev: null,
					minConfidence: null,
					fallbackMessage: `${action}\n\n${v.reason}\n\nProtected path: ${v.detail ?? "(see pi-verdict.json)"}\n\nAllow this access?`,
				},
				{ signal: opts.signal, deadlineAt: opts.deadlineAt },
			);
			if (d === "aborted") return "aborted";
			if (d.allow) {
				// Debug notification omits the action line: as above, notifications must not carry protected-path plaintext
				if (rt.debug) note("🛡️ allow (protected-path confirm)", "info");
				return undefined;
			}
			return { block: true, reason: blockReason("user-declined", declineDetail("user declined protected-path access", d.reason)) };
		}
		const label = ASK_SOURCE_LABEL[v.source];
		const reasonLine = `${label}: ${v.reason}`;
		const d = await confirmAsk(
			ui,
			{
				title: titled("🛡️ Auto Mode confirmation"),
				toolName: call.toolName,
				input: call.input,
				action,
				reasonLine,
				question: "Allow execution?",
				jev: v.source === "classifier" ? parseJevReason(v.reason) : null,
				minConfidence: state.userRules.classifierMinConfidence,
				fallbackMessage: `${action}\n\n${label}: ${v.reason}\n\nAllow execution?`,
			},
			{
				signal: opts.signal,
				deadlineAt: opts.deadlineAt,
				explain: (question) => explainAsk(opts.ctx, call, action, label, v.reason, question),
			},
		);
		if (d === "aborted") return "aborted";
		return d.allow ? undefined : { block: true, reason: blockReason("user-declined", declineDetail("user declined", d.reason)) };
	}

	/** Set the master toggle (shared, #15): /automode command and toggle shortcut use the same entry point, with no extra rules from the interaction surface. */
	function setMasterSwitch(next: boolean, ctx: ExtensionContext) {
		rt.enabled = next;
		refreshStatus(ctx);
	}

	/** UI this factory instance published as the root's (see the registry at module level);
	 *  session_shutdown clears the registry only if it still holds this one. */
	let ownRootUi: UiContext | null = null;

	/** Surface skipped-value and shortcut warnings from a rules (re)load */
	function reportLoadWarnings(report: RulesLoadReport, ctx: ExtensionContext): void {
		if (report.skipped.length > 0) {
			ctx.ui.notify(
				`pi-verdict: skipped ${report.skipped.length} invalid config value(s) in config (${userConfigPath()}${report.project?.applied ? ` + ${report.project.path}` : ""}): ${report.skipped.join(", ")}`,
				"warning",
			);
		}
		if (report.shortcutWarning) ctx.ui.notify(`pi-verdict: ${report.shortcutWarning}`, "warning");
		// item 6c (Phase 6; ADR-0010): the primary signal for the degraded state — fires
		// whether or not the failure produced a skipped entry (a parse failure would otherwise
		// rely on the count line above to imply it).
		if (report.degraded)
			ctx.ui.notify(
				"pi-verdict: policy degraded — your own rules could not be fully loaded, so model-originated allows are withheld (each becomes a confirm) until the config is fixed (ADR-0010)",
				"warning",
			);
	}

	// session_start reloads rules and resets per-session verdict statistics.
	pi.on("session_start", async (_event, ctx) => {
		// Project trust prompt: any await stays inside the prompt branch so the no-project path remains synchronous
		rt.sessionTrustedRoot = null;
		const pp = findProjectConfig(ctx.cwd, agentDirPath());
		if (pp) {
			const root = projectRootOf(pp);
			const store = readTrustStore();
			// ctx.agent is omp-only (pi's ExtensionContext has no `agent`): narrow at runtime
			const isSub = subagentIdentity(ctx) !== null;
			// "undecided" also covers a trusted root whose override changed since approval
			// (hash mismatch) — the user is asked about the new content (ADR-0006).
			if (projectTrustState(root, pp, store) === "undecided" && ctx.hasUI && !isSub) {
				const choice = await ctx.ui.select(
					`🛡️ pi-verdict: this project may add deny rules and protected paths, and remove tool exemptions (allow/tools can only narrow); it cannot widen the gate, disable the built-in floor, or change the classifier/EXPLAIN-GATE models, the free-text rules, the toggle shortcut, autoDeny or audit. Trust this project (${pp})?`,
					[TRUST_CHOICE, NOT_NOW_CHOICE, NEVER_CHOICE],
				);
				if (choice === TRUST_CHOICE) {
					rt.sessionTrustedRoot = root;
					const err = recordTrust(root, "trusted", pp);
					if (err) ctx.ui.notify(`pi-verdict: trust decision not saved (${err}) — applies to this session only`, "warning");
				} else if (choice === NEVER_CHOICE) {
					const err = recordTrust(root, "untrusted", pp);
					if (err) ctx.ui.notify(`pi-verdict: trust decision not saved (${err}) — you will be asked again`, "warning");
				}
				// undefined (dialog dismissed) or NOT_NOW_CHOICE: ignore for this session, persist nothing
			}
		}
		// Subagent gate: the top-level interactive session publishes its UI for subagent asks.
		// A headless root clears the registry; a replaced root (/new, /resume) overwrites it.
		if (subagentIdentity(ctx) === null) {
			rootUi = ctx.hasUI ? ctx.ui : null;
			ownRootUi = rootUi;
		}
		const report = state.reset(ctx.cwd, rt.sessionTrustedRoot);
		state.audit?.prune(); // #54: converge to the AUDIT_KEEP_SESSIONS most recent files at session start
		reportLoadWarnings(report, ctx);
		if (report.project?.applied) ctx.ui.notify(`pi-verdict: project overrides applied from ${report.project.path}`, "info");
		if (report.project && !report.project.trusted)
			ctx.ui.notify(
				`pi-verdict: project config ${report.project.path} ignored — project not trusted (decisions: ${trustStorePath()})`,
				"info",
			);
		// Side-effecting tools warning (item 4, Phase 3): one-time, unconditional — the user
		// chose to list it, the gate just stops being silent about the consequence.
		const sideEffectWarning = sideEffectingToolsWarning(state.userRules.tools);
		if (sideEffectWarning) ctx.ui.notify(sideEffectWarning, "warning");
		// Tool coverage report (item 4, Phase 3): a debug-channel note, not noise — gated
		// behind --auto-mode-debug/PI_AUTO_MODE_DEBUG like every other per-session diagnostic.
		// Host capability may be absent (constraint 2): skip silently rather than depend on a
		// specific host/version.
		if (rt.debug) {
			const hostTools = pi as { getActiveTools?: () => string[]; getAllTools?: () => CoverageToolInfo[] };
			if (typeof hostTools.getActiveTools === "function" && typeof hostTools.getAllTools === "function") {
				const coverage = toolCoverageReport(hostTools.getAllTools(), new Set(hostTools.getActiveTools()), state.userRules.tools);
				const parts: string[] = [];
				if (coverage.noFields.length > 0)
					parts.push(`no declared path/code/command field, stays classifier-only: ${coverage.noFields.join(", ")}`);
				if (coverage.untyped.length > 0)
					parts.push(`unrecognized field type: ${coverage.untyped.map((u) => `${u.tool}.${u.field}`).join(", ")}`);
				if (parts.length > 0) ctx.ui.notify(`🛡️ pi-verdict: tool coverage — ${parts.join("; ")}`, "info");
			}
		}
		refreshStatus(ctx);
		// Last, so every step above stays synchronous: only a root session with a UI shows subagent asks.
		if (subagentIdentity(ctx) === null && ctx.hasUI && state.userRules.subagentGate === "normal" && !state.hostBudgetWarned) {
			const advice = hostBudgetAdvice(state.userRules.subagentAskTimeoutMs, await rt.hostHandlerBudget(ctx));
			if (advice) {
				state.hostBudgetWarned = true;
				ctx.ui.notify(`🛡️ pi-verdict: subagent asks will expire early: ${advice}`, "warning");
			}
		}
	});

	pi.on("session_shutdown", () => {
		if (ownRootUi !== null && rootUi === ownRootUi) rootUi = null;
		ownRootUi = null;
	});

	pi.on("model_select", (_e, ctx) => refreshStatus(ctx));

	// Master toggle shortcut (#15): key comes from the user rules loaded first (fixed for the session—takes effect after config changes on
	// /reload or a new session); handler matches /automode semantics, toggles silently,
	// footer display is the only feedback
	const registeredToggleKey = state.userRules.toggleShortcut;
	if (registeredToggleKey) {
		// KeyId is pi's compile-time union type (a string at runtime); user-configured keys are validated at runtime by KEY_COMBO_RE
		// before an assertion cast; the zero-dependency constraint means no pi internal type path is imported
		type PiShortcutKey = Parameters<ExtensionAPI["registerShortcut"]>[0];
		pi.registerShortcut(registeredToggleKey as PiShortcutKey, {
			description: "Toggle Auto Mode (pi-verdict)",
			handler: (ctx) => setMasterSwitch(!rt.enabled, ctx),
		});
	}
	/** Toggle hint on the Usage line (#15): hidden when no key is registered; otherwise shows the registered key. */
	const toggleHint = () => (registeredToggleKey ? ` · toggle: ${registeredToggleKey}` : "");
	/** Status line denyPaths count (ADR-0002): shown only when configured */
	const denyPathsHint = () => (state.userRules.denyPaths.length > 0 ? `\ndenyPaths: ${state.userRules.denyPaths.length} active` : "");
	/** Status line audit hint (#54): shown only while the sink is active */
	const auditHint = () => (state.audit ? `\naudit: on → ${state.audit.dir}` : "");
	/** Status line cascade hint (#63/#67): shown while the floor or the fallback is configured */
	const fallbackHint = () =>
		state.userRules.classifierMinConfidence !== null || state.userRules.classifierFallbackModel
			? `\n${cascadeSummary(state.fallback.stats, state.userRules.classifierFallbackMode)}`
			: "";
	/** Status line degraded-policy hint (item 6c, Phase 6): named whenever the state holds */
	const policyHint = () => (state.policyDegraded ? "\npolicy degraded: model-originated allows withheld (ADR-0010)" : "");

	pi.registerCommand("automode", {
		description: "Show Auto Mode status, or set it: /automode on|off",
		handler: async (args, ctx) => {
			const arg = args.trim().toLowerCase();
			// Bare call: read-only status.
			if (arg === "") {
				ctx.ui.notify(
					`${rt.enabled ? "🛡️ Auto Mode: on" : "Auto Mode: off"}${policyHint()}${denyPathsHint()}${auditHint()}${fallbackHint()}\nUsage: /automode on|off${toggleHint()}`,
					"info",
				);
				return;
			}
			// Idempotent set: if the value matches the current state, do not toggle; only confirm
			if (arg === "on" || arg === "off") {
				const next = arg === "on";
				const changed = next !== rt.enabled;
				setMasterSwitch(next, ctx);
				const head = next
					? `🛡️ Auto Mode enabled${changed ? "" : " (unchanged)"}: tool calls adjudicated by rules + classifier`
					: `Auto Mode disabled${changed ? "" : " (unchanged)"}: tool calls execute directly`;
				ctx.ui.notify(`${head}${fallbackHint()}`, "info");
				return;
			}
			// Unknown argument: reject strictly and show usage (case has been normalized)
			ctx.ui.notify(`unknown argument: ${arg}\nUsage: /automode (status) | /automode on | /automode off${toggleHint()}`, "warning");
		},
	});

	pi.registerCommand("verdict", {
		description: "Edit pi-verdict rules (allow/deny/denyPaths/tools/rules lists, gateOmpDir switch, footer style): /verdict [user|local]",
		handler: (args, ctx) =>
			runConfigEditor(args, ctx, {
				sessionTrustedRoot: rt.sessionTrustedRoot,
				reloadRules: (c) => {
					reportLoadWarnings(state.reloadRules(c.cwd, rt.sessionTrustedRoot), c);
					refreshStatus(c);
				},
			}),
	});

	/** The dialog's "Explain…" handler: one EXPLAIN-GATE call about the held action. */
	async function explainAsk(
		ctx: ExtensionContext,
		call: { toolName: string; input: Record<string, unknown> },
		action: string,
		reasonLabel: string,
		reason: string,
		question: string | null,
	): Promise<ExplainGateResult> {
		const role = resolveExplainGate(ctx, state);
		if (!role) return { ok: false, error: "no model available" };
		// The EXPLAIN prompt carries the held action — when it names a protected
		// path the model gets the fixed marker; the local dialog that already showed this
		// action to the human is unaffected (it renders the raw text separately).
		const redactFn = sessionRedactor(ctx.cwd); // one construction shared by both payloads
		const redacted = redactFn(call.input);
		return explainGate({
			host: ctx.sessionManager,
			signal: ctx.signal,
			complete: completionForHost(ctx.modelRegistry, rt.compatLoader),
			model: role.model,
			thinking: role.thinking,
			actionLine: redacted ? PROTECTED_PATH_MARKER : action,
			actionDetail: redacted
				? PROTECTED_PATH_MARKER
				: (approveCodeMarkdown(call.toolName, call.input, () => undefined)?.markdown ?? displaySafe(action)),
			// A floor reason names the path it matched, so it gets the same marker as the action.
			reasonLine: `${reasonLabel}: ${redacted ? PROTECTED_PATH_MARKER : reason}`,
			defaultPrompt: state.userRules.explainGatePrompt,
			question,
			// item 6b (Phase 5): the EXPLAIN-GATE transcript is a model-provider payload exactly
			// like the classifier's own — same cwd + anchored bases, same predicate.
			redact: redactFn,
		});
	}

	function describeAction(toolName: string, input: Record<string, unknown>): string {
		return toolCallLine(toolName, input);
	}

	pi.on("tool_call", async (event, ctx) => {
		if (!rt.enabled) return undefined;
		const handlerStart = Date.now();

		const sub = subagentIdentity(ctx);
		const mode = state.userRules.subagentGate;
		if (sub && mode === "off") return undefined;
		const label = sub ? subagentLabel(sub) : null;
		// A subagent with its own UI (not produced by omp today) uses it; otherwise the root UI, else none
		const ui: UiContext | null = !sub || ctx.hasUI ? ctx.ui : rootUi;

		const input = event.input as Record<string, unknown>;
		const call = { toolName: event.toolName, input };
		const action = describeAction(event.toolName, input);
		// The subagent notification sites below embed the action too — same
		// no-protected-plaintext invariant as presentVerdict's notifications. Built once here
		// and reused for the env redactor below.
		const redactFn = sessionRedactor(ctx.cwd);
		const displayAction = redactFn(input) ? PROTECTED_PATH_MARKER : action;

		// Live status (root session + UI only): one widget row above the editor while a model call runs.
		// Text is phase + tool name + model id only; never command or path text (ADR-0002).
		const statusUi = !sub && ctx.hasUI && typeof ctx.ui.setWidget === "function" ? ctx.ui : null;
		let statusShown = false;
		const onPhase = statusUi
			? (phase: "classifier" | "fallback", modelId: string): void => {
					statusShown = true;
					statusUi.setWidget(STATUS_WIDGET_KEY, [
						statusUi.theme.fg(
							"warning",
							phase === "classifier"
								? `🛡️ verdict: classifying ${event.toolName} via ${modelId}…`
								: `🛡️ verdict: fallback classifier ${modelId} on ${event.toolName}…`,
						),
					]);
				}
			: undefined;

		// Pipeline (zero UI) → presentation keyed on source alone.
		const env: AdjudicateEnv = {
			cwd: ctx.cwd,
			// The DI seam adjudicate/resolveAskWithoutHuman already read —
			// published once per call from the handler's session redactor.
			redact: redactFn,
			// a subagent's asks are resolved by the bridge (root UI / second model), never degraded in the pipeline
			hasUI: sub ? true : !!ctx.hasUI,
			getModel: () => resolveClassifier(ctx, pi, state),
			complete: completionForHost(ctx.modelRegistry, rt.compatLoader),
			host: ctx.sessionManager,
			hostKind: rt.hostKind,
			signal: ctx.signal,
			getFallbackModel: () => resolveFallbackClassifier(ctx, state),
			...(onPhase ? { onPhase } : {}),
		};
		let verdict: Verdict;
		try {
			verdict = await adjudicate(state, call, env);
		} finally {
			if (statusShown) statusUi?.setWidget(STATUS_WIDGET_KEY, undefined);
		}
		if (!sub) {
			state.countVerdict(verdict.verdict);
			refreshStatus(ctx);
		}
		const warn = (msg: string): void => (ui ?? ctx.ui).notify(label && !msg.startsWith("🛡️") ? `[${label}] ${msg}` : msg, "warning");
		const auditWarning = state.audit?.drainWarning(); // #54: fail-soft one-shot warning
		if (auditWarning) warn(`pi-verdict: ${auditWarning}`);
		// #62: an interactive ask's record is finalized here — exactly one append after the
		// confirm, carrying the user's answer; a presentVerdict throw still lands the record
		// (without the answer) and the error propagates unchanged. `undefined` = allowed.
		let pendingAudit = verdict.verdict === "ask" ? verdict.pendingAudit : undefined;
		const finalize = (extra: Partial<AuditRecord>): void => {
			if (!pendingAudit) return;
			state.audit?.append({ ...pendingAudit, ...extra });
			pendingAudit = undefined;
			const lateWarning = state.audit?.drainWarning();
			if (lateWarning) warn(`pi-verdict: ${lateWarning}`);
		};
		const present = async (signal?: AbortSignal, deadlineAt?: number): Promise<{ block: true; reason: string } | undefined | "aborted"> => {
			try {
				return await presentVerdict(verdict, call, action, ui ?? ctx.ui, { label, signal, ctx, deadlineAt });
			} catch (err) {
				if (pendingAudit) state.audit?.append(pendingAudit);
				throw err;
			}
		};
		const answerAudit = (presented: { block: true; reason: string } | undefined): Partial<AuditRecord> => ({
			userAnswer: presented === undefined ? "allowed" : "declined",
			answeredAt: new Date().toISOString(),
		});

		// Root session (and pi): unchanged behavior; no signal is passed, so "aborted" cannot occur
		if (!sub) {
			const r = await present();
			const presented = r === "aborted" ? { block: true as const, reason: blockReason("user-declined", "user declined") } : r;
			finalize(answerAudit(presented));
			return presented;
		}

		if (verdict.verdict !== "ask") {
			const r = await present();
			return r === "aborted" ? undefined : r;
		}

		// omp ends this handler after its budget and does not pause it for a dialog on the root UI.
		const budget = await rt.hostHandlerBudget(ctx);
		const hostDeadlineAt = budget === null ? undefined : handlerStart + budget.ms - HOST_RETURN_MARGIN_MS;

		// Subagent ask resolved with no human answer: second model (only an explicit allow permits)
		const finishWithoutHuman = async (resolution: "timeout" | "auto"): Promise<{ block: true; reason: string } | undefined> => {
			// The second model judges the same uncapped action line the first classifier saw;
			// displayAction is cut to 1000 chars for notifications and would hide a payload in the middle.
			const modelAction = redactFn(input) ? PROTECTED_PATH_MARKER : actionCallLine(event.toolName, input).line;
			const res = await resolveAskWithoutHuman(state, env, verdict, modelAction, hostDeadlineAt);
			finalize({ subagent: { ...sub, resolution }, ...(res.fb ? { fallback: res.fb } : {}) });
			const out = (ui ?? ctx.ui).notify.bind(ui ?? ctx.ui);
			if (res.verdict === "allow") {
				if (rt.debug || state.userRules.notifyAllows)
					out(`🛡️ [${label}] allow (second model, no human): ${res.reason}\n  ${displayAction}`, "info");
				return undefined;
			}
			// no path plaintext in notifications (ADR-0002): protected-path asks omit the action line
			out(
				`🛡️ [${label}] Auto Mode blocked (subagent ask, no human): ${res.reason}${verdict.source === "protected-path" ? "" : `\n  ${displayAction}`}`,
				"warning",
			);
			return { block: true, reason: blockReason("subagent-auto", res.reason) };
		};

		if (mode === "normal" && ui !== null) {
			const askTimeoutMs = state.userRules.subagentAskTimeoutMs;
			const window = subagentAskWindow(askTimeoutMs, budget, Date.now() - handlerStart);
			// Fails closed with no second model: what remains of the host budget is too short for a model call.
			const expireOnHostBudget = (): { block: true; reason: string } => {
				finalize({ subagent: { ...sub, resolution: "timeout" } });
				const why = hostBudgetExpiry(askTimeoutMs, budget);
				ui.notify(`🛡️ [${label}] subagent ask expired before omp's handler timeout: ${why}`, "warning");
				return {
					block: true,
					reason: blockReason("subagent-expired", `no human answer before omp's handler budget ran out: ${why} — ${verdict.reason}`),
				};
			};
			if (window.hostLimited && window.ms < MIN_SUBAGENT_DIALOG_MS) return expireOnHostBudget();
			const deadline = AbortSignal.timeout(window.ms);
			const signal = ctx.signal ? AbortSignal.any([deadline, ctx.signal]) : deadline;
			// The race closes the wait even while the ask is still queued behind another dialog.
			const r = await untilAborted(present(signal, Date.now() + window.ms), signal);
			if (r !== "aborted") {
				finalize({ ...answerAudit(r), subagent: { ...sub, resolution: "human" } });
				return r;
			}
			if (ctx.signal?.aborted) {
				finalize({ subagent: { ...sub, resolution: "timeout" } });
				return { block: true, reason: blockReason("subagent-cancelled", "subagent run was cancelled while awaiting approval") };
			}
			if (window.hostLimited) return expireOnHostBudget();
			return finishWithoutHuman("timeout");
		}
		return finishWithoutHuman("auto");
	});
}
