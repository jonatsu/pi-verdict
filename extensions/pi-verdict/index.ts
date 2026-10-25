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
import { actionCallLine, toolCallLine } from "./action-line.ts";
import { type AdjudicateEnv, adjudicate, redactedOr, resolveAskWithoutHuman, sessionRedactor, type Verdict } from "./adjudicate.ts";
import type { AuditRecord } from "./audit.ts";
import { completionForHost } from "./completion.ts";
import type { UserRules } from "./config.ts";
import { resolveClassifier, resolveFallbackClassifier } from "./model-roles.ts";
import { blockReason, POLICY_DEGRADED, type PresentedCall, presentVerdict } from "./present.ts";
import { currentRootUi } from "./root-ui.ts";
import { type AutoModeDeps, createRuntime, refreshStatus as refreshRuntimeStatus } from "./runtime.ts";
import { endSession, reloadRules, startSession } from "./session-start.ts";
import type { FallbackStats } from "./state.ts";
import {
	HOST_RETURN_MARGIN_MS,
	hostBudgetExpiry,
	MIN_SUBAGENT_DIALOG_MS,
	STATUS_WIDGET_KEY,
	subagentAskWindow,
	subagentIdentity,
	subagentLabel,
	type UiContext,
	untilAborted,
} from "./subagent.ts";
import { runConfigEditor } from "./ui/config-editor.ts";

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

// ============================================================================
// Extension body
// ============================================================================

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

	/** Set the master toggle (shared, #15): /automode command and toggle shortcut use the same entry point, with no extra rules from the interaction surface. */
	function setMasterSwitch(next: boolean, ctx: ExtensionContext) {
		rt.enabled = next;
		refreshStatus(ctx);
	}

	pi.on("session_start", (_event, ctx) => startSession(rt, ctx));
	pi.on("session_shutdown", () => endSession(rt));
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
	const policyHint = () => (state.policyDegraded ? `\n${POLICY_DEGRADED.status}` : "");

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
				reloadRules: (c) => reloadRules(rt, c),
			}),
	});

	pi.on("tool_call", async (event, ctx) => {
		if (!rt.enabled) return undefined;
		const handlerStart = Date.now();

		const sub = subagentIdentity(ctx);
		const mode = state.userRules.subagentGate;
		if (sub && mode === "off") return undefined;
		const label = sub ? subagentLabel(sub) : null;
		// A subagent with its own UI (not produced by omp today) uses it; otherwise the root UI, else none
		const ui: UiContext | null = !sub || ctx.hasUI ? ctx.ui : currentRootUi();

		const input = event.input as Record<string, unknown>;
		const call = { toolName: event.toolName, input };
		const action = toolCallLine(event.toolName, input);
		const redactFn = sessionRedactor(state, ctx.cwd);
		const displayAction = redactedOr(redactFn, input, action);
		const pc: PresentedCall = { ...call, action, displayAction, redact: redactFn, ctx, ui: ui ?? ctx.ui, label };

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
				return await presentVerdict(rt, verdict, pc, signal && deadlineAt !== undefined ? { signal, deadlineAt } : undefined);
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
			const presented = r === "aborted" ? { block: true as const, reason: blockReason(state, "user-declined", "user declined") } : r;
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
			const modelAction = redactedOr(redactFn, input, actionCallLine(event.toolName, input).line);
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
			return { block: true, reason: blockReason(state, "subagent-auto", res.reason) };
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
					reason: blockReason(state, "subagent-expired", `no human answer before omp's handler budget ran out: ${why} — ${verdict.reason}`),
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
				return { block: true, reason: blockReason(state, "subagent-cancelled", "subagent run was cancelled while awaiting approval") };
			}
			if (window.hostLimited) return expireOnHostBudget();
			return finishWithoutHuman("timeout");
		}
		return finishWithoutHuman("auto");
	});
}
