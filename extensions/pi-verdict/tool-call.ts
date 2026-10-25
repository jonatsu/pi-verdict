import type { ExtensionContext, ToolCallEvent } from "@earendil-works/pi-coding-agent";
import { resolveCommandCwd } from "./access.ts";
import { actionCallLine, toolCallLine } from "./action-line.ts";
import { type AdjudicateEnv, type AskVerdict, adjudicate, resolveAskWithoutHuman, type Verdict } from "./adjudicate.ts";
import type { AuditRecord } from "./audit.ts";
import type { UserRules } from "./config.ts";
import { resolveClassifier, resolveFallbackClassifier } from "./model-roles.ts";
import { type AskWait, blockReason, type GateBlock, type PresentedCall, presentVerdict } from "./present.ts";
import { anyRedactor, type RedactorFn, redactedOr } from "./redaction.ts";
import { currentRootUi } from "./root-ui.ts";
import { completionFor, type GateRuntime } from "./runtime.ts";
import type { SessionState } from "./state.ts";
import {
	HOST_RETURN_MARGIN_MS,
	type HostBudget,
	hostBudgetExpiry,
	MIN_SUBAGENT_DIALOG_MS,
	STATUS_WIDGET_KEY,
	subagentAskWindow,
	subagentIdentity,
	subagentLabel,
	type UiContext,
	untilAborted,
} from "./subagent.ts";
import { refreshStatus } from "./ui/status.ts";

// ============================================================================
// The tool_call handler: the gate's security boundary
// ============================================================================

type PhaseHook = NonNullable<AdjudicateEnv["onPhase"]>;
type Subagent = { readonly id: string; readonly name: string };

/** The host capabilities one adjudication uses. */
function buildEnv(rt: GateRuntime, ctx: ExtensionContext, isSubagent: boolean, redact: RedactorFn): AdjudicateEnv {
	return {
		cwd: ctx.cwd,
		redact,
		// A subagent's asks go to the root UI or the second model, so the pipeline never degrades them to a deny.
		hasUI: isSubagent ? true : !!ctx.hasUI,
		getModel: () => resolveClassifier(ctx, rt.pi, rt.state),
		complete: completionFor(rt, ctx),
		host: ctx.sessionManager,
		hostKind: rt.hostKind,
		signal: ctx.signal,
		getFallbackModel: () => resolveFallbackClassifier(ctx, rt.state),
	};
}

/** Runs `work` with a live status row above the editor while a model call runs; a root session with a UI only. The
 *  row names the phase, the tool and the model id, never command or path text (ADR-0002). */
async function withStatusWidget<T>(
	ctx: ExtensionContext,
	isRoot: boolean,
	toolName: string,
	work: (onPhase?: PhaseHook) => Promise<T>,
): Promise<T> {
	const statusUi = isRoot && ctx.hasUI && typeof ctx.ui.setWidget === "function" ? ctx.ui : null;
	if (!statusUi) return work();
	let shown = false;
	const onPhase: PhaseHook = (phase, modelId) => {
		shown = true;
		statusUi.setWidget(STATUS_WIDGET_KEY, [
			statusUi.theme.fg(
				"warning",
				phase === "classifier"
					? `🛡️ verdict: classifying ${toolName} via ${modelId}…`
					: `🛡️ verdict: fallback classifier ${modelId} on ${toolName}…`,
			),
		]);
	};
	try {
		return await work(onPhase);
	} finally {
		if (shown) statusUi.setWidget(STATUS_WIDGET_KEY, undefined);
	}
}

/** An ask's audit record, appended exactly once (#62): with the user's answer or the subagent resolution, or bare when
 *  the presentation throws. The pipeline already recorded every other verdict. */
class AskAudit {
	private pending: Readonly<AuditRecord> | undefined;
	private readonly state: SessionState;
	private readonly warn: (msg: string) => void;

	constructor(state: SessionState, verdict: Verdict, warn: (msg: string) => void) {
		this.state = state;
		this.warn = warn;
		this.pending = verdict.verdict === "ask" ? verdict.pendingAudit : undefined;
	}

	finalize(extra: Partial<AuditRecord>): void {
		if (!this.pending) return;
		const record: AuditRecord = { ...this.pending, ...extra };
		this.pending = undefined;
		this.state.audit?.append(record);
		const lateWarning = this.state.audit?.drainWarning();
		if (lateWarning) this.warn(`pi-verdict: ${lateWarning}`);
	}

	/** Appends the record without an answer; the presentation threw, and the error goes on to the host. */
	appendUnanswered(): void {
		if (this.pending) this.state.audit?.append(this.pending);
	}
}

const answered = (presented: GateBlock | undefined): Partial<AuditRecord> => ({
	userAnswer: presented === undefined ? "allowed" : "declined",
	answeredAt: new Date().toISOString(),
});

async function presentAudited(
	rt: GateRuntime,
	verdict: Verdict,
	pc: PresentedCall,
	audit: AskAudit,
	wait?: AskWait,
): Promise<GateBlock | undefined | "aborted"> {
	try {
		return await presentVerdict(rt, verdict, pc, wait);
	} catch (err) {
		audit.appendUnanswered();
		throw err;
	}
}

/** Presents a verdict with no deadline. Nothing aborts that dialog, but an "aborted" all the same counts as a decline,
 *  so it fails closed. */
async function presentNow(rt: GateRuntime, verdict: Verdict, pc: PresentedCall, audit: AskAudit): Promise<GateBlock | undefined> {
	const r = await presentAudited(rt, verdict, pc, audit);
	return r === "aborted" ? { block: true, reason: blockReason(rt.state, "user-declined", "user declined") } : r;
}

/** The gate: adjudicates one tool call and presents the verdict. Returns the block for the host, or undefined to run
 *  the tool. */
export async function handleToolCall(rt: GateRuntime, event: ToolCallEvent, ctx: ExtensionContext): Promise<GateBlock | undefined> {
	if (!rt.enabled) return undefined;
	const handlerStart = Date.now();
	const sub = subagentIdentity(ctx);
	const mode = rt.state.userRules.subagentGate;
	if (sub && mode === "off") return undefined;
	// A subagent with its own UI (omp gives it none today) uses it; otherwise the root UI, else none.
	const ui = !sub || ctx.hasUI ? ctx.ui : currentRootUi();
	// Safe: the host passes a tool's arguments as a plain object, and every layer narrows each field it reads.
	const input = event.input as Record<string, unknown>;
	const adjudicationRedact = rt.state.redactor(ctx.cwd);
	const env = buildEnv(rt, ctx, sub !== null, adjudicationRedact);
	const verdict = await withStatusWidget(ctx, sub === null, event.toolName, (onPhase) =>
		adjudicate(rt.state, { toolName: event.toolName, input }, onPhase ? { ...env, onPhase } : env),
	);
	// Rebuilt after adjudication, so a `denyPaths` entry a `/verdict` edit added while the call was in flight is
	// redacted too; it keeps the earlier redactor's matches, so it fails toward the marker (ADR-0002).
	const redact = anyRedactor(adjudicationRedact, rt.state.redactor(ctx.cwd));
	const { displayedCwd } = resolveCommandCwd(event.toolName, input, ctx.cwd, rt.hostKind);
	const action = toolCallLine(event.toolName, input, displayedCwd);
	const pc: PresentedCall = {
		toolName: event.toolName,
		input,
		action,
		displayedCwd,
		displayAction: redactedOr(redact, input, action),
		redact,
		ctx,
		ui: ui ?? ctx.ui,
		label: sub ? subagentLabel(sub) : null,
	};
	if (!sub) {
		rt.state.countVerdict(verdict.verdict);
		refreshStatus(rt, ctx);
	}
	const warn = (msg: string): void => pc.ui.notify(pc.label && !msg.startsWith("🛡️") ? `[${pc.label}] ${msg}` : msg, "warning");
	const auditWarning = rt.state.audit?.drainWarning(); // #54: a failed audit write warns once and never alters the verdict
	if (auditWarning) warn(`pi-verdict: ${auditWarning}`);
	const audit = new AskAudit(rt.state, verdict, warn);
	if (!sub) return handleRootCall(rt, verdict, pc, audit);
	if (verdict.verdict !== "ask") return presentNow(rt, verdict, pc, audit);
	// The second model's payload takes the presentation redactor too, the wider of the two.
	return handleSubagentAsk(rt, verdict, pc, audit, { sub, mode, ui, ctx, env: { ...env, redact }, handlerStart });
}

/** A root session's call: the user answers on the session's own UI, with no deadline. */
async function handleRootCall(rt: GateRuntime, verdict: Verdict, pc: PresentedCall, audit: AskAudit): Promise<GateBlock | undefined> {
	const presented = await presentNow(rt, verdict, pc, audit);
	audit.finalize(answered(presented));
	return presented;
}

/** A subagent's ask and the host limits it runs under. */
interface SubagentAsk {
	readonly sub: Subagent;
	readonly mode: UserRules["subagentGate"];
	/** The UI a dialog may use: the subagent's own when it has one, else the root session's; null when neither exists. */
	readonly ui: UiContext | null;
	readonly ctx: ExtensionContext;
	readonly env: AdjudicateEnv;
	readonly handlerStart: number;
	/** omp's per-handler budget; null on a host without one. */
	readonly budget: HostBudget | null;
	/** When the second model must have answered for the handler to return inside the budget. */
	readonly hostDeadlineAt: number | undefined;
}

/** A subagent's ask, with omp's handler budget in view: omp ends this handler after its budget and does not pause it
 *  for a dialog on the root UI. */
async function handleSubagentAsk(
	rt: GateRuntime,
	verdict: AskVerdict,
	pc: PresentedCall,
	audit: AskAudit,
	call: Omit<SubagentAsk, "budget" | "hostDeadlineAt">,
): Promise<GateBlock | undefined> {
	const budget = await rt.hostHandlerBudget(call.ctx);
	const hostDeadlineAt = budget === null ? undefined : call.handlerStart + budget.ms - HOST_RETURN_MARGIN_MS;
	const ask: SubagentAsk = { ...call, budget, hostDeadlineAt };
	if (ask.mode === "normal" && ask.ui !== null) return askOnRootUi(rt, verdict, pc, audit, ask);
	return finishWithoutHuman(rt, verdict, pc, audit, ask, "auto");
}

/** Shows a subagent's ask on the root UI within its ask window, then resolves an unanswered ask without a human. */
async function askOnRootUi(
	rt: GateRuntime,
	verdict: AskVerdict,
	pc: PresentedCall,
	audit: AskAudit,
	ask: SubagentAsk,
): Promise<GateBlock | undefined> {
	const askTimeoutMs = rt.state.userRules.subagentAskTimeoutMs;
	const window = subagentAskWindow(askTimeoutMs, ask.budget, Date.now() - ask.handlerStart);
	// Fails closed with no second model: what remains of the host budget is too short for a model call.
	const expireOnHostBudget = (): GateBlock => {
		audit.finalize({ subagent: { ...ask.sub, resolution: "timeout" } });
		const why = hostBudgetExpiry(askTimeoutMs, ask.budget);
		pc.ui.notify(`🛡️ [${pc.label}] subagent ask expired before omp's handler timeout: ${why}`, "warning");
		return {
			block: true,
			reason: blockReason(rt.state, "subagent-expired", `no human answer before omp's handler budget ran out: ${why} — ${verdict.reason}`),
		};
	};
	if (window.hostLimited && window.ms < MIN_SUBAGENT_DIALOG_MS) return expireOnHostBudget();
	const deadline = AbortSignal.timeout(window.ms);
	const signal = ask.ctx.signal ? AbortSignal.any([deadline, ask.ctx.signal]) : deadline;
	// The race closes the wait even while the ask is still queued behind another dialog.
	const r = await untilAborted(presentAudited(rt, verdict, pc, audit, { signal, deadlineAt: Date.now() + window.ms }), signal);
	if (r !== "aborted") {
		audit.finalize({ ...answered(r), subagent: { ...ask.sub, resolution: "human" } });
		return r;
	}
	if (ask.ctx.signal?.aborted) {
		audit.finalize({ subagent: { ...ask.sub, resolution: "timeout" } });
		return { block: true, reason: blockReason(rt.state, "subagent-cancelled", "subagent run was cancelled while awaiting approval") };
	}
	if (window.hostLimited) return expireOnHostBudget();
	return finishWithoutHuman(rt, verdict, pc, audit, ask, "timeout");
}

/** Resolves a subagent's ask with no human answer: only the second model's explicit allow runs the call. */
async function finishWithoutHuman(
	rt: GateRuntime,
	verdict: AskVerdict,
	pc: PresentedCall,
	audit: AskAudit,
	ask: SubagentAsk,
	resolution: "timeout" | "auto",
): Promise<GateBlock | undefined> {
	// The second model judges the same uncapped action line the first classifier saw; `displayAction` is capped for
	// notifications and could hide a payload in the middle.
	const modelAction = redactedOr(pc.redact, pc.input, actionCallLine(pc.toolName, pc.input, pc.displayedCwd).line);
	const res = await resolveAskWithoutHuman(rt.state, ask.env, verdict, modelAction, ask.hostDeadlineAt);
	audit.finalize({ subagent: { ...ask.sub, resolution }, ...(res.fb ? { fallback: res.fb } : {}) });
	if (res.verdict === "allow") {
		if (rt.debug || rt.state.userRules.notifyAllows)
			pc.ui.notify(`🛡️ [${pc.label}] allow (second model, no human): ${res.reason}\n  ${pc.displayAction}`, "info");
		return undefined;
	}
	// No action line for a protected-path ask: notifications carry no protected-path plaintext (ADR-0002).
	pc.ui.notify(
		`🛡️ [${pc.label}] Auto Mode blocked (subagent ask, no human): ${res.reason}${verdict.source === "protected-path" ? "" : `\n  ${pc.displayAction}`}`,
		"warning",
	);
	return { block: true, reason: blockReason(rt.state, "subagent-auto", res.reason) };
}
