import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { parseJevReason } from "../jev-adapter.ts";
import type { AllowVerdict, AskVerdict, DenyVerdict, Verdict, VerdictSource } from "./adjudicate.ts";
import { declineDetail, type ExplainGateResult, explainGate } from "./explain.ts";
import { resolveExplainGate } from "./model-roles.ts";
import { anyRedactor, PROTECTED_PATH_MARKER, type RedactorFn } from "./redaction.ts";
import { completionFor, type GateRuntime } from "./runtime.ts";
import type { SessionState } from "./state.ts";
import type { UiContext } from "./subagent.ts";
import { approveCodeMarkdown, confirmAsk, displaySafe } from "./ui/dialog.ts";

// ============================================================================
// Presentation: a verdict as block reasons, notifications and dialogs
// ============================================================================

/** What the handler returns to the host to stop a tool call; the agent reads `reason` as the tool's error. */
export type GateBlock = { readonly block: true; readonly reason: string };

/** The tag of every block reason: a deny's verdict source, or the step that blocked an ask. */
export type BlockTag = VerdictSource | "user-declined" | "subagent-auto" | "subagent-expired" | "subagent-cancelled";

/** The degraded-policy wording of each surface that names the state (ADR-0010). The footer badge and the withheld
 *  allow's reason prefix keep their short forms in `ui/footer.ts` and `adjudicate.ts`. */
export const POLICY_DEGRADED = {
	blockNote: "[policy degraded: the user's own rules failed to load, so model-originated allows are withheld — ADR-0010]",
	denyNotice: "Auto Mode blocked (policy degraded, allow withheld)",
	status: "policy degraded: model-originated allows withheld (ADR-0010)",
	sessionWarning:
		"pi-verdict: policy degraded — your own rules could not be fully loaded, so model-originated allows are withheld (each becomes a confirm) until the config is fixed (ADR-0010)",
} as const;

/** The ask dialog's reason-line label by verdict source; the protected-path dialog has its own wording. */
const ASK_SOURCE_LABEL: Record<VerdictSource, string> = {
	rule: "Rule",
	"protected-path": "Protected path",
	classifier: "Classifier opinion",
	"fail-closed": "Fail-closed",
	"degraded-policy": "Policy degraded",
};

/** The agent-facing block reason (#53). It must stand alone: structured error signaling does not reach every
 *  provider, and a bare rule or classifier reason can be empty or too terse to read as a block. While the policy is
 *  degraded, every block names that state (ADR-0010). */
export function blockReason(state: SessionState, tag: BlockTag, detail: string): string {
	const stated = state.policyDegraded ? `${detail} ${POLICY_DEGRADED.blockNote}` : detail;
	const clean = stated.trim().replace(/\.+$/, "");
	return `[auto-mode ${tag} block] BLOCKED — this action did NOT run. Reason: ${clean || "(no further reason given)"}. Report the block to the user; never claim it succeeded or completed.`;
}

/** One tool call as the presentation sees it. */
export interface PresentedCall {
	readonly toolName: string;
	readonly input: Record<string, unknown>;
	/** The call as a transcript line, shown in dialogs and block reasons. */
	readonly action: string;
	/** `action`, or the protected-path marker when the call names a protected path: the only form a notification
	 *  carries (ADR-0002). */
	readonly displayAction: string;
	/** The session redactor as of the end of adjudication, widened by the one adjudication used. */
	readonly redact: RedactorFn;
	readonly ctx: ExtensionContext;
	/** The UI the call's notifications and dialogs go to: its own, or the root session's for a subagent. */
	readonly ui: UiContext;
	/** The subagent label that prefixes notifications and dialog titles; null for a root session. */
	readonly label: string | null;
}

/** How long an ask may wait for the human; absent for a root session, which waits as long as the user does. */
export interface AskWait {
	readonly signal: AbortSignal;
	readonly deadlineAt: number;
}

/** Adds the subagent label to a `🛡️` notification or dialog title. */
function titled(pc: PresentedCall, text: string): string {
	return pc.label ? text.replace(/^🛡️ /u, `🛡️ [${pc.label}] `) : text;
}

function note(pc: PresentedCall, msg: string, level: "info" | "warning" | "error"): void {
	pc.ui.notify(titled(pc, msg), level);
}

/** Turns a verdict into what the user and the agent see: the single presentation point. Returns the block for the
 *  host, undefined to run the tool, or "aborted" when `wait` ended an ask before the human answered. */
export async function presentVerdict(
	rt: GateRuntime,
	v: Verdict,
	pc: PresentedCall,
	wait?: AskWait,
): Promise<GateBlock | undefined | "aborted"> {
	switch (v.verdict) {
		case "allow":
			presentAllow(rt, v, pc);
			return undefined;
		case "deny":
			return presentDeny(rt.state, v, pc);
		case "ask":
			return presentAsk(rt, v, pc, wait);
		default: {
			// A fixed message: the verdict may carry a protected path in `detail` (ADR-0002).
			const _unhandled: never = v;
			throw new Error("unhandled verdict");
		}
	}
}

/** Notifies an allow: a classifier allow with `notifyAllows` or debug, a mechanical one only with debug (#60). */
function presentAllow(rt: GateRuntime, v: AllowVerdict, pc: PresentedCall): void {
	if (rt.debug) {
		if (v.source === "rule") note(pc, `🛡️ allow (rule): ${pc.displayAction}`, "info");
		else note(pc, `🛡️ allow (classifier): ${v.reason}\n  ${pc.displayAction}`, "info");
	} else if (rt.state.userRules.notifyAllows && v.source === "classifier") {
		note(pc, `🛡️ allow (classifier): ${v.reason}\n  ${pc.displayAction}`, "info");
	}
}

/** Notifies a deny and returns its block, tagged by the verdict's source. */
function presentDeny(state: SessionState, v: DenyVerdict, pc: PresentedCall): GateBlock {
	// A headless ask reaches the agent as a block; saying so tells it a human could have allowed the call.
	const headlessAsk = (): string => (v.degraded ? `ask degraded to block in non-interactive mode: ${v.reason}` : v.reason);
	switch (v.source) {
		case "degraded-policy":
			note(pc, `🛡️ ${POLICY_DEGRADED.denyNotice}: ${v.reason}\n  ${pc.displayAction}`, "warning");
			return { block: true, reason: blockReason(state, v.source, v.reason) };
		case "protected-path":
			// No action line: notifications carry no protected-path plaintext (ADR-0002).
			note(pc, `🛡️ Auto Mode blocked (non-interactive, protected-path ask→deny): ${v.reason}`, "warning");
			return { block: true, reason: blockReason(state, v.source, `ask degraded to block in non-interactive mode: ${v.reason}`) };
		case "fail-closed":
			note(pc, `🛡️ Auto Mode blocked: ${v.reason}\n  ${pc.displayAction}`, "warning");
			return { block: true, reason: blockReason(state, v.source, v.reason) };
		case "rule":
		case "classifier":
			note(pc, `🛡️ Auto Mode blocked: ${v.reason}\n  ${pc.displayAction}`, "warning");
			return { block: true, reason: blockReason(state, v.source, headlessAsk()) };
		default: {
			const unhandled: never = v.source;
			throw new Error(`unhandled verdict source: ${unhandled}`);
		}
	}
}

/** Puts an ask to the human; interactive only, since the pipeline turns a headless ask into a deny. */
async function presentAsk(rt: GateRuntime, v: AskVerdict, pc: PresentedCall, wait?: AskWait): Promise<GateBlock | undefined | "aborted"> {
	const timing = { signal: wait?.signal, deadlineAt: wait?.deadlineAt };
	if (v.source === "protected-path") {
		// No EXPLAIN-GATE: the protected path must not reach a model provider (ADR-0002).
		const detail = v.detail ?? "(see pi-verdict.json)";
		const d = await confirmAsk(
			pc.ui,
			{
				title: titled(pc, "🛡️ Auto Mode: protected path"),
				toolName: pc.toolName,
				input: pc.input,
				action: pc.action,
				reasonLine: v.reason,
				detail,
				question: "Allow this access?",
				jev: null,
				minConfidence: null,
				fallbackMessage: `${pc.action}\n\n${v.reason}\n\nProtected path: ${detail}\n\nAllow this access?`,
			},
			timing,
		);
		if (d === "aborted") return "aborted";
		if (d.allow) {
			// No action line, as in every notification about a protected path (ADR-0002).
			if (rt.debug) note(pc, "🛡️ allow (protected-path confirm)", "info");
			return undefined;
		}
		return { block: true, reason: blockReason(rt.state, "user-declined", declineDetail("user declined protected-path access", d.reason)) };
	}
	const label = ASK_SOURCE_LABEL[v.source];
	const d = await confirmAsk(
		pc.ui,
		{
			title: titled(pc, "🛡️ Auto Mode confirmation"),
			toolName: pc.toolName,
			input: pc.input,
			action: pc.action,
			reasonLine: `${label}: ${v.reason}`,
			question: "Allow execution?",
			jev: v.source === "classifier" ? parseJevReason(v.reason) : null,
			minConfidence: rt.state.userRules.classifierMinConfidence,
			fallbackMessage: `${pc.action}\n\n${label}: ${v.reason}\n\nAllow execution?`,
		},
		{ ...timing, explain: (question) => explainAsk(rt, pc, `${label}: `, v.reason, question) },
	);
	if (d === "aborted") return "aborted";
	return d.allow ? undefined : { block: true, reason: blockReason(rt.state, "user-declined", declineDetail("user declined", d.reason)) };
}

/** The dialog's "Explain…" handler: one EXPLAIN-GATE call about the held action. A call that names a protected path
 *  reaches the model only as the marker, its reason too, since a floor reason names the path it matched (ADR-0002). */
async function explainAsk(
	rt: GateRuntime,
	pc: PresentedCall,
	reasonPrefix: string,
	reason: string,
	question: string | null,
): Promise<ExplainGateResult> {
	const role = resolveExplainGate(pc.ctx, rt.state);
	if (!role) return { ok: false, error: "no model available" };
	// Widened when the user asks, so a `denyPaths` entry added since the call arrived is redacted too (ADR-0002).
	const redact = anyRedactor(pc.redact, rt.state.redactor(pc.ctx.cwd));
	const hidden = redact(pc.input);
	const shown = (text: string): string => (hidden ? PROTECTED_PATH_MARKER : text);
	return explainGate({
		host: pc.ctx.sessionManager,
		signal: pc.ctx.signal,
		complete: completionFor(rt, pc.ctx),
		model: role.model,
		thinking: role.thinking,
		actionLine: shown(pc.action),
		actionDetail: hidden
			? PROTECTED_PATH_MARKER
			: (approveCodeMarkdown(pc.toolName, pc.input, () => undefined)?.markdown ?? displaySafe(pc.action)),
		reasonLine: `${reasonPrefix}${shown(reason)}`,
		defaultPrompt: rt.state.userRules.explainGatePrompt,
		question,
		// The EXPLAIN-GATE transcript is a model payload like the classifier's, so it takes the same redactor.
		redact,
	});
}
