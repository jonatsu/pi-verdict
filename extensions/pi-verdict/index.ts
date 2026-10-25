/**
 * pi-verdict, a permission gate for pi and omp: a deterministic rule layer adjudicates every tool call to allow, ask
 * or deny, and a model classifier judges the calls the rules cannot decide (docs/architecture.md). This module is the
 * entry the host loads. It registers the flags and wires each hook to the module that owns it; its re-exports are the
 * names the probe and the tests reach through the entry.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { registerMasterSwitch } from "./master-switch.ts";
import { type AutoModeDeps, createRuntime } from "./runtime.ts";
import { endSession, startSession } from "./session-start.ts";
import { handleToolCall } from "./tool-call.ts";
import { registerConfigEditor } from "./ui/config-editor.ts";
import { refreshStatus } from "./ui/status.ts";

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
// Extension entry
// ============================================================================

/** Installs the gate on one session's host API. The master switch starts on unless `--no-auto-mode` is given. */
export default function autoMode(pi: ExtensionAPI, deps: AutoModeDeps = {}): void {
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
	pi.on("session_start", (_event, ctx) => startSession(rt, ctx));
	pi.on("session_shutdown", () => endSession(rt));
	pi.on("model_select", (_e, ctx) => refreshStatus(rt, ctx));
	registerMasterSwitch(rt);
	registerConfigEditor(rt);

	pi.on("tool_call", (event, ctx) => handleToolCall(rt, event, ctx));
}
