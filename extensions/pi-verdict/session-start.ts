import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { type CoverageToolInfo, sideEffectingToolsWarning, toolCoverageReport } from "./access.ts";
import { agentDirPath, findProjectConfig, userConfigPath } from "./agent-dir.ts";
import { POLICY_DEGRADED } from "./present.ts";
import { publishRootUi, releaseRootUi } from "./root-ui.ts";
import type { GateRuntime } from "./runtime.ts";
import type { RulesLoadReport } from "./state.ts";
import { hostBudgetAdvice, subagentIdentity } from "./subagent.ts";
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
import { refreshStatus } from "./ui/status.ts";

// ============================================================================
// session_start: project trust, the rules load and the session's warnings
// ============================================================================

/** Notifies what a rules load or reload reports: skipped values, a bad toggle shortcut, a degraded policy. */
export function reportLoadWarnings(report: RulesLoadReport, ctx: ExtensionContext): void {
	if (report.skipped.length > 0) {
		ctx.ui.notify(
			`pi-verdict: skipped ${report.skipped.length} invalid config value(s) in config (${userConfigPath()}${report.project?.applied ? ` + ${report.project.path}` : ""}): ${report.skipped.join(", ")}`,
			"warning",
		);
	}
	if (report.shortcutWarning) ctx.ui.notify(`pi-verdict: ${report.shortcutWarning}`, "warning");
	// The degraded state's own warning: a parse failure skips no single value, so the count above would miss it.
	if (report.degraded) ctx.ui.notify(POLICY_DEGRADED.sessionWarning, "warning");
}

/** Reloads the rules after a config edit, honoring this session's trust grant, and redraws the footer. */
export function reloadRules(rt: GateRuntime, ctx: ExtensionContext): void {
	reportLoadWarnings(rt.state.reloadRules(ctx.cwd, rt.sessionTrustedRoot), ctx);
	refreshStatus(rt, ctx);
}

/** The trust prompt for a project config the user has not decided on, or null when there is nothing to ask. Root
 *  sessions with a UI only. Null is returned synchronously, so a session with nothing to ask starts without an await. */
function pendingTrustPrompt(rt: GateRuntime, ctx: ExtensionContext): Promise<void> | null {
	const pp = findProjectConfig(ctx.cwd, agentDirPath());
	if (!pp) return null;
	const root = projectRootOf(pp);
	// "undecided" also covers a trusted root whose override changed since approval, so the user judges the new
	// content (ADR-0006).
	if (projectTrustState(root, pp, readTrustStore()) !== "undecided" || !ctx.hasUI || subagentIdentity(ctx) !== null) return null;
	return askProjectTrust(rt, ctx, pp, root);
}

async function askProjectTrust(rt: GateRuntime, ctx: ExtensionContext, pp: string, root: string): Promise<void> {
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
	// Dismissed, or "not now": nothing is recorded, and the project config stays unapplied this session.
}

/** With debug on, names the active tools the tool-access adapter cannot read, which stay classifier-only. A host
 *  without the tool listing gets no report. */
function reportToolCoverage(rt: GateRuntime, ctx: ExtensionContext): void {
	// Safe: both methods are checked to be functions before the calls.
	const hostTools = rt.pi as { getActiveTools?: () => string[]; getAllTools?: () => CoverageToolInfo[] };
	if (typeof hostTools.getActiveTools !== "function" || typeof hostTools.getAllTools !== "function") return;
	const coverage = toolCoverageReport(hostTools.getAllTools(), new Set(hostTools.getActiveTools()), rt.state.userRules.tools);
	const parts: string[] = [];
	if (coverage.noFields.length > 0)
		parts.push(`no declared path/code/command field, stays classifier-only: ${coverage.noFields.join(", ")}`);
	if (coverage.untyped.length > 0) parts.push(`unrecognized field type: ${coverage.untyped.map((u) => `${u.tool}.${u.field}`).join(", ")}`);
	if (parts.length > 0) ctx.ui.notify(`🛡️ pi-verdict: tool coverage — ${parts.join("; ")}`, "info");
}

/** Warns once per session when omp's handler budget would end a subagent's ask before `subagentAskTimeoutMs`. */
async function warnShortHostBudget(rt: GateRuntime, ctx: ExtensionContext): Promise<void> {
	const { state } = rt;
	// Only a root session with a UI shows subagent asks.
	if (subagentIdentity(ctx) !== null || !ctx.hasUI || state.userRules.subagentGate !== "normal" || state.hostBudgetWarned) return;
	const advice = hostBudgetAdvice(state.userRules.subagentAskTimeoutMs, await rt.hostHandlerBudget(ctx));
	if (advice) {
		state.hostBudgetWarned = true;
		ctx.ui.notify(`🛡️ pi-verdict: subagent asks will expire early: ${advice}`, "warning");
	}
}

/** Starts a session: settles project trust, publishes a root session's UI for subagent asks, reloads the rules, and
 *  shows the session's warnings. Every step before the host-budget check runs synchronously unless the trust prompt
 *  is shown. */
export async function startSession(rt: GateRuntime, ctx: ExtensionContext): Promise<void> {
	rt.sessionTrustedRoot = null;
	const prompt = pendingTrustPrompt(rt, ctx);
	if (prompt) await prompt;
	if (subagentIdentity(ctx) === null) rt.publishedRootUi = publishRootUi(ctx.hasUI ? ctx.ui : null);
	const { state } = rt;
	const report = state.reset(ctx.cwd, rt.sessionTrustedRoot);
	state.audit?.prune(); // #54: keeps the most recent session files only
	reportLoadWarnings(report, ctx);
	if (report.project?.applied) ctx.ui.notify(`pi-verdict: project overrides applied from ${report.project.path}`, "info");
	if (report.project && !report.project.trusted)
		ctx.ui.notify(
			`pi-verdict: project config ${report.project.path} ignored — project not trusted (decisions: ${trustStorePath()})`,
			"info",
		);
	// The user chose to exempt a side-effecting tool; the gate says so rather than stay silent about it.
	const sideEffectWarning = sideEffectingToolsWarning(state.userRules.tools);
	if (sideEffectWarning) ctx.ui.notify(sideEffectWarning, "warning");
	if (rt.debug) reportToolCoverage(rt, ctx);
	refreshStatus(rt, ctx);
	// Last, so every step above stays synchronous.
	await warnShortHostBudget(rt, ctx);
}

/** Ends a session: clears the root UI when this session published it. */
export function endSession(rt: GateRuntime): void {
	releaseRootUi(rt.publishedRootUi);
	rt.publishedRootUi = null;
}
