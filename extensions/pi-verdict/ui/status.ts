import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { classifierSpec, findAuthedModel, parseModelSpec } from "../model-roles.ts";
import type { GateRuntime } from "../runtime.ts";
import { type FooterInfo, renderFooter } from "./footer.ts";

// ============================================================================
// The footer status line, drawn from the gate's runtime
// ============================================================================

/** The classifier and fallback models as the footer shows them: the same precedence as the model roles, but with no
 *  warning and no model call. */
function footerInfo(rt: GateRuntime, ctx: ExtensionContext): FooterInfo {
	const rules = rt.state.userRules;
	const raw = classifierSpec(rt.pi, rules);
	const session = ctx.model ?? null;
	let classifier: FooterInfo["classifier"];
	if (raw) {
		const { specPart, level } = parseModelSpec(raw);
		const thinking = level ?? "off";
		const model = findAuthedModel(ctx, specPart);
		if (model) classifier = { id: model.id, thinking, state: "configured" };
		else if (session) classifier = { id: session.id, thinking, state: "unavailable" };
		else classifier = { id: null, thinking: "off", state: "none" };
	} else {
		classifier = session ? { id: session.id, thinking: "off", state: "inherited" } : { id: null, thinking: "off", state: "none" };
	}
	let fallback: FooterInfo["fallback"] = null;
	if (rules.classifierFallbackModel) {
		const { specPart } = parseModelSpec(rules.classifierFallbackModel);
		fallback = { id: findAuthedModel(ctx, specPart)?.id ?? null, mode: rules.classifierFallbackMode };
	}
	return {
		enabled: rt.enabled,
		classifier,
		fallback,
		counts: rt.state.verdictCounts,
		floorOff: !rules.builtinDenyFloor,
		minConfidence: rules.classifierMinConfidence,
		autoDenyOff: !rules.autoDeny,
		subagentGate: rules.subagentGate,
		policyDegraded: rt.state.policyDegraded,
	};
}

/** Redraws the footer status in the configured style, or clears it when the style is `off`. */
export function refreshStatus(rt: GateRuntime, ctx: ExtensionContext): void {
	const style = rt.state.userRules.footer;
	if (style === "off") {
		ctx.ui.setStatus("auto-mode", undefined);
		return;
	}
	ctx.ui.setStatus("auto-mode", renderFooter(footerInfo(rt, ctx), ctx.ui.theme, style));
}
