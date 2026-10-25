import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { type CompatLoader, completionForHost } from "./completion.ts";
import { hostKindOf } from "./floor.ts";
import { classifierSpec, findAuthedModel, parseModelSpec } from "./model-roles.ts";
import { SessionState } from "./state.ts";
import { type HostBudget, readHostHandlerBudget, type UiContext } from "./subagent.ts";
import { type FooterInfo, renderFooter } from "./ui/footer.ts";

// ============================================================================
// The gate's runtime: what every hook of one extension instance shares
// ============================================================================

/** Optional dependency injection for tests (#35): fake the compat fallback loader and the host's
 *  per-handler budget (null = a host without one). */
export interface AutoModeDeps {
	compatLoader?: CompatLoader;
	hostHandlerBudget?: (ctx: ExtensionContext) => Promise<HostBudget | null>;
}

/** What the hooks of one extension instance share. The host builds one instance per session it loads the
 *  extension into, so a subagent session gets its own runtime and state. */
export interface GateRuntime {
	readonly pi: ExtensionAPI;
	readonly state: SessionState;
	/** Notify every verdict, allows included: the `auto-mode-debug` flag or `PI_AUTO_MODE_DEBUG=1`. */
	readonly debug: boolean;
	readonly hostKind: ReturnType<typeof hostKindOf>;
	readonly compatLoader: CompatLoader | undefined;
	readonly hostHandlerBudget: (ctx: ExtensionContext) => Promise<HostBudget | null>;
	/** The master switch; off lets every tool call run ungated. */
	enabled: boolean;
	/** A project root the user trusted for this session only at session start; a rules reload must honor it. */
	sessionTrustedRoot: string | null;
	/** The UI this instance published as the root session's, so shutdown clears only its own. */
	publishedRootUi: UiContext | null;
}

export function createRuntime(pi: ExtensionAPI, deps: AutoModeDeps): GateRuntime {
	return {
		pi,
		state: new SessionState(),
		debug: pi.getFlag("auto-mode-debug") === true || process.env.PI_AUTO_MODE_DEBUG === "1",
		hostKind: hostKindOf(pi),
		compatLoader: deps.compatLoader,
		hostHandlerBudget: deps.hostHandlerBudget ?? ((ctx: ExtensionContext) => readHostHandlerBudget(pi, ctx.cwd)),
		enabled: pi.getFlag("auto-mode") !== false,
		sessionTrustedRoot: null,
		publishedRootUi: null,
	};
}

/** The host's completion function for this context's model registry. */
export function completionFor(rt: GateRuntime, ctx: ExtensionContext): ReturnType<typeof completionForHost> {
	return completionForHost(ctx.modelRegistry, rt.compatLoader);
}

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
