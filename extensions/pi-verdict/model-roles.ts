import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { UserRules } from "./config.ts";
import { EXPLAIN_GATE_ROLE } from "./explain.ts";
import type { ModelChoice, ThinkingLevel } from "./model-call.ts";
import type { SessionState } from "./state.ts";

// ============================================================================
// Model roles: which model the classifier, the fallback and EXPLAIN-GATE use
// ============================================================================

/** pi's thinking levels, the suffix of a `provider/id:thinking` spec (pi's `--model` syntax). */
export const THINKING_LEVELS = ["off", "minimal", "low", "medium", "high", "xhigh", "max"] as const satisfies readonly ThinkingLevel[];

export function isThinkingLevel(s: string): s is ThinkingLevel {
	return (THINKING_LEVELS as readonly string[]).includes(s);
}

/** Splits `provider/id:thinking` into the registry spec and its thinking level. An unknown suffix stays part of the
 *  spec, and `warn` reports it. */
export function parseModelSpec(raw: string, warn: (msg: string) => void = () => {}): { specPart: string; level: ThinkingLevel | null } {
	const slash = raw.lastIndexOf("/");
	const colon = raw.lastIndexOf(":");
	if (colon <= slash + 1) return { specPart: raw, level: null };
	const suffix = raw.slice(colon + 1);
	if (isThinkingLevel(suffix)) return { specPart: raw.slice(0, colon), level: suffix };
	warn(`pi-verdict: invalid thinking-level suffix "${suffix}" (valid: ${THINKING_LEVELS.join("/")}), ignored`);
	return { specPart: raw, level: null };
}

/** Returns the registry model a `provider/id` spec names, only when it has configured auth. Sends no notification. */
export function findAuthedModel(ctx: ExtensionContext, specPart: string): NonNullable<ExtensionContext["model"]> | null {
	const slash = specPart.indexOf("/");
	if (slash <= 0) return null;
	const model = ctx.modelRegistry.find(specPart.slice(0, slash), specPart.slice(slash + 1));
	return model && ctx.modelRegistry.hasConfiguredAuth(model) ? model : null;
}

/** The configured classifier spec by precedence: the `auto-mode-model` flag, `PI_AUTO_MODE_MODEL`, then
 *  `classifierModel`. Empty or unset means the session model. */
export function classifierSpec(pi: ExtensionAPI, rules: Readonly<UserRules>): string | null | undefined {
	// Safe: the flag is registered with type string, so the host returns a string or nothing.
	return (pi.getFlag("auto-mode-model") as string | undefined) ?? process.env.PI_AUTO_MODE_MODEL ?? rules.classifierModel;
}

interface ModelRole {
	/** Names the role in its warn-once keys. */
	readonly key: string;
	readonly spec: string | null | undefined;
	/** An unset or unavailable spec falls back to the session model. */
	readonly sessionFallback: boolean;
	readonly unavailableWarning: string;
}

/** Resolves a role to a model and thinking level, warning once per session about an invalid suffix or an
 *  unavailable model. Null means no model, which the caller fails closed on. */
function resolveModelRole(ctx: ExtensionContext, state: SessionState, role: ModelRole): ModelChoice {
	const warn = (kind: string, msg: string): void => {
		if (state.recordWarning(`${role.key}:${kind}`)) ctx.ui.notify(msg, "warning");
	};
	let thinking: ThinkingLevel = "off";
	if (role.spec) {
		const { specPart, level } = parseModelSpec(role.spec, (msg) => warn("suffix", msg));
		thinking = level ?? "off";
		const model = findAuthedModel(ctx, specPart);
		if (model) return { model, thinking };
		warn("model", role.unavailableWarning);
	}
	// A configured thinking level stays in effect on the session model.
	return role.sessionFallback && ctx.model ? { model: ctx.model, thinking } : null;
}

/** The classifier model: the configured spec, else the session model (self-reflection); null when neither exists. */
export function resolveClassifier(ctx: ExtensionContext, pi: ExtensionAPI, state: SessionState): ModelChoice {
	const spec = classifierSpec(pi, state.userRules);
	return resolveModelRole(ctx, state, {
		key: "classifier",
		spec,
		sessionFallback: true,
		unavailableWarning: `pi-verdict: classifier model "${spec}" unavailable (not found or no configured auth), falling back to session model (self-reflection)`,
	});
}

/** The second-layer classifier: `classifierFallbackModel` only, never the session model, since inheriting it would bill
 *  the same judgment twice instead of adding a second opinion (ADR-0004). Null leaves the cascade inert in shadow
 *  mode and fails a triggered call closed in enforce mode. */
export function resolveFallbackClassifier(ctx: ExtensionContext, state: SessionState): ModelChoice {
	const spec = state.userRules.classifierFallbackModel;
	return resolveModelRole(ctx, state, {
		key: "fallback",
		spec,
		sessionFallback: false,
		unavailableWarning: `pi-verdict: fallback model "${spec}" unavailable (not found or no configured auth) — classifierFallbackModel inactive this session`,
	});
}

/** The EXPLAIN-GATE model: `explainGateModel`, else the session model. The user asked for the call, so the session
 *  model carries no double-billing concern. */
export function resolveExplainGate(ctx: ExtensionContext, state: SessionState): ModelChoice {
	const spec = state.userRules.explainGateModel;
	return resolveModelRole(ctx, state, {
		key: "explain",
		spec,
		sessionFallback: true,
		unavailableWarning: `pi-verdict: ${EXPLAIN_GATE_ROLE} model "${spec}" unavailable (not found or no configured auth), falling back to session model`,
	});
}
