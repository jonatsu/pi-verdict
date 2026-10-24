import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { CompletionFn } from "./completion.ts";

// ============================================================================
// Model call: one request to a model, with the gate's sampling and thinking options
// ============================================================================

/** The two session members the pipeline reads: the branch for the transcript and the session id for prompt
 *  caching. Narrow, so tests need no full `ExtensionContext`. */
export type PipelineHost = Pick<ExtensionContext["sessionManager"], "getBranch" | "getSessionId">;

/** Thinking levels in pi's vocabulary, as written in the `provider/id:thinking` model suffix. */
export type ThinkingLevel = "off" | "minimal" | "low" | "medium" | "high" | "xhigh" | "max";

/** A resolved model and its thinking level, or null when none is configured or authenticated. */
export type ModelChoice = { model: NonNullable<ExtensionContext["model"]>; thinking: ThinkingLevel } | null;

/** One model call's result. `timedOut` marks the attempt's own deadline firing, which `classifyWithModel`
 *  does not retry. */
export type ModelAttempt =
	| { ok: true; text: string; stopReason: string; errorMessage?: string; timedOut: boolean }
	| { ok: false; error: string; timedOut: boolean };

// ============================================================================
// Temperature policy: temperature 0 for determinism, except where a provider rejects it
// ============================================================================

/** APIs that reject the `temperature` parameter outright, so it is never sent to them (#46). */
const APIS_WITHOUT_TEMPERATURE = new Set<string>(["openai-codex-responses"]);

/** Models whose provider rejected a request carrying `temperature` (#47), keyed `api|id` for the process
 *  lifetime. The registry has no sampling metadata, so the provider's error is the only signal. */
const TEMPERATURE_REJECTED_MODELS = new Set<string>();

type TemperatureModel = Pick<NonNullable<ExtensionContext["model"]>, "api" | "id">;

/** True when a request to this model should carry `temperature: 0`. */
function usesTemperature(model: TemperatureModel): boolean {
	return !APIS_WITHOUT_TEMPERATURE.has(model.api) && !TEMPERATURE_REJECTED_MODELS.has(`${model.api}|${model.id}`);
}

/** Records that this model's provider rejected `temperature`, so later calls omit it. */
function noteTemperatureRejected(model: TemperatureModel): void {
	TEMPERATURE_REJECTED_MODELS.add(`${model.api}|${model.id}`);
}

/** The provider rejected the request over the `temperature` parameter itself (#47). */
function temperatureRejection(r: ModelAttempt): boolean {
	if (r.ok) return (r.stopReason === "error" || r.stopReason === "aborted") && /temperature/i.test(r.errorMessage ?? "");
	return /temperature/i.test(r.error);
}

/** One model call, used by the classifier and EXPLAIN-GATE. Returns the text or an error and never throws.
 *  A provider that rejects `temperature` gets one retry without it, and the model is remembered so later
 *  calls omit it (#47); every other model keeps temperature 0 for determinism. */
export async function callModelOnce(
	host: PipelineHost,
	signal: AbortSignal | undefined,
	complete: CompletionFn,
	model: NonNullable<ExtensionContext["model"]>,
	userMessage: string,
	maxTokens: number,
	thinking: ThinkingLevel,
	systemPrompt: string,
	timeoutMs: number,
): Promise<ModelAttempt> {
	// One timeout per attempt, shared by the temperature retry, so the retry cannot double the attempt's cap.
	const timeout = AbortSignal.timeout(timeoutMs);
	const fire = async (withTemperature: boolean): Promise<ModelAttempt> => {
		const signals = [timeout];
		if (signal) signals.push(signal);
		try {
			const response = await complete(
				model,
				{
					systemPrompt,
					messages: [{ role: "user", content: userMessage, timestamp: Date.now() }],
				},
				{
					signal: AbortSignal.any(signals),
					maxTokens,
					...(withTemperature ? { temperature: 0 } : {}),
					// Thinking options go out in both hosts' dialects (#35): pi reads `thinkingEnabled`/`effort`,
					// omp's compat call reads `reasoning`/`disableReasoning`, and each ignores the other's fields.
					// research/thinking-param-blackhole.md records why pi needs the API-native fields.
					...(thinking === "off"
						? { thinkingEnabled: false, disableReasoning: true }
						: {
								thinkingEnabled: true,
								effort: thinking === "minimal" ? ("low" as const) : thinking,
								reasoning: thinking === "minimal" ? ("low" as const) : thinking,
							}),
					cacheRetention: "short",
					sessionId: host.getSessionId(),
				},
			);
			const text = response.content
				.filter((b) => b.type === "text")
				.map((b) => b.text)
				.join("");
			return {
				ok: true,
				text,
				stopReason: response.stopReason ?? "unknown",
				errorMessage: response.errorMessage,
				timedOut: timeout.aborted,
			};
		} catch (err) {
			return { ok: false, error: err instanceof Error ? err.message : String(err), timedOut: timeout.aborted };
		}
	};
	const withTemperature = usesTemperature(model);
	const first = await fire(withTemperature);
	if (withTemperature && temperatureRejection(first)) {
		noteTemperatureRejected(model);
		return fire(false);
	}
	return first;
}
