import type { Context } from "@earendil-works/pi-ai";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { activeTransport, PROVIDER_ID as JEV_PROVIDER_ID, streamDecisions, TRANSPORT_DEFAULTS } from "../jev-adapter.ts";

// ============================================================================
// Host completion binding: one model-call function on both hosts
// ============================================================================

/** The completion call both hosts provide (#35): pi's `ModelRegistry.complete`, or `complete` from the pi-ai
 *  compat module on omp. Options pass through unchanged. */
export type CompletionFn = (
	model: NonNullable<ExtensionContext["model"]>,
	context: { systemPrompt?: string; messages: unknown[] },
	options?: Record<string, unknown>,
) => Promise<{ content: Array<{ type: string; text: string }>; stopReason?: string; errorMessage?: string }>;

/** Loads the pi-ai compat module; tests inject a fake (#35). */
export type CompatLoader = () => Promise<{ complete: CompletionFn }>;

/** Shape of omp's `ModelRegistry.getApiKeyAndHeaders` — the "historical Pi extension facade". */
type ApiKeyAndHeadersResolver = (
	model: NonNullable<ExtensionContext["model"]>,
) => Promise<{ ok: true; apiKey?: string; headers?: Record<string, string> } | { ok: false; error: string }>;

/** Returns the host's completion call: `registry.complete` on pi, else the lazily loaded pi-ai compat module
 *  on omp. The import specifier stays a literal because omp rewrites exactly that literal to its bundled pi-ai.
 *  A load or call error propagates, and the classifier fails closed on it.
 *
 *  [pi-verdict local patch: omp 18.3.0 compat auth gap] The compat `complete` cannot see omp's session
 *  credentials, so the credential from `registry.getApiKeyAndHeaders` is forwarded with each call. When that
 *  method is absent, fails or returns no key, the request is sent unauthenticated, as the compat call makes it. */
export function bindCompletion(
	registry: { complete?: unknown; getApiKeyAndHeaders?: ApiKeyAndHeadersResolver },
	// Safe: the compat module exports `complete` with this call shape on both hosts; a mismatch throws, failing closed.
	compatLoader: CompatLoader = () => import("@earendil-works/pi-ai/compat") as Promise<{ complete: CompletionFn }>,
): CompletionFn {
	if (typeof registry.complete === "function") {
		// Safe: checked to be a function above, and pi's `ModelRegistry.complete` has this signature.
		const complete = registry.complete as CompletionFn;
		return (m, c, o) => complete.call(registry, m, c, o);
	}
	let compat: Promise<{ complete: CompletionFn }> | undefined;
	return async (m, c, o) => {
		compat ??= compatLoader();
		const { complete } = await compat;
		if (typeof registry.getApiKeyAndHeaders === "function") {
			const auth = await registry.getApiKeyAndHeaders(m).catch(() => undefined);
			if (auth?.ok && auth.apiKey) {
				// Safe: the gate's own callers pass no headers, and a host header option is a string record.
				return complete(m, c, {
					...o,
					apiKey: auth.apiKey,
					headers: { ...(o?.headers as Record<string, string> | undefined), ...auth.headers },
				});
			}
		}
		return complete(m, c, o);
	};
}

// One bound completion per registry instance.
const completionCache = new WeakMap<object, CompletionFn>();
function completionFor(registry: { complete?: unknown }, compatLoader?: CompatLoader): CompletionFn {
	let fn = completionCache.get(registry);
	if (!fn) {
		fn = bindCompletion(registry, compatLoader);
		completionCache.set(registry, fn);
	}
	return fn;
}

/** The registry members `completionForHost` reads; `getApiKeyForProvider` exists only on omp. */
type HostRegistry = { complete?: unknown; getApiKeyForProvider?: (provider: string) => Promise<string | undefined> };

/** Returns the completion call for every gate model call (classifier, fallback and EXPLAIN-GATE), with the
 *  same failure behavior as `bindCompletion`.
 *
 *  [pi-verdict local patch: omp 18.3.0 jev/TypeSafe support] omp's compat call cannot see providers that
 *  extensions register, so a jev model on omp is called through `streamDecisions` directly, with its key
 *  resolved on every call. pi dispatches jev through its registry and never takes this branch. */
export function completionForHost(registry: HostRegistry, compatLoader?: CompatLoader): CompletionFn {
	const generic = completionFor(registry, compatLoader);
	const isOmpCompat = typeof registry.complete !== "function";
	return async (m, c, o) => {
		if (!isOmpCompat || m.provider !== JEV_PROVIDER_ID) return generic(m, c, o);
		const transport = activeTransport();
		const jevConfig = TRANSPORT_DEFAULTS[transport];
		let apiKey: string | undefined;
		if (jevConfig.loginProvider && typeof registry.getApiKeyForProvider === "function") {
			apiKey = await registry.getApiKeyForProvider(jevConfig.loginProvider).catch(() => undefined);
		}
		apiKey ||= process.env[jevConfig.keyEnv]?.trim();
		// Safe: `callModelOnce` builds the context with a system prompt and timestamped user messages, as `Context` needs.
		const result = await streamDecisions(transport, m, c as Context, { ...o, apiKey }).result();
		return {
			content: result.content.filter((part): part is { type: "text"; text: string } => part.type === "text"),
			stopReason: result.stopReason,
			errorMessage: result.errorMessage,
		};
	};
}
