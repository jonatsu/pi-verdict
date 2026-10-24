import type { Context } from "@earendil-works/pi-ai";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { activeTransport, PROVIDER_ID as JEV_PROVIDER_ID, streamDecisions, TRANSPORT_DEFAULTS } from "../jev-adapter.ts";

// ============================================================================
// Host completion binding: one model-call function on both hosts
// ============================================================================

// Models whose provider rejected a temperature-bearing request ("`temperature`
// is deprecated for this model" — current-gen Anthropic models, #47). Filled
// adaptively and cached for the extension's lifetime: pi's model registry has
// no sampling-capability metadata and the reject/accept split follows neither
// `api` nor `reasoning`, so the provider's own error is the only reliable
// signal. Later calls for a cached model omit the parameter upfront.
export const TEMPERATURE_REJECTED_MODELS = new Set<string>();

/**
 * Minimal structural shape of a completion call (#35). pi exposes it as
 * ModelRegistry.complete; omp 18 does not, but the pi-ai compat module exports
 * a functionally identical `complete`. Options pass through verbatim on both
 * hosts (thinkingEnabled/effort/cacheRetention included — see
 * research/thinking-param-blackhole.md for why API-native fields matter).
 */
export type CompletionFn = (
	model: NonNullable<ExtensionContext["model"]>,
	context: { systemPrompt?: string; messages: unknown[] },
	options?: Record<string, unknown>,
) => Promise<{ content: Array<{ type: string; text: string }>; stopReason?: string; errorMessage?: string }>;

type CompatLoader = () => Promise<{ complete: CompletionFn }>;

/** Shape of omp's `ModelRegistry.getApiKeyAndHeaders` — the "historical Pi extension facade". */
type ApiKeyAndHeadersResolver = (
	model: NonNullable<ExtensionContext["model"]>,
) => Promise<{ ok: true; apiKey?: string; headers?: Record<string, string> } | { ok: false; error: string }>;

/**
 * Bind the host runtime's completion capability (#35): registry.complete when
 * present (pi), else the pi-ai compat module (omp 18). The literal dynamic
 * import specifier must stay inline — omp's legacy compat rewrites exactly
 * this literal to its bundled pi-ai; the ./compat subpath also exists on pi,
 * so resolution is safe on both hosts. The loader promise is cached; any
 * rejection propagates to the caller (the classifier's fail-closed path owns it).
 *
 * [pi-verdict local patch: omp 18.3.0 compat auth gap] The bundled pi-ai
 * `complete` re-derives credentials from its own internal AuthStorage, which
 * has no visibility into omp's OAuth-backed session credentials (Claude Code
 * subscription tokens, etc.) — every call failed closed with
 * `MissingApiKeyError: No API key for provider: X` even on a fully
 * authenticated session. `registry.getApiKeyAndHeaders` is omp's own
 * documented bridge ("Resolve request authentication through the historical
 * Pi extension facade") returning the exact credential the live session
 * already uses — forward it explicitly so the compat call skips its broken
 * internal resolution. Falls through to the unauthenticated call (and its
 * original fail-closed error) when the registry lacks this method (real pi
 * never takes this branch) or when auth genuinely isn't configured.
 */
export function bindCompletion(
	registry: { complete?: unknown; getApiKeyAndHeaders?: ApiKeyAndHeadersResolver },
	compatLoader: CompatLoader = () => import("@earendil-works/pi-ai/compat") as Promise<{ complete: CompletionFn }>,
): CompletionFn {
	if (typeof registry.complete === "function") {
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

// Session-lifetime cache keyed by registry instance: resolve once per registry.
const completionCache = new WeakMap<object, CompletionFn>();
function completionFor(registry: { complete?: unknown }, compatLoader?: CompatLoader): CompletionFn {
	let fn = completionCache.get(registry);
	if (!fn) {
		fn = bindCompletion(registry, compatLoader);
		completionCache.set(registry, fn);
	}
	return fn;
}

/** Minimal shape `completeForClassifier` needs from `ctx.modelRegistry` beyond
 *  what `bindCompletion` already requires: omp's real `getApiKeyForProvider`,
 *  used only on the jev/omp branch below (absent on real pi's ModelRegistry,
 *  which never takes that branch). */
type ClassifierRegistry = { complete?: unknown; getApiKeyForProvider?: (provider: string) => Promise<string | undefined> };

/**
 * [pi-verdict local patch: omp 18.3.0 jev/TypeSafe support] omp's compat
 * completion bridge (`bindCompletion`'s fallback branch) talks to the bundled
 * pi-ai package's own, unrelated provider registry — it has no visibility
 * into providers extensions register on `ctx.modelRegistry` (see
 * jev-adapter.ts's omp registration comment), so a `classifierModel:
 * "typesafe/jev-latest"` selection would 404 there even though
 * `ctx.modelRegistry.find()`/`hasConfiguredAuth()` correctly resolve it.
 * Detect the omp-compat case (`registry.complete` absent) targeting jev's
 * provider id and call `streamDecisions()` directly, resolving the OpenRouter
 * (or TypeSafe-direct) API key fresh via `getApiKeyForProvider` on every call
 * — not the static snapshot `registerProvider` uses only for the sync
 * `hasConfiguredAuth` check. Real pi never takes this branch: `registry.complete`
 * exists there, so `generic` already dispatches to jev's registered
 * `provider.api.streamSimple` (auth via `provider.auth.apiKey.resolve`)
 * unmodified.
 */
export function completeForClassifier(registry: ClassifierRegistry, deps: AutoModeDeps): CompletionFn {
	const generic = completionFor(registry, deps.compatLoader);
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
		const result = await streamDecisions(transport, m, c as Context, { ...o, apiKey }).result();
		return {
			content: result.content.filter((part): part is { type: "text"; text: string } => part.type === "text"),
			stopReason: result.stopReason,
			errorMessage: result.errorMessage,
		};
	};
}

/** Optional dependency injection for tests (#35): fake the compat fallback loader. */
export interface AutoModeDeps {
	compatLoader?: CompatLoader;
}
