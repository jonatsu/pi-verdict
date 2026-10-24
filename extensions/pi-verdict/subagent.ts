import type { ExtensionContext } from "@earendil-works/pi-coding-agent";

// ============================================================================
// Subagent bridge (omp)
// ============================================================================

export type UiContext = ExtensionContext["ui"];

/** Widget key of the live classifier-status row. */
export const STATUS_WIDGET_KEY = "verdict";

/** omp-only: `ctx.agent = { kind: "main" | "sub", id, name, … }` (pi's ExtensionContext has no `agent`).
 *  Returns the subagent's identity, or null for a root session / pi. */
export function subagentIdentity(ctx: ExtensionContext): { id: string; name: string } | null {
	const agent = (ctx as { agent?: unknown }).agent;
	if (typeof agent !== "object" || agent === null) return null;
	const a = agent as { kind?: unknown; id?: unknown; name?: unknown };
	if (a.kind !== "sub") return null;
	return { id: typeof a.id === "string" ? a.id : "?", name: typeof a.name === "string" ? a.name : "?" };
}

export function subagentLabel(id: { id: string; name: string }): string {
	return id.id === id.name ? `subagent ${id.id}` : `subagent ${id.id} (${id.name})`;
}

// ============================================================================
// Host handler budget (omp)
// ============================================================================

/** omp's per-handler `tool_call` budget, `extensionHandlers.toolCallTimeoutMs`. `configured` is false when the
 *  value is the host default or could not be read. */
export interface HostBudget {
	readonly ms: number;
	readonly configured: boolean;
}

/** Mirrors omp's `EXTENSION_HANDLER_TIMEOUT_MS`, the budget a missing or invalid setting falls back to (18.12.6). */
export const OMP_HANDLER_TIMEOUT_DEFAULT_MS = 30_000;
/** How long before the host budget ends a subagent ask dialog closes, so pi-verdict blocks the call itself. */
export const HOST_BUDGET_MARGIN_MS = 3_000;
/** How long before the host budget ends the second model must have answered. */
export const HOST_RETURN_MARGIN_MS = 1_000;
/** A host-limited window shorter than this is not worth a dialog: the ask expires at once. */
export const MIN_SUBAGENT_DIALOG_MS = 2_000;
/** Headroom the docs ask for between the host budget and `subagentAskTimeoutMs`. */
export const HOST_BUDGET_HEADROOM_MS = 60_000;

const HANDLER_TIMEOUT_KEY = ["extensionHandlers", "toolCallTimeoutMs"] as const;
const OMP_DEFAULT_BUDGET: HostBudget = { ms: OMP_HANDLER_TIMEOUT_DEFAULT_MS, configured: false };

/** The budget omp derives from a configured value: a configured `null` is unset, and a non-positive,
 *  non-finite or non-number value falls back to the default. Returns undefined when unset. */
function budgetFromValue(value: unknown): HostBudget | undefined {
	if (value === undefined || value === null) return undefined;
	return typeof value === "number" && Number.isFinite(value) && value > 0 ? { ms: value, configured: true } : OMP_DEFAULT_BUDGET;
}

function layerValue(layer: unknown): unknown {
	let node: unknown = layer;
	for (const key of HANDLER_TIMEOUT_KEY) {
		if (typeof node !== "object" || node === null) return undefined;
		// Safe: a non-null object, and every property read is narrowed by budgetFromValue.
		node = (node as Record<string, unknown>)[key];
	}
	return node;
}

const loadSettingsManager = async (): Promise<unknown> => (await import("@earendil-works/pi-coding-agent")).SettingsManager;

/** Returns the host's per-handler `tool_call` budget, or null on a host without one (pi). On omp it reads
 *  `extensionHandlers.toolCallTimeoutMs` through the legacy `SettingsManager.create(cwd)`, which resolves the
 *  calling session's settings while a handler runs. `rawValue` gives the value omp enforces, merged over every
 *  layer; without it the project layer wins over the global one, which misses a `--config` overlay, runtime
 *  overrides and an overlay parent's view. A failed read assumes the omp default of 30000 ms. Any value that
 *  differs from the enforced one moves the dialog's close: a longer enforced budget closes it early, and a
 *  shorter one lets omp block the call first, as without this read. */
export async function readHostHandlerBudget(
	pi: object,
	cwd: string,
	loader: () => Promise<unknown> = loadSettingsManager,
): Promise<HostBudget | null> {
	if (!("logger" in pi && "typebox" in pi)) return null;
	try {
		const settingsManager = await loader();
		// Safe: optional chaining covers a nullish module value, and `create` is checked to be a function.
		const create = (settingsManager as { create?: unknown } | null | undefined)?.create;
		if (typeof create !== "function") return OMP_DEFAULT_BUDGET;
		const manager: unknown = create.call(settingsManager, cwd);
		if (typeof manager !== "object" || manager === null) return OMP_DEFAULT_BUDGET;
		// Safe: a non-null object; each method is checked to be a function before the call.
		const m = manager as { rawValue?: unknown; getProjectSettings?: unknown; getGlobalSettings?: unknown };
		if (typeof m.rawValue === "function") {
			// The shape omp's `configuredValue` reads from a setting handle (18.12.6).
			const value: unknown = m.rawValue.call(manager, { segments: HANDLER_TIMEOUT_KEY, definition: {} });
			return budgetFromValue(value) ?? OMP_DEFAULT_BUDGET;
		}
		const layer = (get: unknown): unknown => (typeof get === "function" ? layerValue(get.call(manager)) : undefined);
		return budgetFromValue(layer(m.getProjectSettings)) ?? budgetFromValue(layer(m.getGlobalSettings)) ?? OMP_DEFAULT_BUDGET;
	} catch {
		return OMP_DEFAULT_BUDGET;
	}
}

/** How long a subagent's ask may wait on the root UI: `subagentAskTimeoutMs`, or less when the host budget
 *  (less `HOST_BUDGET_MARGIN_MS`) ends first. `hostLimited` says which bound applies. */
export function subagentAskWindow(
	askTimeoutMs: number,
	budget: HostBudget | null,
	elapsedMs: number,
): { readonly ms: number; readonly hostLimited: boolean } {
	if (budget === null) return { ms: askTimeoutMs, hostLimited: false };
	const hostMs = Math.max(0, budget.ms - elapsedMs - HOST_BUDGET_MARGIN_MS);
	return hostMs < askTimeoutMs ? { ms: hostMs, hostLimited: true } : { ms: askTimeoutMs, hostLimited: false };
}

const budgetSpelling = (budget: HostBudget): string =>
	`omp's extensionHandlers.toolCallTimeoutMs (${budget.ms} ms${budget.configured ? "" : ", default"})`;

/** Advice to raise the host budget, or null when it already covers `askTimeoutMs` plus the headroom. */
export function hostBudgetAdvice(askTimeoutMs: number, budget: HostBudget | null): string | null {
	if (budget === null || budget.ms >= askTimeoutMs + HOST_BUDGET_HEADROOM_MS) return null;
	return `${budgetSpelling(budget)} ends a subagent's tool call before subagentAskTimeoutMs (${askTimeoutMs} ms); set it to at least ${askTimeoutMs + HOST_BUDGET_HEADROOM_MS} in omp's config.yml`;
}

/** Why a host-limited ask expired, naming the budget and the setting to raise. */
export function hostBudgetExpiry(askTimeoutMs: number, budget: HostBudget | null): string {
	if (budget === null) return "the host's handler budget ran out";
	return (
		hostBudgetAdvice(askTimeoutMs, budget) ??
		`${budgetSpelling(budget)} ran out before the ask could be answered; raise it in omp's config.yml`
	);
}

/** Resolves to "aborted" as soon as `signal` aborts, even while `work` waits in the dialog queue. */
export function untilAborted<T>(work: Promise<T>, signal: AbortSignal): Promise<T | "aborted"> {
	if (signal.aborted) return Promise.resolve("aborted");
	let onAbort = (): void => {};
	const aborted = new Promise<"aborted">((resolve) => {
		onAbort = () => resolve("aborted");
		signal.addEventListener("abort", onAbort, { once: true });
	});
	return Promise.race([work, aborted]).finally(() => signal.removeEventListener("abort", onAbort));
}

let dialogTail: Promise<void> = Promise.resolve();
export function serializeDialog<T>(fn: () => Promise<T>): Promise<T> {
	const run = dialogTail.then(fn, fn);
	dialogTail = run.then(
		() => undefined,
		() => undefined,
	);
	return run;
}
