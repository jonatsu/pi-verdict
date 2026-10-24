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
/** Headroom the docs ask for between the host budget and `subagentAskTimeoutMs`. */
export const HOST_BUDGET_HEADROOM_MS = 60_000;

const HANDLER_TIMEOUT_KEY = ["extensionHandlers", "toolCallTimeoutMs"] as const;

function readTimeoutSetting(layer: unknown): number | undefined {
	let node: unknown = layer;
	for (const key of HANDLER_TIMEOUT_KEY) {
		if (typeof node !== "object" || node === null) return undefined;
		// Safe: a non-null object, and every property read is narrowed below.
		node = (node as Record<string, unknown>)[key];
	}
	if (node === undefined || node === null) return undefined;
	// omp replaces a non-positive or non-finite value with its default.
	return typeof node === "number" && Number.isFinite(node) && node > 0 ? node : OMP_HANDLER_TIMEOUT_DEFAULT_MS;
}

/** Returns the host's per-handler `tool_call` budget, or null on a host without one (pi). On omp it reads
 *  `extensionHandlers.toolCallTimeoutMs` through the legacy `SettingsManager.create(cwd)`, which resolves the
 *  calling session's settings while a handler runs; the project layer wins over the global one. A failed read
 *  assumes the omp default, which can only close a dialog early. */
export async function readHostHandlerBudget(pi: object, cwd: string): Promise<HostBudget | null> {
	if (!("logger" in pi && "typebox" in pi)) return null;
	try {
		const { SettingsManager } = await import("@earendil-works/pi-coding-agent");
		const manager: unknown = SettingsManager.create(cwd);
		// Safe: each method is checked to be a function before the call; a null manager throws into the catch.
		const m = manager as { getProjectSettings?: unknown; getGlobalSettings?: unknown };
		const layer = (name: "getProjectSettings" | "getGlobalSettings"): unknown => {
			const get = m[name];
			return typeof get === "function" ? get.call(manager) : undefined;
		};
		const ms = readTimeoutSetting(layer("getProjectSettings")) ?? readTimeoutSetting(layer("getGlobalSettings"));
		if (ms !== undefined) return { ms, configured: true };
	} catch {
		// fall through to the default
	}
	return { ms: OMP_HANDLER_TIMEOUT_DEFAULT_MS, configured: false };
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
