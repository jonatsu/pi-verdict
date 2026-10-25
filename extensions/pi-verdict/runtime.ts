import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { type CompatLoader, type CompletionFn, completionForHost } from "./completion.ts";
import { type HostKind, hostKindOf } from "./floor.ts";
import { SessionState } from "./state.ts";
import { type HostBudget, readHostHandlerBudget, type UiContext } from "./subagent.ts";

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
	readonly hostKind: HostKind;
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
export function completionFor(rt: GateRuntime, ctx: ExtensionContext): CompletionFn {
	return completionForHost(ctx.modelRegistry, rt.compatLoader);
}
