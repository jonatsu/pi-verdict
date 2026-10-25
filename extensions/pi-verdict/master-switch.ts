import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { UserRules } from "./config.ts";
import type { GateRuntime } from "./runtime.ts";
import { type FallbackStats, POLICY_DEGRADED } from "./state.ts";
import { refreshStatus } from "./ui/status.ts";

// ============================================================================
// The master switch: /automode and the toggle shortcut (#15)
// ============================================================================

/** Sets the master switch; `/automode` and the toggle shortcut share it, so both behave alike. */
function setMasterSwitch(rt: GateRuntime, next: boolean, ctx: ExtensionContext): void {
	rt.enabled = next;
	refreshStatus(rt, ctx);
}

/** The `/automode` status line for the confidence cascade; shadow mode names what enforce would have done. */
function cascadeSummary(s: Readonly<FallbackStats>, mode: UserRules["classifierFallbackMode"]): string {
	if (s.triggered === 0) return "confidence cascade: not triggered this session";
	const enforced = mode === "enforce";
	return `confidence cascade (${mode}): triggered ${s.triggered} · agreed ${s.agreed} · ${enforced ? "overruled" : "would-overrule"} ${s.overruled} · ${enforced ? "rescued-allow" : "would-rescue-allow"} ${s.rescuedAllow} · errored ${s.errored}`;
}

/** The cascade line, shown while the confidence floor or the fallback model is configured (#63, #67). */
function fallbackHint(rt: GateRuntime): string {
	const { userRules, fallback } = rt.state;
	return userRules.classifierMinConfidence !== null || userRules.classifierFallbackModel
		? `\n${cascadeSummary(fallback.stats, userRules.classifierFallbackMode)}`
		: "";
}

/** The `/automode` status: the switch, then each state worth naming while it holds. */
function statusText(rt: GateRuntime, toggleHint: string): string {
	const { state } = rt;
	const policy = state.policyDegraded ? `\n${POLICY_DEGRADED.status}` : "";
	const denyPaths = state.userRules.denyPaths.length > 0 ? `\ndenyPaths: ${state.userRules.denyPaths.length} active` : "";
	const audit = state.audit ? `\naudit: on → ${state.audit.dir}` : "";
	return `${rt.enabled ? "🛡️ Auto Mode: on" : "Auto Mode: off"}${policy}${denyPaths}${audit}${fallbackHint(rt)}\nUsage: /automode on|off${toggleHint}`;
}

/** Registers the toggle shortcut and the `/automode` command. The key comes from the rules loaded when the extension
 *  starts, so a changed `toggleShortcut` applies from the next session or `/reload`. The shortcut toggles silently;
 *  the footer is its only feedback. */
export function registerMasterSwitch(rt: GateRuntime): void {
	const { pi } = rt;
	const toggleKey = rt.state.userRules.toggleShortcut;
	if (toggleKey) {
		// Safe: KeyId is pi's compile-time union of key strings, and the config loader validated the key's shape.
		type PiShortcutKey = Parameters<ExtensionAPI["registerShortcut"]>[0];
		pi.registerShortcut(toggleKey as PiShortcutKey, {
			description: "Toggle Auto Mode (pi-verdict)",
			handler: (ctx) => setMasterSwitch(rt, !rt.enabled, ctx),
		});
	}
	const toggleHint = toggleKey ? ` · toggle: ${toggleKey}` : "";

	pi.registerCommand("automode", {
		description: "Show Auto Mode status, or set it: /automode on|off",
		handler: async (args, ctx) => {
			const arg = args.trim().toLowerCase();
			if (arg === "") {
				ctx.ui.notify(statusText(rt, toggleHint), "info");
				return;
			}
			if (arg === "on" || arg === "off") {
				// Idempotent: setting the current value only confirms it.
				const next = arg === "on";
				const changed = next !== rt.enabled;
				setMasterSwitch(rt, next, ctx);
				const head = next
					? `🛡️ Auto Mode enabled${changed ? "" : " (unchanged)"}: tool calls adjudicated by rules + classifier`
					: `Auto Mode disabled${changed ? "" : " (unchanged)"}: tool calls execute directly`;
				ctx.ui.notify(`${head}${fallbackHint(rt)}`, "info");
				return;
			}
			ctx.ui.notify(`unknown argument: ${arg}\nUsage: /automode (status) | /automode on | /automode off${toggleHint}`, "warning");
		},
	});
}
