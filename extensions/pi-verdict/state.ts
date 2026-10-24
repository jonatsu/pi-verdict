import * as path from "node:path";
import { agentDirPath, OWN_FILE_PATH } from "./agent-dir.ts";
import { AuditLog } from "./audit.ts";
import { loadUserRules, type UserRules } from "./config.ts";
import { anchorDenyPaths } from "./deny-paths.ts";
import { buildProtectedSet, type ProtectedSet } from "./self-protection.ts";

// ============================================================================
// Confidence cascade stats (#63/#67: observe-first, session-memory state; the #7 discipline)
// ============================================================================

interface FallbackStats {
	triggered: number; // the floor fired or the first layer fail-closed (with a fallback configured)
	agreed: number; // fallback verdict equals the first layer's (fail-closed defaults to deny)
	overruled: number; // fallback verdict differs (enforce applies it; shadow observes the would-be)
	errored: number; // fallback unresolvable or its call failed
	rescuedAllow: number; // #71: fallback allows after a fail-closed origin; a subset of overruled
}

class FallbackCascade {
	readonly stats: FallbackStats = { triggered: 0, agreed: 0, overruled: 0, errored: 0, rescuedAllow: 0 };

	/** Session reset (#7 discipline: session-memory state) */
	reset(): void {
		Object.assign(this.stats, { triggered: 0, agreed: 0, overruled: 0, errored: 0, rescuedAllow: 0 });
	}

	note(first: "allow" | "ask" | "deny" | null, fb: "allow" | "ask" | "deny" | null): void {
		this.stats.triggered++;
		if (fb === null) {
			this.stats.errored++;
			return;
		}
		// A fail-closed origin produced no first-layer verdict; its default outcome is deny
		if (first === null && fb === "allow") this.stats.rescuedAllow++;
		if ((first ?? "deny") !== fb) this.stats.overruled++;
		else this.stats.agreed++;
	}

	/** Summary line for /automode */
	summary(mode: "shadow" | "enforce"): string {
		const s = this.stats;
		if (s.triggered === 0) return "confidence cascade: not triggered this session";
		return `confidence cascade (${mode}): triggered ${s.triggered} · agreed ${s.agreed} · ${mode === "enforce" ? "overruled" : "would-overrule"} ${s.overruled} · ${mode === "enforce" ? "rescued-allow" : "would-rescue-allow"} ${s.rescuedAllow} · errored ${s.errored}`;
	}
}

// ============================================================================
// Session state: session-scoped state of the adjudication pipeline (reset list centralized in one place)
// ============================================================================

/** Outcome of a rules (re)load, for the presentation layer to notify on */
export interface RulesLoadReport {
	skipped: string[];
	shortcutWarning: string | null;
	project: { path: string; trusted: boolean; applied: boolean } | null;
	/** item 6c (Phase 6): copied from LoadedRules — the presentation layer shows it as a
	 *  footer badge, an `/automode` status line and every block reason while set. */
	degraded: boolean;
}

/**
 * Session-scoped state of the adjudication pipeline. reset() owns the session_start reset list—add new session state
 * here only, so install and session_start no longer each maintain an initialization point. Exported only for tests (the internal seam's
 * test surface, grouped with adjudicate).
 */
export class SessionState {
	readonly fallback = new FallbackCascade();
	readonly prot: ProtectedSet;
	userRules: UserRules;
	audit: AuditLog | null;
	private denyPathBases: string[] | null = null;
	private readonly agentDir: string | null;
	/** Final pipeline verdicts this session (root calls only; an ask counts once whatever the user answers). Reset on session start, kept across /verdict reloads. */
	verdictCounts = { allow: 0, ask: 0, deny: 0 };
	/** item 6c (Phase 6): the user's own policy failed to load (parse/load/trusted-project
	 *  failure, or a skipped deny/denyPaths entry) — while true, every model-originated allow
	 *  becomes an ask (ADR-0010). Part of the reset list via reloadRules. */
	policyDegraded = false;
	/** The warning that the host's handler budget is too short for subagent asks was shown this session. */
	hostBudgetWarned = false;

	constructor(userRules?: UserRules, agentDir: string | null = null) {
		this.agentDir = agentDir;
		this.prot = buildProtectedSet(agentDir ?? agentDirPath(), OWN_FILE_PATH);
		// item 6c: load once (not once as a default param + once here) so rules and
		// policyDegraded always come from the same load — a direct construction (tests,
		// install before session_start) must not depend on reloadRules having run.
		const loaded = loadUserRules();
		this.userRules = userRules ?? loaded.rules;
		this.policyDegraded = loaded.degraded;
		this.audit = this.makeAudit(this.userRules);
	}

	/** #54: the audit flag follows the rules (applies to new sessions); the dir is anchored to the install path */
	private makeAudit(rules: UserRules): AuditLog | null {
		return rules.audit && this.agentDir ? new AuditLog(path.join(this.agentDir, "verdicts")) : null;
	}

	/** Reload user (+ trusted project) rules and re-anchor denyPaths to `cwd` (ADR-0002: once per session
	 *  start; /verdict re-anchors after a config edit). Leaves fallback stats untouched. */
	reloadRules(cwd: string, sessionTrustedRoot: string | null = null): RulesLoadReport {
		const loaded = loadUserRules(cwd, sessionTrustedRoot);
		this.userRules = loaded.rules;
		this.policyDegraded = loaded.degraded; // item 6c (Phase 6): /verdict reloads must carry it too (F11)
		this.denyPathBases = anchorDenyPaths(loaded.rules.denyPaths, cwd); // anchored to the session cwd, once (ADR-0002)
		this.audit = this.makeAudit(loaded.rules);
		return { skipped: loaded.skipped, shortcutWarning: loaded.shortcutWarning, project: loaded.project, degraded: loaded.degraded };
	}

	/** Session reset: reload rules, re-anchor denyPaths to the session cwd, and reset verdict statistics. */
	reset(cwd: string, sessionTrustedRoot: string | null = null): RulesLoadReport {
		const report = this.reloadRules(cwd, sessionTrustedRoot);
		this.fallback.reset();
		this.verdictCounts = { allow: 0, ask: 0, deny: 0 };
		this.hostBudgetWarned = false;
		return report;
	}

	/** denyPaths bases: anchored at session_start; this lazy fallback only guards an out-of-order first tool_call
	 *  (pi normally runs session_start first); once anchored, do not derive again. */
	anchoredDenyPathBases(cwd: string): string[] {
		if (this.denyPathBases === null) this.denyPathBases = anchorDenyPaths(this.userRules.denyPaths, cwd);
		return this.denyPathBases;
	}
}
