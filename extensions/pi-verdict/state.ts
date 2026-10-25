import * as path from "node:path";
import { agentDirPath, OWN_FILE_PATH } from "./agent-dir.ts";
import { AuditLog } from "./audit.ts";
import { type LoadedRules, loadUserRules, type UserRules } from "./config.ts";
import { anchorDenyPaths } from "./deny-paths.ts";
import { buildProtectedSet, type ProtectedSet } from "./self-protection.ts";

// ============================================================================
// Confidence cascade statistics (#63, #67): kept in memory for the session only
// ============================================================================

export interface FallbackStats {
	/** The confidence floor fired, or the first layer failed closed, with a fallback model configured. */
	triggered: number;
	/** The fallback ruled as the first layer did; a fail-closed first layer counts as deny. */
	agreed: number;
	/** The fallback ruled otherwise; enforce mode applies its ruling, shadow mode only records it. */
	overruled: number;
	/** The fallback model was unresolvable or its call failed. */
	errored: number;
	/** The fallback allowed a call whose first layer failed closed (#71); a subset of `overruled`. */
	rescuedAllow: number;
}

class FallbackCascade {
	readonly stats: FallbackStats = { triggered: 0, agreed: 0, overruled: 0, errored: 0, rescuedAllow: 0 };

	reset(): void {
		Object.assign(this.stats, { triggered: 0, agreed: 0, overruled: 0, errored: 0, rescuedAllow: 0 });
	}

	/** Records one cascade run: `first` is null when the first layer failed closed, `fb` is null when the fallback errored. */
	note(first: "allow" | "ask" | "deny" | null, fb: "allow" | "ask" | "deny" | null): void {
		this.stats.triggered++;
		if (fb === null) {
			this.stats.errored++;
			return;
		}
		if (first === null && fb === "allow") this.stats.rescuedAllow++;
		if ((first ?? "deny") !== fb) this.stats.overruled++;
		else this.stats.agreed++;
	}
}

// ============================================================================
// Session state
// ============================================================================

type VerdictCounts = { allow: number; ask: number; deny: number };

/** What a rules load reported besides the rules, for the presentation layer to notify on. */
export type RulesLoadReport = Omit<LoadedRules, "rules">;

/**
 * The adjudication pipeline's per-session state. `reset()` is the single reset list, so every new
 * per-session field registers there.
 */
export class SessionState {
	readonly fallback = new FallbackCascade();
	readonly protectedSet: ProtectedSet;
	userRules: UserRules;
	audit: AuditLog | null;
	private denyPathBases: string[] | null = null;
	private readonly agentDir: string;
	/** Root-session verdicts only; an ask counts once whatever the user answers. A `/verdict` reload keeps them. */
	private counts: VerdictCounts = { allow: 0, ask: 0, deny: 0 };
	/** The user's own policy did not load in full; while set, every model-originated allow becomes an ask (ADR-0010). */
	policyDegraded = false;
	/** The warning that the host's handler budget is too short for subagent asks was shown this session. */
	hostBudgetWarned = false;

	/** Anchors self-protection and the audit log to `agentDir`, and loads the user rules, so a state used before
	 *  `session_start` already gates. A config that fails to load gives empty rules with the floor on and sets
	 *  `policyDegraded` (ADR-0010). */
	constructor(agentDir: string = agentDirPath()) {
		this.agentDir = agentDir;
		this.protectedSet = buildProtectedSet(agentDir, OWN_FILE_PATH);
		const loaded = loadUserRules();
		this.userRules = loaded.rules;
		this.policyDegraded = loaded.degraded;
		this.audit = this.makeAudit(this.userRules);
	}

	private makeAudit(rules: UserRules): AuditLog | null {
		return rules.audit ? new AuditLog(path.join(this.agentDir, "verdicts")) : null;
	}

	/** Reloads the user and trusted project rules and anchors `denyPaths` to `cwd` (ADR-0002); `/verdict` calls it after
	 *  a config edit. Keeps the cascade statistics and verdict counts. */
	reloadRules(cwd: string, sessionTrustedRoot: string | null = null): RulesLoadReport {
		const { rules, ...report } = loadUserRules(cwd, sessionTrustedRoot);
		this.userRules = rules;
		this.policyDegraded = report.degraded;
		this.denyPathBases = anchorDenyPaths(rules.denyPaths, cwd);
		this.audit = this.makeAudit(rules);
		return report;
	}

	/** Starts a session: reloads the rules for `cwd` and clears every per-session field. */
	reset(cwd: string, sessionTrustedRoot: string | null = null): RulesLoadReport {
		const report = this.reloadRules(cwd, sessionTrustedRoot);
		this.fallback.reset();
		this.counts = { allow: 0, ask: 0, deny: 0 };
		this.hostBudgetWarned = false;
		return report;
	}

	get verdictCounts(): Readonly<VerdictCounts> {
		return this.counts;
	}

	countVerdict(verdict: keyof VerdictCounts): void {
		this.counts[verdict]++;
	}

	/** Returns the `denyPaths` bases anchored at `session_start`. A tool call that arrives first anchors them to its
	 *  own cwd, once. */
	anchoredDenyPathBases(cwd: string): string[] {
		if (this.denyPathBases === null) this.denyPathBases = anchorDenyPaths(this.userRules.denyPaths, cwd);
		return this.denyPathBases;
	}
}
