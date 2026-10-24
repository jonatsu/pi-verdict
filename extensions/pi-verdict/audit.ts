import * as fs from "node:fs";
import * as path from "node:path";

// ============================================================================
// Gray-zone verdict audit (#54): opt-in JSONL decision records, observe-only
// (never an adjudication input)
// ============================================================================

const AUDIT_KEEP_SESSIONS = 20;

/** #63/#67: second-layer outcome on a cascaded call. The record's top-level fields keep
 *  first-layer semantics for corpus comparability; the verdict actually applied under
 *  enforce lives in `effective` (failure rows carry the ask the human got). */
export interface FallbackAudit {
	model: string;
	mode: "shadow" | "enforce";
	triggeredBy: "confidence" | "fail-closed" | "subagent-ask";
	/** jev confidence that fired the floor; null unless triggeredBy = "confidence" */
	confidence: number | null;
	/** null = the fallback call itself failed (unresolvable model, timeout, parse) */
	verdict: "allow" | "ask" | "deny" | null;
	reason: string | null;
	durationMs: number;
	error: string | null;
	/** the verdict applied (pre headless-degradation); absent for a shadow-mode cascade, and "deny" for a
	 *  subagent ask in shadow mode, where the opinion is recorded but never applied */
	effective?: "allow" | "ask" | "deny";
}

/** One adjudication record (#54; #62 widened the surface to protected-path asks and
 *  added the ground-truth fields). Full fidelity on purpose: the file is
 *  local-trust-domain (same as pi-verdict.json, per the ADR-0002 boundary note),
 *  so protected-path plaintext is allowed here — it never leaves the machine nor
 *  flows into agent context. */
export interface AuditRecord {
	ts: string;
	sessionId: string;
	cwd: string;
	model: string | null;
	tool: string;
	input: unknown;
	actionLine: string;
	thinking: string | null;
	transcript: string | null;
	rawResponse: string | null;
	verdict: "allow" | "ask" | "deny";
	reason: string;
	/** #62: protected-path asks are recorded too — their user answers grade the
	 *  denyPaths rules; rule allow/deny verdicts remain unaudited. "rule" covers a
	 *  rule-layer ask whose askSource is not "protected-path" (ask-source seam).
	 *  "degraded-policy" is a model-originated allow converted to an ask while the
	 *  user's own policy failed to load (item 6c, Phase 6; ADR-0010). */
	source: "model" | "fail-closed" | "protected-path" | "rule" | "degraded-policy";
	degraded: boolean;
	/** #62 ground truth: the user's answer to an interactive ask confirm. Present only
	 *  on records whose confirm actually ran; headless/degraded asks omit it. */
	userAnswer?: "allowed" | "declined";
	/** #62: ISO timestamp of the confirm resolution; `ts` stays adjudication time. */
	answeredAt?: string;
	/** #62: protected-path records only — the matched path. */
	detail?: string;
	/** #67: the confidence floor fired — the first-layer verdict was demoted. */
	demoted?: true;
	/** #63/#67: second-layer outcome when the fallback was consulted. */
	fallback?: FallbackAudit;
	/** asks raised in a subagent session: who resolved them */
	subagent?: { id: string; name: string; resolution: "human" | "timeout" | "auto" };
}

/** Audit sink (#54): append-only and fail-soft (the first write failure surfaces
 *  once via drainWarning; verdicts are never affected). The dir is created
 *  lazily — audit on with no gray-zone call all session leaves zero filesystem trace. */
export class AuditLog {
	private warning: string | null = null;
	private warned = false;
	constructor(readonly dir: string) {}

	append(record: AuditRecord): void {
		// sessionId comes from the host with no shape guarantee: narrow to a safe filename charset
		const file = path.join(this.dir, `${record.sessionId.replace(/[^a-zA-Z0-9_-]/g, "_")}.jsonl`);
		try {
			fs.mkdirSync(this.dir, { recursive: true });
			fs.appendFileSync(file, JSON.stringify(record) + "\n");
		} catch (err) {
			if (!this.warned) {
				this.warned = true;
				this.warning = `audit log write failed (${err instanceof Error ? err.message : String(err)}) — verdict records are NOT being persisted to ${this.dir}; adjudication is unaffected`;
			}
		}
	}

	/** One-shot drain: the extension handler polls after every tool_call; first failure warns, the rest stay silent */
	drainWarning(): string | null {
		const w = this.warning;
		this.warning = null;
		return w;
	}

	/** Keep the most recent AUDIT_KEEP_SESSIONS session files (called at session_start, best-effort) */
	prune(): void {
		let files: string[];
		try {
			files = fs.readdirSync(this.dir).filter((f) => f.endsWith(".jsonl"));
		} catch {
			return;
		}
		if (files.length <= AUDIT_KEEP_SESSIONS) return;
		const byMtime = files
			.map((f) => {
				let m = 0;
				try {
					m = fs.statSync(path.join(this.dir, f)).mtimeMs;
				} catch {}
				return { f, m };
			})
			.sort((a, b) => b.m - a.m);
		for (const { f } of byMtime.slice(AUDIT_KEEP_SESSIONS)) {
			try {
				fs.unlinkSync(path.join(this.dir, f));
			} catch {}
		}
	}
}
