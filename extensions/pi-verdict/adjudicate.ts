import { parseJevConfidence } from "../jev-adapter.ts";
import { actionCallLine } from "./action-line.ts";
import type { AuditRecord, FallbackAudit } from "./audit.ts";
import {
	ADJUDICATION_BUDGET_MS,
	CLASSIFIER_TIMEOUT_MS,
	type ClassifierOutcome,
	classifyWithModel,
	FALLBACK_TIMEOUT_MS,
} from "./classifier.ts";
import type { CompletionFn } from "./completion.ts";
import type { UserRules } from "./config.ts";
import type { ModelChoice, PipelineHost } from "./model-call.ts";
import { HOST_REDACTION_PLATFORM, PROTECTED_PATH_MARKER, type RedactorFn, redactorFor } from "./redaction.ts";
import { classifyByRules } from "./rules.ts";
import type { SessionState } from "./state.ts";

// ============================================================================
// Adjudication pipeline (adjudicate): the sole verdict entry point for tool_call → Verdict, with no UI dependency
// ============================================================================

/** Verdict source: a key in the presentation template (orthogonal to degraded). rule = rule layer;
 *  protected-path = denyPaths match; classifier = gray-zone classifier
 *  result (including its fail-closed result, which uses the same presentation template); fail-closed = no classifier model available;
 *  degraded-policy = a model-originated allow converted to an ask while the user's own policy
 *  failed to load (item 6c, Phase 6; ADR-0010). */
export type VerdictSource = "rule" | "protected-path" | "classifier" | "fail-closed" | "degraded-policy";

/** Pipeline output for one tool call. Protected-path detail is UI-only; `degraded`
 *  marks asks converted to denies when no interactive UI is available. */
export interface Verdict {
	verdict: "allow" | "ask" | "deny";
	reason: string;
	detail?: string;
	source: VerdictSource;
	degraded: boolean;
	/** #62: pending audit record for an interactive ask — adjudicate defers the append so
	 *  the handler can attach the user's answer after the confirm resolves. The handler
	 *  owns the single finalize: append with userAnswer/answeredAt, or without them when
	 *  presentation throws. Unset for every non-interactive verdict. */
	pendingAudit?: AuditRecord;
	/** Set on every ask: how the ask resolves without a human (subagent auto/timeout). "consult" = put it to the second model; "deny" = already ruled on by the cascade or not model-resolvable. */
	autoResolve?: "consult" | "deny";
}

/** Per-call environment: host capabilities unrelated to presentation. model is lazily evaluated through getModel—preserving the original “resolve only for gray zone”
 *  behavior (fallback warnings do not appear on calls already decided by rules); null → fail-closed.
 *  getFallbackModel(#63) is even lazier: resolve only after the gate is triggered. */
export interface AdjudicateEnv {
	cwd: string;
	hasUI: boolean;
	getModel: () => ModelChoice;
	complete: CompletionFn;
	host: PipelineHost;
	signal?: AbortSignal;
	getFallbackModel?: () => ModelChoice;
	/** Live-status hook: called right before each gray-zone model call; UI-free (the handler renders it). */
	onPhase?: (phase: "classifier" | "fallback", modelId: string) => void;
	/** Transcript redaction predicate (item 6b, Phase 5) — built once per call by adjudicate
	 *  from cwd + the anchored denyPaths bases; omitted in tests that don't exercise it. */
	redact?: RedactorFn;
	/** item 7: end-to-end adjudication budget override — a TEST SEAM. Production always uses
	 *  ADJUDICATION_BUDGET_MS (the extension never reads the host's configured bound), while the
	 *  budget tests need a sub-second deadline to observe the behavior without waiting 27 s. */
	adjudicationBudgetMs?: number;
}

/** #67: the confidence floor. Below it the first layer abstains and the call cascades —
 *  to the fallback if configured, else to the human (headless degrades to deny). Numeric
 *  confidence exists only on jev-formatted reasons; LLM first layers never demote. */
function confidenceDemotion(outcome: ClassifierOutcome, rules: UserRules): { confidence: number } | null {
	if (rules.classifierMinConfidence === null || outcome.source === "fail-closed") return null;
	const conf = parseJevConfidence(outcome.reason);
	if (conf !== null && conf < rules.classifierMinConfidence) return { confidence: conf };
	return null;
}

interface CascadeResult {
	/** set whenever the confidence floor fired (with or without a fallback) */
	demoted?: true;
	/** audit material; present when the fallback was consulted */
	fb?: FallbackAudit;
	/** the applied outcome when the cascade changes it (pre-degradation — the caller's
	 *  tail applies the usual headless ask → deny rule) */
	effective?: { verdict: "allow" | "ask" | "deny"; reason: string; source: "classifier" | "fail-closed" };
}

/** #67: run the cascade for one triggered call. `first` is the first-layer verdict, or
 *  null when the first layer never produced one (fail-closed origin). Semantics:
 *  - demotion with no fallback → ask the human
 *  - shadow → the fallback records its opinion; a demotion still asks the human, a
 *    fail-closed deny stands
 *  - enforce → the fallback adjudicates de novo, with one carve-out family (#71): a demoted
 *    first-layer deny or ask may not be auto-relaxed to an allow — the human decides; a
 *    fail-closed origin has no first-layer verdict, so any fallback ruling applies
 *  - fallback failure/unresolvable on a cascaded call → ask the human (the tier that was
 *    to adjudicate is down); headless degrades downstream */
async function runConfidenceCascade(
	state: SessionState,
	env: AdjudicateEnv,
	first: { verdict: "allow" | "ask" | "deny"; reason: string } | null,
	trigger: { kind: "demotion"; confidence: number } | { kind: "fail-closed" },
	denyPathsActive: boolean,
	actionLine: string,
	redact: RedactorFn,
	deadlineAt: number,
): Promise<CascadeResult> {
	const rules = state.userRules;
	const demotionAsk = (): CascadeResult["effective"] => ({
		verdict: "ask",
		reason: `${first!.reason} (confidence ${trigger.kind === "demotion" ? trigger.confidence : "?"}% is below your classifierMinConfidence of ${rules.classifierMinConfidence}%)`,
		source: "classifier",
	});
	const getFb = env.getFallbackModel;
	if (!rules.classifierFallbackModel || !getFb) {
		// A fail-closed without a fallback keeps its deny; a demotion asks the human
		return trigger.kind === "demotion" ? { demoted: true, effective: demotionAsk() } : {};
	}
	const mode = rules.classifierFallbackMode;
	const start = Date.now();
	const base = {
		mode,
		triggeredBy: trigger.kind === "demotion" ? ("confidence" as const) : ("fail-closed" as const),
		confidence: trigger.kind === "demotion" ? trigger.confidence : null,
	};
	const demotedMark = trigger.kind === "demotion" ? ({ demoted: true } as const) : {};
	const shadowApplied = trigger.kind === "demotion" ? { effective: demotionAsk() } : {};
	const failed = (model: string, error: string): CascadeResult => {
		state.fallback.note(first?.verdict ?? null, null);
		const fb: FallbackAudit = { ...base, model, verdict: null, reason: null, durationMs: Date.now() - start, error };
		if (mode === "shadow") return { ...demotedMark, fb, ...shadowApplied };
		return {
			...demotedMark,
			fb: { ...fb, effective: "ask" },
			effective: { verdict: "ask", reason: "fallback classifier unavailable (first layer abstained) — your call", source: "fail-closed" },
		};
	};
	const resolved = getFb();
	if (!resolved) return failed(rules.classifierFallbackModel, "fallback model unresolvable (not found or no configured auth)");
	env.onPhase?.("fallback", resolved.model.id);
	const outcome = await classifyWithModel(
		env.host,
		env.signal,
		env.complete,
		resolved.model,
		actionLine,
		resolved.thinking,
		denyPathsActive,
		FALLBACK_TIMEOUT_MS,
		state.userRules.classifierRules,
		redact,
		// item 7: the fallback is the last step, so nothing is reserved behind it — it may use
		// whatever the shared deadline has left.
		{ deadlineAt, reserveMs: 0 },
	);
	if (outcome.source !== "model") return failed(resolved.model.id, outcome.reason);
	state.fallback.note(first?.verdict ?? null, outcome.verdict);
	const fb: FallbackAudit = {
		...base,
		model: resolved.model.id,
		verdict: outcome.verdict,
		reason: outcome.reason,
		durationMs: Date.now() - start,
		error: null,
	};
	if (mode === "shadow") return { ...demotedMark, fb, ...shadowApplied };
	// #71: a fallback may not auto-relax a demoted deny or ask; fail-closed has no
	// first-layer verdict, so an allow from the fallback is a de novo ruling.
	if (trigger.kind === "demotion" && (first?.verdict === "deny" || first?.verdict === "ask") && outcome.verdict === "allow") {
		return {
			demoted: true,
			fb: { ...fb, effective: "ask" },
			effective: {
				verdict: "ask",
				reason: `${outcome.reason} (first layer said ${first!.verdict} at confidence ${trigger.confidence}%; second opinion allows — your call)`,
				source: "classifier",
			},
		};
	}
	return {
		...demotedMark,
		fb: { ...fb, effective: outcome.verdict },
		effective: { verdict: outcome.verdict, reason: outcome.reason, source: "classifier" },
	};
}

/** Subagent gate: resolve an ask with no human answer. The UI-free counterpart of the
 *  cascade. Only an explicit second-model allow in enforce mode permits the call; every other outcome
 *  denies, and a shadow-mode opinion is recorded but never applied.
 *  Asks that did not come from the classifier (protected path, rule/fail-closed asks that
 *  exist only under autoDeny:false) never reach the model: `autoResolve` is "deny" there. */
export async function resolveAskWithoutHuman(
	state: SessionState,
	env: AdjudicateEnv,
	v: Verdict,
	actionLine: string,
): Promise<{ verdict: "allow" | "deny"; reason: string; fb?: FallbackAudit }> {
	// item 6c (Phase 6; ADR-0010): while the user's own policy failed to load, a genuine
	// model-originated allow is withheld — no human answered, so the ask cannot be escalated
	// and degrades straight to a deny, named for the degraded state. Plain denials below are
	// unchanged: they never granted anything. (There is no Verdict.source seam here: this
	// path never produces a Verdict, it only reports allow/deny.)
	const withhold = (modelAllowReason: string): { verdict: "allow" | "deny"; reason: string } =>
		state.policyDegraded
			? { verdict: "deny", reason: `${WITHHELD_ALLOW_PREFIX}${modelAllowReason}` }
			: { verdict: "allow", reason: modelAllowReason };
	if (v.autoResolve !== "consult") return { verdict: "deny", reason: `no human answer — ${v.reason}` };
	const rules = state.userRules;
	if (!rules.classifierFallbackModel || !env.getFallbackModel) {
		return { verdict: "deny", reason: `no human answer and no second model configured (classifierFallbackModel) — ${v.reason}` };
	}
	const start = Date.now();
	const base = { mode: rules.classifierFallbackMode, triggeredBy: "subagent-ask" as const, confidence: null };
	const resolved = env.getFallbackModel();
	if (!resolved) {
		const error = "fallback model unresolvable (not found or no configured auth)";
		return {
			verdict: "deny",
			reason: `no human answer; second model unavailable (not found or no configured auth) — ${v.reason}`,
			fb: {
				...base,
				model: rules.classifierFallbackModel,
				verdict: null,
				reason: null,
				durationMs: Date.now() - start,
				error,
				effective: "deny",
			},
		};
	}
	const outcome = await classifyWithModel(
		env.host,
		env.signal,
		env.complete,
		resolved.model,
		actionLine,
		resolved.thinking,
		rules.denyPaths.length > 0,
		FALLBACK_TIMEOUT_MS,
		rules.classifierRules,
		// item 7 boundary: the subagent ask path runs in the handler outside the root-session
		// adjudication deadline, so no budget is passed — its documented guidance stays "raise the
		// host toolCallTimeoutMs above subagentAskTimeoutMs + 60000" (docs/configuration.md).
		// The second-model prompt is a model payload like any other —
		// without this it shipped past tool calls unredacted, defeating Phase 5 (ADR-0002).
		env.redact ?? redactorFor(env.cwd, state.anchoredDenyPathBases(env.cwd)),
	);
	state.fallback.note("ask", outcome.source === "model" ? outcome.verdict : null);
	const allowed = outcome.source === "model" && outcome.verdict === "allow";
	const opinion = outcome.source === "model" ? outcome.verdict : "error";
	// Shadow mode records the second model's opinion and never lets it change the outcome, so with no human
	// the ask denies whatever the model said.
	const result: { verdict: "allow" | "deny"; reason: string } =
		rules.classifierFallbackMode === "shadow"
			? {
					verdict: "deny",
					reason: `no human answer; classifierFallbackMode is shadow, so the second model's opinion (${opinion}) is recorded only — ${v.reason}`,
				}
			: allowed
				? withhold(`second model allows: ${outcome.reason}`)
				: { verdict: "deny", reason: `second model did not approve (${opinion}): ${outcome.reason}` };
	return {
		...result,
		fb: {
			...base,
			model: resolved.model.id,
			verdict: outcome.source === "model" ? outcome.verdict : null,
			reason: outcome.source === "model" ? outcome.reason : null,
			durationMs: Date.now() - start,
			error: outcome.source === "model" ? null : outcome.reason,
			effective: result.verdict,
		},
	};
}

/**
 * Pipeline implementation: built-in floor → user deny → denyPaths ask → user allow
 * → gray-zone classifier. Ask degradation and fail-closed handling live here; the
 * handler presents verdicts using source alone. Exported for tests (#35).
 */
/** [pi-verdict local patch: autoDeny] reason suffix on asks that would have been auto-denies */
const AUTO_DENY_OFF_SUFFIX = " (autoDeny is off: this would have been denied — your call)";

/** item 6c (ADR-0010): shared naming for a withheld model-originated allow — all three
 *  conversion sites (gray first layer, fail-closed cascade, subagent second model) build
 *  their reason from this prefix. */
const WITHHELD_ALLOW_PREFIX = "policy degraded: allow withheld (ADR-0010) — ";

/** item 6c (ADR-0010): the one predicate the conversion sites share — the policy is broken
 *  AND this result would have been an allow, so it is withheld (an ask, or a denial where
 *  no human can be asked). */
const withholdsModelAllow = (policyDegraded: boolean, verdict: "allow" | "ask" | "deny" | undefined): boolean =>
	policyDegraded && verdict === "allow";

export async function adjudicate(
	state: SessionState,
	call: { toolName: string; input: Record<string, unknown> },
	env: AdjudicateEnv,
): Promise<Verdict> {
	// The call-level check is strict (path-word boundaries): a match there is a hard ask, unlike
	// the wide transcript redactor below, where over-redaction is harmless.
	const rule = classifyByRules(
		call.toolName,
		call.input,
		env.cwd,
		state.userRules,
		state.prot,
		state.anchoredDenyPathBases(env.cwd),
		state.policyDegraded, // item 6c (Phase 6): suspend user allow/tools while the policy is degraded (ADR-0010)
		redactorFor(env.cwd, state.anchoredDenyPathBases(env.cwd), HOST_REDACTION_PLATFORM, true),
	);
	if (rule.verdict === "allow") return { verdict: "allow", reason: rule.reason ?? "", source: "rule", degraded: false };
	if (rule.verdict === "deny") {
		if (!rule.selfProtect && !state.userRules.autoDeny && env.hasUI)
			return { verdict: "ask", reason: (rule.reason ?? "") + AUTO_DENY_OFF_SUFFIX, source: "rule", degraded: false, autoResolve: "deny" };
		return { verdict: "deny", reason: rule.reason ?? "", source: "rule", degraded: false };
	}

	// #62: the audit surface widens to protected-path asks (their user answers grade the
	// denyPaths rules); rule allow/deny stay unaudited (no corpus value, #54). Record
	// building is split from appending: an interactive ask returns via pendingAudit and the
	// handler appends after the confirm resolves (with the ground truth); everything else
	// appends immediately. Recording stays observe-only — it never changes a verdict; write
	// failures stay fail-soft in the sink and surface once via drainWarning.
	// item 6a (Phase 4): the action under review is never elided — actionCallLine is exempt
	// from toolCallLine's MAX_ENTRY_CHARS cap (an over-cap action already returned its own ask
	// above, inside classifyByRules, so overCap is always false by the time control reaches
	// here; discarded rather than re-asserted to avoid a redundant, easy-to-drift invariant).
	const { line: actionLine } = actionCallLine(call.toolName, call.input);
	const buildRecord = (
		v: Pick<AuditRecord, "verdict" | "reason" | "source" | "degraded">,
		raw: ClassifierOutcome["auditRaw"] | null,
	): AuditRecord => ({
		ts: new Date().toISOString(),
		sessionId: env.host.getSessionId(),
		cwd: env.cwd,
		model: raw?.modelId ?? null,
		tool: call.toolName,
		input: call.input,
		actionLine,
		thinking: raw?.thinking ?? null,
		transcript: raw?.transcript ?? null,
		rawResponse: raw?.rawResponse ?? null,
		...v,
	});

	if (rule.verdict === "ask") {
		const askSource = rule.askSource ?? "protected-path";
		// denyPaths match → terminal ask (ADR-0002): exception for the declaring user to decide; no UI degrades to deny
		if (env.hasUI) {
			const ppRecord: AuditRecord = {
				...buildRecord({ verdict: "ask", reason: rule.reason ?? "", source: askSource, degraded: false }, null),
				detail: rule.detail,
			};
			return {
				verdict: "ask",
				reason: rule.reason ?? "",
				detail: rule.detail,
				source: askSource,
				degraded: false,
				autoResolve: "deny",
				...(state.audit ? { pendingAudit: ppRecord } : {}),
			};
		}
		// headless: the ask degrades to deny — recorded like the gray-zone rule (the effective post-degradation verdict is what lands in the record)
		state.audit?.append({
			...buildRecord({ verdict: "deny", reason: rule.reason ?? "", source: askSource, degraded: true }, null),
			detail: rule.detail,
		});
		return { verdict: "deny", reason: rule.reason ?? "", detail: rule.detail, source: askSource, degraded: true };
	}

	// Gray zone → classifier; no available model → fail-closed

	// item 7: one end-to-end deadline for the whole gray-zone decision, below omp's default
	// toolCallTimeoutMs (30 000 ms) — without it the documented worst case (25 + 25 + 15 + 15 s)
	// outlives the host bound and the handler is killed mid-cascade. Computed here so the no-model
	// fail-closed path shares the same deadline with the normal path.
	const deadlineAt = Date.now() + (env.adjudicationBudgetMs ?? ADJUDICATION_BUDGET_MS);
	const resolved = env.getModel();
	// One redactor per adjudication, built from cwd + the anchored denyPaths bases, passed to every
	// model call that renders a transcript from this session's branch (first layer, cascade
	// fallback, and the EXPLAIN-GATE path, which builds its own from state).
	const redact = env.redact ?? redactorFor(env.cwd, state.anchoredDenyPathBases(env.cwd));
	// The strict check above decides the deterministic ask; the wide one still keeps a protected
	// path out of every model payload, so a call it matches reaches a model only as the marker.
	// The audit record keeps the raw action line (ADR-0002: audit never leaves the machine).
	const modelActionLine = redact(call.input) ? PROTECTED_PATH_MARKER : actionLine;
	if (!resolved) {
		const reason = "no classifier model available (fail-closed)";
		// #71: a fail-closed default deny is not a negative judgment. Record the applied
		// fallback verdict when one exists; a headless ask is recorded as its degraded deny.
		const cascade = await runConfidenceCascade(
			state,
			env,
			null,
			{ kind: "fail-closed" },
			state.userRules.denyPaths.length > 0,
			modelActionLine,
			redact,
			deadlineAt,
		);
		const eff = cascade.effective;
		// item 6c (Phase 6; ADR-0010): while the user's own policy failed to load, a
		// model-originated allow (the cascade's second model here) becomes an ask — the
		// normal headless ask→deny degradation applies unchanged.
		const effDegraded = withholdsModelAllow(state.policyDegraded, eff?.verdict);
		const effVerdict = effDegraded ? ("ask" as const) : eff?.verdict;
		const effReason = (effDegraded && eff ? `${WITHHELD_ALLOW_PREFIX}${eff.reason}` : eff?.reason) ?? reason;
		const effSource: VerdictSource = effDegraded ? "degraded-policy" : (eff?.source ?? "fail-closed");
		const effAskHeadless = effVerdict === "ask" && !env.hasUI;
		// What the audit record itself shows: an interactive ask records as the ask that ran;
		// a headless (or absent) result records the deny that was applied.
		let fcVerdict: AuditRecord["verdict"] = "deny";
		if (effVerdict === "allow") fcVerdict = "allow";
		else if (effVerdict === "ask" && !effAskHeadless) fcVerdict = "ask";
		const fcRecord = buildRecord(
			{
				verdict: fcVerdict,
				reason: effReason,
				// AuditRecord vocabulary (#54): the record's origin stays "fail-closed" (the
				// no-first-model origin) unless the degraded-policy conversion fired; it never
				// carries "model"/"classifier" here — that is the gray path's own record.
				source: effDegraded ? "degraded-policy" : "fail-closed",
				degraded: effAskHeadless,
			},
			null,
		);
		if (cascade.fb) fcRecord.fallback = cascade.fb;
		if (effVerdict === "ask" && env.hasUI) {
			return {
				verdict: "ask",
				reason: effReason,
				source: effSource,
				degraded: false,
				autoResolve: "deny",
				...(state.audit ? { pendingAudit: fcRecord } : {}),
			};
		}
		if (effVerdict !== "allow" && !state.userRules.autoDeny && env.hasUI) {
			return {
				verdict: "ask",
				reason: effReason + AUTO_DENY_OFF_SUFFIX,
				source: effSource,
				degraded: false,
				autoResolve: "deny",
				...(state.audit ? { pendingAudit: fcRecord } : {}),
			};
		}
		state.audit?.append(fcRecord);
		if (effVerdict === "allow") return { verdict: "allow", reason: effReason, source: "classifier", degraded: false };
		if (effVerdict === "deny") return { verdict: "deny", reason: effReason, source: effSource, degraded: effAskHeadless };
		// ask: no UI degrades it to deny — but only a genuine ask conversion is "degraded";
		// a missing cascade result (no effective verdict at all) is a plain fail-closed deny.
		if (effVerdict === "ask") return { verdict: "deny", reason: effReason, source: effSource, degraded: true };
		return { verdict: "deny", reason, source: "fail-closed", degraded: false };
	}

	env.onPhase?.("classifier", resolved.model.id);
	// item 7: hold time back for the fallback only when one is configured.
	const reserveMs = state.userRules.classifierFallbackModel && env.getFallbackModel ? FALLBACK_TIMEOUT_MS : 0;
	const outcome = await classifyWithModel(
		env.host,
		env.signal,
		env.complete,
		resolved.model,
		modelActionLine,
		resolved.thinking,
		state.userRules.denyPaths.length > 0,
		CLASSIFIER_TIMEOUT_MS,
		state.userRules.classifierRules,
		redact,
		{ deadlineAt, reserveMs },
	);

	// #67 cascade: a confidence-floor demotion, or a classifier fail-closed outcome
	// (the first layer produced no verdict)
	const demotion = confidenceDemotion(outcome, state.userRules);
	const cascade =
		demotion || outcome.source === "fail-closed"
			? await runConfidenceCascade(
					state,
					env,
					demotion ? { verdict: outcome.verdict, reason: outcome.reason } : null,
					demotion ? { kind: "demotion", confidence: demotion.confidence } : { kind: "fail-closed" },
					state.userRules.denyPaths.length > 0,
					modelActionLine,
					redact,
					deadlineAt,
				)
			: {};
	let effVerdict = cascade.effective?.verdict ?? outcome.verdict;
	let effReason = cascade.effective?.reason ?? outcome.reason;
	let effSource: VerdictSource = cascade.effective?.source ?? "classifier";
	// item 6c (Phase 6; ADR-0010): while the user's own policy failed to load, a
	// model-originated allow (first layer or the cascade's second model) becomes an ask —
	// the normal headless ask→deny degradation below applies unchanged.
	const effDegraded = withholdsModelAllow(state.policyDegraded, effVerdict);
	if (effDegraded) {
		effReason = `${WITHHELD_ALLOW_PREFIX}${effReason}`;
		effSource = "degraded-policy";
		effVerdict = "ask";
	}

	// #62/#67: top-level keeps first-layer semantics except that a fail-closed origin
	// rescued by an enforcing fallback records its applied verdict, not the default deny.
	const appliedAskHeadless = !env.hasUI && effVerdict === "ask";
	const fcRescued = cascade.effective !== undefined && outcome.source === "fail-closed";
	const grayRecord = buildRecord(
		{
			verdict: appliedAskHeadless ? "deny" : fcRescued ? effVerdict : outcome.verdict,
			reason: fcRescued ? effReason : outcome.reason,
			// item 6c: the record names the degraded-policy origin when the conversion fired;
			// otherwise the first layer's own outcome (model/fail-closed vocabulary, #54).
			source: effDegraded ? "degraded-policy" : outcome.source,
			degraded: appliedAskHeadless,
		},
		outcome.auditRaw ?? null,
	);
	if (cascade.demoted) grayRecord.demoted = true;
	if (cascade.fb) grayRecord.fallback = cascade.fb;
	// #62: an interactive ask defers the append to the handler finalize (ground truth);
	// every other outcome appends immediately as before
	if (env.hasUI && (effVerdict === "ask" || (effVerdict === "deny" && !state.userRules.autoDeny))) {
		// Subagent gate: how this ask resolves without a human. A cascaded ask (the second model already
		// ruled) is never auto-allowed: its only route to an allow is the ADR-0004 carve-out, which turns a
		// demoted ask or deny plus a second-model allow into an ask so that a human decides. Only an ask the
		// cascade never reached may still be put to the second model.
		const autoResolve: NonNullable<Verdict["autoResolve"]> =
			effVerdict === "deny" || effSource !== "classifier" || cascade.fb ? "deny" : "consult";
		return {
			verdict: "ask",
			reason: effVerdict === "deny" ? effReason + AUTO_DENY_OFF_SUFFIX : effReason,
			source: effSource,
			degraded: false,
			autoResolve,
			...(state.audit ? { pendingAudit: grayRecord } : {}),
		};
	}
	state.audit?.append(grayRecord);
	if (effVerdict === "allow") return { verdict: "allow", reason: effReason, source: effSource, degraded: false };
	if (effVerdict === "deny") return { verdict: "deny", reason: effReason, source: effSource, degraded: false };
	// ask: no UI degrades it to deny.
	return { verdict: "deny", reason: effReason, source: effSource, degraded: true };
}
