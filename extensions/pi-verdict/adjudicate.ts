import { parseJevConfidence } from "../jev-adapter.ts";
import { actionCallLine } from "./action-line.ts";
import type { AuditRecord, FallbackAudit } from "./audit.ts";
import {
	ADJUDICATION_BUDGET_MS,
	CLASSIFIER_TIMEOUT_MS,
	type ClassifierOutcome,
	classifyWithModel,
	FALLBACK_TIMEOUT_MS,
	type ModelCall,
	type VerdictWord,
} from "./classifier.ts";
import type { CompletionFn } from "./completion.ts";
import type { UserRules } from "./config.ts";
import type { HostKind } from "./floor.ts";
import type { ModelChoice, PipelineHost } from "./model-call.ts";
import { HOST_REDACTION_PLATFORM, PROTECTED_PATH_MARKER, type RedactorFn, redactorFor } from "./redaction.ts";
import { classifyByRules } from "./rules.ts";
import type { RuleResult } from "./shell.ts";
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

interface VerdictBase {
	readonly reason: string;
	readonly source: VerdictSource;
}

export interface AllowVerdict extends VerdictBase {
	readonly verdict: "allow";
	readonly degraded: false;
}

export interface DenyVerdict extends VerdictBase {
	readonly verdict: "deny";
	/** True when the deny is an ask that no human could answer. */
	readonly degraded: boolean;
	/** The matched protected path: UI-only, never sent to the agent or a model (ADR-0002). */
	readonly detail?: string;
}

export interface AskVerdict extends VerdictBase {
	readonly verdict: "ask";
	readonly degraded: false;
	/** The matched protected path: UI-only, never sent to the agent or a model (ADR-0002). */
	readonly detail?: string;
	/** How the ask resolves without a human: "consult" puts it to the second model; "deny" denies it,
	 *  because the cascade already ruled or no model may resolve it. */
	readonly autoResolve: "consult" | "deny";
	/** The ask's audit record, appended by the handler once the human answers (#62); unset with audit off. */
	readonly pendingAudit?: Readonly<AuditRecord>;
}

/** Pipeline output for one tool call. */
export type Verdict = AllowVerdict | DenyVerdict | AskVerdict;

/** Per-call environment: host capabilities unrelated to presentation. model is lazily evaluated through getModel—preserving the original “resolve only for gray zone”
 *  behavior (fallback warnings do not appear on calls already decided by rules); null → fail-closed.
 *  getFallbackModel(#63) is even lazier: resolve only after the gate is triggered. */
export interface AdjudicateEnv {
	cwd: string;
	hasUI: boolean;
	getModel: () => ModelChoice;
	complete: CompletionFn;
	host: PipelineHost;
	/** Which host runs the gate; the rule layer grades `xd://` targets by it. */
	hostKind: HostKind;
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

/** A tool call as the pipeline receives it. */
interface ToolCall {
	readonly toolName: string;
	readonly input: Record<string, unknown>;
}

/** One adjudication's inputs, shared by every step that builds its verdict or its audit record. */
interface Adjudication {
	readonly state: SessionState;
	readonly env: AdjudicateEnv;
	readonly call: ToolCall;
	/** The uncapped action line the audit record keeps; models see `ModelCall.actionLine` instead. */
	readonly actionLine: string;
}

/** A decision before presentation: what to do, why, and the source the presentation keys on. */
interface Ruling {
	readonly verdict: VerdictWord;
	readonly reason: string;
	readonly source: VerdictSource;
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

const WITHHELD_ALLOW_PREFIX = "policy degraded: allow withheld (ADR-0010) — ";

/** Applies the degraded-policy rule to a model's ruling (ADR-0010): while the user's own policy failed to
 *  load, an allow becomes `withheldAs`, an ask where a human can answer and a deny where none can, with a
 *  reason naming the state. Every other ruling passes unchanged. */
function withholdModelAllow<V extends VerdictWord, W extends "ask" | "deny">(
	policyDegraded: boolean,
	ruling: { verdict: V; reason: string },
	withheldAs: W,
): { verdict: V | W; reason: string; withheld: boolean } {
	if (!policyDegraded || ruling.verdict !== "allow") return { ...ruling, withheld: false };
	return { verdict: withheldAs, reason: `${WITHHELD_ALLOW_PREFIX}${ruling.reason}`, withheld: true };
}

/** Names a model-path ruling in both vocabularies. The verdict's source drives presentation; the audit
 *  record's source keeps the first layer's own origin (#54). A withheld allow is degraded-policy in both. */
function modelPathSources(
	withheld: boolean,
	presented: "classifier" | "fail-closed",
	origin: ClassifierOutcome["source"],
): { verdict: VerdictSource; record: AuditRecord["source"] } {
	return withheld ? { verdict: "degraded-policy", record: "degraded-policy" } : { verdict: presented, record: origin };
}

/** The model call every classifier consulted for this action shares. */
function modelCallFor(state: SessionState, env: AdjudicateEnv, actionLine: string, redact: RedactorFn): ModelCall {
	return {
		host: env.host,
		signal: env.signal,
		complete: env.complete,
		actionLine,
		denyPathsActive: state.userRules.denyPaths.length > 0,
		classifierRules: state.userRules.classifierRules,
		redact,
	};
}

/** Returns the audit record for this adjudication's call with the given outcome. */
function buildRecord(
	a: Adjudication,
	v: Pick<AuditRecord, "verdict" | "reason" | "source" | "degraded">,
	raw: ClassifierOutcome["auditRaw"] | null,
	extra: Pick<AuditRecord, "detail" | "demoted" | "fallback"> = {},
): Readonly<AuditRecord> {
	return {
		ts: new Date().toISOString(),
		sessionId: a.env.host.getSessionId(),
		cwd: a.env.cwd,
		model: raw?.modelId ?? null,
		tool: a.call.toolName,
		input: a.call.input,
		actionLine: a.actionLine,
		thinking: raw?.thinking ?? null,
		transcript: raw?.transcript ?? null,
		rawResponse: raw?.rawResponse ?? null,
		...v,
		...extra,
	};
}

/** Who triggered a fallback consult, as its audit entry records it. */
type FallbackTrigger = Pick<FallbackAudit, "mode" | "triggeredBy" | "confidence">;

/** Returns the audit entry of one fallback consult: the model's ruling, or the error when it gave none. */
function fallbackAudit(trigger: FallbackTrigger, model: string, startedAt: number, ruling: ClassifierOutcome | string): FallbackAudit {
	const answered = typeof ruling !== "string" && ruling.source === "model" ? ruling : null;
	return {
		...trigger,
		model,
		verdict: answered?.verdict ?? null,
		reason: answered?.reason ?? null,
		durationMs: Date.now() - startedAt,
		error: answered ? null : typeof ruling === "string" ? ruling : ruling.reason,
	};
}

const FALLBACK_UNRESOLVABLE = "fallback model unresolvable (not found or no configured auth)";

interface CascadeResult {
	/** set whenever the confidence floor fired (with or without a fallback) */
	demoted?: true;
	/** audit material; present when the fallback was consulted */
	fb?: FallbackAudit;
	/** the applied outcome when the cascade changes it (pre-degradation — the caller's
	 *  tail applies the usual headless ask → deny rule) */
	effective?: { verdict: VerdictWord; reason: string; source: "classifier" | "fail-closed" };
}

/** What sent a call to the cascade: a demoted first-layer ruling, or a first layer that gave none. */
type CascadeTrigger = { kind: "demotion"; confidence: number; first: { verdict: VerdictWord; reason: string } } | { kind: "fail-closed" };

/** #67: run the cascade for one triggered call. Semantics:
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
	call: ModelCall,
	trigger: CascadeTrigger,
	deadlineAt: number,
): Promise<CascadeResult> {
	const rules = state.userRules;
	const first = trigger.kind === "demotion" ? trigger.first : null;
	const demotionAsk = (t: Extract<CascadeTrigger, { kind: "demotion" }>): CascadeResult["effective"] => ({
		verdict: "ask",
		reason: `${t.first.reason} (confidence ${t.confidence}% is below your classifierMinConfidence of ${rules.classifierMinConfidence}%)`,
		source: "classifier",
	});
	const getFb = env.getFallbackModel;
	if (!rules.classifierFallbackModel || !getFb) {
		// A fail-closed without a fallback keeps its deny; a demotion asks the human
		return trigger.kind === "demotion" ? { demoted: true, effective: demotionAsk(trigger) } : {};
	}
	const mode = rules.classifierFallbackMode;
	const start = Date.now();
	const audited: FallbackTrigger = {
		mode,
		triggeredBy: trigger.kind === "demotion" ? "confidence" : "fail-closed",
		confidence: trigger.kind === "demotion" ? trigger.confidence : null,
	};
	const demotedMark = trigger.kind === "demotion" ? ({ demoted: true } as const) : {};
	const shadowApplied = trigger.kind === "demotion" ? { effective: demotionAsk(trigger) } : {};
	const failed = (model: string, error: string): CascadeResult => {
		state.fallback.note(first?.verdict ?? null, null);
		const fb = fallbackAudit(audited, model, start, error);
		if (mode === "shadow") return { ...demotedMark, fb, ...shadowApplied };
		return {
			...demotedMark,
			fb: { ...fb, effective: "ask" },
			effective: { verdict: "ask", reason: "fallback classifier unavailable (first layer abstained) — your call", source: "fail-closed" },
		};
	};
	const resolved = getFb();
	if (!resolved) return failed(rules.classifierFallbackModel, FALLBACK_UNRESOLVABLE);
	env.onPhase?.("fallback", resolved.model.id);
	// The fallback is the last step, so it may use whatever the shared deadline has left.
	const outcome = await classifyWithModel(call, resolved, FALLBACK_TIMEOUT_MS, { deadlineAt, reserveMs: 0 });
	if (outcome.source !== "model") return failed(resolved.model.id, outcome.reason);
	state.fallback.note(first?.verdict ?? null, outcome.verdict);
	const fb = fallbackAudit(audited, resolved.model.id, start, outcome);
	if (mode === "shadow") return { ...demotedMark, fb, ...shadowApplied };
	// #71: a fallback may not auto-relax a demoted deny or ask; fail-closed has no
	// first-layer verdict, so an allow from the fallback is a de novo ruling.
	if (trigger.kind === "demotion" && trigger.first.verdict !== "allow" && outcome.verdict === "allow") {
		return {
			demoted: true,
			fb: { ...fb, effective: "ask" },
			effective: {
				verdict: "ask",
				reason: `${outcome.reason} (first layer said ${trigger.first.verdict} at confidence ${trigger.confidence}%; second opinion allows — your call)`,
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
 *  exist only under autoDeny:false) never reach the model: `autoResolve` is "deny" there.
 *  `deadlineAt` (epoch ms) bounds the second model by the host's handler budget; past it the model fails closed. */
export async function resolveAskWithoutHuman(
	state: SessionState,
	env: AdjudicateEnv,
	v: Verdict,
	actionLine: string,
	deadlineAt?: number,
): Promise<{ verdict: "allow" | "deny"; reason: string; fb?: FallbackAudit }> {
	if (v.verdict !== "ask" || v.autoResolve !== "consult") return { verdict: "deny", reason: `no human answer — ${v.reason}` };
	const rules = state.userRules;
	if (!rules.classifierFallbackModel || !env.getFallbackModel) {
		return { verdict: "deny", reason: `no human answer and no second model configured (classifierFallbackModel) — ${v.reason}` };
	}
	const start = Date.now();
	const audited: FallbackTrigger = { mode: rules.classifierFallbackMode, triggeredBy: "subagent-ask", confidence: null };
	const resolved = env.getFallbackModel();
	if (!resolved) {
		return {
			verdict: "deny",
			reason: `no human answer; second model unavailable (not found or no configured auth) — ${v.reason}`,
			fb: { ...fallbackAudit(audited, rules.classifierFallbackModel, start, FALLBACK_UNRESOLVABLE), effective: "deny" },
		};
	}
	// The second-model prompt is a model payload like any other, so it is redacted too (ADR-0002).
	const call = modelCallFor(state, env, actionLine, env.redact ?? redactorFor(env.cwd, state.anchoredDenyPathBases(env.cwd)));
	const outcome = await classifyWithModel(
		call,
		resolved,
		FALLBACK_TIMEOUT_MS,
		deadlineAt === undefined ? undefined : { deadlineAt, reserveMs: 0 },
	);
	state.fallback.note("ask", outcome.source === "model" ? outcome.verdict : null);
	const allowed = outcome.source === "model" && outcome.verdict === "allow";
	const opinion = outcome.source === "model" ? outcome.verdict : "error";
	// Shadow mode records the second model's opinion and never lets it change the outcome, so with no human
	// the ask denies whatever the model said.
	const { verdict, reason }: { verdict: "allow" | "deny"; reason: string } =
		rules.classifierFallbackMode === "shadow"
			? {
					verdict: "deny",
					reason: `no human answer; classifierFallbackMode is shadow, so the second model's opinion (${opinion}) is recorded only — ${v.reason}`,
				}
			: allowed
				? // No human can answer, so a withheld allow denies.
					withholdModelAllow(state.policyDegraded, { verdict: "allow", reason: `second model allows: ${outcome.reason}` }, "deny")
				: { verdict: "deny", reason: `second model did not approve (${opinion}): ${outcome.reason}` };
	return { verdict, reason, fb: { ...fallbackAudit(audited, resolved.model.id, start, outcome), effective: verdict } };
}

/** [pi-verdict local patch: autoDeny] reason suffix on asks that would have been auto-denies */
const AUTO_DENY_OFF_SUFFIX = " (autoDeny is off: this would have been denied — your call)";

/** How a ruling settles into a verdict. */
interface Settlement {
	readonly ruling: Ruling;
	/** Builds the audit record, told whether the ruling is an ask no human can answer; null leaves the call
	 *  unaudited. */
	readonly record: ((headlessAsk: boolean) => Readonly<AuditRecord>) | null;
	readonly autoResolve: AskVerdict["autoResolve"];
	readonly detail?: string;
	/** False for a deny that `autoDeny: false` may not turn into an ask (self-protection, ADR-0005). */
	readonly autoDenyExempt: boolean;
}

/** Turns a ruling into the verdict the handler presents. With a UI, an ask stays an ask, and so does a deny
 *  while `autoDeny` is off; the ask carries its audit record for the handler to finish. Without a UI an ask
 *  fails closed to a deny marked `degraded`, and every other record is appended here. */
function settle(a: Adjudication, s: Settlement): Verdict {
	const { state, env } = a;
	const { verdict, reason, source } = s.ruling;
	const headlessAsk = verdict === "ask" && !env.hasUI;
	const record = s.record?.(headlessAsk) ?? null;
	const detail = s.detail === undefined ? {} : { detail: s.detail };
	const autoDenyOff = verdict === "deny" && s.autoDenyExempt && !state.userRules.autoDeny;
	if (env.hasUI && (verdict === "ask" || autoDenyOff)) {
		return {
			verdict: "ask",
			reason: verdict === "deny" ? reason + AUTO_DENY_OFF_SUFFIX : reason,
			...detail,
			source,
			degraded: false,
			autoResolve: s.autoResolve,
			...(state.audit && record ? { pendingAudit: record } : {}),
		};
	}
	if (record) state.audit?.append(record);
	switch (verdict) {
		case "allow":
			return { verdict: "allow", reason, source, degraded: false };
		case "deny":
			return { verdict: "deny", reason, ...detail, source, degraded: false };
		case "ask":
			return { verdict: "deny", reason, ...detail, source, degraded: true };
		default: {
			const unhandled: never = verdict;
			throw new Error(`unhandled ruling: ${unhandled}`);
		}
	}
}

/** Settles a rule-layer ask: a protected-path or rule ask that only the user who declared it may answer
 *  (ADR-0002), so it never reaches a model. Its record is the first audited rule-layer outcome (#62). */
function adjudicateRuleAsk(a: Adjudication, rule: RuleResult): Verdict {
	const reason = rule.reason ?? "";
	const source = rule.askSource ?? "protected-path";
	return settle(a, {
		ruling: { verdict: "ask", reason, source },
		record: (headlessAsk) =>
			buildRecord(a, { verdict: headlessAsk ? "deny" : "ask", reason, source, degraded: headlessAsk }, null, { detail: rule.detail }),
		autoResolve: "deny",
		detail: rule.detail,
		autoDenyExempt: true,
	});
}

/** Settles a gray call when no classifier model is available: the fallback's ruling applies when there is
 *  one, since a missing first layer is no negative judgment (#71); otherwise it fails closed. */
async function adjudicateWithoutModel(a: Adjudication, modelCall: ModelCall, deadlineAt: number): Promise<Verdict> {
	const reason = "no classifier model available (fail-closed)";
	const cascade = await runConfidenceCascade(a.state, a.env, modelCall, { kind: "fail-closed" }, deadlineAt);
	const applied = withholdModelAllow(a.state.policyDegraded, cascade.effective ?? { verdict: "deny", reason }, "ask");
	const sources = modelPathSources(applied.withheld, cascade.effective?.source ?? "fail-closed", "fail-closed");
	return settle(a, {
		ruling: { verdict: applied.verdict, reason: applied.reason, source: sources.verdict },
		// The record shows the verdict applied: an interactive ask as the ask that ran, a headless one as its deny.
		record: (headlessAsk) =>
			buildRecord(
				a,
				{ verdict: headlessAsk ? "deny" : applied.verdict, reason: applied.reason, source: sources.record, degraded: headlessAsk },
				null,
				cascade.fb ? { fallback: cascade.fb } : {},
			),
		autoResolve: "deny",
		autoDenyExempt: true,
	});
}

/** How a gray-zone ask resolves without a human. Only an ask the cascade never reached may go to the
 *  second model: a cascaded ask's only route to an allow is the ADR-0004 carve-out, which a human decides. */
function autoResolveFor(ruling: Ruling, cascade: CascadeResult): AskVerdict["autoResolve"] {
	return ruling.verdict === "ask" && ruling.source === "classifier" && !cascade.fb ? "consult" : "deny";
}

/** Settles a gray call through the classifier, and through the cascade when the first layer abstains. */
async function adjudicateGrayZone(
	a: Adjudication,
	modelCall: ModelCall,
	choice: NonNullable<ModelChoice>,
	deadlineAt: number,
): Promise<Verdict> {
	const { state, env } = a;
	env.onPhase?.("classifier", choice.model.id);
	// item 7: hold time back for the fallback only when one is configured.
	const reserveMs = state.userRules.classifierFallbackModel && env.getFallbackModel ? FALLBACK_TIMEOUT_MS : 0;
	const outcome = await classifyWithModel(modelCall, choice, CLASSIFIER_TIMEOUT_MS, { deadlineAt, reserveMs });

	// #67 cascade: a confidence-floor demotion, or a classifier fail-closed outcome
	// (the first layer produced no verdict)
	const demotion = confidenceDemotion(outcome, state.userRules);
	const cascade: CascadeResult =
		demotion || outcome.source === "fail-closed"
			? await runConfidenceCascade(
					state,
					env,
					modelCall,
					demotion
						? { kind: "demotion", confidence: demotion.confidence, first: { verdict: outcome.verdict, reason: outcome.reason } }
						: { kind: "fail-closed" },
					deadlineAt,
				)
			: {};
	const applied = withholdModelAllow(state.policyDegraded, cascade.effective ?? outcome, "ask");
	const sources = modelPathSources(applied.withheld, cascade.effective?.source ?? "classifier", outcome.source);
	const ruling: Ruling = { verdict: applied.verdict, reason: applied.reason, source: sources.verdict };
	// #62/#67: the record keeps the first layer's ruling, except that a fail-closed origin
	// rescued by the fallback records the verdict applied, not the default deny.
	const rescued = cascade.effective !== undefined && outcome.source === "fail-closed";
	return settle(a, {
		ruling,
		record: (headlessAsk) =>
			buildRecord(
				a,
				{
					verdict: headlessAsk ? "deny" : rescued ? applied.verdict : outcome.verdict,
					reason: rescued ? applied.reason : outcome.reason,
					source: sources.record,
					degraded: headlessAsk,
				},
				outcome.auditRaw,
				{ ...(cascade.demoted ? { demoted: true } : {}), ...(cascade.fb ? { fallback: cascade.fb } : {}) },
			),
		autoResolve: autoResolveFor(ruling, cascade),
		autoDenyExempt: true,
	});
}

/**
 * Pipeline implementation: the rule layer, then the gray-zone classifier. Ask degradation
 * and fail-closed handling live here; the handler presents verdicts using source alone.
 * Exported for tests (#35).
 */
export async function adjudicate(state: SessionState, call: ToolCall, env: AdjudicateEnv): Promise<Verdict> {
	// The call-level check is strict (path-word boundaries): a match there is a hard ask, unlike
	// the wide transcript redactor below, where over-redaction is harmless.
	const denyPathBases = state.anchoredDenyPathBases(env.cwd);
	const rule = classifyByRules(call.toolName, call.input, {
		cwd: env.cwd,
		userRules: state.userRules,
		protectedSet: state.prot,
		denyPathBases,
		policyDegraded: state.policyDegraded,
		namesProtectedPath: redactorFor(env.cwd, denyPathBases, HOST_REDACTION_PLATFORM, true),
		host: env.hostKind,
	});
	if (rule.verdict === "allow") return { verdict: "allow", reason: rule.reason ?? "", source: "rule", degraded: false };
	// item 6a (Phase 4): the action under review is never elided — actionCallLine is exempt
	// from toolCallLine's MAX_ENTRY_CHARS cap (an over-cap action already returned its own ask
	// above, inside classifyByRules, so overCap is always false by the time control reaches
	// here; discarded rather than re-asserted to avoid a redundant, easy-to-drift invariant).
	const a: Adjudication = { state, env, call, actionLine: actionCallLine(call.toolName, call.input).line };
	switch (rule.verdict) {
		case "deny":
			// Rule allows and denies stay unaudited (#54).
			return settle(a, {
				ruling: { verdict: "deny", reason: rule.reason ?? "", source: "rule" },
				record: null,
				autoResolve: "deny",
				autoDenyExempt: !rule.selfProtect,
			});
		case "ask":
			return adjudicateRuleAsk(a, rule);
		case "gray":
			break;
		default: {
			const unhandled: never = rule.verdict;
			throw new Error(`unhandled rule verdict: ${unhandled}`);
		}
	}

	// item 7: one end-to-end deadline for the whole gray-zone decision, below omp's default
	// toolCallTimeoutMs (30 000 ms) — without it the documented worst case (25 + 25 + 15 + 15 s)
	// outlives the host bound and the handler is killed mid-cascade. Computed here so the no-model
	// fail-closed path shares the same deadline with the normal path.
	const deadlineAt = Date.now() + (env.adjudicationBudgetMs ?? ADJUDICATION_BUDGET_MS);
	const resolved = env.getModel();
	// One redactor per adjudication, built from cwd + the anchored denyPaths bases, passed to every
	// model call that renders a transcript from this session's branch (first layer, cascade
	// fallback, and the EXPLAIN-GATE path, which builds its own from state).
	const redact = env.redact ?? redactorFor(env.cwd, denyPathBases);
	// The strict check above decides the deterministic ask; the wide one still keeps a protected
	// path out of every model payload, so a call it matches reaches a model only as the marker.
	// The audit record keeps the raw action line (ADR-0002: audit never leaves the machine).
	const modelCall = modelCallFor(state, env, redact(call.input) ? PROTECTED_PATH_MARKER : a.actionLine, redact);
	if (!resolved) return adjudicateWithoutModel(a, modelCall, deadlineAt);
	return adjudicateGrayZone(a, modelCall, resolved, deadlineAt);
}
