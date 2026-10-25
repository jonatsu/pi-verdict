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
// Adjudication pipeline: the UI-free path from a tool call to its verdict
// ============================================================================

/** Which presentation a verdict gets. `classifier` covers the first layer's own fail-closed deny;
 *  `fail-closed` means no classifier model was available or the fallback failed; `degraded-policy` is a
 *  model allow withheld while the user's own policy failed to load (ADR-0010). */
export type VerdictSource = "rule" | "protected-path" | "classifier" | "fail-closed" | "degraded-policy";

interface VerdictBase {
	readonly reason: string;
	readonly source: VerdictSource;
}

export interface AllowVerdict extends VerdictBase {
	readonly verdict: "allow";
	/** Only the rule layer and a model allow; a withheld model allow is an ask or a deny. */
	readonly source: "rule" | "classifier";
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

/** The host capabilities one adjudication uses, injected so tests can fake them. The models resolve
 *  lazily, so a call the rule layer decides raises no model warning: `getModel` only for the gray zone,
 *  where null fails closed, and `getFallbackModel` only once the cascade fires (#63). */
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
	/** The session's transcript redactor; when unset, adjudicate builds it from the anchored denyPaths bases. */
	redact?: RedactorFn;
	/** Test seam for the end-to-end budget: production always uses `ADJUDICATION_BUDGET_MS`. */
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
type Ruling =
	| { readonly verdict: "allow"; readonly reason: string; readonly source: AllowVerdict["source"] }
	| { readonly verdict: "ask" | "deny"; readonly reason: string; readonly source: VerdictSource };

/** Returns a model-path ruling with its presentation source; an allow always comes from a model, so it
 *  presents as the classifier's. */
function modelRuling(applied: { verdict: VerdictWord; reason: string }, source: VerdictSource): Ruling {
	if (applied.verdict === "allow") return { verdict: "allow", reason: applied.reason, source: "classifier" };
	return { verdict: applied.verdict, reason: applied.reason, source };
}

/** Returns the confidence when the first layer's ruling falls below `classifierMinConfidence`, so the call
 *  cascades (#67), else null. Only a jev reason carries a confidence, so other first layers never demote. */
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
	/** Set whenever the confidence floor fired, with or without a fallback. */
	demoted?: true;
	/** The fallback's audit entry; present when the fallback was consulted. */
	fb?: FallbackAudit;
	/** The ruling the cascade applies, when it changes the outcome; `settle` still degrades a headless ask. */
	effective?: { verdict: VerdictWord; reason: string; source: "classifier" | "fail-closed" };
}

/** What sent a call to the cascade: a demoted first-layer ruling, or a first layer that gave none. */
type CascadeTrigger = { kind: "demotion"; confidence: number; first: { verdict: VerdictWord; reason: string } } | { kind: "fail-closed" };

/** Runs the confidence cascade for one triggered call (#67, ADR-0004). Without a fallback, a demotion asks
 *  the human and a fail-closed deny stands. In shadow mode the fallback's opinion is only recorded. In
 *  enforce mode it rules anew, except that it may not relax a demoted deny or ask to an allow, which then
 *  asks the human (#71); a fallback that fails or cannot be resolved also asks the human. */
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

/** Resolves a subagent's ask that no human answered. Fails closed: only an explicit second-model allow in
 *  enforce mode permits the call, and only for an ask whose `autoResolve` is "consult"; every other outcome
 *  denies, including a shadow-mode opinion. `deadlineAt` (epoch ms) bounds the second model by the host's
 *  handler budget. */
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
	let ruling: { verdict: "allow" | "deny"; reason: string };
	if (rules.classifierFallbackMode === "shadow") {
		// Shadow mode never lets the second model change the outcome, so with no human the ask denies.
		ruling = {
			verdict: "deny",
			reason: `no human answer; classifierFallbackMode is shadow, so the second model's opinion (${opinion}) is recorded only — ${v.reason}`,
		};
	} else if (allowed) {
		// No human can answer, so a withheld allow denies.
		ruling = withholdModelAllow(state.policyDegraded, { verdict: "allow", reason: `second model allows: ${outcome.reason}` }, "deny");
	} else {
		ruling = { verdict: "deny", reason: `second model did not approve (${opinion}): ${outcome.reason}` };
	}
	const { verdict, reason } = ruling;
	return { verdict, reason, fb: { ...fallbackAudit(audited, resolved.model.id, start, outcome), effective: verdict } };
}

/** [pi-verdict local patch: autoDeny] reason suffix on asks that would have been auto-denies */
const AUTO_DENY_OFF_SUFFIX = " (autoDeny is off: this would have been denied — your call)";

/** The audit record of a ruling, before `settle` maps a headless ask to its deny. */
interface RecordDraft {
	/** The verdict the record shows when a human can answer, or when the ruling is no ask. */
	readonly verdict: VerdictWord;
	readonly reason: string;
	readonly source: AuditRecord["source"];
	readonly raw: ClassifierOutcome["auditRaw"] | null;
	readonly extra?: Pick<AuditRecord, "detail" | "demoted" | "fallback">;
}

/** How a ruling settles into a verdict. */
interface Settlement {
	readonly ruling: Ruling;
	/** The ruling's audit record; null leaves the call unaudited. */
	readonly record: RecordDraft | null;
	readonly autoResolve: AskVerdict["autoResolve"];
	readonly detail?: string;
	/** Whether `autoDeny: false` may turn this deny into an ask; default true. A self-protection deny sets
	 *  false, so it stays a deny (ADR-0005). */
	readonly autoDenyApplies?: boolean;
}

/** Turns a ruling into the verdict the handler presents. With a UI, an ask stays an ask, and so does a deny
 *  while `autoDeny` is off; the ask carries its audit record for the handler to finish. Without a UI an ask
 *  fails closed to a deny marked `degraded`, and every other record is appended here. */
function settle(a: Adjudication, s: Settlement): Verdict {
	const { state, env } = a;
	const { verdict, reason, source } = s.ruling;
	const headlessAsk = verdict === "ask" && !env.hasUI;
	// A headless ask is recorded as the deny it degrades to.
	const draft = s.record;
	const record = draft
		? buildRecord(
				a,
				{ verdict: headlessAsk ? "deny" : draft.verdict, reason: draft.reason, source: draft.source, degraded: headlessAsk },
				draft.raw,
				draft.extra,
			)
		: null;
	const detail = s.detail === undefined ? {} : { detail: s.detail };
	const autoDenyOff = verdict === "deny" && s.autoDenyApplies !== false && !state.userRules.autoDeny;
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
	const { ruling } = s;
	switch (ruling.verdict) {
		case "allow":
			return { verdict: "allow", reason, source: ruling.source, degraded: false };
		case "deny":
			return { verdict: "deny", reason, ...detail, source, degraded: false };
		case "ask":
			return { verdict: "deny", reason, ...detail, source, degraded: true };
		default: {
			const unhandled: never = ruling;
			throw new Error(`unhandled ruling: ${String(unhandled)}`);
		}
	}
}

/** Settles a rule-layer ask: a protected-path or rule ask that only the user who declared it may answer
 *  (ADR-0002), so it never reaches a model. Unlike rule allows and denies, it is audited (#62). */
function adjudicateRuleAsk(a: Adjudication, rule: RuleResult): Verdict {
	const reason = rule.reason ?? "";
	const source = rule.askSource ?? "protected-path";
	return settle(a, {
		ruling: { verdict: "ask", reason, source },
		record: { verdict: "ask", reason, source, raw: null, extra: { detail: rule.detail } },
		autoResolve: "deny",
		detail: rule.detail,
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
		ruling: modelRuling(applied, sources.verdict),
		record: {
			verdict: applied.verdict,
			reason: applied.reason,
			source: sources.record,
			raw: null,
			extra: cascade.fb ? { fallback: cascade.fb } : {},
		},
		autoResolve: "deny",
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
	// Time is held back for the fallback only when one is configured.
	const reserveMs = state.userRules.classifierFallbackModel && env.getFallbackModel ? FALLBACK_TIMEOUT_MS : 0;
	const outcome = await classifyWithModel(modelCall, choice, CLASSIFIER_TIMEOUT_MS, { deadlineAt, reserveMs });

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
	const ruling = modelRuling(applied, sources.verdict);
	// The record keeps the first layer's ruling, except that a first layer that gave none records the
	// fallback's applied verdict instead of its default deny.
	const rescued = cascade.effective !== undefined && outcome.source === "fail-closed";
	return settle(a, {
		ruling,
		record: {
			verdict: rescued ? applied.verdict : outcome.verdict,
			reason: rescued ? applied.reason : outcome.reason,
			source: sources.record,
			raw: outcome.auditRaw,
			extra: { ...(cascade.demoted ? { demoted: true } : {}), ...(cascade.fb ? { fallback: cascade.fb } : {}) },
		},
		autoResolve: autoResolveFor(ruling, cascade),
	});
}

/** Returns the verdict for one tool call: the rule layer's, else the gray-zone classifier's. Fails closed:
 *  a missing or failing model denies, and an ask with no UI becomes a deny marked `degraded`. */
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
	// The action under review is never elided: the rule layer already asked about an over-cap action.
	const a: Adjudication = { state, env, call, actionLine: actionCallLine(call.toolName, call.input).line };
	switch (rule.verdict) {
		case "deny":
			// Rule allows and denies stay unaudited (#54).
			return settle(a, {
				ruling: { verdict: "deny", reason: rule.reason ?? "", source: "rule" },
				record: null,
				autoResolve: "deny",
				autoDenyApplies: !rule.selfProtect,
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

	// One deadline covers the whole gray-zone decision, the no-model path included.
	const deadlineAt = Date.now() + (env.adjudicationBudgetMs ?? ADJUDICATION_BUDGET_MS);
	const resolved = env.getModel();
	// One redactor for every model payload this adjudication sends (ADR-0002).
	const redact = env.redact ?? redactorFor(env.cwd, denyPathBases);
	// The strict check above decides the deterministic ask; the wide one still keeps a protected
	// path out of every model payload, so a call it matches reaches a model only as the marker.
	// The audit record keeps the raw action line (ADR-0002: audit never leaves the machine).
	const modelCall = modelCallFor(state, env, redact(call.input) ? PROTECTED_PATH_MARKER : a.actionLine, redact);
	if (!resolved) return adjudicateWithoutModel(a, modelCall, deadlineAt);
	return adjudicateGrayZone(a, modelCall, resolved, deadlineAt);
}
