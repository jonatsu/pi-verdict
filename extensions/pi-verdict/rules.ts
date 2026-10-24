import {
	commandText,
	isCommandTool,
	isHostInternalUrl,
	multiTargetDetailSuffix,
	readMayRelocate,
	type ToolAccess,
	toolAccess,
	userRuleTargets,
} from "./access.ts";
import { ACTION_LINE_MAX_CHARS, actionCallLine } from "./action-line.ts";
import { hitCodeLoadPath } from "./code-loading.ts";
import type { UserRules } from "./config.ts";
import { hitDenyPaths, hitOmpDir } from "./deny-paths.ts";
import { classifyReads, classifyWrites, globStaysInProject, s0DirectoryBeneath } from "./floor.ts";
import type { RedactorFn } from "./redaction.ts";
import { type ProtectedSet, selfProtectCheck } from "./self-protection.ts";
import { allowAdmits, classifyBash, pyEvalShellLines, type RuleResult } from "./shell.ts";

/** What the rule layer reads besides the call itself: the session's policy and protected sets. */
export interface RuleContext {
	readonly cwd: string;
	readonly user: UserRules;
	readonly prot: ProtectedSet;
	readonly denyPathBases: readonly string[];
	/** item 6c (Phase 6; ADR-0010): while the user's own policy failed to load, the user
	 *  allow loop and the tools exemption are suspended (steps 4/5) — deny-side layers and
	 *  the floor above them are unchanged, and everything they do not decide falls through
	 *  to the classifier, whose allow is then withheld by adjudicate. */
	readonly policyDegraded: boolean;
	/** True when the call names a user-declared protected path through a spelling the denyPaths
	 *  tokeniser cannot extract, such as a home variable behind a command substitution. */
	readonly namesProtectedPath: RedactorFn;
}

/** The facts that stop a user `allow` rule or `tools` entry from vouching for a call. */
interface VouchFlags {
	readonly policyDegraded: boolean;
	readonly relocatable: boolean;
	readonly internalUrl: boolean;
}

/**
 * Returns the rule layer's verdict for a tool call: the first layer that decides it, in the order
 * `docs/layers.md` documents and the probe asserts, or the floor's own grade when none does.
 */
export function classifyByRules(toolName: string, input: Record<string, unknown>, ctx: RuleContext): RuleResult {
	const selfProtected = selfProtectCheck(toolName, input, ctx.cwd, ctx.prot);
	if (selfProtected) return selfProtected;

	const access = toolAccess(toolName, input);
	const graded = gradeBase(toolName, input, access, ctx);
	if (graded.base.verdict === "deny") return graded.base; // Built-in floor: deny takes precedence over all user rules
	const internalUrl = namesInternalUrl(toolName, access);
	const base = withholdFloorAllow(graded.base, toolName, access, internalUrl, ctx.cwd);
	const flags: VouchFlags = { policyDegraded: ctx.policyDegraded, relocatable: graded.relocatable, internalUrl };
	const targets = userRuleTargets(toolName, input, ctx.cwd);

	return (
		userDeny(targets, access, ctx.user) ??
		forcedOmpGate(toolName, input, access, ctx) ??
		denyPathsAsk(toolName, input, access, ctx) ??
		protectedSpellingAsk(input, ctx) ??
		codeLoadingAsk(toolName, input, ctx) ??
		overCapAsk(toolName, input) ??
		userAllow(toolName, input, targets, access, flags, ctx.user) ??
		toolsExemption(toolName, access, flags, ctx.user) ??
		opaqueAsk(access) ??
		base
	);
}

/** Grades the call against the built-in floor. `relocatable` marks a relative `read` target that
 *  does not exist, which no rule may vouch for. */
function gradeBase(
	toolName: string,
	input: Record<string, unknown>,
	access: ToolAccess,
	ctx: RuleContext,
): { base: RuleResult; relocatable: boolean } {
	const floorOn = ctx.user.builtinDenyFloor;
	if (isCommandTool(toolName)) return { base: classifyBash(commandText(input), floorOn), relocatable: false };
	if (access.direction === "mutating") {
		// Opaque calls have nothing for classifyWrites to grade; their own ask fires below,
		// after the deny-side layers and the tools exemption get first look.
		const base: RuleResult = access.opaque ? { verdict: "gray" } : classifyWrites(access.gradedWrites, ctx.cwd, floorOn);
		return { base, relocatable: false };
	}
	if (access.direction === "observing") {
		const readTargets = access.gradedReads.length > 0 ? access.gradedReads : [ctx.cwd];
		let base = classifyReads(readTargets, ctx.cwd, floorOn);
		// A scope search below a credential directory's parent walks into it, so the floor's allow
		// for the parent is not a verdict; a plain read of a directory is not a search.
		if (base.verdict === "allow" && access.scope && readTargets.some((t) => s0DirectoryBeneath(t, ctx.cwd))) {
			base = { verdict: "gray", reason: "search scope contains a credential directory" };
		}
		// The host reads a missing relative target from a workspace file it finds by suffix, so no rule
		// may vouch for the spelling; the classifier sees the call instead.
		const relocatable = toolName === "read" && access.reads.some((t) => readMayRelocate(t, ctx.cwd));
		if (relocatable && base.verdict === "allow") {
			base = { verdict: "gray", reason: "relative read target does not exist (the host may open another file)" };
		}
		return { base, relocatable };
	}
	if (access.kind === "code" && access.command !== null && input.language === "py") {
		// Phase 3 (F13): the bash floor applies to a Python eval cell's extracted shell-out
		// lines only (pyEvalShellLines) — never the whole code text, which the floor's danger
		// regexes/tripwire/allowAdmits never see (those stay bash-command-only).
		const shellText = pyEvalShellLines(access.command).join("\n");
		return { base: shellText ? classifyBash(shellText, floorOn) : { verdict: "gray" }, relocatable: false };
	}
	return { base: { verdict: "gray", reason: `tool not covered by built-in rules: ${toolName}` }, relocatable: false };
}

/** A target in one of the host's internal URL schemes is served by a handler (a remote host, a
 *  vault), not by the project file its text resolves to, so no rule may vouch for it. */
function namesInternalUrl(toolName: string, access: ToolAccess): boolean {
	return (
		(access.direction === "observing" || toolName === "ast_edit") && [...access.gradedReads, ...access.gradedWrites].some(isHostInternalUrl)
	);
}

/** Turns the floor's allow gray for a target it cannot vouch for: an internal URL, or a glob. */
function withholdFloorAllow(base: RuleResult, toolName: string, access: ToolAccess, internalUrl: boolean, cwd: string): RuleResult {
	if (base.verdict !== "allow") return base;
	if (internalUrl) return { verdict: "gray", reason: "target is an internal URL, not a project path" };
	// A glob target names files the prefix grade cannot see, so the floor's allow is not a
	// verdict for it; the deny-side layers below still run on the prefix. `glob` alone only lists
	// names, so it keeps the allow while everything it can reach stays inside the project.
	if (access.globbed && !(toolName === "glob" && globStaysInProject(access.gradedReads, cwd)))
		return { verdict: "gray", reason: "path contains glob metacharacters (not graded as a literal path)" };
	return base;
}

/** True when a user `allow` rule or `tools` entry may admit the call. */
function canVouch(access: ToolAccess, flags: VouchFlags): boolean {
	return !flags.policyDegraded && !access.globbed && !access.opaque && !flags.relocatable && !flags.internalUrl;
}

// User deny (known-tool targets only — R2-2: an unknown tool's shape-inferred fields
// never reach user rules; Item 10 / F11: deny fires on ANY target match). kind "code"
// (eval, item 4): the whole code text is also a deny target — user allow stays excluded
// (targets, reused below for allow, never gains the code text).
function userDeny(targets: readonly string[], access: ToolAccess, user: UserRules): RuleResult | null {
	const denyTargets = access.kind === "code" && access.command !== null ? [...targets, access.command] : targets;
	for (const re of user.deny) {
		if (denyTargets.some((t) => re.test(t))) return { verdict: "deny", reason: `user deny rule: ${re.source}` };
	}
	return null;
}

// Forced .omp gate: terminal ask, after user deny, before denyPaths/user allow. Not gated
// by `targets` — callPathCandidates (which hitOmpDir uses) also covers an unknown tool's
// adapter-derived fields. Reason carries no path (it travels back into agent context); the
// path is UI-only detail.
function forcedOmpGate(toolName: string, input: Record<string, unknown>, access: ToolAccess, ctx: RuleContext): RuleResult | null {
	if (!ctx.user.gateOmpDir) return null;
	const omp = hitOmpDir(toolName, input, ctx.cwd);
	if (!omp) return null;
	return {
		verdict: "ask",
		reason: "forced gate: access to a .omp directory (gateOmpDir)",
		detail: omp + multiTargetDetailSuffix(access),
		askSource: "protected-path",
	};
}

// denyPaths hit → terminal ask (ADR-0002): after user deny, before user allow — a
// protected path is the user's exception to their own allow rules. Also not gated by
// `targets` (an unknown tool's extracted targets now hit this ask where today nothing
// grades them — the surviving BREAKING change). The matched path goes to `detail` (confirm
// dialog only): reasons travel back into the agent context, so plaintext there would leak
// the declaration.
function denyPathsAsk(toolName: string, input: Record<string, unknown>, access: ToolAccess, ctx: RuleContext): RuleResult | null {
	const hit = hitDenyPaths(toolName, input, ctx.cwd, ctx.denyPathBases);
	if (!hit) return null;
	return {
		verdict: "ask",
		reason: "user-declared protected path (denyPaths) [path withheld; see pi-verdict.json]",
		detail: hit + multiTargetDetailSuffix(access),
		askSource: "protected-path",
	};
}

// A model that sees only a marker in place of such a call cannot judge it, and a protected path
// overrides the user's own allow rules (ADR-0002), so the gate asks without a model call.
function protectedSpellingAsk(input: Record<string, unknown>, ctx: RuleContext): RuleResult | null {
	if (!ctx.namesProtectedPath(input)) return null;
	return {
		verdict: "ask",
		reason: "call names a user-declared protected path (denyPaths) [path withheld; see pi-verdict.json]",
		askSource: "protected-path",
	};
}

// A write where the host loads code runs in every later session, which is more than the one
// action a classifier is asked about, so a human decides (ADR-0011). It is a built-in
// protection and goes off with the floor. Its reason carries the path, so it runs after both
// protected-path asks: a path the user declared keeps its withheld reason (ADR-0002).
function codeLoadingAsk(toolName: string, input: Record<string, unknown>, ctx: RuleContext): RuleResult | null {
	if (!ctx.user.builtinDenyFloor) return null;
	const code = hitCodeLoadPath(toolName, input, ctx.cwd);
	if (!code) return null;
	return {
		verdict: "ask",
		reason: `host code-loading location (${code.kind}): ${code.path} — the host runs it in later sessions, so a human must confirm the call (ADR-0011)`,
		askSource: "rule",
	};
}

// Over-cap action → terminal ask (item 6a, Phase 4; Claude-review F8): after the deny-side
// layers (a dangerous prefix the floor DID read still denies above), before user allow —
// "the user allow check must never run before the over-cap check" is the literal ordering
// requirement; deny-side layers running first is safe (they can only narrow, never widen,
// what happens to an action the floor could not fully read).
function overCapAsk(toolName: string, input: Record<string, unknown>): RuleResult | null {
	if (!actionCallLine(toolName, input).overCap) return null;
	return { verdict: "ask", reason: `action too long to grade safely (over ${ACTION_LINE_MAX_CHARS} chars)`, askSource: "rule" };
}

// User allow (known-tool targets only, same scope as user deny above). ADR-0008: a user
// allow admits ONE simple command. A compound command, an unsound parse, a redirection or
// a write-shaped git invocation is never rule-allowed — it reaches the classifier.
// Suspended while policyDegraded (ADR-0010): a partially-loaded policy's allow list may
// still be present while a deny/denyPaths entry was dropped — granting mechanical allows
// on that basis is the fail-open direction this closes.
// An opaque call's path/paths are model-supplied while its real target is unknown, so no
// rule can vouch for it (the same call is denied without an allow rule configured).
function userAllow(
	toolName: string,
	input: Record<string, unknown>,
	targets: readonly string[],
	access: ToolAccess,
	flags: VouchFlags,
	user: UserRules,
): RuleResult | null {
	if (targets.length === 0 || !canVouch(access, flags)) return null;
	if (isCommandTool(toolName) && !allowAdmits(commandText(input))) return null;
	for (const re of user.allow) {
		if (targets.every((t) => re.test(t))) return { verdict: "allow", reason: "user allow rule" };
	}
	return null;
}

// tools exemption: exact-name allowlist, checked AFTER every deny-side layer above and
// BEFORE the opaque ask / gray fall-through (ADR-0009) — a listed tool carrying a
// protected-path target now faces the ask above instead of a silent allow here. kind
// "code" (eval, item 4): leaves the tools exemption family entirely — its documented scope
// is non-code tools; a user who listed eval here loses the exemption (BREAKING). Suspended
// with user allow while policyDegraded (ADR-0010).
function toolsExemption(toolName: string, access: ToolAccess, flags: VouchFlags, user: UserRules): RuleResult | null {
	if (!user.tools.includes(toolName) || access.kind === "code" || !canVouch(access, flags)) return null;
	return { verdict: "allow", reason: "user tools allow rule" };
}

// Opaque ask: a known mutating call (write/edit/ast_edit) with no extractable target at
// all — deterministic ask, headless → deny (never for an unknown tool: see toolAccess).
function opaqueAsk(access: ToolAccess): RuleResult | null {
	if (access.direction !== "mutating" || !access.opaque) return null;
	return { verdict: "ask", reason: "mutating call with no extractable target", askSource: "rule" };
}
