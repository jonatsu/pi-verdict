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
	/** Set while the user's own policy failed to load in whole or part (ADR-0010): user `allow` rules
	 *  and the `tools` exemption are suspended, and the floor and the deny-side layers still run. */
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
	if (graded.verdict === "deny") return graded; // the floor's deny beats every user rule
	const relocatable = readsRelocatable(toolName, access, ctx.cwd);
	const internalUrl = namesInternalUrl(toolName, access);
	const base = withholdFloorAllow(graded, toolName, access, { relocatable, internalUrl }, ctx.cwd);
	const flags: VouchFlags = { policyDegraded: ctx.policyDegraded, relocatable, internalUrl };
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

/** Returns the built-in floor's grade for the call, before any target shape turns its allow gray. */
function gradeBase(toolName: string, input: Record<string, unknown>, access: ToolAccess, ctx: RuleContext): RuleResult {
	const floorOn = ctx.user.builtinDenyFloor;
	if (isCommandTool(toolName)) return classifyBash(commandText(input), floorOn);
	if (access.direction === "mutating") {
		// Opaque calls have nothing for classifyWrites to grade; their own ask fires below,
		// after the deny-side layers and the tools exemption get first look.
		return access.opaque ? { verdict: "gray" } : classifyWrites(access.gradedWrites, ctx.cwd, floorOn);
	}
	if (access.direction === "observing") return classifyReads(observedTargets(access, ctx.cwd), ctx.cwd, floorOn);
	if (access.kind === "code" && access.command !== null && input.language === "py") {
		// The bash floor grades only the shell lines of a Python cell: its rules are written for
		// commands, so the code text itself never reaches them.
		const shellText = pyEvalShellLines(access.command).join("\n");
		return shellText ? classifyBash(shellText, floorOn) : { verdict: "gray" };
	}
	return { verdict: "gray", reason: `tool not covered by built-in rules: ${toolName}` };
}

/** Returns an observing call's read targets; a pathless one reads the cwd. */
function observedTargets(access: ToolAccess, cwd: string): string[] {
	return access.gradedReads.length > 0 ? access.gradedReads : [cwd];
}

/** True when a `read` names a missing relative target: the host then reads a workspace file it finds by
 *  suffix, so no rule may vouch for the spelling. */
function readsRelocatable(toolName: string, access: ToolAccess, cwd: string): boolean {
	return access.direction === "observing" && toolName === "read" && access.reads.some((t) => readMayRelocate(t, cwd));
}

/** A target in one of the host's internal URL schemes is served by a handler (a remote host, a
 *  vault), not by the project file its text resolves to, so no rule may vouch for it. */
function namesInternalUrl(toolName: string, access: ToolAccess): boolean {
	return (
		(access.direction === "observing" || toolName === "ast_edit") && [...access.gradedReads, ...access.gradedWrites].some(isHostInternalUrl)
	);
}

/** Turns the floor's allow gray for a call it cannot vouch for, so the classifier sees the call. */
function withholdFloorAllow(
	base: RuleResult,
	toolName: string,
	access: ToolAccess,
	shape: { readonly relocatable: boolean; readonly internalUrl: boolean },
	cwd: string,
): RuleResult {
	if (base.verdict !== "allow") return base;
	// A scope search below a credential directory's parent walks into it; a plain read of a
	// directory is not a search.
	if (access.direction === "observing" && access.scope && observedTargets(access, cwd).some((t) => s0DirectoryBeneath(t, cwd)))
		return { verdict: "gray", reason: "search scope contains a credential directory" };
	if (shape.relocatable) return { verdict: "gray", reason: "relative read target does not exist (the host may open another file)" };
	if (shape.internalUrl) return { verdict: "gray", reason: "target is an internal URL, not a project path" };
	// A glob target names files the prefix grade cannot see, so the floor's allow is not a
	// verdict for it; the deny-side layers below still run on the prefix. `glob` alone only lists
	// names, so it keeps the allow while everything it can reach stays inside the project.
	if (access.globbed && !(toolName === "glob" && globStaysInProject(access.gradedReads, cwd)))
		return { verdict: "gray", reason: "path contains glob metacharacters (not graded as a literal path)" };
	return base;
}

/** True when a user `allow` rule or `tools` entry may admit the call. Neither may while the policy is
 *  degraded (ADR-0010), nor for a target a rule cannot read as a literal project path (a glob, an
 *  internal URL, a relocatable read), nor for an opaque call, whose real target is unknown. */
function canVouch(access: ToolAccess, flags: VouchFlags): boolean {
	return !flags.policyDegraded && !access.globbed && !access.opaque && !flags.relocatable && !flags.internalUrl;
}

/** Denies when a user `deny` rule matches any target. Only a known tool's targets count, so a rule never
 *  keys on an unknown tool's payload by accident; an eval cell's code text is a deny target, never an
 *  allow target. */
function userDeny(targets: readonly string[], access: ToolAccess, user: UserRules): RuleResult | null {
	const denyTargets = access.kind === "code" && access.command !== null ? [...targets, access.command] : targets;
	for (const re of user.deny) {
		if (denyTargets.some((t) => re.test(t))) return { verdict: "deny", reason: `user deny rule: ${re.source}` };
	}
	return null;
}

/** Asks on any `.omp` access while `gateOmpDir` is on, an unknown tool's targets included. The path goes
 *  to `detail` only, because the reason reaches the agent. */
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

/** Asks on a declared protected path, an unknown tool's targets included; a declaration is the user's
 *  exception to their own allow rules (ADR-0002). The path goes to `detail` only, because the reason
 *  reaches the agent and would leak the declaration. */
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

/** Asks on a call the strict redactor matches. A model that sees only a marker in place of such a call
 *  cannot judge it, and a protected path overrides the user's allow rules (ADR-0002). */
function protectedSpellingAsk(input: Record<string, unknown>, ctx: RuleContext): RuleResult | null {
	if (!ctx.namesProtectedPath(input)) return null;
	return {
		verdict: "ask",
		reason: "call names a user-declared protected path (denyPaths) [path withheld; see pi-verdict.json]",
		askSource: "protected-path",
	};
}

/** Asks on a write where the host loads code: it runs in every later session, which is more than the
 *  one action a classifier is asked about (ADR-0011). It goes off with the floor. Its reason carries the
 *  path, so it runs after both protected-path asks, which withhold theirs. */
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

/** Asks on an action longer than the floor reads, before user allow, so no rule allows an unread tail.
 *  The deny-side layers run first; they can only narrow the outcome. */
function overCapAsk(toolName: string, input: Record<string, unknown>): RuleResult | null {
	if (!actionCallLine(toolName, input).overCap) return null;
	return { verdict: "ask", reason: `action too long to grade safely (over ${ACTION_LINE_MAX_CHARS} chars)`, askSource: "rule" };
}

/** Allows when a user `allow` rule matches every target. A command must be one simple command
 *  (ADR-0008): a compound command, an unsound parse, a redirection or a write-shaped git call reaches
 *  the classifier instead. */
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

/** Allows a tool listed in `tools` by exact name, after every deny-side layer (ADR-0009). An eval cell
 *  is never exempt, because its code can do anything a command can. */
function toolsExemption(toolName: string, access: ToolAccess, flags: VouchFlags, user: UserRules): RuleResult | null {
	if (!user.tools.includes(toolName) || access.kind === "code" || !canVouch(access, flags)) return null;
	return { verdict: "allow", reason: "user tools allow rule" };
}

/** Asks on a known mutating call whose payload names no target; an unknown tool is never opaque. */
function opaqueAsk(access: ToolAccess): RuleResult | null {
	if (access.direction !== "mutating" || !access.opaque) return null;
	return { verdict: "ask", reason: "mutating call with no extractable target", askSource: "rule" };
}
