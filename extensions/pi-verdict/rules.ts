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

/** One tool call as every rule step reads it. */
interface RuleCall {
	readonly toolName: string;
	readonly input: Record<string, unknown>;
	readonly access: ToolAccess;
	/** The targets user rules match; empty for an unknown tool. */
	readonly targets: readonly string[];
	/** A `read` of a missing relative target, which the host may serve from another file. */
	readonly relocatable: boolean;
	/** A target in one of the host's internal URL schemes. */
	readonly internalUrl: boolean;
	/** True when a user `allow` rule or `tools` entry may admit the call. */
	readonly vouchable: boolean;
}

/**
 * Returns the rule layer's verdict for a tool call: the first layer that decides it, in the order
 * `docs/layers.md` documents and the probe asserts, or the floor's own grade when none does.
 */
export function classifyByRules(toolName: string, input: Record<string, unknown>, ctx: RuleContext): RuleResult {
	const call = readCall(toolName, input, ctx);
	const selfProtected = selfProtectCheck(toolName, input, call.access, ctx.cwd, ctx.prot);
	if (selfProtected) return selfProtected;

	const floorGrade = withholdFloorAllow(gradeBase(call, ctx), call, ctx);
	if (floorGrade.verdict === "deny") return floorGrade; // the floor's deny beats every user rule

	return (
		// Deny-side layers: each can only narrow what the call may do.
		userDeny(call, ctx) ??
		forcedOmpGate(call, ctx) ??
		denyPathsAsk(call, ctx) ??
		protectedSpellingAsk(call, ctx) ??
		codeLoadingAsk(call, ctx) ??
		overCapAsk(call, ctx) ??
		// Allow layers, reached only when no deny-side layer decided.
		userAllow(call, ctx) ??
		toolsExemption(call, ctx) ??
		// What no rule decided: the opaque ask, then the floor's grade.
		opaqueAsk(call, ctx) ??
		floorGrade
	);
}

/** Reads the call's targets once for every step. */
function readCall(toolName: string, input: Record<string, unknown>, ctx: RuleContext): RuleCall {
	const access = toolAccess(toolName, input);
	const relocatable = access.direction === "observing" && toolName === "read" && access.reads.some((t) => readMayRelocate(t, ctx.cwd));
	const internalUrl =
		(access.direction === "observing" || toolName === "ast_edit") &&
		[...access.gradedReads, ...access.gradedWrites].some(isHostInternalUrl);
	return {
		toolName,
		input,
		access,
		targets: userRuleTargets(toolName, input, ctx.cwd),
		relocatable,
		internalUrl,
		vouchable: !ctx.policyDegraded && !access.globbed && !access.opaque && !relocatable && !internalUrl,
	};
}

/** Returns the built-in floor's grade for the call, before any target shape turns its allow gray. */
function gradeBase(call: RuleCall, ctx: RuleContext): RuleResult {
	const { toolName, input, access } = call;
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

/** Turns the floor's allow gray for a call it cannot vouch for, so the classifier sees the call. */
function withholdFloorAllow(grade: RuleResult, call: RuleCall, ctx: RuleContext): RuleResult {
	const { toolName, access } = call;
	if (grade.verdict !== "allow") return grade;
	// A scope search below a credential directory's parent walks into it; a plain read of a
	// directory is not a search.
	if (access.direction === "observing" && access.scope && observedTargets(access, ctx.cwd).some((t) => s0DirectoryBeneath(t, ctx.cwd)))
		return { verdict: "gray", reason: "search scope contains a credential directory" };
	// The host reads a missing relative target from a workspace file it finds by suffix.
	if (call.relocatable) return { verdict: "gray", reason: "relative read target does not exist (the host may open another file)" };
	// An internal URL is served by a handler (a remote host, a vault), not by the project file its
	// text resolves to.
	if (call.internalUrl) return { verdict: "gray", reason: "target is an internal URL, not a project path" };
	// A glob target names files the prefix grade cannot see; the deny-side layers still run on the
	// prefix. `glob` alone only lists names, so it keeps the allow while everything it can reach
	// stays inside the project.
	if (access.globbed && !(toolName === "glob" && globStaysInProject(access.gradedReads, ctx.cwd)))
		return { verdict: "gray", reason: "path contains glob metacharacters (not graded as a literal path)" };
	return grade;
}

/** Denies when a user `deny` rule matches any target. Only a known tool's targets count, so a rule never
 *  keys on an unknown tool's payload by accident; an eval cell's code text is a deny target, never an
 *  allow target. */
function userDeny(call: RuleCall, ctx: RuleContext): RuleResult | null {
	const { access, targets } = call;
	const denyTargets = access.kind === "code" && access.command !== null ? [...targets, access.command] : targets;
	for (const re of ctx.user.deny) {
		if (denyTargets.some((t) => re.test(t))) return { verdict: "deny", reason: `user deny rule: ${re.source}` };
	}
	return null;
}

/** Asks on any `.omp` access while `gateOmpDir` is on, an unknown tool's targets included. The path goes
 *  to `detail` only, because the reason reaches the agent. */
function forcedOmpGate(call: RuleCall, ctx: RuleContext): RuleResult | null {
	if (!ctx.user.gateOmpDir) return null;
	const omp = hitOmpDir(call.toolName, call.input, ctx.cwd);
	if (!omp) return null;
	return {
		verdict: "ask",
		reason: "forced gate: access to a .omp directory (gateOmpDir)",
		detail: omp + multiTargetDetailSuffix(call.access),
		askSource: "protected-path",
	};
}

/** Asks on a declared protected path, an unknown tool's targets included; a declaration is the user's
 *  exception to their own allow rules (ADR-0002). The path goes to `detail` only, because the reason
 *  reaches the agent and would leak the declaration. */
function denyPathsAsk(call: RuleCall, ctx: RuleContext): RuleResult | null {
	const hit = hitDenyPaths(call.toolName, call.input, ctx.cwd, ctx.denyPathBases);
	if (!hit) return null;
	return {
		verdict: "ask",
		reason: "user-declared protected path (denyPaths) [path withheld; see pi-verdict.json]",
		detail: hit + multiTargetDetailSuffix(call.access),
		askSource: "protected-path",
	};
}

/** Asks on a call the strict redactor matches. A model that sees only a marker in place of such a call
 *  cannot judge it, and a protected path overrides the user's allow rules (ADR-0002). */
function protectedSpellingAsk(call: RuleCall, ctx: RuleContext): RuleResult | null {
	if (!ctx.namesProtectedPath(call.input)) return null;
	return {
		verdict: "ask",
		reason: "call names a user-declared protected path (denyPaths) [path withheld; see pi-verdict.json]",
		askSource: "protected-path",
	};
}

/** Asks on a write where the host loads code: it runs in every later session, which is more than the
 *  one action a classifier is asked about (ADR-0011). It goes off with the floor. Its reason carries the
 *  path, so it runs after both protected-path asks, which withhold theirs. */
function codeLoadingAsk(call: RuleCall, ctx: RuleContext): RuleResult | null {
	if (!ctx.user.builtinDenyFloor) return null;
	const code = hitCodeLoadPath(call.toolName, call.input, ctx.cwd);
	if (!code) return null;
	return {
		verdict: "ask",
		reason: `host code-loading location (${code.kind}): ${code.path} — the host runs it in later sessions, so a human must confirm the call (ADR-0011)`,
		askSource: "rule",
	};
}

/** Asks on an action longer than the floor reads, before user allow, so no rule allows an unread tail.
 *  The deny-side layers run first; they can only narrow the outcome. */
function overCapAsk(call: RuleCall, _ctx: RuleContext): RuleResult | null {
	if (!actionCallLine(call.toolName, call.input).overCap) return null;
	return { verdict: "ask", reason: `action too long to grade safely (over ${ACTION_LINE_MAX_CHARS} chars)`, askSource: "rule" };
}

/** Allows when a user `allow` rule matches every target. A command must be one simple command
 *  (ADR-0008): a compound command, an unsound parse, a redirection or a write-shaped git call reaches
 *  the classifier instead. Never while the policy is degraded (ADR-0010), nor for a target a rule cannot
 *  read as a literal project path (a glob, an internal URL, a relocatable read), nor for an opaque call,
 *  whose real target is unknown. */
function userAllow(call: RuleCall, ctx: RuleContext): RuleResult | null {
	if (call.targets.length === 0 || !call.vouchable) return null;
	if (isCommandTool(call.toolName) && !allowAdmits(commandText(call.input))) return null;
	for (const re of ctx.user.allow) {
		if (call.targets.every((t) => re.test(t))) return { verdict: "allow", reason: "user allow rule" };
	}
	return null;
}

/** Allows a tool listed in `tools` by exact name, after every deny-side layer (ADR-0009), on the same
 *  condition as a user `allow` rule. An eval cell is never exempt, because its code can do anything a
 *  command can. */
function toolsExemption(call: RuleCall, ctx: RuleContext): RuleResult | null {
	if (!ctx.user.tools.includes(call.toolName) || call.access.kind === "code" || !call.vouchable) return null;
	return { verdict: "allow", reason: "user tools allow rule" };
}

/** Asks on a known mutating call whose payload names no target; an unknown tool is never opaque. */
function opaqueAsk(call: RuleCall, _ctx: RuleContext): RuleResult | null {
	if (call.access.direction !== "mutating" || !call.access.opaque) return null;
	return { verdict: "ask", reason: "mutating call with no extractable target", askSource: "rule" };
}
