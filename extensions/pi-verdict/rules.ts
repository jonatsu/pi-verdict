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
import { allowOperandsAdmit } from "./allow-operands.ts";
import { hitCodeLoadPath } from "./code-loading.ts";
import { type CommandRule, type CommandRuleAction, matchingCommandRules } from "./command-rules.ts";
import type { UserRules } from "./config.ts";
import { commandWorkingDirectory, type DeleteContext, deleteGrader } from "./delete-grade.ts";
import { hitDenyPaths, hitOmpDir } from "./deny-paths.ts";
import { classifyReads, classifyWrites, globStaysInProject, type HostKind, isDeviceUrl, s0DirectoryBeneath } from "./floor.ts";
import { overrideFor } from "./floor-overrides.ts";
import { baseForms } from "./paths.ts";
import type { CallPredicate } from "./redaction.ts";
import { secretReads } from "./secret-reads.ts";
import { type ProtectedSet, selfProtectCheck } from "./self-protection.ts";
import {
	allowAdmits,
	classifyBash,
	classifyPyShellLines,
	type FloorHit,
	type FloorLift,
	pyEvalShellLines,
	type RuleResult,
} from "./shell.ts";
import type { ShellState } from "./shell-state.ts";

/** What the rule layer reads besides the call itself: the session's policy and protected sets. */
export interface RuleContext {
	/** The directory the call runs in (`resolveCommandCwd`), which every relative path of the call resolves
	 *  from. It is the session cwd unless a `bash` call names its own. */
	readonly commandCwd: string;
	/** False when the call names a directory the gate cannot resolve; no allow rule may then vouch for it. */
	readonly commandCwdExact: boolean;
	/** The session cwd. The gate grades it as the project, which a git allow must stay inside. */
	readonly sessionCwd: string;
	/** The command cwd as shown beside a command, or null when it is the session cwd. */
	readonly displayedCwd: string | null;
	readonly userRules: UserRules;
	readonly protectedSet: ProtectedSet;
	readonly denyPathBases: readonly string[];
	/** Set while the user's own policy failed to load in whole or part (ADR-0010): user `allow` rules
	 *  and the `tools` exemption are suspended, and the floor and the deny-side layers still run. */
	readonly policyDegraded: boolean;
	/** True when the call names a user-declared protected path through a spelling the denyPaths
	 *  tokeniser cannot extract, such as a home variable behind a command substitution. */
	readonly namesProtectedPath: CallPredicate;
	/** The host, which decides whether an `xd://` target is a tool device (omp) or a relative path (pi). */
	readonly host: HostKind;
	/** What the commands of the session, this one included, void among the user allows (ADR-0008). */
	readonly shellState: ShellState;
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
	/** The command rules the call's shell text matches, in rule order (ADR-0013). */
	readonly commandRules: readonly CommandRule[];
}

/**
 * Returns the rule layer's verdict for a tool call: the first layer that decides it, in the order
 * `docs/layers.md` documents and the probe asserts, or the floor's own grade when none does.
 */
export function classifyByRules(toolName: string, input: Record<string, unknown>, ctx: RuleContext): RuleResult {
	const call = readCall(toolName, input, ctx);
	const selfProtected = selfProtectCheck(toolName, input, call.access, ctx.commandCwd, ctx.protectedSet);
	if (selfProtected) return selfProtected;

	const baseGrade = gradeBase(call, ctx);
	const floorGrade = withholdFloorAllow(baseGrade, call, ctx);
	if (floorGrade.verdict === "deny") return floorGrade; // the floor's deny beats every user rule

	const decided =
		// Deny-side layers: each can only narrow what the call may do.
		userDeny(call, ctx) ??
		commandRuleHit(call, "deny") ??
		forcedOmpGate(call, ctx) ??
		denyPathsAsk(call, ctx) ??
		protectedSpellingAsk(call, ctx) ??
		codeLoadingAsk(call, ctx) ??
		softenedFloorAsk(baseGrade) ??
		commandRuleHit(call, "ask") ??
		overCapAsk(call, ctx) ??
		// Allow layers, reached only when no deny-side layer decided.
		userAllow(call, ctx) ??
		toolsExemption(call, ctx) ??
		// What no rule decided: the opaque ask, then the floor's grade.
		opaqueAsk(call, ctx) ??
		floorGrade;
	return baseGrade.overridden && !decided.overridden ? { ...decided, overridden: baseGrade.overridden } : decided;
}

const DEVICE_TRANSPORTS: ReadonlySet<string> = new Set(["read", "write"]);

/** Reads the call's targets once for every step. */
function readCall(toolName: string, input: Record<string, unknown>, ctx: RuleContext): RuleCall {
	const access = toolAccess(toolName, input);
	const relocatable =
		access.direction === "observing" && toolName === "read" && access.reads.some((t) => readMayRelocate(t, ctx.commandCwd));
	// On omp a device URL is the floor's to grade only through the `read` and `write` transports omp
	// drives devices with; any other tool naming one is held back like every internal URL.
	const internalUrl = [...access.gradedReads, ...access.gradedWrites]
		.filter(isHostInternalUrl)
		.some((t) =>
			ctx.host === "omp" && isDeviceUrl(t) ? !DEVICE_TRANSPORTS.has(toolName) : access.direction === "observing" || toolName === "ast_edit",
		);
	return {
		toolName,
		input,
		access,
		targets: userRuleTargets(toolName, input, ctx.commandCwd),
		relocatable,
		internalUrl,
		vouchable: ctx.commandCwdExact && !ctx.policyDegraded && !access.globbed && !access.opaque && !relocatable && !internalUrl,
		commandRules: matchingCommandRules(shellText(toolName, input, access), ctx.userRules.commandRules),
	};
}

/** The shell text of a call: a command tool's command, or the shell lines of a Python cell; empty otherwise. */
function shellText(toolName: string, input: Record<string, unknown>, access: ToolAccess): string {
	if (isCommandTool(toolName)) return commandText(input);
	if (access.kind === "code" && access.command !== null && input.language === "py") return pyEvalShellLines(access.command).join("\n");
	return "";
}

/** Returns the built-in floor's grade for the call, before any target shape turns its allow gray. */
function gradeBase(call: RuleCall, ctx: RuleContext): RuleResult {
	const { toolName, input, access } = call;
	const floorOn = ctx.userRules.builtinDenyFloor;
	const overrides = ctx.userRules.floorOverrides;
	if (isCommandTool(toolName)) {
		const command = commandText(input);
		const directories = directoryContext(ctx);
		return classifyBash(command, floorOn, shellLift(ctx, command), {
			deletes: deleteGrader(directories),
			reads: (text) => gradeSecretReads(text, ctx, directories),
		});
	}
	if (access.direction === "mutating") {
		// Opaque calls have nothing for classifyWrites to grade; their own ask fires below,
		// after the deny-side layers and the tools exemption get first look.
		return access.opaque ? { verdict: "gray" } : classifyWrites(access.gradedWrites, ctx.commandCwd, floorOn, ctx.host, overrides);
	}
	if (access.direction === "observing") {
		return classifyReads(observedTargets(access, ctx.commandCwd), ctx.commandCwd, floorOn, ctx.host, overrides);
	}
	if (access.kind === "code" && access.command !== null && input.language === "py") {
		// The bash floor grades only the shell lines of a Python cell: its rules are written for
		// commands, so the code text itself never reaches them.
		const lines = shellText(toolName, input, access);
		return lines ? classifyPyShellLines(lines, floorOn, shellLift(ctx, lines)) : { verdict: "gray" };
	}
	return { verdict: "gray", reason: `tool not covered by built-in rules: ${toolName}` };
}

/** The secret files a shell command reads (ADR-0014). Fails closed: a grading that throws denies the call, so
 *  no error becomes a classifier allow. */
function gradeSecretReads(command: string, ctx: RuleContext, directories: DeleteContext): readonly FloorHit[] {
	try {
		return secretReads(command, {
			commandCwd: ctx.commandCwd,
			workingDirectory: commandWorkingDirectory(command, directories),
			homeReassigned: ctx.shellState.homeOperands,
		});
	} catch {
		return [{ rule: "S0", reason: "rule S0: the gate could not grade the files this shell command reads", forms: [] }];
	}
}

/** The directories a shell command's paths resolve against, and what the session's shell may have moved. */
function directoryContext(ctx: RuleContext): DeleteContext {
	return {
		sessionCwd: ctx.sessionCwd,
		commandCwd: ctx.commandCwd,
		commandCwdExact: ctx.commandCwdExact,
		homeReassigned: ctx.shellState.homeOperands,
		workingDirectoryUnknown: ctx.shellState.workingDirectory,
	};
}

/** Matches an option or variable that moves where a command works (`git -C`, `env -C/x`, `GIT_DIR=`,
 *  `core.worktree`), which a scoped override cannot place; quoted or not. */
const DIRECTORY_OPTION = /(?:^|\s)['"]?(?:-C|--git-dir|--work-tree|--chdir)|\bGIT_(?:DIR|WORK_TREE)=|core\.worktree/;

/** Returns how the overrides lift a shell floor rule. A graded delete is scoped by its target's forms. Any
 *  other rule names no target the floor can see, so a scoped override applies only while the session cwd,
 *  the command cwd and the directory a leading `cd X &&` moves to all sit inside its scope, in every form.
 *  Fails closed: any other directory change, an option or variable that moves it, or a directory the gate cannot resolve
 *  keeps every rule on. */
function shellLift(ctx: RuleContext, command: string): FloorLift {
	// Read only when a scoped override needs it, so a call no override touches pays nothing.
	let cwdForms: readonly string[] | undefined;
	const directoryForms = (): readonly string[] => {
		if (cwdForms !== undefined) return cwdForms;
		// A variable an earlier call set for a command (`export GIT_WORK_TREE=…`) can move where it works too.
		const voided = ctx.shellState.commands.size > 0;
		const workingDirectory = voided ? null : commandWorkingDirectory(command, directoryContext(ctx));
		cwdForms =
			workingDirectory !== null && !DIRECTORY_OPTION.test(command)
				? [...baseForms(ctx.sessionCwd), ...baseForms(ctx.commandCwd), ...baseForms(workingDirectory)]
				: [];
		return cwdForms;
	};
	const overrides = ctx.userRules.floorOverrides;
	return (id, targetForms) => (overrides.has(id) ? (overrideFor(overrides, id, targetForms ?? directoryForms())?.action ?? null) : null);
}

/** Asks on a floor deny a `floorOverrides` entry softened (ADR-0013). It runs after the protected-path and
 *  code-loading asks, so a user deny or a declared protected path still decides first. It reads the
 *  floor's grade before any target shape turned it gray, so the softened ask survives that. */
function softenedFloorAsk(baseGrade: RuleResult): RuleResult | null {
	const softened = baseGrade.carriedAsk;
	if (softened === undefined) return null;
	return { verdict: "ask", reason: `${softened.reason} (softened to an ask by floorOverrides)`, askSource: "rule", rule: softened.rule };
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
	if (
		access.direction === "observing" &&
		access.scope &&
		observedTargets(access, ctx.commandCwd).some((t) => s0DirectoryBeneath(t, ctx.commandCwd))
	)
		return { verdict: "gray", reason: "search scope contains a credential directory" };
	// The host reads a missing relative target from a workspace file it finds by suffix.
	if (call.relocatable) return { verdict: "gray", reason: "relative read target does not exist (the host may open another file)" };
	// An internal URL is served by a handler (a remote host, a vault), not by the project file its
	// text resolves to.
	if (call.internalUrl) return { verdict: "gray", reason: "target is an internal URL, not a project path" };
	// A glob target names files the prefix grade cannot see; the deny-side layers still run on the
	// prefix. `glob` alone only lists names, so it keeps the allow while everything it can reach
	// stays inside the project.
	if (access.globbed && !(toolName === "glob" && globStaysInProject(access.gradedReads, ctx.commandCwd)))
		return { verdict: "gray", reason: "path contains glob metacharacters (not graded as a literal path)" };
	return grade;
}

/** Denies when a user `deny` rule matches any target. Only a known tool's targets count, so a rule never
 *  keys on an unknown tool's payload by accident; an eval cell's code text is a deny target, never an
 *  allow target. An internal URL is also a deny target as written, because its path form collapses `//`. */
function userDeny(call: RuleCall, ctx: RuleContext): RuleResult | null {
	const { access, targets } = call;
	const urls = access.direction === "unknown" ? [] : [...access.gradedReads, ...access.gradedWrites].filter(isHostInternalUrl);
	const denyTargets = [...targets, ...urls, ...(access.kind === "code" && access.command !== null ? [access.command] : [])];
	for (const re of ctx.userRules.deny) {
		if (denyTargets.some((t) => re.test(t))) return { verdict: "deny", reason: `user deny rule: ${re.source}`, rule: "user-deny" };
	}
	return null;
}

/** Decides by the first matching command rule with the given action (ADR-0013): a deny beside the user
 *  `deny` regexes, an ask after the code-loading ask. Both run before every allow layer. The reason is the
 *  rule's own, which the user wrote for the agent to read. */
function commandRuleHit(call: RuleCall, action: CommandRuleAction): RuleResult | null {
	const rule = call.commandRules.find((r) => r.action === action);
	if (rule === undefined) return null;
	const reason = `command rule ${rule.id}: ${rule.reason}`;
	return action === "deny" ? { verdict: "deny", reason, rule: rule.id } : { verdict: "ask", reason, askSource: "rule", rule: rule.id };
}

/** Asks on any `.omp` access while `gateOmpDir` is on, an unknown tool's targets included. The path goes
 *  to `detail` only, because the reason reaches the agent. */
function forcedOmpGate(call: RuleCall, ctx: RuleContext): RuleResult | null {
	if (!ctx.userRules.gateOmpDir) return null;
	const omp = hitOmpDir(call.toolName, call.input, ctx.commandCwd);
	if (!omp) return null;
	return {
		verdict: "ask",
		reason: "forced gate: access to a .omp directory (gateOmpDir)",
		detail: omp + multiTargetDetailSuffix(call.access),
		askSource: "protected-path",
		rule: "gate-omp-dir",
	};
}

/** Asks on a declared protected path, an unknown tool's targets included; a declaration is the user's
 *  exception to their own allow rules (ADR-0002). The path goes to `detail` only, because the reason
 *  reaches the agent and would leak the declaration. */
function denyPathsAsk(call: RuleCall, ctx: RuleContext): RuleResult | null {
	const hit = hitDenyPaths(call.toolName, call.input, ctx.commandCwd, ctx.denyPathBases);
	if (!hit) return null;
	return {
		verdict: "ask",
		reason: "user-declared protected path (denyPaths) [path withheld; see pi-verdict.json]",
		detail: hit + multiTargetDetailSuffix(call.access),
		askSource: "protected-path",
		rule: "deny-paths",
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
		rule: "deny-paths-spelling",
	};
}

/** Asks on a write where the host loads code: it runs in every later session, which is more than the
 *  one action a classifier is asked about (ADR-0011). It goes off with the floor. Its reason carries the
 *  path, so it runs after both protected-path asks, which withhold theirs. */
function codeLoadingAsk(call: RuleCall, ctx: RuleContext): RuleResult | null {
	if (!ctx.userRules.builtinDenyFloor) return null;
	const overrides = ctx.userRules.floorOverrides;
	const lifted = (hitPath: string): boolean => overrideFor(overrides, "code-loading", baseForms(hitPath))?.action === "off";
	const code = hitCodeLoadPath(call.toolName, call.input, ctx.commandCwd, ctx.protectedSet.agentDir, lifted);
	if (!code) return null;
	return {
		verdict: "ask",
		reason: `host code-loading location (${code.kind}): ${code.path} — the host runs it in later sessions, so a human must confirm the call (ADR-0011)`,
		askSource: "rule",
		rule: "code-loading",
	};
}

/** Asks on an action longer than the floor reads, before user allow, so no rule allows an unread tail.
 *  The deny-side layers run first; they can only narrow the outcome. */
function overCapAsk(call: RuleCall, ctx: RuleContext): RuleResult | null {
	if (!actionCallLine(call.toolName, call.input, ctx.displayedCwd).overCap) return null;
	return {
		verdict: "ask",
		reason: `action too long to grade safely (over ${ACTION_LINE_MAX_CHARS} chars)`,
		askSource: "rule",
		rule: "over-cap",
	};
}

/** Allows when a user `allow` rule matches every target. A command must be one simple command
 *  (ADR-0008): a compound command, an unsound parse, a redirection, a write-shaped git call, or an
 *  operand that is a secret, a system path or an unresolvable expansion reaches the classifier instead.
 *  Never while the policy is degraded (ADR-0010), nor for a target a rule cannot read as a literal
 *  project path (a glob, an internal URL, a relocatable read), nor for an opaque call, whose real target
 *  is unknown. */
function userAllow(call: RuleCall, ctx: RuleContext): RuleResult | null {
	if (call.targets.length === 0 || !call.vouchable) return null;
	// The regexes run first: they are cheaper than the operand grading, which reads the filesystem.
	if (!ctx.userRules.allow.some((re) => call.targets.every((t) => re.test(t)))) return null;
	if (isCommandTool(call.toolName) && !commandAdmitted(call.toolName, commandText(call.input), ctx)) return null;
	return { verdict: "allow", reason: "user allow rule", rule: "user-allow" };
}

/** True when a user allow rule may admit this command: one simple command (ADR-0008) whose operands the
 *  floor lets a file tool read. */
function commandAdmitted(toolName: string, command: string, ctx: RuleContext): boolean {
	const shell = toolName === "powershell" ? "powershell" : "bash";
	return (
		allowAdmits(command) &&
		allowOperandsAdmit(command, { commandCwd: ctx.commandCwd, sessionCwd: ctx.sessionCwd, shellState: ctx.shellState, shell })
	);
}

/** Allows a tool listed in `tools` by exact name, after every deny-side layer (ADR-0009), on the same
 *  condition as a user `allow` rule. An eval cell is never exempt, because its code can do anything a
 *  command can. */
function toolsExemption(call: RuleCall, ctx: RuleContext): RuleResult | null {
	if (!ctx.userRules.tools.includes(call.toolName) || call.access.kind === "code" || !call.vouchable) return null;
	return { verdict: "allow", reason: "user tools allow rule", rule: "user-tools" };
}

/** Asks on a known mutating call whose payload names no target; an unknown tool is never opaque. */
function opaqueAsk(call: RuleCall, _ctx: RuleContext): RuleResult | null {
	if (call.access.direction !== "mutating" || !call.access.opaque) return null;
	return { verdict: "ask", reason: "mutating call with no extractable target", askSource: "rule", rule: "opaque" };
}
