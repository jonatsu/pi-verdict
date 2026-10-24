import { isCommandTool, isHostInternalUrl, multiTargetDetailSuffix, readMayRelocate, toolAccess, userRuleTargets } from "./access.ts";
import { ACTION_LINE_MAX_CHARS, actionCallLine, type RedactorFn } from "./classifier.ts";
import { hitCodeLoadPath } from "./code-loading.ts";
import type { UserRules } from "./config.ts";
import { hitDenyPaths, hitOmpDir } from "./deny-paths.ts";
import { classifyReads, classifyWrites, globStaysInProject, s0DirectoryBeneath } from "./floor.ts";
import { type ProtectedSet, selfProtectCheck } from "./self-protection.ts";
import { allowAdmits, classifyBash, pyEvalShellLines, type RuleResult } from "./shell.ts";

/**
 * Tool call → rule-layer verdict. Order (#12; ADR-0005 adds layer 0; ADR-0002 inserts denyPaths;
 * ADR-0009 moves the tools exemption after the deny-side layers and adds the opaque ask; item 4
 * (eval semantics) grades kind "code" through steps 1–2 and 5, never 4 — see ADR-0009's
 * Phase 3 amendment):
 *   0. self-protection — deny is terminal (no config exempts it, not even builtinDenyFloor:false)
 *   1. built-in base (bash danger regex floor / path sensitivity grading over every adapter
 *      target; a py eval cell's extracted shell-out lines only) — deny is terminal (the floor
 *      can be turned off via builtinDenyFloor)
 *   2. user deny → deny (beats allow; a code call's whole text is also a deny target)
 *   2a. gateOmpDir (default off): path/command/code text touching a `.omp` directory → ask
 *   3. denyPaths hit → terminal ask (ADR-0002: the declaring user adjudicates; before user allow)
 *      then the code-loading ask (ADR-0011): a write where the host loads code → ask; off
 *      with the floor
 *   3a. over-cap action → terminal ask (item 6a, Phase 4): never a mechanical allow on an
 *       action the floor could not fully read (F8's ordering gap)
 *   4. user allow → allow (never for kind "code": a code call always reaches the classifier
 *      unless something above denies or asks first; never while policyDegraded — ADR-0010;
 *      never for an opaque call or a glob path)
 *   5. custom-tool exact match (user.tools) → allow (bypasses classifier; never for kind "code";
 *      never while policyDegraded — ADR-0010; never for an opaque call or a glob path)
 *   6. opaque ask: a known mutating call (write/edit/ast_edit) with no extractable target
 *   7. base (observing default allow/gray; everything else gray) → classifier
 */
export function classifyByRules(
	toolName: string,
	input: Record<string, unknown>,
	cwd: string,
	user: UserRules,
	prot: ProtectedSet,
	denyPathBases: string[],
	/** item 6c (Phase 6; ADR-0010): while the user's own policy failed to load, the user
	 *  allow loop and the tools exemption are suspended (steps 4/5) — deny-side layers and
	 *  the floor above them are unchanged, and everything they do not decide falls through
	 *  to the classifier, whose allow is then withheld by adjudicate. */
	policyDegraded: boolean,
	/** True when the call names a user-declared protected path through a spelling the denyPaths
	 *  tokeniser cannot extract, such as a home variable behind a command substitution. */
	namesProtectedPath: RedactorFn = () => false,
): RuleResult {
	const sp = selfProtectCheck(toolName, input, cwd, prot);
	if (sp) return sp;

	const access = toolAccess(toolName, input);
	let base: RuleResult;
	let relocatable = false;
	if (isCommandTool(toolName)) {
		base = classifyBash(String(input.command ?? ""), user.builtinDenyFloor);
	} else if (access.direction === "mutating") {
		// Opaque calls have nothing for classifyWrites to grade; their own ask fires below,
		// after the deny-side layers and the tools exemption get first look.
		base = access.opaque ? { verdict: "gray" } : classifyWrites(access.gradedWrites, cwd, user.builtinDenyFloor);
	} else if (access.direction === "observing") {
		const readTargets = access.gradedReads.length > 0 ? access.gradedReads : [cwd];
		base = classifyReads(readTargets, cwd, user.builtinDenyFloor);
		// A scope search below a credential directory's parent walks into it, so the floor's allow
		// for the parent is not a verdict; a plain read of a directory is not a search.
		if (base.verdict === "allow" && access.scope && readTargets.some((t) => s0DirectoryBeneath(t, cwd))) {
			base = { verdict: "gray", reason: "search scope contains a credential directory" };
		}
		// The host reads a missing relative target from a workspace file it finds by suffix, so no rule
		// may vouch for the spelling; the classifier sees the call instead.
		relocatable = toolName === "read" && access.reads.some((t) => readMayRelocate(t, cwd));
		if (relocatable && base.verdict === "allow") {
			base = { verdict: "gray", reason: "relative read target does not exist (the host may open another file)" };
		}
	} else if (access.kind === "code" && access.command !== null && input.language === "py") {
		// Phase 3 (F13): the bash floor applies to a Python eval cell's extracted shell-out
		// lines only (pyEvalShellLines) — never the whole code text, which the floor's danger
		// regexes/tripwire/allowAdmits never see (those stay bash-command-only).
		const shellText = pyEvalShellLines(access.command).join("\n");
		base = shellText ? classifyBash(shellText, user.builtinDenyFloor) : { verdict: "gray" };
	} else {
		base = { verdict: "gray", reason: `tool not covered by built-in rules: ${toolName}` };
	}
	if (base.verdict === "deny") return base; // Built-in floor: deny takes precedence over all user rules
	// A target in one of the host's internal URL schemes is served by a handler (a remote host, a
	// vault), not by the project file its text resolves to, so no rule may vouch for it.
	const internalUrl =
		(access.direction === "observing" || toolName === "ast_edit") &&
		[...access.gradedReads, ...access.gradedWrites].some(isHostInternalUrl);
	if (internalUrl && base.verdict === "allow") {
		base = { verdict: "gray", reason: "target is an internal URL, not a project path" };
	}
	// A glob target names files the prefix grade cannot see, so the floor's allow is not a
	// verdict for it; the deny-side layers below still run on the prefix. `glob` alone only lists
	// names, so it keeps the allow while everything it can reach stays inside the project.
	if (access.globbed && base.verdict === "allow" && !(toolName === "glob" && globStaysInProject(access.gradedReads, cwd)))
		base = { verdict: "gray", reason: "path contains glob metacharacters (not graded as a literal path)" };

	// User deny (known-tool targets only — R2-2: an unknown tool's shape-inferred fields
	// never reach user rules; Item 10 / F11: deny fires on ANY target match). kind "code"
	// (eval, item 4): the whole code text is also a deny target — user allow stays excluded
	// (targets, reused below for allow, never gains the code text).
	const targets = userRuleTargets(toolName, input, cwd);
	const denyTargets = access.kind === "code" && access.command !== null ? [...targets, access.command] : targets;
	for (const re of user.deny) {
		if (denyTargets.some((t) => re.test(t))) return { verdict: "deny", reason: `user deny rule: ${re.source}` };
	}
	// Forced .omp gate: terminal ask, after user deny, before denyPaths/user allow. Not gated
	// by `targets` — callPathCandidates (which hitOmpDir uses) also covers an unknown tool's
	// adapter-derived fields. Reason carries no path (it travels back into agent context); the
	// path is UI-only detail.
	if (user.gateOmpDir) {
		const omp = hitOmpDir(toolName, input, cwd);
		if (omp)
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
	const hit = hitDenyPaths(toolName, input, cwd, denyPathBases);
	if (hit) {
		return {
			verdict: "ask",
			reason: "user-declared protected path (denyPaths) [path withheld; see pi-verdict.json]",
			detail: hit + multiTargetDetailSuffix(access),
			askSource: "protected-path",
		};
	}
	// A model that sees only a marker in place of such a call cannot judge it, and a protected path
	// overrides the user's own allow rules (ADR-0002), so the gate asks without a model call.
	if (namesProtectedPath(input)) {
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
	if (user.builtinDenyFloor) {
		const code = hitCodeLoadPath(toolName, input, cwd);
		if (code)
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
	if (actionCallLine(toolName, input).overCap) {
		return {
			verdict: "ask",
			reason: `action too long to grade safely (over ${ACTION_LINE_MAX_CHARS} chars)`,
			askSource: "rule",
		};
	}
	// User allow (known-tool targets only, same scope as user deny above). ADR-0008: a user
	// allow admits ONE simple command. A compound command, an unsound parse, a redirection or
	// a write-shaped git invocation is never rule-allowed — it reaches the classifier.
	// Suspended while policyDegraded (ADR-0010): a partially-loaded policy's allow list may
	// still be present while a deny/denyPaths entry was dropped — granting mechanical allows
	// on that basis is the fail-open direction this closes.
	// An opaque call's path/paths are model-supplied while its real target is unknown, so no
	// rule can vouch for it (the same call is denied without an allow rule configured).
	if (targets.length > 0 && !policyDegraded && !access.globbed && !access.opaque && !relocatable && !internalUrl) {
		const allowOk = !isCommandTool(toolName) || allowAdmits(String(input.command ?? ""));
		if (allowOk) {
			for (const re of user.allow) {
				if (targets.every((t) => re.test(t))) return { verdict: "allow", reason: "user allow rule" };
			}
		}
	}

	// tools exemption: exact-name allowlist, checked AFTER every deny-side layer above and
	// BEFORE the opaque ask / gray fall-through (ADR-0009) — a listed tool carrying a
	// protected-path target now faces the ask above instead of a silent allow here. kind
	// "code" (eval, item 4): leaves the tools exemption family entirely — its documented scope
	// is non-code tools; a user who listed eval here loses the exemption (BREAKING). Suspended
	// with user allow while policyDegraded (ADR-0010).
	if (
		user.tools.includes(toolName) &&
		access.kind !== "code" &&
		!policyDegraded &&
		!access.globbed &&
		!access.opaque &&
		!relocatable &&
		!internalUrl
	)
		return { verdict: "allow", reason: "user tools allow rule" };

	// Opaque ask: a known mutating call (write/edit/ast_edit) with no extractable target at
	// all — deterministic ask, headless → deny (never for an unknown tool: see toolAccess).
	if (access.direction === "mutating" && access.opaque) {
		return { verdict: "ask", reason: "mutating call with no extractable target", askSource: "rule" };
	}

	return base;
}
