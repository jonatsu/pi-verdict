import * as os from "node:os";
import * as path from "node:path";
import { collectStrings, commandText, isCommandTool, type ToolAccess } from "./access.ts";
import { escapeRegExp } from "./agent-dir.ts";
import { expandHome, toRuleForm } from "./floor.ts";
import { baseForms, isWithin, kernelForms, rebuiltForms, relativeBeneath } from "./paths.ts";
import type { RuleResult } from "./shell.ts";

// ============================================================================
// Self-protection layer (ADR-0005): the gate cannot be turned off by the thing it gates
//
// A hard deny over the gate's own files that neither `builtinDenyFloor:false` nor a user
// allow rule exempts; `docs/layers.md` lists the protected scope. Every write that reaches
// the gate is agent-initiated, so the reason points the user to a manual edit. The audit
// directory also denies reads, because its records carry raw model output (#54). There is
// no in-memory tamper baseline, so concurrent sessions never fight over each other's edits.
// The shell check is a substring match and stays obfuscatable (ADR-0001): it raises the
// bar for a rewrite, it does not prevent one.
// ============================================================================

/** The module the gate value-imports from the extensions root beside it (`jev-adapter.ts`). */
const JEV_ADAPTER_FILE = "jev-adapter.ts";

export interface ProtectedSet {
	/** Protected files, in lexical and realpath forms. */
	exact: string[];
	/** Protected directories, matched by prefix: the audit directory and a package or module install. */
	prefixes: string[];
	/** Write guards for a protected file at no fixed path (a project `plugin-overrides.json`). */
	writePatterns: RegExp[];
	/** Paths whose reads deny too: the audit directory and the trust store. */
	readDenied: string[];
	/** Trees within which an ancestor of a read-denied path denies too, since `grep <agentDir>` reads every
	 *  record; bounded to the gate's own trees, so a home or root listing passes. */
	guardRoots: string[];
	/** Shell command signatures, matched as substrings. */
	bashPatterns: RegExp[];
	/** The agent directory the set was built for; `$PI_CODING_AGENT_DIR` in a command expands to it. */
	agentDir: string;
}

/**
 * Returns the paths and command signatures self-protection guards. `ownFile` is the gate's install
 * location (`OWN_FILE_PATH`), or null when it cannot be resolved; the config, trust store and audit
 * directory stay protected either way. The installed copy is protected only under an install root, so a
 * dev checkout stays writable.
 */
export function buildProtectedSet(agentDir: string, ownFile: string | null): ProtectedSet {
	const exact = new Set<string>();
	const prefixes = new Set<string>();
	// The gate's decision inputs: the policy and the project-trust store.
	for (const f of baseForms(path.join(agentDir, "config", "pi-verdict.json"))) exact.add(f);
	for (const f of baseForms(path.join(agentDir, "config", "pi-verdict-trust.json"))) exact.add(f);

	const install = ownFile ? installTargets(agentDir, ownFile) : [];
	for (const { target, isExact } of install) (isExact ? exact : prefixes).add(target);
	const installTargetPaths = new Set(install.map((t) => t.target));

	const plugins = pluginRoots(agentDir);
	const enablement = enablementFiles(plugins);
	for (const f of enablement) exact.add(f);
	// Matches a project `plugin-overrides.json` under `.omp` or `.pi`, which can disable the gate too.
	const writePatterns = [/(?:^|[\\/])\.(?:omp|pi)[\\/]plugin-overrides\.json$/];

	// Every spelling of a gate config path contains its file name; the install, enablement and audit
	// paths need each spelling.
	const bashPatterns: RegExp[] = [/pi-verdict\.json/, /pi-verdict-trust\.json/, /plugin-overrides\.json/];
	if (installTargetPaths.size > 0) bashPatterns.push(pathAlternation([...installTargetPaths], agentDir));
	if (enablement.length > 0) bashPatterns.push(pathAlternation(enablement, agentDir));

	// The trust store is read-denied beside the audit directory, because reading it maps the route
	// to tampering with it.
	const verdictsForms = baseForms(path.join(agentDir, "verdicts"));
	const trustForms = baseForms(path.join(agentDir, "config", "pi-verdict-trust.json"));
	for (const f of verdictsForms) prefixes.add(f);
	bashPatterns.push(pathAlternation(verdictsForms, agentDir));
	const readDenied = [...verdictsForms, ...trustForms];

	// A filesystem root is never a guard root, so a root listing stays readable (pinned by the test
	// `an agent directory directly under the root keeps a root listing readable`).
	const guardRoots = new Set<string>();
	for (const root of [agentDir, path.dirname(agentDir), ...plugins]) {
		for (const f of baseForms(root)) if (f !== path.parse(f).root) guardRoots.add(f);
	}

	return { exact: [...exact], prefixes: [...prefixes], writePatterns, readDenied, guardRoots: [...guardRoots], bashPatterns, agentDir };
}

type InstallKind = "extensions" | "npm" | "git";

/** One install root of a host layout, in every spelling `baseForms` gives it. */
interface InstallRootFamily {
	readonly kind: InstallKind;
	readonly roots: readonly string[];
}

/** A protected path of the installed copy: an exact file, or a directory protected by prefix. */
interface InstallTarget {
	readonly target: string;
	readonly isExact: boolean;
}

/** A target relative to an install root. */
interface RelativeTarget {
	readonly rel: readonly string[];
	readonly isExact: boolean;
}

/** Returns every install root the host may load the gate from, grouped by spelling. */
function installRootFamilies(agentDir: string): InstallRootFamily[] {
	const agentBases = new Set(baseForms(agentDir));
	const configRootBases = new Set([...agentBases].map((b) => path.dirname(b)));
	const layouts: { seg: string[]; kind: InstallKind; bases: Set<string> }[] = [
		{ seg: ["extensions"], kind: "extensions", bases: agentBases },
		// omp plugin installs, under the agent dir or (omp 18.1+) beside it
		{ seg: ["plugins", "node_modules"], kind: "npm", bases: new Set([...agentBases, ...configRootBases]) },
		// pi package installs: `<agentDir>/npm/node_modules/<pkg>` and `<agentDir>/git/<host>/<path>`
		{ seg: ["npm", "node_modules"], kind: "npm", bases: agentBases },
		{ seg: ["git"], kind: "git", bases: agentBases },
	];
	const families: InstallRootFamily[] = [];
	for (const { seg, kind, bases } of layouts) {
		for (const base of bases) families.push({ kind, roots: baseForms(path.join(base, ...seg)) });
	}
	return families;
}

/** Returns the protected targets of the installed copy at `ownFile`: the single-file form protects the
 *  file itself (exact), the module-directory and package forms the directory or package root (prefix).
 *  Each install root is one directory in several spellings (lexical, realpath: a symlinked directory or a
 *  macOS /var → /private/var cannot misalign the set), so a match under any spelling protects the same
 *  relative targets under every spelling. Empty for a dev checkout. */
function installTargets(agentDir: string, ownFile: string): InstallTarget[] {
	const out: InstallTarget[] = [];
	const ownForms = [...new Set(baseForms(ownFile))];
	for (const { kind, roots } of installRootFamilies(agentDir)) {
		for (const installRoot of roots) {
			for (const rel of relativeToAny(ownForms, installRoot)) {
				for (const { rel: targetRel, isExact } of relativeInstallTargets(kind, rel.split(path.sep))) {
					for (const target of spellEveryRoot(roots, targetRel)) out.push({ target, isExact });
				}
			}
		}
	}
	return out;
}

/** Returns the path below `root` of each form that lies under it. */
function relativeToAny(forms: readonly string[], root: string): string[] {
	return forms.map((form) => relativeBeneath(form, root)).filter((rel): rel is string => rel !== null);
}

/** Returns `rel` joined onto every spelling of its install root, each in its `baseForms`. */
function spellEveryRoot(roots: readonly string[], rel: readonly string[]): string[] {
	return roots.flatMap((root) => baseForms(path.join(root, ...rel)));
}

/** Returns the targets to protect for the gate file at `segs` inside an install root of `kind`. */
function relativeInstallTargets(kind: InstallKind, segs: readonly string[]): RelativeTarget[] {
	// A single-file copy also protects the sibling adapter module it imports, since rewriting
	// that changes the gate as surely as rewriting the main file.
	if (segs.length === 1) {
		return [
			{ rel: segs, isExact: true },
			{ rel: [JEV_ADAPTER_FILE], isExact: true },
		];
	}
	const targets: RelativeTarget[] = [{ rel: segs.slice(0, packageDepth(kind, segs)), isExact: false }];
	// A module directory directly under an extensions root (extensions/pi-verdict/index.ts)
	// imports the adapter from the root beside it, outside the directory prefix. A top-level
	// `<dir>.ts` or `<dir>.js` is a decoy entry: the host dedupes extensions by name, keeps the
	// first, and discovers top-level files before `*/index.ts`.
	if (kind === "extensions" && segs.length === 2 && !segs[0].startsWith("@")) {
		targets.push(
			{ rel: [JEV_ADAPTER_FILE], isExact: true },
			{ rel: [`${segs[0]}.ts`], isExact: true },
			{ rel: [`${segs[0]}.js`], isExact: true },
		);
	}
	return targets;
}

/** Segments of the package root inside an install root. npm scopes are two-segment dirs
 *  (@scope/pkg): protect the package, not the whole scope dir. A git install is
 *  `<host>/<path>/…` with a path of unknown depth, so the package ends where `extensions` starts. */
function packageDepth(kind: InstallKind, segs: readonly string[]): number {
	if (kind === "git") {
		const at = segs.findIndex((seg, k) => k >= 2 && seg === "extensions");
		return at > 0 ? at : Math.min(3, segs.length - 1);
	}
	return segs[0].startsWith("@") ? 2 : 1;
}

/** Returns the plugin workspace roots: `plugins/` inside the agent directory and beside it. */
function pluginRoots(agentDir: string): string[] {
	const roots = new Set<string>();
	for (const root of [path.join(agentDir, "plugins"), path.join(path.dirname(agentDir), "plugins")]) {
		for (const f of baseForms(root)) roots.add(f);
	}
	return [...roots];
}

/** Returns the plugin workspace manifest and lock files, which can disable the gate for later sessions
 *  without a verdict; writes to them deny, and reads pass. */
function enablementFiles(plugins: readonly string[]): string[] {
	const files = new Set<string>();
	for (const root of plugins) {
		for (const name of ["omp-plugins.lock.json", "package.json"]) {
			for (const f of baseForms(path.join(root, name))) files.add(f);
		}
	}
	return [...files];
}

/** Regex alternation matching any spelling of the given absolute paths in a shell command:
 *  the literal path, its ~/ form, its $HOME/ form, and its $PI_CODING_AGENT_DIR/ form. */
function pathAlternation(forms: string[], agentDir: string): RegExp {
	const home = os.homedir();
	const alts = new Set<string>(forms.map(escapeRegExp));
	for (const f of forms) {
		const homeRel = relativeBeneath(f, home);
		if (homeRel !== null) {
			alts.add(escapeRegExp("~/" + homeRel));
			alts.add("\\$HOME/" + escapeRegExp(homeRel));
		}
		for (const base of baseForms(agentDir)) {
			const agentRel = relativeBeneath(f, base);
			if (agentRel !== null) alts.add("\\$PI_CODING_AGENT_DIR/" + escapeRegExp(agentRel));
		}
	}
	return new RegExp(`(?:${[...alts].join("|")})`);
}

/** Returns true when a write to `rawPath` lands in the protected set in any form it resolves to. A
 *  nonexistent target is rebuilt from its nearest existing ancestor (#20), so a symlink cannot route
 *  around the check. */
export function isProtectedWritePath(rawPath: string, cwd: string, prot: ProtectedSet): boolean {
	if (!rawPath) return false;
	for (const c of [...rebuiltForms(path.resolve(cwd, expandHome(rawPath))), ...kernelForms(rawPath, cwd)]) {
		if (prot.exact.includes(c)) return true;
		if (prot.prefixes.some((p) => isWithin(c, p))) return true;
		if (prot.writePatterns.some((re) => re.test(toRuleForm(c)))) return true;
	}
	return false;
}

/** Returns true when a read of `rawPath` reaches the audit directory or the trust store. Inside the
 *  gate's own trees an ancestor of either counts too, since `grep <agentDir>` reads every record. */
export function isProtectedReadPath(rawPath: string | undefined, cwd: string, prot: ProtectedSet): boolean {
	if (prot.readDenied.length === 0) return false;
	const target = rawPath ?? cwd; // a pathless read reads the cwd (#48)
	for (const c of [...rebuiltForms(path.resolve(cwd, expandHome(target))), ...kernelForms(target, cwd)]) {
		if (prot.readDenied.some((p) => isWithin(c, p))) return true;
		if (prot.guardRoots.some((root) => isWithin(c, root)) && prot.readDenied.some((p) => isWithin(p, c))) return true;
	}
	return false;
}

/** Returns the directories a shell command changes into with `cd` or `pushd`, `$HOME` and
 *  `$PI_CODING_AGENT_DIR` expanded, because `cd <agentDir> && cat verdicts/*.jsonl` names no
 *  protected path the substring check could see. */
function bashDirectoryTargets(command: string, agentDir: string): string[] {
	const out: string[] = [];
	const re = /(?:^|[;&|()\s])(?:cd|pushd)\s+(?:"([^"]+)"|'([^']+)'|([^\s;&|()]+))/g;
	for (const m of command.matchAll(re)) {
		let raw = m[1] ?? m[2] ?? m[3] ?? "";
		if (!raw || raw === "-") continue;
		raw = raw.replace(/^\$HOME(?=\/|$)/, os.homedir()).replace(/^\$PI_CODING_AGENT_DIR(?=\/|$)/, agentDir);
		out.push(raw);
	}
	return out;
}

/** Returns a deny that no configuration exempts when the call's inputs touch the gate's own files, or
 *  null to hand the call to the next layer. The access direction selects the check; the paths come
 *  from the call's inputs, so a tool the gate does not know gets the write check. */
export function selfProtectCheck(
	toolName: string,
	input: Record<string, unknown>,
	access: ToolAccess,
	cwd: string,
	prot: ProtectedSet,
): RuleResult | null {
	if (isCommandTool(toolName)) {
		const cmd = commandText(input);
		const cdHit = bashDirectoryTargets(cmd, prot.agentDir).some((t) => isProtectedReadPath(t, cwd, prot));
		return prot.bashPatterns.some((re) => re.test(cmd)) || cdHit ? selfDeny(COMMAND_TOUCHES_GATE) : null;
	}
	const strings = collectStrings(input);
	switch (access.direction) {
		case "observing":
			for (const s of [...strings, ...access.gradedReads]) {
				if (isProtectedReadPath(s, cwd, prot))
					return selfDeny(
						`self-protection layer (#54): ${s} holds the gate's verdict audit records or trust store — agent reads are denied (untrusted raw model output inside); view them outside the agent`,
					);
			}
			return null;
		case "mutating":
		case "unknown":
			return selfProtectWrite(strings, access, cwd, prot);
		default: {
			const unhandled: never = access.direction;
			return unhandled;
		}
	}
}

/** The write check, which also covers a tool the gate does not know. */
function selfProtectWrite(strings: readonly string[], access: ToolAccess, cwd: string, prot: ProtectedSet): RuleResult | null {
	// Any input string in the protected set denies. The adapter's targets count too, because an
	// apply-patch header names its file inside one raw string.
	for (const s of [...strings, ...access.gradedWrites, ...access.gradedReads]) {
		if (isProtectedWritePath(s, cwd, prot))
			return selfDeny(
				`self-protection layer (ADR-0005): ${s} is part of the permission gate itself; agent-side modification is denied — edit it manually outside the agent if intended`,
			);
	}
	// An eval cell can run shell lines, so the command signatures run over its code text too.
	const code = access.kind === "code" ? access.command : null;
	if (code !== null && prot.bashPatterns.some((re) => re.test(code))) return selfDeny(COMMAND_TOUCHES_GATE);
	return null;
}

const COMMAND_TOUCHES_GATE = "self-protection layer (ADR-0005): command touches the permission gate's own files — user-editable only";

/** A self-protection deny, which no configuration exempts (`autoDeny:false` included). */
function selfDeny(reason: string): RuleResult {
	return { verdict: "deny", reason, selfProtect: true };
}
