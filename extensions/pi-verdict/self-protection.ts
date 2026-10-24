import * as os from "node:os";
import * as path from "node:path";
import { isCommandTool, MUTATING_TOOL_NAMES, OBSERVING_TOOL_NAMES, toolAccess } from "./access.ts";
import { agentDirPath, escapeRegExp } from "./agent-dir.ts";
import { expandHome, toRuleForm } from "./floor.ts";
import { baseForms, kernelForms, rebuiltForms } from "./paths.ts";
import { inputStrings } from "./redaction.ts";
import type { RuleResult } from "./shell.ts";

// ============================================================================
// Self-protection layer (ADR-0005): gate integrity over configuration exemption
//
// The gate cannot be turned off by the thing it gates. A hard deny over the gate's
// own files, immune to builtinDenyFloor:false and to user allow rules; the #54
// verdicts audit directory additionally denies reads (records carry untrusted raw
// model output that must not flow back into agent context). Protected scope:
//   - <agentDir>/config/pi-verdict.json (the gate's decision input)
//   - <agentDir>/config/pi-verdict-trust.json (project-trust decisions)
//   - the installed extension copy, with its sibling jev-adapter.ts in the single-file
//     and module-directory forms (pi under <agentDir>/extensions/, omp under
//     plugins/node_modules/<pkg>/ in its config root — the install forms listed
//     with resolveAgentDir; dev checkouts are not in scope)
//   - <agentDir>/verdicts/ (write + read)
// Semantics: every in-gate write is by definition agent-initiated → deny (the
// reason points the user to manual edits); reads pass outside the audit dir; the
// user's own editor writes never pass through the gate. Deliberately snapshot-free
// (ADR-0005): no in-memory tamper baseline, so concurrent sessions never fight over
// one another's legitimate edits. The bash side is a substring match and stays
// obfuscatable (honest declaration, ADR-0001): it raises the bar, it is not a
// guarantee against a direct rewrite outside a tool call.
// ============================================================================

/** The module the gate value-imports from the extensions root beside it (`jev-adapter.ts`). */
const JEV_ADAPTER_FILE = "jev-adapter.ts";

export interface ProtectedSet {
	/** exact protected files (lexical absolute + realpath forms) */
	exact: string[];
	/** protected directory prefixes (npm package install form: the whole package dir) */
	prefixes: string[];
	/** path-shaped write guards that name no fixed file (project `plugin-overrides.json`) */
	writePatterns: RegExp[];
	/** read-denied paths: the #54 audit dir and the trust store */
	readDenied: string[];
	/** trees within which an ancestor of a read-denied path is itself read-denied
	 *  (`grep <agentDir>` reads every record through the directory); bounded to the
	 *  gate's own trees so a home/root listing is not caught */
	guardRoots: string[];
	/** bash/powershell command-string signatures (substring match, obfuscatable) */
	bashPatterns: RegExp[];
}

/**
 * Build the protected set. ownFile is this module's path (import.meta.url resolved;
 * null = unresolvable, config/trust/verdicts still protected). The installed copy is
 * protected only when ownFile sits under one of the install roots (the forms listed
 * with resolveAgentDir, plus pi's `<agentDir>/npm` and `<agentDir>/git` package installs); dev checkouts (source inside the cwd) are NOT protected —
 * in-project development writes are legitimate daily work.
 */
export function buildProtectedSet(agentDir: string, ownFile: string | null): ProtectedSet {
	const exact = new Set<string>();
	const prefixes = new Set<string>();
	// The gate's decision inputs: the policy and the project-trust store.
	for (const f of baseForms(path.join(agentDir, "config", "pi-verdict.json"))) exact.add(f);
	for (const f of baseForms(path.join(agentDir, "config", "pi-verdict-trust.json"))) exact.add(f);

	// Installed copy target: single-file form → the file itself (exact); module-directory
	// and package forms → the directory or package root (prefix). Each install root is one
	// directory in several spellings (lexical, realpath: a symlinked directory or a macOS
	// /var → /private/var cannot misalign the set), so a match under any spelling protects
	// the same relative targets under every spelling.
	const extTargets = new Set<string>();
	if (ownFile) {
		type RootKind = "extensions" | "npm" | "git";
		const agentBases = new Set(baseForms(agentDir));
		const configRootBases = new Set([...agentBases].map((b) => path.dirname(b)));
		const layouts: { seg: string[]; kind: RootKind; bases: Set<string> }[] = [
			{ seg: ["extensions"], kind: "extensions", bases: agentBases },
			// omp plugin installs, under the agent dir or (omp 18.1+) beside it
			{ seg: ["plugins", "node_modules"], kind: "npm", bases: new Set([...agentBases, ...configRootBases]) },
			// pi package installs: `<agentDir>/npm/node_modules/<pkg>` and `<agentDir>/git/<host>/<path>`
			{ seg: ["npm", "node_modules"], kind: "npm", bases: agentBases },
			{ seg: ["git"], kind: "git", bases: agentBases },
		];
		const families: { kind: RootKind; roots: string[] }[] = [];
		for (const { seg, kind, bases } of layouts) {
			for (const base of bases) families.push({ kind, roots: baseForms(path.join(base, ...seg)) });
		}
		// Segments of the package root inside an install root. npm scopes are two-segment dirs
		// (@scope/pkg): protect the package, not the whole scope dir. A git install is
		// `<host>/<path>/…` with a path of unknown depth, so the package ends where `extensions` starts.
		const packageDepth = (kind: RootKind, segs: string[]): number => {
			if (kind === "git") {
				const at = segs.findIndex((seg, k) => k >= 2 && seg === "extensions");
				return at > 0 ? at : Math.min(3, segs.length - 1);
			}
			return segs[0].startsWith("@") ? 2 : 1;
		};
		const ownForms = new Set(baseForms(ownFile));
		for (const { kind, roots } of families) {
			for (const extRoot of roots) {
				for (const own of ownForms) {
					if (!own.startsWith(extRoot + path.sep)) continue;
					const segs = path.relative(extRoot, own).split(path.sep);
					const singleFile = segs.length === 1;
					// A single-file copy also protects the sibling adapter module it imports, since rewriting
					// that changes the gate as surely as rewriting the main file.
					const targets: { rel: string[]; isExact: boolean }[] = singleFile
						? [
								{ rel: segs, isExact: true },
								{ rel: [JEV_ADAPTER_FILE], isExact: true },
							]
						: [{ rel: segs.slice(0, packageDepth(kind, segs)), isExact: false }];
					// A module directory directly under an extensions root (extensions/pi-verdict/index.ts)
					// imports the adapter from the root beside it, outside the directory prefix. A top-level
					// `<dir>.ts` or `<dir>.js` is a decoy entry: the host dedupes extensions by name, keeps the
					// first, and discovers top-level files before `*/index.ts`.
					if (!singleFile && kind === "extensions" && segs.length === 2 && !segs[0].startsWith("@")) {
						targets.push(
							{ rel: [JEV_ADAPTER_FILE], isExact: true },
							{ rel: [`${segs[0]}.ts`], isExact: true },
							{ rel: [`${segs[0]}.js`], isExact: true },
						);
					}
					for (const root of roots) {
						for (const { rel, isExact } of targets) {
							for (const f of baseForms(path.join(root, ...rel))) {
								(isExact ? exact : prefixes).add(f);
								extTargets.add(f);
							}
						}
					}
				}
			}
		}
	}

	// Gate enablement surface (R5): the plugin workspace manifest/lock and any project
	// `plugin-overrides.json` (`.omp`/`.pi`) can disable the gate for later sessions
	// without a verdict. Writes deny; reads may pass. The plugin workspace is derived
	// from the anchor (dot-dir sibling of `agent/`), not by counting path parents.
	const pluginRoots = new Set<string>();
	for (const root of [path.join(agentDir, "plugins"), path.join(path.dirname(agentDir), "plugins")]) {
		for (const f of baseForms(root)) pluginRoots.add(f);
	}
	const enablementFiles = new Set<string>();
	for (const root of pluginRoots) {
		for (const name of ["omp-plugins.lock.json", "package.json"]) {
			for (const f of baseForms(path.join(root, name))) {
				exact.add(f);
				enablementFiles.add(f);
			}
		}
	}
	const writePatterns = [/(?:^|[\\/])\.(?:omp|pi)[\\/]plugin-overrides\.json$/];

	// bash signatures: the gate filenames (any spelling contains them) + the installed-copy,
	// enablement and #54 paths
	const bashPatterns: RegExp[] = [/pi-verdict\.json/, /pi-verdict-trust\.json/, /plugin-overrides\.json/];
	if (extTargets.size > 0) bashPatterns.push(pathAlternation([...extTargets], agentDir));
	if (enablementFiles.size > 0) bashPatterns.push(pathAlternation([...enablementFiles], agentDir));

	// #54 verdicts dir: gate-owned audit storage. The trust store joins it as read-denied
	// (R6) — reading it is reconnaissance for the tampering route. Writes ride the normal
	// prefixes; reads are denied separately.
	const verdictsForms = baseForms(path.join(agentDir, "verdicts"));
	const trustForms = baseForms(path.join(agentDir, "config", "pi-verdict-trust.json"));
	for (const f of verdictsForms) prefixes.add(f);
	bashPatterns.push(pathAlternation(verdictsForms, agentDir));
	const readDenied = [...verdictsForms, ...trustForms];

	// Trees within which an ancestor directory of a read-denied path is itself read-denied
	// (bounded: a home or root listing must not be caught).
	const guardRoots = new Set<string>();
	for (const root of [agentDir, path.dirname(agentDir), ...pluginRoots]) {
		for (const f of baseForms(root)) guardRoots.add(f);
	}

	return { exact: [...exact], prefixes: [...prefixes], writePatterns, readDenied, guardRoots: [...guardRoots], bashPatterns };
}

/** Regex alternation matching any spelling of the given absolute paths in a shell command:
 *  the literal path, its ~/ form, its $HOME/ form, and its $PI_CODING_AGENT_DIR/ form. */
function pathAlternation(forms: string[], agentDir: string): RegExp {
	const home = os.homedir();
	const alts = new Set<string>(forms.map(escapeRegExp));
	for (const f of forms) {
		if (f.startsWith(home + path.sep)) {
			const rel = f.slice(home.length + 1);
			alts.add(escapeRegExp("~/" + rel));
			alts.add("\\$HOME/" + escapeRegExp(rel));
		}
		for (const base of baseForms(agentDir)) {
			if (f.startsWith(base + path.sep)) alts.add("\\$PI_CODING_AGENT_DIR/" + escapeRegExp(f.slice(base.length + 1)));
		}
	}
	return new RegExp(`(?:${[...alts].join("|")})`);
}

/** Does the resolved write path hit the protected set? realpath guards against a symlink
 *  bypass; a nonexistent target rebuilds its real form from the nearest existing ancestor (#20). */
export function isProtectedWritePath(rawPath: string, cwd: string, prot: ProtectedSet): boolean {
	if (!rawPath) return false;
	for (const c of [...rebuiltForms(path.resolve(cwd, expandHome(rawPath))), ...kernelForms(rawPath, cwd)]) {
		if (prot.exact.includes(c)) return true;
		for (const p of prot.prefixes) {
			if (c === p || c.startsWith(p + path.sep)) return true;
		}
		if (prot.writePatterns.some((re) => re.test(toRuleForm(c)))) return true;
	}
	return false;
}

/** Read-deny for the #54 audit dir and the trust store, ancestry-aware within the gate's
 *  own trees: `grep <agentDir>` reads every record through the directory, so an ancestor
 *  of a read-denied path denies too (bounded by guardRoots — a home/root listing passes). */
export function isProtectedReadPath(rawPath: string | undefined, cwd: string, prot: ProtectedSet): boolean {
	if (prot.readDenied.length === 0) return false;
	const target = rawPath ?? cwd; // #48: absent path → cwd is the effective target
	for (const c of [...rebuiltForms(path.resolve(cwd, expandHome(target))), ...kernelForms(target, cwd)]) {
		for (const p of prot.readDenied) {
			if (c === p || c.startsWith(p + path.sep)) return true;
		}
		for (const root of prot.guardRoots) {
			if ((c === root || c.startsWith(root + path.sep)) && prot.readDenied.some((p) => p === c || p.startsWith(c + path.sep))) return true;
		}
	}
	return false;
}

/** Direction the self-protection check applies to a call. The tool name only selects
 *  whose semantics apply; the paths come from the call's inputs (R3), so an unenumerated
 *  tool (ast_edit, an MCP filesystem tool, a later-added name) gets the write treatment. */
function selfProtectDirection(toolName: string): "write" | "read" | "command" | "unknown" {
	if (isCommandTool(toolName)) return "command";
	if (MUTATING_TOOL_NAMES.has(toolName)) return "write";
	if (OBSERVING_TOOL_NAMES.has(toolName)) return "read";
	return "unknown";
}

/** Directories a shell command changes into (`cd`/`pushd` targets), with ~/$HOME/
 *  $PI_CODING_AGENT_DIR expanded. `cd <agentDir> && cat verdicts/*.jsonl` is the route
 *  the absolute-path substring check cannot see. */
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

/** Self-protection verdict (layer 0, before everything): a call whose *inputs* touch the
 *  gate's own files → a non-exemptable deny; otherwise null, handing off to the layers
 *  below. Name-keyed routing selects direction; it is not the mechanism. */
export function selfProtectCheck(toolName: string, input: Record<string, unknown>, cwd: string, prot: ProtectedSet): RuleResult | null {
	const direction = selfProtectDirection(toolName);
	if (direction === "command") {
		const cmd = String(input.command ?? "");
		const cdHit = bashDirectoryTargets(cmd, agentDirPath()).some((t) => isProtectedReadPath(t, cwd, prot));
		if (prot.bashPatterns.some((re) => re.test(cmd)) || cdHit) {
			return {
				verdict: "deny",
				reason: "self-protection layer (ADR-0005): command touches the permission gate's own files — user-editable only",
				selfProtect: true,
			};
		}
		return null;
	}
	const strings = inputStrings(input);
	const access = toolAccess(toolName, input);
	if (direction === "read") {
		for (const s of [...strings, ...access.gradedReads]) {
			if (isProtectedReadPath(s, cwd, prot)) {
				return {
					verdict: "deny",
					reason: `self-protection layer (#54): ${s} holds the gate's verdict audit records or trust store — agent reads are denied (untrusted raw model output inside); view them outside the agent`,
					selfProtect: true,
				};
			}
		}
		return null;
	}
	// write + unknown: any input string landing in the protected set is a write, fail-safe.
	// The adapter's own writes/reads are tested too (Claude-review F7, today's gap): an
	// apply-patch `*** Update File: <agentDir>/config/pi-verdict.json` is a single raw input
	// string the blind scan above treats as one opaque path, not a patch to parse.
	for (const s of [...strings, ...access.gradedWrites, ...access.gradedReads]) {
		if (isProtectedWritePath(s, cwd, prot)) {
			return {
				verdict: "deny",
				reason: `self-protection layer (ADR-0005): ${s} is part of the permission gate itself; agent-side modification is denied — edit it manually outside the agent if intended`,
				selfProtect: true,
			};
		}
	}
	// kind "code" (eval): the command-direction substring signatures also run over the code
	// text — `eval` writing the gate's own files via `!cmd`/`%%bash` must not bypass them.
	if (access.kind === "code" && access.command !== null && prot.bashPatterns.some((re) => re.test(access.command as string))) {
		return {
			verdict: "deny",
			reason: "self-protection layer (ADR-0005): command touches the permission gate's own files — user-editable only",
			selfProtect: true,
		};
	}
	return null;
}
