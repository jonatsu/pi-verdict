import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { agentDirPath, escapeRegExp } from "./agent-dir.ts";
import { baseForms, fold, kernelWalk, rebuiltForms } from "./paths.ts";
import type { RuleResult } from "./shell.ts";

// ============================================================================
// Rule layer: file-path sensitivity (from research report §4.4)
// ============================================================================

/** S-rule regexes are written against POSIX spelling. On win32 (path.sep "\\") convert
 *  separators to "/" and drop the drive letter so `C:\proj\.ssh\id_rsa` and `/etc/x`
 *  (which path.resolve roots at the cwd drive) match like their POSIX counterparts.
 *  On POSIX a backslash is a legal filename character and is left untouched. */
export const toRuleForm = (f: string): string => (path.sep === "\\" ? f.replace(/\\/g, "/").replace(/^[A-Za-z]:(?=\/)/, "") : f);

export function expandHome(p: string): string {
	return p.startsWith("~") ? path.join(os.homedir(), p.slice(1)) : p;
}

/** The user's home in rule form — lexical and, when it resolves, realpath — regex-escaped. The
 *  XDG credential homes sit at exactly `<home>/.config/<name>`, so anchoring there keeps a repository
 *  path that merely contains `.config/age` (or `foo.config/age`) out of S0. The sibling dot entries
 *  (`.ssh`, `.aws`, `.gnupg`, `.config/gh`) stay segment-anywhere by the established S0 discipline; the
 *  two fork additions were the only ones the review named as unintentional over-match. */
const HOME_RULE_ROOTS: string[] = (() => {
	const lexical = toRuleForm(path.resolve(os.homedir()));
	const roots = [lexical];
	try {
		const real = toRuleForm(fs.realpathSync(lexical));
		if (real !== lexical) roots.push(real);
	} catch {
		/* home unresolvable → lexical root only */
	}
	return roots.map(escapeRegExp);
})();
/** Rule forms of an XDG config root — lexical and, when it resolves, realpath — regex-escaped. */
const xdgRootForms = (raw: string): string[] => {
	const lexical = toRuleForm(raw);
	const roots = [lexical];
	try {
		const real = toRuleForm(fs.realpathSync(lexical));
		if (real !== lexical) roots.push(real);
	} catch {
		/* root unresolvable → lexical root only */
	}
	return roots.map(escapeRegExp);
};

/** The XDG config root (item 9, plan-review F15): `XDG_CONFIG_HOME` REPLACES `~/.config` — it
 *  does not nest under it — so `$XDG_CONFIG_HOME/gnupg` (etc.) is the same credential home at a
 *  different root. An empty or relative value is ignored, as the XDG spec requires; unset → no
 *  alternatives and the anchored S0 entries keep their home-only patterns. App-level honouring of
 *  `XDG_CONFIG_HOME` by these tools (gnupg/age/sops/glab/gh) is unverified — anchoring is the
 *  conservative direction. `GNUPGHOME` stays out: an explicit override is the recorded `deliberate`
 *  case. */
const XDG_CONFIG_ROOTS: string[] = (() => {
	const raw = process.env.XDG_CONFIG_HOME;
	if (!raw || !path.isAbsolute(raw)) return [];
	return xdgRootForms(raw);
})();

/** The two home-anchored S0 entries (the fork's dotless credential homes, glab) as unions over the
 *  XDG root. Anchored to the home rather than any `.config` substring: a repository that ships
 *  `.config/age/data` reaches the classifier instead of hard-denying. `gh` appears in the XDG
 *  branch only — the sibling segment-anywhere `.config/gh` entry already covers the non-XDG
 *  spelling. `gcloud` is the OAuth token and service-account key store. The sibling dot entries
 *  (`.ssh`, `.aws`, `.gnupg`) stay segment-anywhere by the established S0 discipline. An empty root list contributes
 *  no alternation branch (conditional concat — an empty `|` arm would let the names match at string
 *  start). Rebuilt by `setXdgConfigRootsForTests`: the module-load evaluation would otherwise pin
 *  `XDG_CONFIG_HOME` and leave item 9 untestable under `bun test`. */
const buildAnchoredS0 = (xdgRoots: string[]): [RegExp, RegExp] => {
	const home = HOME_RULE_ROOTS.map((r) => `${r}/\\.config/`).join("|");
	const xdg = xdgRoots.map((r) => `${r}/`).join("|");
	// The gcloud entry follows eugeniughelbur/jev-engineering@82655a6d policy.json (MIT, Copyright (c) 2026 Eugeniu Ghelbur).
	return [
		new RegExp(`^(?:${home}(?:gnupg|age|sops|gcloud)${xdgRoots.length > 0 ? `|${xdg}(?:gnupg|age|sops|gh|gcloud)` : ""})(/|$)`, "i"),
		new RegExp(`^(?:${home}glab-cli${xdgRoots.length > 0 ? `|${xdg}glab-cli` : ""})(/|$)`, "i"),
	];
};
let anchoredS0 = buildAnchoredS0(XDG_CONFIG_ROOTS);

/** The settings and auth database inside the agent dir this session is anchored to (and its SQLite
 *  sidecar files), matched where the dir is custom (`PI_CODING_AGENT_DIR`) and the static
 *  `.omp/agent` entry in `S0_SECRET` cannot see it. Rebuilt only when the agent dir changes. */
let agentDbRule: { dir: string; re: RegExp } | null = null;
function agentDbS0(): RegExp[] {
	const dir = agentDirPath();
	if (agentDbRule?.dir !== dir) {
		agentDbRule = {
			dir,
			re: new RegExp(`^(?:${xdgRootForms(path.resolve(dir)).join("|")})/agent\\.db(?:-wal|-shm|-journal)?(?::|\\?|$)`, "i"),
		};
	}
	return [agentDbRule.re];
}

/** Test seam; null restores the production roots (mirrors `setTmpdirBasesForTests`). Takes raw
 *  dirs and derives their rule forms, so a test needs no regex escaping; empty and relative
 *  values are ignored exactly as the production `XDG_CONFIG_HOME` guard does. */
export function setXdgConfigRootsForTests(roots: string[] | null): void {
	anchoredS0 = buildAnchoredS0(
		roots === null ? XDG_CONFIG_ROOTS : roots.filter((r) => r && path.isAbsolute(r)).flatMap((r) => xdgRootForms(r)),
	);
}

// All S-rules match case-insensitively (#21): on case-insensitive filesystems
// (default macOS APFS, Windows) case variants name the same file — realpath
// normalization covers existing targets, /i covers the lexical forms of
// nonexistent ones; on linux the uppercase spelling usually does not exist and
// the occasional false positive fails toward deny (safe direction).
const S0_SECRET = [
	/\.ssh(\/|$)/i,
	/\.aws(\/|$)/i,
	/\.gnupg(\/|$)/i,
	// Fork: the dotless credential homes (`~/.config/(gnupg|age|sops|gcloud|glab-cli)`) and their XDG
	// alternatives live in `anchoredS0` — see `buildAnchoredS0` below `HOME_RULE_ROOTS`.
	/(^|\/)\.env(\.|$)/i,
	/credentials?(\.|\/|$)/i,
	/(^|\/)id_rsa/i,
	/\.pem$/i,
	/_history$/i,
	/\.config\/gh(\/|$)/i,
	/\.(?:pi|omp)\/agent\/auth\.json$/i,
	// omp's settings and auth store; the SQLite sidecar files hold the same pages, and a `:table` or
	// `?q=` suffix is the host's own read selector on the database. After `omp config init-xdg` the
	// host keeps it at `$XDG_DATA_HOME/omp/agent.db` (the agent dir is flattened away), so a bare `omp`
	// segment counts as well as the dotted `.omp/agent` and `.pi/agent` trees.
	/(?:\.(?:pi|omp)\/agent|(?:^|\/)omp(?:\/agent)?)\/agent\.db(?:-wal|-shm|-journal)?(?::|\?|$)/i,
	// V8 (security audit): add common plaintext credential files
	/(^|\/)\.netrc$/i,
	/(^|\/)\.npmrc$/i,
	/(^|\/)\.pypirc$/i,
	/(^|\/)\.envrc$/i,
	/(^|\/)\.vault-token$/i,
	/\.kube(\/|$)/i,
	/\.docker\/config\.json$/i,
	/\.gem\/credentials$/i,
	// A process environment, which holds the secrets exported to it: `/proc/<pid>/environ`, the
	// `self` and `thread-self` links, and a thread's `task/<tid>/environ`.
	/^\/proc\/(?:\d+|self|thread-self)\/(?:task\/\d+\/)?environ$/i,
];
// /private prefixes: macOS firmlinks — /etc, /var are really /private/etc,
// /private/var, and realpath'd toolchain output uses the real spelling (#21)
// Split into two families (#83): only directory-prefix rules are lifted by the
// per-user temp exemption; the authorized_keys basename rule always remains.
const S1_SYSTEM_DIRS = [/^\/etc(\/|$)/i, /^\/private\/(etc|var)(\/|$)/i, /^\/usr(\/|$)/i, /^\/var(\/|$)/i, /^\/System(\/|$)/i];
const S1_SYSTEM_FILES = [/(^|\/)authorized_keys$/i];
const S1_SYSTEM = [...S1_SYSTEM_DIRS, ...S1_SYSTEM_FILES];

/** Compute macOS confstr-family temp bases at the confstr depth. A hand-set
 *  TMPDIR must not widen the system-path exemption beyond /var/folders/<xx>/<yy>.
 *  Other platforms are inert because their temp directories do not match S1. */
export function computeTmpdirBases(platform: NodeJS.Platform, tmp: string, realpath: (p: string) => string | null): string[] {
	if (platform !== "darwin" || !tmp) return [];
	const lexical = path.resolve(tmp);
	const real = realpath(lexical);
	const bases = real === null ? [lexical] : [lexical, real];
	const confstrFamily = /^(?:\/private)?\/var\/folders\/[^/]+\/[^/]+(?:\/|$)/;
	return bases.every((b) => confstrFamily.test(b)) ? bases : [];
}

/** Resolve the process temp directory once; its location is stable for a session. */
function defaultTmpdirBases(): string[] {
	return computeTmpdirBases(process.platform, os.tmpdir(), (p) => {
		try {
			return fs.realpathSync(p);
		} catch {
			return null;
		}
	});
}

let tmpdirExemptBases = defaultTmpdirBases();

/** Test seam; null restores the production bases. */
export function setTmpdirBasesForTests(bases: string[] | null): void {
	tmpdirExemptBases = bases ?? defaultTmpdirBases();
}

/** Exempt only when every canonical target form stays inside a trusted temp base. */
const tmpdirExempt = (forms: string[]): boolean =>
	tmpdirExemptBases.length > 0 && forms.every((f) => tmpdirExemptBases.some((b) => f === b || f.startsWith(b + path.sep)));
const S2_USER_RC = [
	/\.(bashrc|zshrc|profile|bash_profile|gitconfig)$/i,
	/crontab/i,
	/Library\/LaunchAgents(\/|$)/i,
	/\.config\/systemd(\/|$)/i,
];
const S3_GIT_META = [/(^|\/)\.git\/(hooks|config|modules)(\/|$)/i, /(^|\/)\.gitmodules$/i];

/** The host the gate runs in. Only omp registers internal URL schemes such as `xd://`; pi opens the same
 *  text as a relative path. */
export type HostKind = "omp" | "pi";

/** Returns `omp` for an extension API that carries omp's `logger` and `typebox`, else `pi`. */
export function hostKindOf(pi: object): HostKind {
	return "logger" in pi && "typebox" in pi ? "omp" : "pi";
}

const DEVICE_URL = /^xd:\/\//i;

/** Matches the device URLs omp serves: `xd://`, `xd://<device>` and `xd://<device>/<topic>`, each name
 *  free of `/`, `?` and `#`. */
const DEVICE_TARGET = /^xd:\/\/([^/?#]*)(?:\/([^/?#]+))?$/i;

/** omp devices whose write runs host code (apply or discard a staged preview, submit a plan, file a tool
 *  report) without a nested tool call for the gate to see. */
const UNDISPATCHED_DEVICES: ReadonlySet<string> = new Set(["resolve", "reject", "propose", "report_issue"]);

/** Matches a device name that WHATWG URL parsing leaves as written: no credentials, port, whitespace or
 *  control characters that omp's `new URL(...).href` would drop to reach another device. */
const PLAIN_DEVICE_NAME = /^[A-Za-z0-9_-]+$/;

/** True for an `xd://` URL in any scheme case; on omp it names a tool device. */
export function isDeviceUrl(target: string): boolean {
	return DEVICE_URL.test(target);
}

/** Grades an omp `xd://` device URL, which names no file: a read returns generated documentation, and a
 *  write runs the named tool as its own gated tool call, so both are a rule allow. A write to a device
 *  that runs host code directly, a URL the host rejects, or a name outside `PLAIN_DEVICE_NAME` (which
 *  URL parsing may rewrite into an excluded device) stays gray for the classifier
 *  (research/2026-10-25-xd-device-dispatch.md, ADR-0009). */
function classifyDeviceUrl(rawPath: string, isWrite: boolean): RuleResult {
	const gray: RuleResult = { verdict: "gray", reason: "host tool device URL, not a file path" };
	const target = DEVICE_TARGET.exec(rawPath);
	if (target === null) return gray;
	const [, name, topic] = target;
	if (isWrite && (topic !== undefined || !PLAIN_DEVICE_NAME.test(name) || UNDISPATCHED_DEVICES.has(name.toLowerCase()))) return gray;
	return { verdict: "allow" };
}

/** Grades one target: an `xd://` URL on omp by its device, everything else by its path. Off omp an `xd://`
 *  target is a relative path to pi, so its path grade stands, but its allow turns gray: a missed omp
 *  detection must not turn a device write into a silent in-project allow. */
function gradeTarget(rawPath: string, cwd: string, isWrite: boolean, floorOn: boolean, host: HostKind): RuleResult {
	if (!isDeviceUrl(rawPath)) return classifyPath(rawPath, cwd, isWrite, floorOn);
	if (host === "omp") return classifyDeviceUrl(rawPath, isWrite);
	const grade = classifyPath(rawPath, cwd, isWrite, floorOn);
	return grade.verdict === "allow" ? { verdict: "gray", reason: "xd:// target outside omp, not graded as a project path" } : grade;
}

/** Read-class tools: reading S0 is high risk (deny); allow other reads. isWrite: write/edit use full classification. */
export function classifyPath(rawPath: string, cwd: string, isWrite: boolean, floorOn: boolean): RuleResult {
	// Dual-form matching (#20): rules test every canonical form of the target —
	// a project-local symlink aliasing ~/.ssh or a .git/hooks dir must not pass
	// the floor on its lexical spelling alone. The kernel walk adds the spelling the
	// kernel would open when a symlink component precedes `..` or the leaf is a symlink
	// itself (path-layer review items 4, 7–8); one walk feeds this and the check below.
	const { forms, ruleForms, walk } = canonicalPathForms(rawPath, cwd);
	const hit = (rules: RegExp[]) => ruleForms.some((f) => rules.some((r) => r.test(f)));
	// When the floor is off: downgrade all built-in denies to gray (never promote to allow); preserve non-deny branches (allow/gray).
	const D = floorOn
		? (reason: string): RuleResult => ({ verdict: "deny", reason })
		: (reason: string): RuleResult => ({ verdict: "gray", reason });

	// S0: the static entries plus the two home/XDG-anchored credential-home entries
	// (`anchoredS0`, item 9) — the seam rebuilds those at test time.
	if (hit(S0_SECRET) || hit(anchoredS0) || hit(agentDbS0())) return D(`S0 secrets/credential path: ${rawPath}`);
	// #83: exempt only the directory-prefix family under a trusted macOS temp base.
	const s1Rules = tmpdirExempt(forms) ? S1_SYSTEM_FILES : S1_SYSTEM;
	if (!isWrite) {
		if (hit(s1Rules)) return { verdict: "gray", reason: `read system config path: ${rawPath}` };
		return { verdict: "allow" };
	}
	if (hit(s1Rules)) return D(`write to system directory: ${rawPath}`);
	if (hit(S3_GIT_META)) return D(`write to .git metadata (executable code entry point): ${rawPath}`);
	if (hit(S2_USER_RC)) return { verdict: "gray", reason: `write to user config/persistence entry point: ${rawPath}` };
	// Item 8 (plan-review F20): a write whose kernel target is unknowable (symlink loop,
	// unreadable link target) fails closed — the lexical spelling must not grade as a plain
	// in-cwd write whose destination the floor never saw. Reads stay alone: the open fails
	// ELOOP and exposes nothing. Through D(...): with builtinDenyFloor:false this degrades
	// to gray like every other floor branch.
	if (isWrite && walk.unresolved) return D("unresolved symlink (write fail-closed)");
	// In-cwd write allowance (#20): every canonical form must sit inside the cwd
	// (in either its lexical or real form) — a lexical prefix hit whose real
	// form escapes the project (symlink alias) grades as an outside-cwd write.
	if (formsInCwd(forms, cwd)) return { verdict: "allow" };
	return { verdict: "gray", reason: `write outside project directory (CWD): ${rawPath}` };
}

/** Every canonical form of a target the path rules test: lexical and realpath-rebuilt, plus the
 *  kernel-walked spelling, each also in rule form. */
function canonicalPathForms(rawPath: string, cwd: string): { forms: string[]; ruleForms: string[]; walk: ReturnType<typeof kernelWalk> } {
	const abs = path.resolve(cwd, expandHome(rawPath));
	const walk = kernelWalk(rawPath, cwd);
	const forms = [...new Set([...rebuiltForms(abs), ...(walk.resolved === null ? [] : rebuiltForms(walk.resolved))])];
	return { forms, ruleForms: forms.map(toRuleForm), walk };
}

/** Does every form sit inside the cwd, in either its lexical or its real spelling? */
function formsInCwd(forms: string[], cwd: string): boolean {
	const cwdBases = new Set(baseForms(path.resolve(cwd)));
	return forms.every((f) => [...cwdBases].some((b) => f === b || f.startsWith(b + path.sep)));
}

/** A `glob` call names files and never reads their contents, so it may be a rule allow where a
 *  `grep` of the same pattern may not: its literal prefix and every other graded form must stay inside the
 *  project, and none may hit a credential (S0) or git metadata (S3) rule. A declared `denyPaths` base
 *  under the prefix and a `.omp` directory are asked about by their own layers before this grade is read. */
export function globStaysInProject(targets: string[], cwd: string): boolean {
	return targets.every((t) => {
		// `ssh://host/etc` is a URL, not a project path, whatever directory the text resolves to.
		if (/^[a-z][a-z0-9+.-]+:/i.test(t)) return false;
		const { forms, ruleForms, walk } = canonicalPathForms(t, cwd);
		const hit = (rules: RegExp[]) => ruleForms.some((f) => rules.some((r) => r.test(f)));
		return !walk.unresolved && !hit(S0_SECRET) && !hit(anchoredS0) && !hit(agentDbS0()) && !hit(S3_GIT_META) && formsInCwd(forms, cwd);
	});
}

/** Grades every mutating target through classifyPath's existing write tiers
 *  (S0/S1/S3/S2, kernelWalk per target, the unresolved-write fail-closed
 *  branch per target): deny on the first tier hit (first target wins); the
 *  in-cwd allowance fires only when at least one target exists and EVERY
 *  target sits in-cwd; any remaining S2/outside-cwd target grades gray.
 *  Single-target inputs behave bit-for-bit as today — classifyPath itself is
 *  unchanged and does all the grading; this only combines N results. */
export function classifyWrites(targets: string[], cwd: string, floorOn: boolean, host: HostKind): RuleResult {
	const results = targets.map((t) => gradeTarget(t, cwd, true, floorOn, host));
	const deny = results.find((r) => r.verdict === "deny");
	if (deny) return deny;
	if (results.every((r) => r.verdict === "allow")) return { verdict: "allow" };
	const gray = results.find((r) => r.verdict === "gray");
	return gray ?? { verdict: "gray", reason: `write outside project directory (CWD): ${targets.join(", ")}` };
}

/** Read-side analog of classifyWrites: the worst outcome wins (deny beats gray
 *  beats allow) so a list-split part cannot silently evade the floor either
 *  (Claude-review F6 — over-extraction is the safe direction on both sides). */
/** Credential directories under the home directory that the S0 floor denies by path. */
const S0_HOME_DIRECTORIES = [
	".ssh",
	".aws",
	".gnupg",
	".kube",
	".config/gnupg",
	".config/age",
	".config/sops",
	".config/glab-cli",
	".config/gh",
	".config/gcloud",
];

/** Does the target strictly contain one of S0_HOME_DIRECTORIES? A target that is or sits inside
 *  one is already an S0 deny, so only the ancestors (`~/.config`, `~`) matter here. */
export function s0DirectoryBeneath(target: string, cwd: string): boolean {
	const abs = path.resolve(cwd, expandHome(target));
	const homes = baseForms(os.homedir());
	return baseForms(abs).some((t) => {
		const prefix = t.endsWith(path.sep) ? t : t + path.sep;
		return homes.some((h) => S0_HOME_DIRECTORIES.some((rel) => fold(path.join(h, ...rel.split("/"))).startsWith(fold(prefix))));
	});
}

export function classifyReads(targets: string[], cwd: string, floorOn: boolean, host: HostKind): RuleResult {
	if (targets.length === 0) return { verdict: "allow" };
	const results = targets.map((t) => gradeTarget(t, cwd, false, floorOn, host));
	const deny = results.find((r) => r.verdict === "deny");
	if (deny) return deny;
	const gray = results.find((r) => r.verdict === "gray");
	return gray ?? { verdict: "allow" };
}
