import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { agentDirPath, escapeRegExp } from "./agent-dir.ts";
import { type FloorOverrides, NO_OVERRIDES, overrideFor } from "./floor-overrides.ts";
import { baseForms, fold, kernelWalk, rebuiltForms } from "./paths.ts";
import { BASH_FLOOR_RULE_IDS, LiftedRules, type RuleResult } from "./shell.ts";

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
const XDG_CONFIG_ROOTS: readonly string[] = (() => {
	const raw = process.env.XDG_CONFIG_HOME;
	return raw && path.isAbsolute(raw) ? [raw] : [];
})();
let xdgConfigRoots: readonly string[] = XDG_CONFIG_ROOTS;

/** The dotless credential homes directly under `~/.config`. The gcloud entry follows
 *  eugeniughelbur/jev-engineering@82655a6d policy.json (MIT, Copyright (c) 2026 Eugeniu Ghelbur). */
const CONFIG_CREDENTIAL_HOMES: readonly string[] = ["gnupg", "age", "sops", "gcloud", "glab-cli"];
/** The same homes under a relocated XDG config root, plus `gh`, whose `~/.config` spelling the
 *  segment-anywhere `.config/gh` entry already covers. */
const XDG_CREDENTIAL_HOMES: readonly string[] = [...CONFIG_CREDENTIAL_HOMES, "gh"];

/** The home-anchored S0 entry over the dotless credential homes, a union over the XDG roots.
 *  Anchored to the home rather than any `.config` substring: a repository that ships
 *  `.config/age/data` reaches the classifier instead of hard-denying. The sibling dot entries
 *  (`.ssh`, `.aws`, `.gnupg`) stay segment-anywhere by the established S0 discipline. An empty root
 *  list contributes no alternation branch, since an empty `|` arm would let the names match at
 *  string start. Rebuilt by `setXdgConfigRootsForTests`, so tests need not pin `XDG_CONFIG_HOME`. */
const buildAnchoredS0 = (roots: readonly string[]): S0Entry[] => {
	const names = (list: readonly string[]) => list.map(escapeRegExp).join("|");
	const home = HOME_RULE_ROOTS.map((r) => `${r}/\\.config/`).join("|");
	const xdg = roots.flatMap(xdgRootForms).map((r) => `${r}/`);
	const xdgBranch = xdg.length > 0 ? `|(?:${xdg.join("|")})(?:${names(XDG_CREDENTIAL_HOMES)})` : "";
	return [{ id: "config-homes", rule: new RegExp(`^(?:(?:${home})(?:${names(CONFIG_CREDENTIAL_HOMES)})${xdgBranch})(/|$)`, "i") }];
};
let anchoredS0 = buildAnchoredS0(xdgConfigRoots);

/** The settings and auth database inside the agent dir this session is anchored to (and its SQLite
 *  sidecar files), matched where the dir is custom (`PI_CODING_AGENT_DIR`) and the static
 *  `.omp/agent` entry in `S0_SECRET` cannot see it. Rebuilt only when the agent dir changes. */
let agentDbRule: { dir: string; re: RegExp } | null = null;
function agentDbS0(): S0Entry[] {
	const dir = agentDirPath();
	if (agentDbRule?.dir !== dir) {
		agentDbRule = {
			dir,
			re: new RegExp(`^(?:${xdgRootForms(path.resolve(dir)).join("|")})/agent\\.db(?:-wal|-shm|-journal)?(?::|\\?|$)`, "i"),
		};
	}
	return [{ id: "agent-db", rule: agentDbRule.re }];
}

/** Test seam; null restores the production roots (mirrors `setTmpdirBasesForTests`). Takes raw
 *  dirs and derives their rule forms, so a test needs no regex escaping; empty and relative
 *  values are ignored exactly as the production `XDG_CONFIG_HOME` guard does. */
export function setXdgConfigRootsForTests(roots: string[] | null): void {
	xdgConfigRoots = roots === null ? XDG_CONFIG_ROOTS : roots.filter((r) => r && path.isAbsolute(r));
	anchoredS0 = buildAnchoredS0(xdgConfigRoots);
}

// All S-rules match case-insensitively (#21): on case-insensitive filesystems
// (default macOS APFS, Windows) case variants name the same file — realpath
// normalization covers existing targets, /i covers the lexical forms of
// nonexistent ones; on linux the uppercase spelling usually does not exist and
// the occasional false positive fails toward deny (safe direction).
/** One S0 entry: its id, which `floorOverrides` and the audit name as `S0:<id>` (ADR-0013), and its pattern. */
interface S0Entry {
	readonly id: string;
	readonly rule: RegExp;
}

/** The S0 entries that name a credential inside a directory, each with the home-relative directories it
 *  guards there, so a recursive search of a parent (`s0DirectoryBeneath`) reads the same set the path
 *  grade does. */
const S0_DIRECTORY_RULES: readonly (S0Entry & { readonly homeDirs: readonly string[] })[] = [
	{ id: "ssh", rule: /\.ssh(\/|$)/i, homeDirs: [".ssh"] },
	{ id: "aws", rule: /\.aws(\/|$)/i, homeDirs: [".aws"] },
	{ id: "gnupg", rule: /\.gnupg(\/|$)/i, homeDirs: [".gnupg"] },
	{ id: "kube", rule: /\.kube(\/|$)/i, homeDirs: [".kube"] },
	{ id: "gh", rule: /\.config\/gh(\/|$)/i, homeDirs: [".config/gh"] },
	{ id: "docker", rule: /\.docker\/config\.json$/i, homeDirs: [".docker"] },
	{ id: "gem", rule: /\.gem\/credentials$/i, homeDirs: [".gem"] },
	{ id: "agent-auth", rule: /\.(?:pi|omp)\/agent\/auth\.json$/i, homeDirs: [".omp/agent", ".pi/agent"] },
	// omp's settings and auth store; the SQLite sidecar files hold the same pages, and a `:table` or
	// `?q=` suffix is the host's own read selector on the database. After `omp config init-xdg` the
	// host keeps it at `$XDG_DATA_HOME/omp/agent.db` (the agent dir is flattened away), so a bare `omp`
	// segment counts as well as the dotted `.omp/agent` and `.pi/agent` trees.
	{
		id: "agent-db",
		rule: /(?:\.(?:pi|omp)\/agent|(?:^|\/)omp(?:\/agent)?)\/agent\.db(?:-wal|-shm|-journal)?(?::|\?|$)/i,
		homeDirs: [".omp/agent", ".pi/agent", ".local/share/omp"],
	},
];

const S0_SECRET: readonly S0Entry[] = [
	...S0_DIRECTORY_RULES,
	// The dotless credential homes under `~/.config` and their XDG alternatives live in `anchoredS0`.
	// `.env` and its variants, but not the `.example`, `.sample` and `.template` files a project ships.
	{ id: "env", rule: /(^|\/)\.env(?!\.(?:example|sample|template)$)(\.|$)/i },
	{ id: "credentials", rule: /credentials?(\.|\/|$)/i },
	// Private SSH key names, but not their `.pub` public halves.
	{ id: "id-rsa", rule: /(^|\/)id_rsa(?![^/]*\.pub$)/i },
	{ id: "id-ed25519", rule: /(^|\/)id_ed25519(?![^/]*\.pub$)/i },
	{ id: "id-ecdsa", rule: /(^|\/)id_ecdsa(?![^/]*\.pub$)/i },
	{ id: "id-dsa", rule: /(^|\/)id_dsa(?![^/]*\.pub$)/i },
	{ id: "pem", rule: /\.pem$/i },
	// Key stores, key files and password vaults by extension.
	{ id: "key", rule: /\.key$/i },
	{ id: "p12", rule: /\.p12$/i },
	{ id: "pfx", rule: /\.pfx$/i },
	{ id: "jks", rule: /\.jks$/i },
	{ id: "keystore", rule: /\.keystore$/i },
	{ id: "kdbx", rule: /\.kdbx$/i },
	{ id: "ovpn", rule: /\.ovpn$/i },
	{ id: "ppk", rule: /\.ppk$/i },
	{ id: "history", rule: /_history$/i },
	// V8 (security audit): add common plaintext credential files
	{ id: "netrc", rule: /(^|\/)\.netrc$/i },
	{ id: "npmrc", rule: /(^|\/)\.npmrc$/i },
	{ id: "pypirc", rule: /(^|\/)\.pypirc$/i },
	{ id: "envrc", rule: /(^|\/)\.envrc$/i },
	{ id: "vault-token", rule: /(^|\/)\.vault-token$/i },
	// A process environment, which holds the secrets exported to it: `/proc/<pid>/environ`, the
	// `self` and `thread-self` links, and a thread's `task/<tid>/environ`.
	{ id: "proc-environ", rule: /^\/proc\/(?:\d+|self|thread-self)\/(?:task\/\d+\/)?environ$/i },
];

/** The S0 ids of key material: a write that creates such a file is graded gray rather than denied, because
 *  generating a test key is ordinary work and a new file holds nothing yet (ADR-0013). */
const KEY_MATERIAL_IDS: ReadonlySet<string> = new Set([
	"pem",
	"key",
	"p12",
	"pfx",
	"jks",
	"keystore",
	"kdbx",
	"ovpn",
	"ppk",
	"id-rsa",
	"id-ed25519",
	"id-ecdsa",
	"id-dsa",
]);

const PUBLIC_KEY = /\.pub$/i;

/** Returns the ids of every S0 entry a rule form hits: the static ones, the home and XDG anchored
 *  credential homes, or the agent directory's database. A read of a `.pub` public key does not hit a
 *  credential home; a write there still does. Each form is tested on its own, so a public-key name whose
 *  real path is a private key still hits. */
function s0Hits(ruleForms: readonly string[], isWrite: boolean): string[] {
	const homes = new Set<S0Entry>([...S0_DIRECTORY_RULES, ...anchoredS0]);
	const entries = [...S0_SECRET, ...anchoredS0, ...agentDbS0()];
	const hits = (e: S0Entry, f: string): boolean => e.rule.test(f) && (isWrite || !homes.has(e) || !PUBLIC_KEY.test(f));
	return [...new Set(entries.filter((e) => ruleForms.some((f) => hits(e, f))).map((e) => e.id))];
}

/** True when a rule form hits any S0 entry, graded as a write so no read exemption applies. */
function hitsS0(ruleForms: readonly string[]): boolean {
	return s0Hits(ruleForms, true).length > 0;
}

/** True when any form of a target hits an S0 entry with no read exemption. For a shell operand, which the
 *  gate cannot tell a read from a write (`cp x ~/.ssh/a.pub`). */
export function hitsS0AsWrite(rawPath: string, cwd: string): boolean {
	return hitsS0(canonicalPathForms(rawPath, cwd).ruleForms);
}

/** True when the write target does not exist in any form: its lexical path and every rebuilt or
 *  kernel-walked form fail `lstat` with ENOENT or ENOTDIR, so a dangling symlink counts as existing.
 *  Fails closed: any other `lstat` error counts as existing. */
function isNewFile(abs: string, forms: readonly string[]): boolean {
	return [abs, ...forms].every((f) => {
		try {
			fs.lstatSync(f);
			return false;
		} catch (err) {
			const code = err instanceof Error && "code" in err ? err.code : undefined;
			return code === "ENOENT" || code === "ENOTDIR";
		}
	});
}
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
	return { verdict: "allow", rule: "device" };
}

/** Grades one target: an `xd://` URL on omp by its device, everything else by its path. Off omp an `xd://`
 *  target is a relative path to pi, so its path grade stands, but its allow turns gray: a missed omp
 *  detection must not turn a device write into a silent in-project allow. */
function gradeTarget(
	rawPath: string,
	cwd: string,
	isWrite: boolean,
	floorOn: boolean,
	host: HostKind,
	overrides: FloorOverrides,
): RuleResult {
	if (!isDeviceUrl(rawPath)) return classifyPath(rawPath, cwd, isWrite, floorOn, overrides);
	if (host === "omp") return classifyDeviceUrl(rawPath, isWrite);
	const grade = classifyPath(rawPath, cwd, isWrite, floorOn, overrides);
	return grade.verdict === "allow" ? { verdict: "gray", reason: "xd:// target outside omp, not graded as a project path" } : grade;
}

/** Read-class tools: reading S0 is high risk (deny); allow other reads. isWrite: write/edit use full classification.
 *  A `floorOverrides` entry that applies to every form of the target lifts its rule (ADR-0013): `off` skips it, and
 *  `ask` carries an ask that the rule layer raises after the protected-path asks. */
export function classifyPath(
	rawPath: string,
	cwd: string,
	isWrite: boolean,
	floorOn: boolean,
	overrides: FloorOverrides = NO_OVERRIDES,
): RuleResult {
	// Dual-form matching (#20): rules test every canonical form of the target —
	// a project-local symlink aliasing ~/.ssh or a .git/hooks dir must not pass
	// the floor on its lexical spelling alone. The kernel walk adds the spelling the
	// kernel would open when a symlink component precedes `..` or the leaf is a symlink
	// itself (path-layer review items 4, 7–8); one walk feeds this and the check below.
	const { abs, forms, ruleForms, walk } = canonicalPathForms(rawPath, cwd);
	const hit = (rules: RegExp[]) => ruleForms.some((f) => rules.some((r) => r.test(f)));
	const lifted = new LiftedRules();
	// When the floor is off: downgrade all built-in denies to gray (never promote to allow); preserve non-deny branches (allow/gray).
	// When an override lifts the rule for this target, grading goes on (null).
	const D = (rule: string, reason: string): RuleResult | null => {
		if (!floorOn) return { verdict: "gray", reason };
		const override = overrideFor(overrides, rule, forms);
		if (override === null) return { verdict: "deny", reason, rule };
		lifted.add(rule, reason, override.action);
		return null;
	};

	const s0 = s0Hits(ruleForms, isWrite);
	// Creating a key file goes to the classifier; overwriting one, or creating one in a credential home
	// (whose own hit is no key-material id), stays denied.
	const createsKey = isWrite && s0.some((id) => KEY_MATERIAL_IDS.has(id)) && isNewFile(abs, forms);
	for (const id of s0) {
		if (createsKey && KEY_MATERIAL_IDS.has(id)) continue;
		const denied = D(`S0:${id}`, `S0 secrets/credential path: ${rawPath}`);
		if (denied) return denied;
	}
	// #83: exempt only the directory-prefix family under a trusted macOS temp base.
	const s1Rules = tmpdirExempt(forms) ? S1_SYSTEM_FILES : S1_SYSTEM;
	if (!isWrite) {
		if (hit(s1Rules)) return lifted.onto({ verdict: "gray", reason: `read system config path: ${rawPath}` });
		return lifted.onto({ verdict: "allow", rule: "path-read" });
	}
	const system = hit(s1Rules) ? D("S1", `write to system directory: ${rawPath}`) : null;
	if (system) return system;
	const gitMeta = hit(S3_GIT_META) ? D("S3", `write to .git metadata (executable code entry point): ${rawPath}`) : null;
	if (gitMeta) return gitMeta;
	if (hit(S2_USER_RC)) return lifted.onto({ verdict: "gray", reason: `write to user config/persistence entry point: ${rawPath}` });
	// Item 8 (plan-review F20): a write whose kernel target is unknowable (symlink loop,
	// unreadable link target) fails closed — the lexical spelling must not grade as a plain
	// in-cwd write whose destination the floor never saw. Reads stay alone: the open fails
	// ELOOP and exposes nothing. Through D(...): with builtinDenyFloor:false this degrades
	// to gray like every other floor branch; no override lifts it (NOT_OVERRIDABLE).
	if (isWrite && walk.unresolved) {
		const unresolved = D("unresolved-symlink", "unresolved symlink (write fail-closed)");
		if (unresolved) return unresolved;
	}
	// In-cwd write allowance (#20): every canonical form must sit inside the cwd
	// (in either its lexical or real form) — a lexical prefix hit whose real
	// form escapes the project (symlink alias) grades as an outside-cwd write.
	if (createsKey) return lifted.onto({ verdict: "gray", reason: `write creates a key-material file: ${rawPath}` });
	if (formsInCwd(forms, cwd)) return lifted.onto({ verdict: "allow", rule: "path-write" });
	return lifted.onto({ verdict: "gray", reason: `write outside project directory (CWD): ${rawPath}` });
}

/** Returns a combined grade that keeps the first carried ask and every lifted id of the per-target grades. */
function withLifted(grade: RuleResult, parts: readonly RuleResult[]): RuleResult {
	const overridden = parts.flatMap((p) => p.overridden ?? []);
	if (overridden.length === 0) return grade;
	const carriedAsk = parts.find((p) => p.carriedAsk !== undefined)?.carriedAsk;
	return { ...grade, overridden, ...(carriedAsk ? { carriedAsk } : {}) };
}

/** Every canonical form of a target the path rules test: lexical and realpath-rebuilt, plus the
 *  kernel-walked spelling, each also in rule form. */
function canonicalPathForms(
	rawPath: string,
	cwd: string,
): { abs: string; forms: string[]; ruleForms: string[]; walk: ReturnType<typeof kernelWalk> } {
	const abs = path.resolve(cwd, expandHome(rawPath));
	const walk = kernelWalk(rawPath, cwd);
	const forms = [...new Set([...rebuiltForms(abs), ...(walk.resolved === null ? [] : rebuiltForms(walk.resolved))])];
	return { abs, forms, ruleForms: forms.map(toRuleForm), walk };
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
		return !walk.unresolved && !hitsS0(ruleForms) && !hit(S3_GIT_META) && formsInCwd(forms, cwd);
	});
}

/** Grades every mutating target through classifyPath's existing write tiers
 *  (S0/S1/S3/S2, kernelWalk per target, the unresolved-write fail-closed
 *  branch per target): deny on the first tier hit (first target wins); the
 *  in-cwd allowance fires only when at least one target exists and EVERY
 *  target sits in-cwd; any remaining S2/outside-cwd target grades gray.
 *  Single-target inputs behave bit-for-bit as today — classifyPath itself is
 *  unchanged and does all the grading; this only combines N results. */
export function classifyWrites(
	targets: string[],
	cwd: string,
	floorOn: boolean,
	host: HostKind,
	overrides: FloorOverrides = NO_OVERRIDES,
): RuleResult {
	const results = targets.map((t) => gradeTarget(t, cwd, true, floorOn, host, overrides));
	const deny = results.find((r) => r.verdict === "deny");
	if (deny) return deny;
	if (results.every((r) => r.verdict === "allow"))
		return withLifted({ verdict: "allow", rule: sharedRule(results, "path-write") }, results);
	const gray = results.find((r) => r.verdict === "gray");
	return withLifted(gray ?? { verdict: "gray", reason: `write outside project directory (CWD): ${targets.join(", ")}` }, results);
}

/** The directories that hold what the S0 entries guard, as absolute paths: the home-relative ones of
 *  `S0_DIRECTORY_RULES` and of the dotless credential homes, the same homes under each XDG config
 *  root, the agent directory, and omp's data directory under `$XDG_DATA_HOME`. */
function credentialDirectories(): string[] {
	const home = os.homedir();
	const homeRelative = [...S0_DIRECTORY_RULES.flatMap((d) => d.homeDirs), ...CONFIG_CREDENTIAL_HOMES.map((name) => `.config/${name}`)];
	const xdgData = process.env.XDG_DATA_HOME;
	return [
		...homeRelative.map((rel) => path.join(home, ...rel.split("/"))),
		...xdgConfigRoots.flatMap((root) => XDG_CREDENTIAL_HOMES.map((name) => path.join(root, name))),
		path.resolve(agentDirPath()),
		...(xdgData && path.isAbsolute(xdgData) ? [path.join(xdgData, "omp")] : []),
	];
}

/** Matches `/proc` and the process and thread directories below it that hold an `environ` file. */
const PROC_ENVIRON_ANCESTOR = /^\/proc(?:\/(?:\d+|self|thread-self)(?:\/task(?:\/\d+)?)?)?\/?$/i;

/** Is the target one of `credentialDirectories()` or an ancestor of one, or a `/proc` directory that
 *  holds a process environment, so a recursive search of it reads a credential? A directory such as `~/.ssh` is already an S0 deny; the agent directory and
 *  `~/.docker` are not, because only some files inside them are secret. */
export function s0DirectoryBeneath(target: string, cwd: string): boolean {
	const abs = path.resolve(cwd, expandHome(target));
	if (baseForms(abs).some((t) => PROC_ENVIRON_ANCESTOR.test(toRuleForm(t)))) return true;
	const dirs = credentialDirectories().flatMap((d) => baseForms(d).map(fold));
	return baseForms(abs).some((t) => {
		const folded = fold(t);
		const prefix = folded.endsWith(path.sep) ? folded : folded + path.sep;
		return dirs.some((d) => d === folded || d.startsWith(prefix));
	});
}

/** Read-side analog of classifyWrites: the worst outcome wins (deny beats gray
 *  beats allow) so a list-split part cannot silently evade the floor either
 *  (Claude-review F6 — over-extraction is the safe direction on both sides). */
export function classifyReads(
	targets: string[],
	cwd: string,
	floorOn: boolean,
	host: HostKind,
	overrides: FloorOverrides = NO_OVERRIDES,
): RuleResult {
	if (targets.length === 0) return { verdict: "allow", rule: "path-read" };
	const results = targets.map((t) => gradeTarget(t, cwd, false, floorOn, host, overrides));
	const deny = results.find((r) => r.verdict === "deny");
	if (deny) return deny;
	const gray = results.find((r) => r.verdict === "gray");
	return withLifted(gray ?? { verdict: "allow", rule: sharedRule(results, "path-read") }, results);
}

/** The rule id every target's allow shares, such as `device` for an omp device URL, else `fallback`. */
function sharedRule(results: readonly RuleResult[], fallback: string): string {
	const first = results[0]?.rule;
	return first !== undefined && results.every((r) => r.rule === first) ? first : fallback;
}

/** The id of every built-in rule a `floorOverrides` entry may name (ADR-0013): each S0 entry as `S0:<id>`,
 *  the S1 and S3 write tiers, every bash floor rule, and the code-loading ask. */
export const FLOOR_RULE_IDS: ReadonlySet<string> = new Set([
	...[...S0_SECRET.map((e) => e.id), "config-homes", "agent-db"].map((id) => `S0:${id}`),
	"S1",
	"S3",
	...BASH_FLOOR_RULE_IDS,
	"code-loading",
]);
