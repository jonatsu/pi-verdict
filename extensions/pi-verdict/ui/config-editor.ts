import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { agentDirPath, findProjectConfig, projectDotDir, samePath, userConfigPath } from "../agent-dir.ts";
import { EMPTY_RULES, USER_CONFIG_TEMPLATE } from "../config.ts";
import type { GateRuntime } from "../runtime.ts";
import { reloadRules } from "../session-start.ts";
import { projectRootOf, projectTrustState, readTrustStore, rootIn } from "../trust.ts";

// ============================================================================
// Config editor helpers (/verdict)
// ============================================================================

const EDITABLE_LIST_KEYS = ["allow", "deny", "denyPaths", "tools", "rules"] as const;
type EditableListKey = (typeof EDITABLE_LIST_KEYS)[number];
const LIST_KEY_DESC: Record<EditableListKey, string> = {
	allow: "regexes that auto-allow",
	deny: "regexes that auto-deny",
	denyPaths: "protected paths (always ask)",
	tools: "MCP/custom tool names that auto-allow",
	rules: "free-text classifier rules",
};
const LIST_KEY_PLACEHOLDER: Record<EditableListKey, string> = {
	allow: "regex, e.g. ^git status\\b",
	deny: "regex, e.g. ^git push --force",
	denyPaths: "path, e.g. ~/.aws/",
	tools: "exact tool name, e.g. ask",
	rules: "free-text rule for the classifier",
};
const GATE_OMP_DIR_DESC = "forced ask on any .omp directory access";
const FOOTER_DESC = "footer status style";

/** Where a project config would be written for `cwd`: the existing one if discovered, else `<cwd>/<dotdir>/pi-verdict.json`.
 *  null when `findProjectConfig`'s stop rule (home dir / agent tree root) would never discover a file there. */
function projectConfigTarget(cwd: string, agentDir: string): string | null {
	const found = findProjectConfig(cwd, agentDir);
	if (found) return found;
	if (samePath(cwd, os.homedir()) || samePath(cwd, path.dirname(path.dirname(agentDir)))) return null;
	return path.join(path.resolve(cwd), projectDotDir(agentDir), "pi-verdict.json");
}

/** Parse a config file into its top-level object. A missing file yields the first-run template (user) or `{}` (local). */
function readConfigObject(file: string, kind: "user" | "local"): { raw: Record<string, unknown> } | { error: string } {
	if (!fs.existsSync(file)) return { raw: kind === "user" ? (JSON.parse(USER_CONFIG_TEMPLATE) as Record<string, unknown>) : {} };
	let parsed: unknown;
	try {
		parsed = JSON.parse(fs.readFileSync(file, "utf8"));
	} catch (e) {
		return { error: `${file} is not valid JSON (${e instanceof Error ? e.message : String(e)}) — fix it by hand` };
	}
	if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
		return { error: `${file}: top level must be a JSON object — fix it by hand` };
	}
	return { raw: parsed as Record<string, unknown> };
}

/** Write the config object back as pretty JSON; null on success, the error message otherwise */
function writeConfigObject(file: string, raw: Record<string, unknown>): string | null {
	try {
		fs.mkdirSync(path.dirname(file), { recursive: true });
		fs.writeFileSync(file, JSON.stringify(raw, null, 2) + "\n");
		return null;
	} catch (e) {
		return e instanceof Error ? e.message : String(e);
	}
}

/** Validate and canonicalize a typed list entry; null = blank input (treated as cancel) */
function normalizeEntry(key: EditableListKey, input: string): { value: string } | { error: string } | null {
	const text = input.replace(/[\r\n]+$/, ""); // editor dialogs may append a trailing newline
	if (text.trim() === "") return null;
	if (key !== "rules" && /[\r\n]/.test(text)) return { error: "must be a single line" };
	if (key === "allow" || key === "deny") {
		// verbatim: patterns like "rm " rely on their spaces
		try {
			new RegExp(text);
		} catch (e) {
			return { error: `invalid regex: ${e instanceof Error ? e.message : String(e)}` };
		}
		return { value: text };
	}
	return { value: text.trim() }; // matches loadUserRules trimming
}

/** Display form of a list entry; non-strings stay visible as JSON so they can be removed or fixed */
function entryLabel(x: unknown): string {
	return typeof x === "string" ? x : JSON.stringify(x);
}

// ============================================================================
// The /verdict editor
// ============================================================================

type ConfigKind = "user" | "local";

/** What the editor needs from the running gate. */
interface ConfigEditorHost {
	/** The project root the user trusted for this session only; a reload must honor it. */
	readonly sessionTrustedRoot: string | null;
	/** Reloads the rules after a saved edit and reports the load. */
	readonly reloadRules: (ctx: ExtensionContext) => void;
}

/** One menu choice of a scalar key: the value it writes, its menu label, and its name in the key menu. */
interface ScalarChoice {
	readonly value: boolean | string;
	readonly label: string;
	readonly state: string;
}

/** A scalar key the editor sets from a menu; its default comes from `EMPTY_RULES`. */
interface ScalarKey {
	readonly key: "gateOmpDir" | "footer";
	readonly desc: string;
	readonly choices: readonly ScalarChoice[];
	/** The key menu's state text for a value of the wrong type. */
	readonly invalidState: string;
	/** What a wrongly typed value is not, for the fix-by-hand warning. */
	readonly expected: string;
}

const SCALAR_KEYS: readonly ScalarKey[] = [
	{
		key: "gateOmpDir",
		desc: GATE_OMP_DIR_DESC,
		choices: [
			{ value: true, label: "On — ask before any .omp directory access", state: "on" },
			{ value: false, label: "Off — no forced gate on .omp directories", state: "off" },
		],
		invalidState: "invalid: not a boolean",
		expected: "a boolean",
	},
	{
		key: "footer",
		desc: FOOTER_DESC,
		choices: [
			{ value: "full", label: "full — Nerd Font powerline blocks", state: "full" },
			{ value: "compact", label: "compact — plain one-line text", state: "compact" },
			{ value: "off", label: "off — no footer status", state: "off" },
		],
		invalidState: "invalid",
		expected: '"full"|"compact"|"off"',
	},
];

const choiceLabel = (s: ScalarKey, c: ScalarChoice): string => (c.value === EMPTY_RULES[s.key] ? `${c.label} (default)` : c.label);

/** Picks the file `/verdict [user|local]` edits; null when there is none (already notified) or the user cancelled. */
async function pickTarget(args: string, ctx: ExtensionContext): Promise<{ kind: ConfigKind; file: string } | null> {
	const arg = args.trim().toLowerCase();
	const localFile = projectConfigTarget(ctx.cwd, agentDirPath());
	if (arg === "user") return { kind: "user", file: userConfigPath() };
	if (arg === "local") {
		if (localFile !== null) return { kind: "local", file: localFile };
		ctx.ui.notify("pi-verdict: no project config location here (cwd is your home dir or the agent tree root)", "warning");
		return null;
	}
	if (arg !== "") {
		ctx.ui.notify(`unknown argument: ${arg}\nUsage: /verdict [user|local]`, "warning");
		return null;
	}
	const targets: Array<{ kind: ConfigKind; file: string; label: string }> = [
		{ kind: "user", file: userConfigPath(), label: `User — ${userConfigPath()}` },
	];
	if (localFile !== null) targets.push({ kind: "local", file: localFile, label: `Local (project) — ${localFile}` });
	const choice = await ctx.ui.select(
		"pi-verdict: which config?",
		targets.map((t) => t.label),
	);
	const picked = targets.find((t) => t.label === choice);
	return picked ? { kind: picked.kind, file: picked.file } : null;
}

/** Registers the `/verdict` command, which edits the user or project config through menus and reloads the rules
 *  after each save. */
export function registerConfigEditor(rt: GateRuntime): void {
	rt.pi.registerCommand("verdict", {
		description: "Edit pi-verdict rules (allow/deny/denyPaths/tools/rules lists, gateOmpDir switch, footer style): /verdict [user|local]",
		handler: (args, ctx) =>
			runConfigEditor(args, ctx, { sessionTrustedRoot: rt.sessionTrustedRoot, reloadRules: (c) => reloadRules(rt, c) }),
	});
}

async function runConfigEditor(args: string, ctx: ExtensionContext, host: ConfigEditorHost): Promise<void> {
	if (!ctx.hasUI) {
		ctx.ui.notify("pi-verdict: /verdict needs an interactive UI", "warning");
		return;
	}
	const target = await pickTarget(args, ctx);
	if (target === null) return;
	const loaded = readConfigObject(target.file, target.kind);
	if ("error" in loaded) {
		ctx.ui.notify(`pi-verdict: ${loaded.error}`, "error");
		return;
	}
	if (target.kind === "local") {
		const root = projectRootOf(target.file);
		const trusted =
			(host.sessionTrustedRoot !== null && rootIn(root, [host.sessionTrustedRoot])) ||
			projectTrustState(root, target.file, readTrustStore()) === "trusted";
		if (!trusted)
			ctx.ui.notify(
				`pi-verdict: project ${root} is not trusted — edits are saved but not applied until you trust it (prompted at session start)`,
				"info",
			);
	}
	await new ConfigFileEditor(ctx, host, target.kind, target.file, loaded.raw).run();
}

/** One editing session over one config file; `raw` is the file's object as last saved. */
class ConfigFileEditor {
	private readonly ctx: ExtensionContext;
	private readonly host: ConfigEditorHost;
	private readonly kind: ConfigKind;
	private readonly file: string;
	private raw: Record<string, unknown>;

	constructor(ctx: ExtensionContext, host: ConfigEditorHost, kind: ConfigKind, file: string, raw: Record<string, unknown>) {
		this.ctx = ctx;
		this.host = host;
		this.kind = kind;
		this.file = file;
		this.raw = raw;
	}

	/** The key menu, until the user picks Done or dismisses it. */
	async run(): Promise<void> {
		const DONE = "Done";
		for (;;) {
			const options = [
				...EDITABLE_LIST_KEYS.map((key) => this.listKeyOption(key)),
				...SCALAR_KEYS.map((s) => this.scalarKeyOption(s)),
				DONE,
			];
			const choice = await this.ctx.ui.select(`pi-verdict: edit ${this.file}`, options);
			if (choice === undefined || choice === DONE) return;
			const idx = options.indexOf(choice);
			const key = EDITABLE_LIST_KEYS[idx];
			const scalar = SCALAR_KEYS[idx - EDITABLE_LIST_KEYS.length];
			if (key !== undefined) {
				if (this.raw[key] !== undefined && !Array.isArray(this.raw[key])) {
					this.ctx.ui.notify(`pi-verdict: ${key} in ${this.file} is not an array — fix it by hand`, "warning");
					continue;
				}
				await this.editList(key);
			} else if (scalar !== undefined) {
				const v = this.raw[scalar.key];
				if (v !== undefined && !scalar.choices.some((c) => c.value === v)) {
					this.ctx.ui.notify(`pi-verdict: ${scalar.key} in ${this.file} is not ${scalar.expected} — fix it by hand`, "warning");
					continue;
				}
				await this.editScalar(scalar);
			} else return;
		}
	}

	private listKeyOption(key: EditableListKey): string {
		const v = this.raw[key];
		const desc = LIST_KEY_DESC[key];
		if (v === undefined) return this.kind === "local" ? `${key} (not set: global applies) — ${desc}` : `${key} (0) — ${desc}`;
		if (Array.isArray(v)) return `${key} (${v.length}) — ${desc}`;
		return `${key} (invalid: not an array) — ${desc}`;
	}

	private scalarKeyOption(s: ScalarKey): string {
		const v = this.raw[s.key];
		let state: string;
		if (v === undefined) {
			const fallback = s.choices.find((c) => c.value === EMPTY_RULES[s.key]);
			state = this.kind === "local" ? "not set: global applies" : `${fallback?.state}, default`;
		} else state = s.choices.find((c) => c.value === v)?.state ?? s.invalidState;
		return `${s.key} (${state}) — ${s.desc}`;
	}

	/** Writes `key` (or drops it when undefined) and reloads the rules; false when nothing was saved. */
	private save(nextValue: unknown, key: string): boolean {
		const next: Record<string, unknown> = { ...this.raw };
		if (nextValue === undefined) delete next[key];
		else next[key] = nextValue;
		const err = writeConfigObject(this.file, next);
		if (err) {
			this.ctx.ui.notify(`pi-verdict: could not save ${this.file}: ${err}`, "error");
			return false;
		}
		this.raw = next;
		this.host.reloadRules(this.ctx);
		this.ctx.ui.notify(`pi-verdict: ${key} saved to ${this.file} — rules reloaded`, "info");
		return true;
	}

	/** The value menu of a scalar key; a local file can also unset it to inherit the global value. */
	private async editScalar(s: ScalarKey): Promise<void> {
		const UNSET = `× Unset (inherit global ${s.key})`;
		const options = s.choices.map((c) => choiceLabel(s, c));
		if (this.kind === "local" && s.key in this.raw) options.push(UNSET);
		const choice = await this.ctx.ui.select(`${s.key} — ${this.file}`, options);
		if (choice === UNSET) {
			this.save(undefined, s.key);
			return;
		}
		const picked = s.choices.find((c) => choiceLabel(s, c) === choice);
		if (picked) this.save(picked.value, s.key);
	}

	/** Normalizes and duplicate-checks a typed entry; undefined when there is nothing to save (notified or cancelled). */
	private acceptEntry(key: EditableListKey, input: string | undefined, list: unknown[], selfIndex: number): string | undefined {
		if (input === undefined) return undefined;
		const n = normalizeEntry(key, input);
		if (n === null) return undefined;
		if ("error" in n) {
			this.ctx.ui.notify(`pi-verdict: ${key}: ${n.error} — not saved`, "warning");
			return undefined;
		}
		if (list.some((x, j) => j !== selfIndex && x === n.value)) {
			this.ctx.ui.notify(`pi-verdict: already in ${key}`, "info");
			return undefined;
		}
		return n.value;
	}

	/** The entry menu of a list key, until the user goes back. */
	private async editList(key: EditableListKey): Promise<void> {
		const ADD = "+ Add";
		const BACK = "← Back";
		const UNSET = `× Unset (inherit global ${key})`;
		for (;;) {
			const cur = this.raw[key];
			const list: unknown[] = Array.isArray(cur) ? cur : [];
			const options = [ADD, ...list.map((x, i) => `${i + 1}. ${entryLabel(x)}`)];
			if (this.kind === "local" && key in this.raw) options.push(UNSET);
			options.push(BACK);
			const choice = await this.ctx.ui.select(`${key} — ${this.file}`, options);
			if (choice === undefined || choice === BACK) return;
			if (choice === ADD) await this.addEntry(key, list);
			else if (choice === UNSET) {
				if (await this.ctx.ui.confirm(`Unset ${key} in ${this.file}?`, `The project will inherit the global ${key} list.`)) {
					if (this.save(undefined, key)) return;
				}
			} else await this.editEntry(key, list, options.indexOf(choice) - 1);
		}
	}

	private async addEntry(key: EditableListKey, list: unknown[]): Promise<void> {
		const value = this.acceptEntry(key, await this.ctx.ui.input(`Add to ${key}`, LIST_KEY_PLACEHOLDER[key]), list, -1);
		if (value === undefined) return;
		const base = await this.listBase(key, list);
		if (base !== undefined) this.save([...base, value], key);
	}

	/** The list a new entry extends. A project's first entry starts from the user's pick of a copy of the global list
	 *  or an empty one; undefined when the user cancelled. */
	private async listBase(key: EditableListKey, list: unknown[]): Promise<unknown[] | undefined> {
		if (key in this.raw) return list;
		if (this.kind !== "local") return [];
		const g = readConfigObject(userConfigPath(), "user");
		// Safe: `Array.isArray` checked the value, and the filter keeps only strings.
		const gv = "raw" in g && Array.isArray(g.raw[key]) ? (g.raw[key] as unknown[]).filter((x): x is string => typeof x === "string") : [];
		const copyLabel = `Copy of global list (${gv.length})`;
		const start = await this.ctx.ui.select(`Project "${key}" replaces the global list for this project. Start from:`, [
			copyLabel,
			"Empty list",
		]);
		if (start === undefined) return undefined;
		return start === copyLabel ? gv : [];
	}

	private async editEntry(key: EditableListKey, list: unknown[], i: number): Promise<void> {
		const x = list[i];
		const act = await this.ctx.ui.select(`${key} #${i + 1}: ${entryLabel(x)}`, ["Edit", "Remove", "← Back"]);
		if (act === "Edit") {
			const value = this.acceptEntry(key, await this.ctx.ui.editor(`Edit ${key} #${i + 1}`, entryLabel(x)), list, i);
			if (value === undefined || value === x) return;
			this.save(
				list.map((e, j) => (j === i ? value : e)),
				key,
			);
		} else if (act === "Remove") {
			if (await this.ctx.ui.confirm(`Remove from ${key}?`, entryLabel(x)))
				this.save(
					list.filter((_, j) => j !== i),
					key,
				);
		}
	}
}
