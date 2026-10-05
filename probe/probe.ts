// Probe runner: the shared gate-testing contract, executed offline against the real extension.
//
// Three runs per case (A/B/C) assert the LAYER that must decide the call, not the verdict text:
//   A  headless  (hasUI:false, no model)  → fail-closed for gray-zone; the ask→deny degradation
//   B  interactive (hasUI:true, stub model) → classifier exercises the gray-zone path
//   C  consumer-policy fixture, headless   → proves the floor, not the deployed policy, covers a case
//
// Env setup MUST precede the extension import: the extension computes HOME_RULE_ROOTS (and,
// after commit 5, XDG_CONFIG_ROOTS) at module load. cases.ts/fixtures.ts import types only, so
// they do not hoist runtime work above this setup.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
// The extension is loaded dynamically rather than statically: its module-level HOME_RULE_ROOTS
// is computed from the environment at load, so PI_CODING_AGENT_DIR / XDG_CONFIG_HOME must be set
// first. This is the "test cases that intentionally exercise module loading boundaries"
// exception; the specifier is a literal only because no runtime choice exists.
import type { AdjudicateEnv, SessionState, Verdict } from "../extensions/pi-verdict.ts";
import { buildCases, type Case, withAgentDir } from "./cases.ts";
import { buildFixtures, cleanupFixtures, type FixtureTree } from "./fixtures.ts";

/** The shape of the dynamically loaded extension module (only the members the probe calls). */
interface Extension {
	adjudicate: (state: SessionState, call: { toolName: string; input: Record<string, unknown> }, env: AdjudicateEnv) => Promise<Verdict>;
	SessionState: new (userRules?: unknown, agentDir?: string | null) => SessionState;
}

// ---- environment (before the extension import) ---------------------------------------
const agentDir = fs.mkdtempSync(path.join(os.tmpdir(), ".pv-probe-agent-"));
process.env.PI_CODING_AGENT_DIR = agentDir;

let ext: Extension;
let fx: FixtureTree;

/** The host model type `AdjudicateEnv.getModel` returns (host's `Model<any>`). */
type HostModel = NonNullable<ReturnType<AdjudicateEnv["getModel"]>>["model"];

/**
 * A minimal model stub. The classifier reads only `id`; no other field of the host model is
 * touched on the gray-zone path, so a single cast at this boundary is sufficient.
 */
function stubModel(id: string): HostModel {
	return { id } as unknown as HostModel;
}

/** Build the per-run AdjudicateEnv. */
function envFor(hasUI: boolean, withModel: boolean): AdjudicateEnv {
	return {
		cwd: fx.work,
		hasUI,
		getModel: withModel ? () => ({ model: stubModel("probe-stub"), thinking: "off" as const }) : () => null,
		complete: async () => {
			if (!withModel) throw new Error("probe: classifier reached under run A (no model)");
			return { content: [{ type: "text", text: "<verdict>allow</verdict> probe stub" }], stopReason: "stop" };
		},
		host: { getBranch: () => [], getSessionId: () => "probe" },
		signal: undefined,
		getFallbackModel: undefined,
	};
}

/** Write the config for a case (or `{}`), construct the state, and reload against the cwd. */
function makeState(config: Record<string, unknown> | null): { state: SessionState; skipped: string[] } {
	const cfgPath = path.join(agentDir, "config", "pi-verdict.json");
	fs.mkdirSync(path.dirname(cfgPath), { recursive: true });
	fs.writeFileSync(cfgPath, JSON.stringify(config ?? {}, null, 2));
	const state = new ext.SessionState();
	const report = state.reloadRules(fx.work);
	return { state, skipped: report.skipped };
}

/** Resolve the consumer-policy fixture: env override → real override → synthetic. */
function resolveConsumerPolicy(): Record<string, unknown> {
	const here = path.dirname(fileURLToPath(import.meta.url));
	const candidates = [
		process.env.PI_VERDICT_PROBE_POLICY,
		path.join(here, "consumer-policy.real.json"),
		path.join(here, "consumer-policy.json"),
	].filter((p): p is string => typeof p === "string" && p.length > 0);
	for (const p of candidates) {
		if (!fs.existsSync(p)) continue;
		const parsed = JSON.parse(fs.readFileSync(p, "utf8")) as Record<string, unknown>;
		delete parsed._meta;
		return parsed;
	}
	throw new Error("probe: no consumer-policy fixture found (env, real override, or synthetic)");
}

interface CaseResult {
	c: Case;
	/** Which run decided a mismatch ("A"/"B"/"C"), or "kernel" for the truth check. */
	channel: string;
	message: string;
	pass: boolean;
}

/** Assert one verdict against the expectation for a given run; returns an error string or null. */
function assertLayer(v: Verdict, c: Case, run: "A" | "B" | "C"): string | null {
	const exp = c.expected;
	let want: { source: string; verdict: string };
	switch (exp.layer) {
		case "rule":
			want = { source: "rule", verdict: "deny" };
			break;
		case "allow":
			want = { source: "rule", verdict: "allow" };
			break;
		case "classifier":
			// Run B exercises the model; A and C are headless → fail-closed.
			want = run === "B" ? { source: "classifier", verdict: "allow" } : { source: "fail-closed", verdict: "deny" };
			break;
		case "protected-path":
			// Run A is headless → the ask degrades to deny; run B is interactive → ask.
			want = run === "B" ? { source: "protected-path", verdict: "ask" } : { source: "protected-path", verdict: "deny" };
			break;
		case "rule-ask":
			// Rule-layer ask (e.g. an opaque write, an over-cap action): run B is interactive →
			// ask; A and C are headless → the ask degrades to deny (checked below).
			want = run === "B" ? { source: "rule", verdict: "ask" } : { source: "rule", verdict: "deny" };
			break;
		case "degraded-policy":
			// ADR-0010: a model-originated allow withheld while the user's own policy failed to
			// load. Only run B can produce this source: it has the stub model whose allow is
			// then converted to an ask. Runs A and C have no model, so a gray call fail-closes
			// BEFORE any model allow could exist — the same A/C shape as the `classifier` layer.
			want = run === "B" ? { source: "degraded-policy", verdict: "ask" } : { source: "fail-closed", verdict: "deny" };
			break;
	}
	if (v.source !== want.source || v.verdict !== want.verdict) {
		return `run ${run}: got ${v.source}/${v.verdict}, expected ${want.source}/${want.verdict}`;
	}
	// A rule deny must never pass as a degraded rule-ask: headless/consumer runs require the
	// explicit degradation flag, not just the deny verdict.
	if (exp.layer === "rule-ask" && run !== "B" && !v.degraded) {
		return `run ${run}: expected degraded:true (ask demoted to deny), got degraded:${v.degraded}`;
	}
	const reason = v.reason ?? "";
	if (exp.ruleId !== undefined && !reason.includes(`rule ${exp.ruleId}:`)) {
		return `run ${run}: reason lacks rule ${exp.ruleId}: — ${JSON.stringify(reason)}`;
	}
	if (exp.reasonIncludes !== undefined && !reason.includes(exp.reasonIncludes)) {
		return `run ${run}: reason lacks ${JSON.stringify(exp.reasonIncludes)} — ${JSON.stringify(reason)}`;
	}
	return null;
}

/** Run one case under all applicable runs. */
async function runCase(c: Case, consumerPolicy: Record<string, unknown>): Promise<CaseResult> {
	// kernelOpens ground-truth check (runner-side, independent of the gate): the raw spelling the
	// gate sees must actually open the same file the kernel target names. Node's fs collapses
	// `..` lexically before the syscall, which is exactly the disagreement these cases test, so
	// the oracle is a raw-path reader (`cat`), which passes the spelling to open(2) untouched.
	if (c.kernelOpens !== undefined) {
		try {
			const raw = String(c.input.path);
			const rawAbs = path.isAbsolute(raw) ? raw : `${fx.work}/${raw}`;
			const read = execFileSync("cat", [rawAbs]);
			const kernel = fs.readFileSync(c.kernelOpens);
			if (!read.equals(kernel)) {
				return { c, channel: "kernel", message: `raw spelling did not open ${c.kernelOpens}`, pass: false };
			}
		} catch (e) {
			return { c, channel: "kernel", message: `kernel truth read failed: ${(e as Error).message}`, pass: false };
		}
	}

	const call = { toolName: c.tool, input: c.input };
	const { state: stateA, skipped: skipA } = makeState(c.config ?? null);
	if (skipA.length > 0 && !c.degradedConfig) {
		return { c, channel: "A", message: `config skipped entries: ${skipA.join(", ")}`, pass: false };
	}
	const a = await ext.adjudicate(stateA, call, envFor(false, false));
	const b = await ext.adjudicate(stateA, call, envFor(true, true));

	const runs: Array<["A" | "B" | "C", Verdict]> = [
		["A", a],
		["B", b],
	];
	if (c.policy === "consumer") {
		const { state: stateC, skipped: skipC } = makeState(consumerPolicy);
		if (skipC.length > 0) {
			return { c, channel: "C", message: `consumer config skipped entries: ${skipC.join(", ")}`, pass: false };
		}
		runs.push(["C", await ext.adjudicate(stateC, call, envFor(false, false))]);
	}

	// The layer must agree across every run; the first mismatch reports.
	for (const [name, v] of runs) {
		const err = assertLayer(v, c, name);
		if (err) return { c, channel: name, message: err, pass: false };
	}
	return { c, channel: "", message: "", pass: true };
}

// ---- main ----------------------------------------------------------------------------
async function main(): Promise<void> {
	const args = process.argv.slice(2);
	const filterIdx = args.indexOf("--filter");
	const filter = filterIdx >= 0 ? args[filterIdx + 1] : undefined;

	fx = buildFixtures(agentDir);
	process.env.XDG_CONFIG_HOME = fx.xdg;
	ext = (await import("../extensions/pi-verdict.ts")) as Extension;
	const consumerPolicy = resolveConsumerPolicy();

	const all = buildCases(fx).map((c) => withAgentDir(c, agentDir));
	const cases = filter ? all.filter((c) => c.label.includes(filter)) : all;
	if (cases.length === 0) {
		console.error(`probe: no cases match filter ${JSON.stringify(filter)}`);
		process.exitCode = 1;
		return;
	}

	let pass = 0;
	let fail = 0;
	let open = 0;
	let openPassed = false;

	for (const c of cases) {
		if (c.skipOn === "win32" && process.platform === "win32") {
			console.log(`- skipped ${c.label} [${c.family}]`);
			continue;
		}
		const r = await runCase(c, consumerPolicy);
		const tag = c.item !== undefined ? `item=${c.item}` : c.ref !== undefined ? `ref=${c.ref}` : "";
		if (c.expected.known === "open") {
			if (r.pass) {
				console.log(`\u2717 ${c.label} [${c.family}] ${tag} \u2014 open case now passes (remove the marker)`);
				openPassed = true;
			} else {
				console.log(`~ ${c.label} [${c.family}] ${tag}`);
				open += 1;
			}
			continue;
		}
		if (r.pass) {
			pass += 1;
			console.log(`\u2713 ${c.label} [${c.family}] ${tag}`);
		} else {
			fail += 1;
			console.log(`\u2717 ${c.label} [${c.family}] ${tag} \u2014 ${r.message}`);
		}
	}

	console.log(`\n${pass} pass, ${fail} fail, ${open} open`);
	process.exitCode = fail > 0 || openPassed ? 1 : 0;
}

main()
	.catch((e) => {
		console.error("probe: fatal:", e);
		process.exitCode = 1;
	})
	.finally(() => {
		try {
			if (fx) cleanupFixtures(fx.root);
			cleanupFixtures(agentDir);
		} catch {
			/* teardown is best-effort */
		}
	});
