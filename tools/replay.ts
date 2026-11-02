// Replay: re-run the recorded gray-zone calls of an audit log against the current build, and count how
// the rule layer now decides them. A development tool, not part of CI, because the audit data is private.
//
// It reads the audit files and the policy read-only, runs the gate under a temporary agent dir with a
// classifier stub, and never touches the network or the live agent dir. Output holds counts and rule
// ids only; `--show` adds the recorded action lines, and only to a terminal, since a record may hold a
// protected path (ADR-0002).

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { parseArgs } from "node:util";
// Types only: the extension itself loads after PI_CODING_AGENT_DIR points at the temporary dir.
import type * as Gate from "../extensions/pi-verdict/index.ts";

/** The members of the extension module a replay uses. */
export interface ReplayGate {
	readonly adjudicate: typeof Gate.adjudicate;
	readonly SessionState: typeof Gate.SessionState;
	readonly AuditLog: typeof Gate.AuditLog;
}

/** One audit file: its name and its JSONL text. */
export interface AuditFile {
	readonly name: string;
	readonly text: string;
}

/** A recorded gray-zone call that the replay changed, for `--show`. */
export interface ReplayChange {
	readonly from: string;
	readonly to: string;
	readonly actionLine: string;
}

/** What a replay counts. Every map is keyed by a verdict and a rule id, never by call content. */
export interface ReplayReport {
	files: number;
	/** Lines that are not a JSON object of a known record shape. */
	unreadable: number;
	/** Rule-layer allows and denies as recorded, keyed `verdict:rule`: the share of calls each rule decides. */
	recordedRuleVerdicts: Record<string, number>;
	/** Rule-layer asks as recorded, keyed by their source. */
	recordedAsks: Record<string, number>;
	/** Recorded gray-zone calls, the replay's input. */
	gray: number;
	/** Gray-zone calls skipped because their cwd no longer exists, so their paths would grade differently. */
	cwdMissing: number;
	stillGray: number;
	/** Gray-zone calls the rule layer now allows, keyed by rule id. */
	nowAllowed: Record<string, number>;
	/** Gray-zone calls the rule layer now denies or asks about, keyed `verdict:rule`. */
	nowDeniedOrAsked: Record<string, number>;
	/** Recorded classifier verdicts against the user's answer to the ask, keyed `verdict->answer`. */
	answers: Record<string, number>;
	/** Filled only when the caller asks for the changed calls. */
	changes: ReplayChange[];
}

/** The fields of a full audit record the replay reads; the rest of the record is ignored. */
interface GrayRecord {
	readonly sessionId: string;
	readonly cwd: string;
	readonly tool: string;
	readonly input: Record<string, unknown>;
	readonly actionLine: string;
}

const GRAY_SOURCES: ReadonlySet<string> = new Set(["model", "fail-closed", "degraded-policy"]);
const REPLAY_SENTINEL = "replay classifier stub";

function isObject(v: unknown): v is Record<string, unknown> {
	return typeof v === "object" && v !== null && !Array.isArray(v);
}

function bump(map: Record<string, number>, key: string): void {
	map[key] = (map[key] ?? 0) + 1;
}

/** Returns the gray-zone call a full record holds, or null when a field it needs is missing. */
function grayRecord(r: Record<string, unknown>): GrayRecord | null {
	const { sessionId, cwd, tool, input, actionLine } = r;
	if (typeof sessionId !== "string" || typeof cwd !== "string" || typeof tool !== "string" || !isObject(input)) return null;
	return { sessionId, cwd, tool, input, actionLine: typeof actionLine === "string" ? actionLine : "" };
}

/** The host model type `AdjudicateEnv.getModel` returns. */
type HostModel = NonNullable<ReturnType<Gate.AdjudicateEnv["getModel"]>>["model"];

/** The environment of one replayed call: a UI, so an ask stays an ask, and a classifier stub that allows
 *  with a sentinel reason, so a call still in the gray zone is recognizable. */
function replayEnv(record: GrayRecord): Gate.AdjudicateEnv {
	return {
		cwd: record.cwd,
		hostKind: "omp",
		hasUI: true,
		// The classifier reads only the model's `id`, so this partial model is enough at runtime.
		getModel: () => ({ model: { id: "replay-stub" } as unknown as HostModel, thinking: "off" as const }),
		complete: async () => ({ content: [{ type: "text", text: `<verdict>allow</verdict> ${REPLAY_SENTINEL}` }], stopReason: "stop" }),
		host: { getBranch: () => [], getSessionId: () => record.sessionId },
	};
}

/** Replays the gray-zone records of `files` through `gate`, one session state per file, in record order.
 *  Rule ids come from the gate's own compact rule-verdict records, captured in memory. */
export async function replayAudit(gate: ReplayGate, files: readonly AuditFile[], opts: { show?: boolean } = {}): Promise<ReplayReport> {
	const report: ReplayReport = {
		files: files.length,
		unreadable: 0,
		recordedRuleVerdicts: {},
		recordedAsks: {},
		gray: 0,
		cwdMissing: 0,
		stillGray: 0,
		nowAllowed: {},
		nowDeniedOrAsked: {},
		answers: {},
		changes: [],
	};
	let lastRule = "unlabeled";
	class CapturedAudit extends gate.AuditLog {
		override append(record: Parameters<Gate.AuditLog["append"]>[0]): void {
			if ("kind" in record) lastRule = record.rule;
		}
	}
	for (const file of files) {
		const state = new gate.SessionState();
		let sessionCwd: string | null = null;
		for (const line of file.text.split("\n")) {
			if (!line.trim()) continue;
			let parsed: unknown;
			try {
				parsed = JSON.parse(line);
			} catch {
				report.unreadable++;
				continue;
			}
			if (!isObject(parsed)) {
				report.unreadable++;
				continue;
			}
			if (parsed.kind === "rule") {
				bump(report.recordedRuleVerdicts, `${String(parsed.verdict)}:${String(parsed.rule)}`);
				continue;
			}
			const source = String(parsed.source);
			if (!GRAY_SOURCES.has(source)) {
				if (parsed.verdict === "ask" || parsed.degraded === true) bump(report.recordedAsks, source);
				else report.unreadable++;
				continue;
			}
			if (typeof parsed.userAnswer === "string") bump(report.answers, `${String(parsed.verdict)}->${parsed.userAnswer}`);
			const record = grayRecord(parsed);
			if (record === null) {
				report.unreadable++;
				continue;
			}
			report.gray++;
			if (!fs.existsSync(record.cwd)) {
				report.cwdMissing++;
				continue;
			}
			if (record.cwd !== sessionCwd) {
				state.reset(record.cwd);
				sessionCwd = record.cwd;
			}
			state.audit = new CapturedAudit(os.tmpdir());
			lastRule = "unlabeled";
			const v = await gate.adjudicate(state, { toolName: record.tool, input: record.input }, replayEnv(record));
			let to: string;
			if (v.source === "rule" && v.verdict === "allow") {
				to = `allow:${lastRule}`;
				bump(report.nowAllowed, lastRule);
			} else if (lastRule !== "unlabeled") {
				// A rule deny, which `autoDeny: false` presents as an ask.
				to = `deny:${lastRule}`;
				bump(report.nowDeniedOrAsked, to);
			} else if (v.source === "rule" || v.source === "protected-path") {
				to = `${v.verdict}:${v.source}-ask`;
				bump(report.nowDeniedOrAsked, to);
			} else {
				report.stillGray++;
				continue;
			}
			if (opts.show) report.changes.push({ from: `${String(parsed.verdict)}:${source}`, to, actionLine: record.actionLine });
		}
	}
	return report;
}

/** Renders a report as plain text, the change list last. */
export function renderReport(report: ReplayReport): string {
	const lines = [
		`audit files: ${report.files}`,
		`unreadable lines: ${report.unreadable}`,
		`recorded gray-zone calls: ${report.gray}`,
		`  skipped, cwd missing: ${report.cwdMissing}`,
		`  still gray: ${report.stillGray}`,
	];
	const section = (title: string, map: Record<string, number>): void => {
		lines.push(`${title}:`);
		const entries = Object.entries(map).sort(([a, x], [b, y]) => y - x || a.localeCompare(b));
		if (entries.length === 0) lines.push("  (none)");
		for (const [key, n] of entries) lines.push(`  ${key}: ${n}`);
	};
	section("now rule-allowed, by rule", report.nowAllowed);
	section("now denied or asked, by rule", report.nowDeniedOrAsked);
	section("recorded rule verdicts", report.recordedRuleVerdicts);
	section("recorded rule-layer asks", report.recordedAsks);
	section("recorded verdict -> user answer", report.answers);
	for (const c of report.changes) lines.push(`${c.from} -> ${c.to}  ${c.actionLine}`);
	return lines.join("\n");
}

/** Copies the live policy, with audit off, and the trust store into the temporary agent dir. */
function stagePolicy(liveAgentDir: string, tmpAgentDir: string): void {
	const config = path.join(tmpAgentDir, "config");
	fs.mkdirSync(config, { recursive: true });
	const policyPath = path.join(liveAgentDir, "config", "pi-verdict.json");
	const policy: unknown = fs.existsSync(policyPath) ? JSON.parse(fs.readFileSync(policyPath, "utf8")) : {};
	fs.writeFileSync(path.join(config, "pi-verdict.json"), JSON.stringify({ ...(isObject(policy) ? policy : {}), audit: false }));
	const trust = path.join(liveAgentDir, "config", "pi-verdict-trust.json");
	if (fs.existsSync(trust)) fs.copyFileSync(trust, path.join(config, "pi-verdict-trust.json"));
}

async function main(): Promise<void> {
	const { values } = parseArgs({
		options: {
			"agent-dir": { type: "string" },
			show: { type: "boolean", default: false },
		},
	});
	const liveAgentDir = values["agent-dir"] ?? process.env.PI_CODING_AGENT_DIR ?? path.join(os.homedir(), ".omp", "agent");
	if (values.show && !process.stdout.isTTY) {
		console.error("replay: --show prints recorded action lines, which may hold protected paths, so it writes only to a terminal");
		process.exit(1);
	}
	const verdicts = path.join(liveAgentDir, "verdicts");
	if (!fs.existsSync(verdicts)) {
		console.error(`replay: no audit directory at ${verdicts}; turn on "audit" and use the agent first`);
		process.exit(1);
	}
	const files = fs
		.readdirSync(verdicts)
		.filter((f) => f.endsWith(".jsonl"))
		.sort()
		.map((name) => ({ name, text: fs.readFileSync(path.join(verdicts, name), "utf8") }));
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pv-replay-"));
	try {
		stagePolicy(liveAgentDir, tmp);
		// The gate anchors its config and home rules at module load, so the environment comes first.
		process.env.PI_CODING_AGENT_DIR = tmp;
		const gate: ReplayGate = await import("../extensions/pi-verdict/index.ts");
		console.log(renderReport(await replayAudit(gate, files, { show: values.show })));
	} finally {
		fs.rmSync(tmp, { recursive: true, force: true });
	}
}

if (import.meta.main) await main();
