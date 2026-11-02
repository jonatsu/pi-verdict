// Rulebook fixture check (ADR-0013): runs each rulebook's `tests` fixtures against pi-verdict's command-rule
// matcher, as cc-safety-net's `rule verify` does against its own. Fixtures never run at load, because the
// matcher over-approximates and a failing `allowed` fixture must not degrade a session's policy.
//
// Usage: bun run rules-verify [rulebook.json …]
// With no file, it checks the `commandRuleFiles` the user config names, read-only, under the agent dir
// (`--agent-dir`, default `PI_CODING_AGENT_DIR` or `~/.omp/agent`), resolved as the gate resolves them.
// Exit code 0 when every fixture passes.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
	commandRuleSet,
	type LoadedRulebook,
	matchingCommandRules,
	newArgBudget,
	parseRulebook,
	readRuleFile,
} from "../extensions/pi-verdict/command-rules.ts";

/** Returns a failure line for each fixture the rulebook's own rules decide otherwise. A blocked fixture
 *  needs a rule to match, and when it names one, that rule must match first, as cc-safety-net reads it; an
 *  allowed one needs none. */
export function verifyRulebook(book: LoadedRulebook): string[] {
	const set = commandRuleSet(book.rules);
	return book.tests.flatMap((fixture, index) => {
		const first = matchingCommandRules(fixture.command, set)[0]?.name;
		if (fixture.expect === "blocked" && (first === undefined || (fixture.rule !== undefined && first !== fixture.rule))) {
			return [
				`tests[${index}]: expected ${fixture.rule ?? "a rule"} to block ${JSON.stringify(fixture.command)}, but ${first ?? "no rule"} matched first`,
			];
		}
		if (fixture.expect === "allowed" && first !== undefined) {
			return [`tests[${index}]: expected ${JSON.stringify(fixture.command)} to be allowed, but ${first} matched`];
		}
		return [];
	});
}

/** A rulebook's text by the path given on the command line, or by a configured name. */
type Source = { readonly label: string; readonly read: () => { text: string } | { error: string } };

/** The rule files the user config names, read as the gate reads them. */
function configuredSources(agentDir: string): Source[] {
	const raw = JSON.parse(fs.readFileSync(path.join(agentDir, "config", "pi-verdict.json"), "utf8")) as { commandRuleFiles?: unknown };
	const files: unknown[] = Array.isArray(raw.commandRuleFiles) ? raw.commandRuleFiles : [];
	return files.map((f) => ({ label: String(f), read: () => readRuleFile(f, agentDir) }));
}

function namedSource(file: string): Source {
	return {
		label: file,
		read: () => {
			try {
				return { text: fs.readFileSync(file, "utf8") };
			} catch (err) {
				return { error: `${file} cannot be read (${err instanceof Error ? err.message : String(err)})` };
			}
		},
	};
}

function main(): void {
	const args = process.argv.slice(2);
	const at = args.indexOf("--agent-dir");
	const agentDir = at === -1 ? (process.env.PI_CODING_AGENT_DIR ?? path.join(os.homedir(), ".omp", "agent")) : args[at + 1];
	const named = args.filter((a, i) => a !== "--agent-dir" && args[i - 1] !== "--agent-dir");
	const sources = named.length > 0 ? named.map(namedSource) : configuredSources(agentDir);
	if (sources.length === 0) {
		console.log("rules-verify: no rulebook named and none configured");
		return;
	}
	let failed = 0;
	for (const source of sources) {
		const read = source.read();
		if ("error" in read) {
			console.log(`FAIL ${source.label}\n     ${read.error}`);
			failed++;
			continue;
		}
		const book = parseRulebook(read.text, "user-command", newArgBudget());
		const problems = [...book.errors, ...verifyRulebook(book)];
		console.log(
			`${problems.length === 0 ? "ok  " : "FAIL"} ${book.book ?? source.label}: ${book.rules.length} rules, ${book.tests.length} fixtures`,
		);
		for (const p of problems) console.log(`     ${p}`);
		failed += problems.length;
	}
	if (failed > 0) process.exit(1);
}

if (import.meta.main) main();
