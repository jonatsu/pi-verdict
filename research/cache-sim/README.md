# Offline Replay of Verdict-Cache Benefits (.issue #5 Decision Basis)

We replayed historical Claude Code permission-classifier verdicts from Langfuse offline to measure the hit rate and counterfactual consistency of a “two-key LRU (128) verdict cache.” **Conclusion: the two-key hit rate was only 3.2%, with benefits concentrated in retry/polling loops. This does not support a claim of significant overall benefit → defer the cache and measure pi’s own hit rate with a shadow cache.**

## Data and Method

- Data source: self-hosted Langfuse v4 instance (address undisclosed), 2026-08-24 → 08-26 window; `type=GENERATION` + `max_tokens=64` features selected **1,2xx CC stage-1 classifier calls / 2x sessions** (counts redacted; hundreds of MB of metadata fetched + I/O fetched in parallel by ID, with zero failures)
- Key structural finding: the CC classifier input transcript consists of **append-only text parts** (exactly one entry per part); the action under review is the last part before `</transcript>`, and a user message is a part beginning with `User: ` — entry boundaries are exact, with no need for heuristic splitting
- Key design (matching the #5 decision): `commandKey` = the raw action part; `contextKey` = hash of the most recent 5 User entries; replay an LRU of 128 per session; failed outputs (`<block>` unparseable, 47 entries) are not cached (matching the rule that fail-closed outcomes are not cached)
- Counterfactual consistency: every historical call actually occurred, so on a hit we can compare the “cached verdict vs. actual output verdict”

## Scripts

- `fetch-io.ts` — fetch observed I/O concurrently, 10 requests at a time, by ID; write NDJSON (credentials use `LANGFUSE_*` environment variables)
- `simulate.ts` — session-level two-key LRU replay: hit rate/miss composition/consistency/savings estimate/high-frequency repeated actions
- `kinds.ts` — split gray-zone composition by tool family (MCP vs. Bash repetition-rate differences)

Reproduce: `npx langfuse-cli api observations list --type GENERATION --from-start-time <t> --fields core,basic,model,usage --limit 500 --all --json` → filter for `max_tokens==64` to get `cand-ids.json` → `bun fetch-io.ts` → `bun simulate.ts`

## Results (2026-08-26 Replay)

| Metric | Value |
|---|---|
| Two-key hit rate | **41/1265 = 3.2%** |
| Command-key upper bound (ignoring context) | 8.2% (`contextHash` removes 45% of command-level repeats) |
| Miss composition | no-entry 1144(90%)/ context-changed 33 |
| Consistency on hits | 39/41 consistent; **0 dangerous disagreements (cached allow/actual deny)**; 2 conservative disagreements |
| Replay distribution on hits | allow 39 / deny 2 |
| Savings (CC-side measure) | 606s latency + 40K input tokens / 2 days |

Structural distribution:

- Benefits concentrated in **retry/polling loops** — `Bash sleep 115; cat …` polling ×18 (38% hit rate in one session, contributing 44% of all hits); MCP validation loops (`browser_snapshot` 23 calls, 14 repeats; `browser_navigate` 15 calls, 10 repeats)
- By tool family: MCP call repetition rate ~29%(38/130), while Bash is only 6% (84% of CC gray-zone calls are one-off Bash)
- By session: most are <3%; the largest session (202 adjudications) is 0%

Conservative extrapolation to pi: the pi prototype has a broader Bash allowlist, and **all MCP/custom tools enter the gray zone**. Its gray-zone mix is more heavily weighted toward the higher-repetition MCP class → pi’s actual hit rate is expected to exceed 3.2%; measure it with a shadow cache.

## Appendix: Verifying ai-guard Semantics (source `pi-permission-ai-guard@0.7.0`)

- The “recoverable tier” is a throttle: 3 consecutive denies short-circuit **only the next** call, then reset the count; the actual fuse is a hard cap of 20 cumulative session denies (never resets)
- The circuit-breaker check runs **before** the cache lookup; `contextHash` = hash of the sanitized user-message stream (excluding the tool-call stream) — the basis for the two-key design
