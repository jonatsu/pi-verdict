# Live verification — 2026-10-04 (fork `v0.16.0-fork.1`)

Observed results for the handoff's verification list, run on Oh-My-Pi 18.5.1 (Linux/WSL2).
The pinned ref is the commit carrying this file; the intermediate logic is `7938bc2` (feat:
self-protection + defaults), `7f28966` (docs), `47fce9e` (package rename), `3f22dee`
(Biome tooling). Diff range for review: `frapetti/main..<pin>`.

## V1 — the fork is what omp loaded

- `omp plugin list` → `● @jonatsu/pi-verdict@0.16.0-fork.1` (and, before the legacy copy is
  removed at cutover, a resurrected `pi-verdict@0.12.1` — see the caveat below).
- `~/.omp/plugins/bun.lock` → `"@jonatsu/pi-verdict": "github:jonatsu/pi-verdict#47fce9e5f85698e92ddde447efddba81a38d1e55"` (installed by SHA pin, not a local path).
- Installed artifact line counts at the pin: `jev-adapter.ts` 467, `pi-verdict.ts` 3613 —
  the fork's files, not 0.12.1's `332`/`2093` (the `47fce9e` build checked 467/3609).
- Anchor: `resolveAgentDir("/home/jonatsu/.omp/plugins/node_modules/@jonatsu/pi-verdict/extensions/pi-verdict.ts", homedir, undefined)` → `/home/jonatsu/.omp/agent`. `~/.pi/agent` exists on this
  machine but predates the install (mtime 00:23:56 vs install 00:45) and is not the gate's
  anchor; the gate reads `<agentDir>/config/pi-verdict.json` under `~/.omp/agent`.
- The legacy `pi-verdict@0.12.1` directory was removed with `omp plugin uninstall pi-verdict`
  before the git-spec install. It reappeared once because the already-running interactive omp
  session (started with the old copy) re-materialised its in-memory plugin list. Uninstalled
  again; `omp plugin list` now shows only `@jonatsu/pi-verdict`. A restart (and the agent-setup
  cutover that removes the vendored copy) makes the removal durable.

## V2 — the Jev classifier answers

Headless run: `omp -p --no-session --no-title --no-lsp --tools bash "Run exactly this bash command once: printf pv_ok_123 …"` (from `/tmp/pv-verify`). The command ran (`stdout: pv_ok_123`) and
the audit record shows a real classifier verdict, not a fail-closed deny:

```
{"model":"jev-latest","tool":"bash","input":{"command":"printf pv_ok_123",…},
 "rawResponse":"<verdict>allow</verdict> jev: allow 99% (confidence 98%; ask 0%, deny 1%)",
 "verdict":"allow","reason":"jev: allow 99% (confidence 98%; ask 0%, deny 1%)",
 "source":"model","degraded":false}
```

## V3 — the exemption list works (`ignoreTools` alias)

Direct `adjudicate` probe against the deployed policy (`PI_CODING_AGENT_DIR=~/.omp/agent`),
each of the eight deployed `ignoreTools` names: `todo`, `ask`, `retain`, `recall`,
`memory_edit`, `reflect`, `learn`, `manage_skill` → `verdict=allow, source=rule, reason="user tools allow rule"`. No classifier call. The deployed policy still uses the legacy
`ignoreTools` key; the loader merges it into `tools` with a one-shot warning.

## V4 — the restored floor denies

Probe results against the deployed policy:

| call | result |
|---|---|
| `write` `<agentDir>/config/pi-verdict.json` | `deny/rule` — `self-protection layer (ADR-0005)` |
| `edit` `<agentDir>/config/pi-verdict-trust.json` | `deny/rule` — `self-protection layer (ADR-0005)` |
| `write` `<agentDir>/verdicts/s.jsonl` | `deny/rule` — `self-protection layer (ADR-0005)` |
| `read` `<agentDir>/verdicts/s.jsonl` | `deny/rule` — `self-protection layer (#54)` |
| `bash "echo x > <agentDir>/config/pi-verdict.json"` | `deny/rule` — `self-protection` |
| `read` `<agentDir>/config/pi-verdict.json` | `allow/rule` (reads pass) |
| write to the policy with `allow:[/.*/]` + `builtinDenyFloor:false` | `deny/rule` — still the self-protection layer |

## V5 — `gateOmpDir` off means quiet

- `read` `<agentDir>/config.yml` → `allow/rule` (no prompt; no forced `.omp` ask).
- `read` `<agentDir>/skills/x/SKILL.md` → `allow/rule`.
- Policy deny still fires: `bash "printenv"` → `deny/rule` — `user deny rule: (^|[\s;&|])printenv\b`.

## V6 — the trust prompt behaves

Covered by the `project trust prompt` suite (all pass, offline): first entry into an untrusted
root prompts once and persists (`recordTrust` writes the root **and its override hash**); the
same session and later sessions are not asked again; `Not now` / dialog-dismissed persist
nothing and are ignored; a subagent never prompts; a malformed trust file applies for the
session, leaves the file untouched and warns; a trusted root whose override content changes is
re-prompted (TOCTOU test); a project override may not change `classifierModel`,
`explainGateModel`, the free-text `rules` or `toggleShortcut` (ignored + warned), while
allowlisted keys still merge.

## V7 — `subagentGate` in each mode

Covered by the `subagent gate (omp ctx.agent.kind = sub)` suite (all pass): `off` adjudicates
nothing; `normal` prompts on the root UI and honours `subagentAskTimeoutMs` (unanswered →
second model, only an `enforce`-mode explicit allow permits; protected-path and `.omp` asks
never auto-allow); `auto` never prompts and resolves via the second model; the default
(`normal`) adjudicates a subagent's rule-layer deny; an invalid mode falls back to `normal`.

## V8 — audit shape

Records appear under `~/.omp/agent/verdicts/<sessionId>.jsonl` with the expected fields
(`ts`, `sessionId`, `cwd`, `model`, `tool`, `input`, `actionLine`, `transcript`, `rawResponse`,
`verdict`, `reason`, `source`, `degraded`); the observed record above has no unexplained allow
(`source: "model"`, a real jev allow). Audit is write-protected and read-denied to the agent by
the restored floor; reviewing records is the user's task.

## V9 — the suite

- `bun run typecheck` → exit 0.
- `bun test` → 308 pass, 1 skip, 0 fail (309 tests, 2 files).
- `bun run lint` (`mise exec -- biome lint .`) → 0 errors, 0 warnings (1 informational).

## Build notes

- `bun install && bun run typecheck && bun test` on the untouched `v0.16.0` baseline: 295 pass,
  1 skip, 0 fail.
- `mise.toml` pins `aqua:biomejs/biome@2.5.15`; `mise.lock` covers 7 platforms. Formatting is
  configured but not enforced in CI yet — a single formatting pass lands after review.
