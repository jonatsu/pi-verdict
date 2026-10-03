# Live verification — 2026-10-04 (fork `v0.16.0-fork.2`)

Observed results for the handoff's verification list, run on Oh-My-Pi 18.5.1 (Linux/WSL2).
The pinned ref is the commit carrying this file; the diff range for review is
`frapetti/main..v0.16.0-fork.2`. First-pass chain: `7938bc2` (self-protection + defaults),
`7f28966` (docs), `47fce9e` (package rename), `3f22dee` (Biome tooling), `e867294`/`0db3685`/
`428c909` (verification record). Review-fix chain: `3239e3a` (R2–R9), `a6912b0` (R1 format).

## V1 — the fork is what omp loaded

- `omp plugin list` at review time showed **both** `@jonatsu/pi-verdict@0.16.0-fork.1` and a
  resurrected `pi-verdict@0.12.1`, and `~/.omp/plugins/package.json` listed both. Cause, named
  at R10: the deployment's `just deploy-config` re-creates the legacy dependency and payload on
  every run — `~/.omp/plugins/package.json`, `~/.omp/plugins/node_modules/pi-verdict` and
  `~/.omp/agent/config/pi-verdict.json` all carry the deploy mtime `01:21:30`. Removing those
  steps is the deployment's cutover work, not the fork's; the fork's own install is the
  git-pinned one below, and it is installed and loaded regardless.
- `~/.omp/plugins/bun.lock` records the pin's commit SHA for `@jonatsu/pi-verdict` as
  `github:jonatsu/pi-verdict#<sha>` (installed by SHA pin, not a local path or a branch).
- Installed artifact: the fork's files (`extensions/jev-adapter.ts`, `extensions/pi-verdict.ts`),
  not 0.12.1's `332`/`2093`; sha256-identical to the pin's, as the reviewer re-confirmed.
- Anchor: `resolveAgentDir("/home/jonatsu/.omp/plugins/node_modules/@jonatsu/pi-verdict/extensions/pi-verdict.ts", homedir, undefined)` → `/home/jonatsu/.omp/agent`. `~/.pi/agent` exists on this
  machine but predates the install and is not the gate's anchor; the gate reads
  `<agentDir>/config/pi-verdict.json` under `~/.omp/agent`.
- A manual `omp plugin uninstall pi-verdict` does not stick while that deploy step exists: the
  next deploy (or the running session's in-memory plugin list) re-materialises it. The durable
  fix is the cutover; until then the duplicate may appear and is the deploy map's, not the
  install's.

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

## R3–R6 probes (review-fix pass, against the deployed policy)

Direct `adjudicate` probes at the pin, `getModel: () => null` (so a control that reaches the
classifier reports `fail-closed`, distinguishing it from a self-protection deny):

| case | result |
|---|---|
| `ast_edit { path: <agentDir>/config/pi-verdict.json, edits: [] }` | `deny/rule` — self-protection (R3) |
| `mcp__fs__write_file { path: <policy> }` | `deny/rule` — self-protection (R3) |
| `some_future_tool { path: <policy> }` | `deny/rule` — self-protection (R3) |
| control: `ast_edit { path: /tmp/verify/src/a.ts }` | reaches the classifier (no self-protection) |
| `bash "cd <agentDir> && cat verdicts/*.jsonl"` | `deny/rule` — self-protection (R4) |
| `bash "cat <agentDir>/verdicts/*.jsonl"` | `deny/rule` — self-protection (R4) |
| `grep { path: <agentDir> }` | `deny/rule` — `#54` (R4, deny not ask) |
| control: `read <agentDir>/config.yml` | `allow/rule` |
| `write ~/.omp/plugins/omp-plugins.lock.json` | `deny/rule` — self-protection (R5) |
| `write ~/.omp/plugins/package.json` | `deny/rule` — self-protection (R5) |
| `write /tmp/proj/.omp/plugin-overrides.json` | `deny/rule` — self-protection (R5) |
| control: `write /tmp/proj/src/a.ts` | reaches the classifier |
| `read <agentDir>/config/pi-verdict-trust.json` | `deny/rule` — `#54` (R6) |
| control: `read <agentDir>/config/pi-verdict.json` | `allow/rule` |

The same cases are pinned as tests in `self-protection layer (ADR-0005)`.

## V9 — the suite

- `bun run typecheck` → exit 0.
- `bun test` → 317 pass, 1 skip, 0 fail (318 tests, 2 files).
- `bun run lint` (`mise exec -- biome lint .`) → 0 errors, 0 warnings (1 informational).
- `mise exec -- biome ci .` → exit 0; unformatting one line makes it exit 1 (verified locally).

## Build notes

- `bun install && bun run typecheck && bun test` on the untouched `v0.16.0` baseline: 295 pass,
  1 skip, 0 fail.
- `mise.toml` pins `aqua:biomejs/biome@2.5.15`; `mise.lock` covers 7 platforms. Formatting is
  applied across `extensions/` and `tests/`, and CI runs `biome ci .` (lint + format + import
  order). The formatting commit is `a6912b0`; its only transformation was the formatter plus
  the organizeImports assist (lint was clean beforehand, so no lint fix was applied).
