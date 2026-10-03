# 0005 - Self-protection layer: hard, config-exempt deny over the gate's own files (snapshot-free)

---
status: accepted
date: 2026-10-04
---

## Background

ADR-0001 introduced a self-protection layer, then removed it in two steps (2026-09-24
runtime tamper detection, 2026-09-25 the write-deny itself). The write-deny was dropped
for development-workflow and multi-session reasons, not because it was ineffective: the
multi-session false positives came from the in-memory snapshot (`IntegrityWatch`), not
from the deny. Without the deny, the gate is only as strong as the model it gates: a
prompt-injected agent can rewrite `<agentDir>/config/pi-verdict.json` (graded as an
ordinary outside-cwd write) or the project trust store and own every later session, and
with `audit: true` the `<agentDir>/verdicts/` records — raw model output and
protected-path plaintext — are agent-readable. This fork restores the property the
deployment plan names: policy changes are user-mediated.

## Decision

Introduce a **self-protection layer** as pipeline layer 0, before the built-in floor.
It cannot be exempted by any configuration: `builtinDenyFloor: false` does not turn it
off, and no user `allow` rule overrides it. Protected scope:

1. `<agentDir>/config/pi-verdict.json` — the gate's decision input.
2. `<agentDir>/config/pi-verdict-trust.json` — project-trust decisions.
3. The installed extension copy, when `import.meta.url` resolves under a recognized
   install root (`extensions/` for pi, `plugins/node_modules/<pkg>/` for omp — the same
   forms as `resolveAgentDir`). A dev checkout is deliberately **not** protected:
   in-project development writes are legitimate.
4. `<agentDir>/verdicts/` — write **and read** denied (records carry untrusted raw model
   output that must not flow back into agent context).

Disposition is a **hard deny** with a reason pointing the user to manual edits; reads of
the policy pass. The deny is never downgraded to an ask, including under `autoDeny:
false` (a `selfProtect` flag on the rule result exempts it). The bash side is a substring
match over the config/trust filenames and the resolved install/verdicts paths — obfuscatable,
so it raises the bar rather than guaranteeing it (the honest ADR-0001 caveat stands).

The layer is deliberately **snapshot-free**: no in-memory baseline, no re-check before
each verdict, no auto-restore. The protected set is derived once per session from the
agent dir and the module path. This is what makes it safe under concurrent sessions: one
session's legitimate edit is never reverted by another that never touched the file.

## Alternatives considered

- **Bring back `IntegrityWatch`** (snapshot + restore): rejected — its false positives
  are exactly why the layer was removed; the write-deny alone carries the security value.
- **Exempt the layer from `autoDeny: false` but keep it as an ask**: rejected — an
  attacker who controls the session can answer the prompt, and a headless session would
  degrade it to deny anyway.
- **Protect the whole `~/.pi/agent` / `~/.omp/agent` tree**: rejected, per ADR-0001 —
  skills, MCP config, and similar are the user's agent-configuration surface, legitimately
  edited on the user's behalf. A user who wants more declares it via `denyPaths`.
- **Protect project override files**: not needed once trust is content-bound (ADR-0006) —
  a modified override re-prompts rather than applying silently, and the trust store itself
  is now write-protected.

## Consequences

- The agent can never manage the gate policy on the user's behalf; the user edits it by
  hand or through `/verdict` (which writes through the extension, not a tool call).
- Extension upgrades replace the installed copy outside any tool call, so they are
  unaffected; a mid-session write through a tool call to the installed copy is denied.
- A read of the audit directory is denied to the agent, by design — reviewing audit
  records is the user's task.
- Verified: the write-deny holds against the policy, the trust file, the install copy and
  the audit dir, and neither `builtinDenyFloor: false` nor `allow: [".*"]` lifts it
  (pinned by `self-protection layer (ADR-0005)` in `tests/pi-verdict.test.ts`).

## Amendment (2026-10-04, review pass — R3/R4/R5/R6)

- **R3 — keyed on the inputs, not a tool-name switch.** Every string value in the tool input is
  resolved and tested against the protected set, before any direction logic, so `ast_edit`, an
  MCP filesystem tool or a later-added name gets the same hard deny. The tool name now only
  selects write/read/command direction; an unenumerated tool is treated as a **write**
  (fail-safe: a false positive on a legitimately-named path is visible, a missed write is not).
- **R4 — ancestry-aware reads, and the bash directory route.** A directory that contains a
  read-denied path (`grep <agentDir>`) **denies rather than asks** — bounded to the gate's own
  trees so a home/root listing is not caught — and the bash route resolves `cd`/`pushd` targets,
  so `cd <agentDir> && cat verdicts/*.jsonl` is caught, not only the absolute spelling. The
  honest residual stands: command text can be built at runtime (variables, `$()`, `printf`, a
  hardlink), so the bash side raises the bar; the guarantee lives on the path-shaped tools.
- **R5 — the gate's enablement surface.** The plugin workspace `omp-plugins.lock.json` and
  `package.json` (plugin root derived from the anchor, `<dotDir>/plugins`) and any project
  `.omp`/`.pi` `plugin-overrides.json` join the protected set: a single write there can disable
  the gate for later sessions with no trust prompt and no verdict. Writes deny; reads pass.
- **R6 — the trust store is read-denied** alongside the audit dir: its contents are
  reconnaissance for the tampering route and the agent has no legitimate use for it.
