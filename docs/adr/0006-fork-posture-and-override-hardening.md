# 0006 - Fork operating posture: fail-closed defaults, scoped project overrides, hash-bound trust

---
status: accepted
date: 2026-10-04
---

## Background

The fork at `v0.16.0` defaults to a posture that is fail-open relative to what our
deployment needs, and its project-override path can widen the gate beyond what the trust
prompt states:

- `gateOmpDir` defaults **on**, inserting a terminal ask between the user-deny layer and
  `denyPaths`/allow for *any* `.omp` path — every deploy, skill read and audit review
  asks (headless: denies), while a user allow rule can no longer permit a `.omp` access.
- `subagentGate` defaults **`off`**, which returns from the `tool_call` hook *before*
  `adjudicate`: every tool call inside a subagent skips the rule layer, the floor and the
  classifier. `task` is in the starter `tools` allowlist, so a prompt injection only has
  to spawn a subagent and work there.
- `classifierFallbackMode` defaults **`shadow`**, the pre-0.12.0 value; upstream's default
  is `enforce` (upstream `8bcd08a`, ADR-0004 amendment).
- The config loader reads `tools`, never the pre-0.17 name `ignoreTools`, and warns about
  nothing — an unmigrated policy silently loses its exemption and the classifier starts
  adjudicating the exempt tools again.
- A trusted project config may set far more than the trust prompt names (free-text
  `rules` injected into the classifier prompt with "takes precedence" wording, the
  classifier/EXPLAIN-GATE model specs — an egress channel, `allow`, `denyPaths`, `tools`).
- Trust is bound to the project root alone, so a later commit or PR to a trusted repo
  silently widens the gate (TOCTOU).

## Decision

**Defaults (the fork's posture).**

1. `gateOmpDir` defaults **`false`**. The self-protection layer (ADR-0005) carries the
   protection over the gate's own tree; the broad terminal ask is not needed and broke
   ordinary `.omp` work. The footer no longer shows a `.omp gate off` warning badge (off
   is now the intended posture); it instead flags `subagent off` as the fail-open deviation.
2. `subagentGate` defaults **`normal`**. A fresh config adjudicates subagent calls: asks
   route to the root UI, and an unanswered ask is resolved by the second model under
   `enforce` (see 3) or denied. `task` stays in the starter allowlist, now that subagent
   calls are actually gated.
3. `classifierFallbackMode` defaults **`enforce`** (matching upstream): with a
   `classifierFallbackModel` configured, the second layer adjudicates cascaded calls. A
   shadow-mode fallback opinion may no longer resolve a subagent ask without a human — the
   `autoResolve: "allow"` shortcut now requires `enforce`.

**Compatibility.**

4. `ignoreTools` is accepted as a **deprecated alias** for `tools` (merged, deduplicated,
   with a one-shot warning). The canonical key is `tools`; renaming the policy key
   silences the warning.

**Project overrides (ADR-0002 trust flow) are scoped and content-bound.**

5. A project override may change only an explicit allowlist: `allow`, `deny`, `denyPaths`,
   `tools`/`ignoreTools`, `builtinDenyFloor`, `gateOmpDir`, `autoDeny`, `audit`,
   `notifyAllows`, `footer`, `classifierMinConfidence`, `classifierFallbackModel`,
   `classifierFallbackMode`, `subagentGate`, `subagentAskTimeoutMs`. Everything else is
   user-only and ignored with a warning — notably `classifierModel`, `explainGateModel`,
   `explainGatePrompt`, the free-text `rules`, and `toggleShortcut`. The trust prompt now
   names this set.
6. Trust is bound to a **hash of the approved override content**: `recordTrust` stores a
   sha256 of the project config, and a trusted root counts only while the file still
   matches it. A changed override re-prompts instead of applying silently. Legacy
   trust-store entries without a hash re-prompt once.

## Alternatives considered

- **Keep `gateOmpDir` on and exempt the agent tree ad hoc**: rejected — the ask fires on
  ordinary work and cannot be allowed by rule; the self-protection layer is the precise
  tool.
- **`subagentGate: "auto"`**: rejected as the default — it never prompts and delegates
  every unanswered ask to the second model; `normal` keeps the human in the loop.
- **Denylist the loosening keys instead of allowlisting**: rejected — a denylist silently
  admits future keys; an allowlist fails closed.
- **Hash-bound trust only, no key scoping**: rejected — the egress model specs and the
  prompt-injecting `rules` should not be project-controllable at all.
- **Keep the shadow cache**: rejected — upstream retired it in `0.12.0` after two
  measurements put its would-be hit rate near 3%, so its per-call probe work buys no
  verdict; deleting it serves the "minimal" pitch.

## Consequences

- A user with `classifierFallbackModel` and no mode key changes behavior on upgrade, from
  observe-only to the second layer adjudicating. Our policy pins `enforce` explicitly.
- Existing trust-store entries re-prompt once (no hash recorded).
- The shadow cache, its `/automode` stats line, the debug annotation and the audit
  `shadow` field are removed; `/verdict` and the audit format are unaffected otherwise.
- Verified by: `default is normal` / `off` / `invalid` subagent tests, the
  `gateOmpDir:true enables the gate` test, the shadow-mode subagent tests, the
  `ignoreTools is a working alias` test, the `TOCTOU` test, and the project-override
  allowlist test.

## Amendment (2026-10-04, review pass — R7)

Project overrides **narrow only**. The shallow merge could delete every user deny rule and
protected path for sessions under a trusted root, and could switch off the floor; decision 5's
allowlist is refined:

- `deny` and `denyPaths` **union** with the user's;
- `allow`, `tools` and `ignoreTools` **intersect** with them (a project cannot widen a pass);
- `builtinDenyFloor` may only be set `true`;
- `autoDeny`, `audit`, `classifierMinConfidence` and `classifierFallbackModel` leave the
  overridable set (authority and egress channels);
- the trust prompt states that accepting means the project may add deny rules and remove
  exemptions, and cannot widen the gate.

Pinned by the `narrows only` test in the `project trust prompt` suite.
