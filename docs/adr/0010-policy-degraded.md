# 0010 - policyDegraded: configuration errors change the fail direction

---
status: accepted
date: 2026-10-05
---

## Context

The gate historically treated a broken *user policy* as a mostly-harmless degradation: a config
parse failure or load exception returned `EMPTY_RULES` with the built-in floor still ON plus a
session-start notification, and the extension kept running. That posture is safe against the floor
being lost, but it is **fail-open about intent**: the declarations the user wrote are gone, and
nothing stops a gray-zone classifier verdict of `allow` from passing with only a notification as
memory that the policy was ever there.

A second, quieter instance of the same direction was worse: when a `deny` regex failed to compile
or a `denyPaths` entry was type-invalid, `loadUserRules` skipped *that entry* and kept the rest —
so the user's `allow` list and `tools` list stayed fully active while one of their protections was
silently dropped (Claude-review F11). A trusted-project override that failed to parse or shape had
the same shape: an override that was *supposed* to narrow the gate simply never applied.

Plan item 6c states the correction: a configuration error **changes the fail direction** — a
broken policy must never make the gate more permissive than a healthy one.

## Decision

**`policyDegraded`** is session state set whenever the user's own policy could not be fully
loaded, and while it holds every model-originated *allow* is withheld:

1. **What sets it** — exactly four families, tracked in `LoadedRules.degraded` and copied to
   `SessionState.policyDegraded` by both the constructor and `reloadRules` (so `session_start`
   *and* the `/verdict` reload path carry it — F11's point that `reset()` alone misses reloads):
   - a user config **parse failure** (invalid JSON),
   - an unexpected **load exception**,
   - a **trusted-project** parse failure or shape failure (a narrowing override that never applied),
   - **any skipped `deny` or `denyPaths` entry** (an uncompilable regex, a type-invalid path), and a
     `deny`/`denyPaths` value that is neither a list nor a single string. A single string is the
     exception: its intent is unambiguous, so it is read as a one-element list with a skip note and
     does not set the flag.

   Scope boundary, deliberate: a skipped `allow`/`tools`/cosmetic key does *not* set the flag —
   those never carried a protection that just got dropped (an unknown-key typo, R9, is likewise
   reported through the skip channel but is not itself a fail-direction change).

2. **Every model-originated allow becomes an ask** (headless → deny, unchanged): the first
   classifier layer, the confidence cascade's effective verdict (fallback model), and the
   subagent second model (`resolveAskWithoutHuman` withholds its allow outright — no human
   answered, so the ask cannot escalate). Each such ask carries `source: "degraded-policy"` through
   the Phase 0 ask-source seam — added to `Verdict.source` and `AuditRecord.source` alongside
   `"rule"` — and `presentVerdict` names it ("Policy degraded" dialog label; a dedicated deny
   branch for the headless case). The probe's `Layer` list and `assertLayer` gained the value
   (machinery first, as `rule-ask` did in Phase 0).

3. **User `allow` and the `tools` exemption are suspended** inside `classifyByRules` (a new
   `policyDegraded` parameter): a partially-loaded policy may still carry an `allow` list while a
   `deny` entry was dropped, and a mechanical rule allow would bypass the classifier the ask would
   otherwise reach. This is **moot for the parse case** (`EMPTY_RULES.allow`/`tools` are already
   empty) and **applied for the skipped-entry case** (F11). The built-in base allowances (in-cwd
   observing reads, the in-cwd write allowance) keep behaving exactly as in a healthy session —
   they are the gate's posture, not user declarations; every other undecided call falls through
   to the classifier, whose allow is withheld by (2).

4. **The state is named everywhere it matters**: a `policy degraded` risk badge in the footer, a
   line in `/automode` status, a suffix on **every** block reason (via the `blockReason` wrapper —
   a silent degradation would contradict the session-start warning's role), and an explicit
   session-start warning as the **primary signal** (it fires whether or not the failure produced a
   skip-channel entry — a parse failure would otherwise only imply it through a count line).

**Unchanged while degraded:** the built-in floor is intact under `EMPTY_RULES` (denies are
unaffected), as are user `deny`, `denyPaths`, `gateOmpDir`, self-protection, the over-cap ask, and
the opaque ask — the deny side can only stay or strengthen; only the allow direction is withheld.

## Consequences

- **BREAKING** (a fail-direction change for configuration errors, plan F18): a session whose
  policy failed to load no longer silently passes classifier allows or mechanical `allow`/`tools`
  allows; each becomes a confirmation (headless: a deny). A user whose config is broken sees asks
  pile up until they fix it — which is the intended signal.
- The subagent second model (`classifierFallbackModel`) can no longer auto-approve a subagent ask
  while degraded — its `allow` is withheld with the same naming.
- Audit records name the origin as `degraded-policy`, so a corpus reader can distinguish "the
  policy was broken" from an ordinary classifier ask.
- Residual (recorded, not fixed here): a *project* override's ignored-but-not-denying keys and an
  unknown-key typo (R9) still surface only through the skip channel; only the four families above
  flip the fail direction.
