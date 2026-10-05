# CONTEXT

The domain glossary for this project. It contains only term definitions, not implementation details or decision records (see docs/adr/ for decisions).

## Terms

### Auto Mode

The core adjudication mode of this product (pi-verdict): tool-call permissions are neither approved by a human one at a time nor allowed through wholesale (Pi's default YOLO behavior); the **rule layer + model classifier** decide automatically. Its semantics align with Claude Code's Auto Mode, but the direction is reversed: Claude Code is "prompt by default → classifier auto-approves"; Pi is "allow by default → classifier auto-blocks." Naming is layered: use the product name pi-verdict for extension entities and persistent artifacts (package, entry file, configuration file); use the functional auto-mode prefix for runtime interfaces (CLI flags, the `/automode` command, environment variables).

### master switch

The enabled state of the Auto Mode gate: session-memory state, enabled by default. There are three controls—CLI flag (across sessions), the `/automode` command (within a session), and the toggle shortcut (within a session, configurable by the user and disableable)—and they are **semantically equivalent**: different entry points for the same state, with no extra rules introduced by the entry point (no restrictions while running, no confirmation dialog, no persistence write-back). They differ only in feedback: the command gives explicit feedback, the shortcut toggles silently, and the footer always shows the state.

### adjudication pipeline

The complete decision process from `tool_call` to a three-state verdict, in order: self-protection layer (layer 0) → built-in floor → user deny → optional `.omp` gate (`gateOmpDir`, off by default) ask → `denyPaths` ask → user allow → gray zone sent to the classifier; ask degradation (no UI → deny) and fail-closed are built into the pipeline semantics. Implementation form: `adjudicate(session, call, env) → Verdict`, a pure function and a deep module with no UI dependencies; presentation (`notify`/`confirm`/`select`) is handled by the extension handler. _Avoid_: verdict pipeline (use adjudication pipeline throughout the repository).

### self-protection layer

Layer 0 of the adjudication pipeline, using hard denials that user policies cannot exempt to protect the gate's decision inputs and verdict records.

### verdict

The determination for a single tool call. The `tool_call` hook produces it; an allow does not intervene, while a block returns `{ block: true, reason }`. Its runtime carrier is a `Verdict` value object (verdict / reason / detail / source / degraded): `detail` is UI-only plaintext (protected paths enter only the local confirmation dialog, per ADR-0002's zero-leakage commitment); `source` distinguishes rule / protected-path / classifier / fail-closed / degraded-policy; `degraded` marks an ask-degradation result.

### verdict notification

The gate's channel for presenting information to the user, carrying only **noteworthy judgments**: deny/ask always notify; classifier allow notifications are enabled by the user rule `notifyAllows` (off by default); mechanical allows are always silent—rule allow is an echo of the regex the user declared, and the protected-path confirmation is visible through the confirmation dialog itself. The division of labor with verdict audit records is that notifications communicate judgments, while the audit log records the full details. Diagnostic notifications are controlled by the debug switch (flag/env), independently of `notifyAllows`; when both are enabled, classifier allow still produces only one notification.

### verdict audit records

Opt-in JSONL decision records for gray-zone verdicts (#54). They are enabled by setting `"audit": true` in `pi-verdict.json`; each record is self-contained (timestamp / session ID / cwd / model / tool and input / action line / thinking level / full transcript / raw response / parsed verdict / source / degraded flag), stored per session at `<agentDir>/verdicts/<sessionId>.jsonl`, with the 20 most recent retained. Starting with #62, the audit scope expanded to protected-path asks—the user's response provides feedback on the quality of the `denyPaths` declaration—and interactive asks record ground truth (`userAnswer`/`answeredAt` are persisted after the confirmation is answered, while `ts` remains the verdict time; a session interrupted during confirmation drops that record); rule-layer allow/deny decisions are still not audited. Records are append-only and do not feed back into verdict inputs; they preserve all details (protected-path plaintext is stored locally only, per the ADR-0002 boundary note). The self-protection layer prevents the agent from reading or writing this directory; write failures are fail-soft and do not affect verdicts.

### rule layer

The first stage of the adjudication pipeline: deterministic rules return hard allow or deny decisions. It consists of two parts: the **built-in deny floor** (dangerous bash regexes + file-path sensitivity tiers, making deny-only claims so false positives err on the safe side) and **user rules** (allow/deny regexes configured and endorsed by the user). The built-in layer provides no allowlist (since 0.2.0; the security-audit conclusion is that allowlist soundness requires shell AST analysis).

### tool-access adapter

A pure, host-agnostic function (`toolAccess(toolName, input) → ToolAccess`, ADR-0009) modeling what a tool call touches: `direction` (observing/mutating/unknown, by tool name), `kind` (file/command/code, by payload shape), `reads`/`writes` (every target the payload names — a singular `path`, a plural `paths` array, or the targets parsed out of a free-text patch's hashline headers / apply-patch lines), `command` (the command or code text), `opaque`, and `scope` (subtree search, drives the bidirectional denyPaths/`.omp`-gate compare). Every file-tool consumer (user rules, denyPaths, the built-in floor, self-protection) reads from it instead of `input.path` alone, closing the gap where a multi-header `edit` leaves omp's derived `path` unset.

### opaque call

A known mutating call (write/edit/ast_edit) whose payload names no target at all: a terminal rule-layer ask (`Verdict.source: "rule"`; headless → deny). When the payload carries patch text, opaqueness is grammar-driven — only what the hashline/apply-patch grammar itself recognizes counts, so a host-derived or model-supplied `path`/`paths` value never by itself rescues a payload whose own patch text is unparseable ("sloppy"). An unknown tool (outside the adapter's known observing/mutating names) is never opaque.

### dual-form matching

The normalization discipline for path-based rule decisions: produce **all canonical forms** for the same target path—lexical absolute form + realpath form—and test each form against the rules; a match on any form takes effect. A symlink alias whose lexical form lies within cwd but whose real path escapes cwd must not thereby be allowed as a "project-local write" (both lexical and realpath forms must lie within cwd). The discipline has three tiers: **base tier** = realpath of the full path, falling back to the lexical form on failure (implemented by `baseForms`; `denyPaths` and every base-side dual-form set have followed this from the start, ADR-0002); **ancestor-rebuild tier** = when the target does not yet exist, rebuild the path step by step from the nearest existing ancestor's realpath (implemented by `rebuiltForms`; the path-sensitivity floor has followed this since #20—use the stronger tier when the cost of an allow is high); **kernel-true tier** = the spelling the kernel itself would open for a verbatim host input, walked component by component with symlinks resolved as the path descends and `..` applied to the already-resolved parent (implemented by `kernelWalk`; runs when the spelling contains `..` or its leaf is a symlink, and a loop or unreadable link target is **unresolved**—writes fail closed; used by the path-sensitivity floor and the self-protection checks (items 7–8), and by `denyPaths` and user-rule path targets for `..`-spellings (item 10: deny matches when any target matches, allow requires every target to match). `denyPaths` does not use ancestor rebuilding: writes through symlink aliases to non-existent targets do not match, and fall through to the classifier + existence hint. _Avoid_: single-form matching that checks only the lexical form (which bypasses symlink aliases entirely); attributing ancestor rebuilding to `denyPaths` (`denyPaths` is base tier plus the kernel-true tier for `..`-spellings, never ancestor rebuild — ADR-0002, pinned by regression tests).

### user rules

Allow/deny regexes configured by the user in `<agentDir>/config/pi-verdict.json`: deny takes precedence over allow, and a blacklist match blocks; targets are full bash command strings / absolute paths for file-type tools. An allow matches only when its target is **one simple command** (ADR-0008): a compound command, a redirection, a re-parser, or a write-shaped `git` invocation falls through to the classifier instead. `builtinDenyFloor: false` disables the built-in deny floor entirely (at the user's own risk). The user, not the author, endorses security claims ("always allow").

### agentDir self-anchoring

Resolution rules for `<agentDir>` (#35, dual-host): the explicit `PI_CODING_AGENT_DIR` override always takes priority; otherwise, infer it from the extension's own install location—when it is under `<home>/<dot-dir>/(agent/)?(plugins/node_modules/<pkg>/)?extensions/`, anchor to `<home>/<dot-dir>/agent` (covering pi's `~/.pi/agent` and omp's `~/.omp/agent`; on omp 18.1+, the plugin directory is alongside `agent/` (`<dot-dir>/plugins/...`), while on versions ≤18.0 it is nested beneath it; both layouts match, and the configuration tree is always at `<dot-dir>/agent/config/`); if it cannot be anchored, fall back to `~/.pi/agent` (dev checkout). **Do not** substitute host-directory-tree existence checks for self-anchoring: on a machine with both hosts, the presence of `~/.omp` must not redirect a run under pi. S0 credential deny rules use the same anchor across both host layouts.

### denyPaths (protected paths)

A list of sensitive paths declared by the user in config; it is a **path-semantic declaration**: normalization (`~` expansion, lexical resolve, symlink resolution through realpath, falling back to the lexical form if realpath fails, case folding on macOS/Windows, plus the kernel-true spelling for `..`-spellings — the dual-form matching kernel-true tier) and path-segment prefix comparison are handled by the **tool**, and extraction covers absolute paths for file-type tools and extractable path tokens in bash command strings. A match produces a **terminal ask** (degrades to deny in non-interactive sessions), preceding user allow and following user deny and the built-in floor. Compared with user-rule deny (a regex blacklist, whose normalization assumptions are the user's responsibility), it is a stronger channel for the same security declaration. Path extraction and matching happen entirely locally; the classifier sees only an **existence hint** (it does not know path plaintext or the verdict for the matching call). _Avoid_: denyPath (singular).

### existence hint

A fixed background sentence injected into the classifier's system prompt: it tells the classifier that the user configured protected paths and that borderline behavior (copying to a temporary directory and then reading, archiving, or indirect reference) should be judged more strictly. This follows from the zero-leakage commitment for `denyPaths`: the classifier knows "they exist," but not "what they are."

### forced .omp gate

Optional rule-layer gate (`gateOmpDir`, default off): when enabled, a tool call whose file path or bash command resolves into a `.omp` path segment (lexical or realpath form, base tier) ends in a terminal ask (non-interactive → deny). It is a built-in declaration, not a user-listed path: it ranks after the built-in floor and user deny, before denyPaths and user allow. Unlike denyPaths it leaves no existence hint for the classifier (the ask is terminal) and scope tools (grep/find/ls) compare their own target only, not their subtree. Switchable from `/verdict` (the one scalar key it edits).

### gray zone

The set of tool calls for which the rule layer reaches no hard conclusion and hands judgment to the model classifier.

### classifier

A model call that assesses risk for gray-zone tool calls. The model is **configurable** and defaults to **self-reflection**; backends need not be generative—typed-decision models are connected through the jev adapter via the same call interface.

### self-reflection

The classifier's default model source: inherit the provider/model currently used by the session for verdict calls, rather than using a fixed external model.

### EXPLAIN-GATE role

A human-invoked model role behind the "Explain…" option of the ask dialog. It receives the held action, the transcript and the gate's stated reason and writes an advisory explanation for the human (a fixed system prompt plus a default task, or the human's own question). Configured by `explainGateModel` (default: the session model) and `explainGatePrompt`. Its output is display-only: it never reaches the agent, the verdict, the audit log or the classifier. Not offered for protected-path asks (ADR-0002: path plaintext stays off the model channel).

### jev adapter

A companion extension distributed with the package: in pi's model registry, it exposes typesafe's jev as a model (`typesafe/jev-latest`), translates classifier model calls into decisions requests (the default OpenRouter endpoint, or direct connection to the official v1 API with `PI_VERDICT_JEV_TRANSPORT=typesafe`), and synthesizes typed decisions into verdict prefix contract text. It participates in adjudication only when `classifierModel` points to it and credentials can be resolved; otherwise, it remains inert and the classifier follows its existing fallback behavior. Credentials all use the provider credential pipeline: the OpenRouter transport reuses pi's OpenRouter login state, while the typesafe transport reads `TYPESAFE_API_KEY` (pi has no typesafe login to reuse); neither uses an extension-provided channel.

### typed decision

The output form of non-generative models: a value from predefined options + a probability distribution + confidence, structurally incapable of producing a form outside the agreed schema. jev is one such model, in contrast with LLM free text; when synthesizing a reason, the adapter passes through probability and confidence.

### verdict prefix contract

The text-form contract for classifier responses: it must begin with `<verdict>allow|ask|deny</verdict>`, followed by a one-line reason; any violation is a parse failure handled fail-closed. Whether the backend is generative or a typed-decision model, its output is ultimately normalized to this form.

### three-state verdict (allow / ask / deny)

The three possible verdict values: if the rule layer or classifier determines an action is safe → **allow** (automatic approval); if it determines the action is dangerous → **deny** (automatic block, returning block and reason); if it cannot determine either way → **ask** (request human confirmation).

### ask degradation

Handling of `ask` when no UI is available (non-interactive modes: `pi -p` / json / rpc): always treat it as deny. This follows from fail-closed behavior in unattended scenarios.

### ask provenance

Where an ask came from — the Phase 0 seam every ask producer rides: `RuleResult.askSource` (`"protected-path"` for the `denyPaths`/`gateOmpDir` asks, `"rule"` for the opaque/over-cap asks, `"degraded-policy"` for withheld model allows under ADR-0010) maps to `Verdict.source` and `AuditRecord.source` inside `adjudicate`; an unset `askSource` maps to `"protected-path"`, preserving today's label for anything the seam does not yet know about. Presentation, notifications and the audit corpus key on this source rather than on verdict text — the layer map that names each value is `docs/layers.md`.

### fail-closed

Default behavior for any exceptional path (classifier error, timeout, unparseable output): block, never silently allow.

### policyDegraded

Session state (ADR-0010) set when the user's own policy could not be fully loaded: a config parse failure, a load exception, a trusted-project parse/shape failure, or any skipped `deny`/`denyPaths` entry. While set, **every model-originated allow is withheld** (the first classifier layer and the confidence-cascade fallback become an **ask** — `source: "degraded-policy"`, headless → deny; the subagent second model is **denied outright**, no human left to ask) and user `allow`/`tools` are suspended inside the rule layer, so a partially-loaded policy can never be more permissive than a healthy one. The built-in floor and every deny-side layer are unchanged. Named in the footer risk badge, `/automode` status, every block reason, and a session-start warning (the primary signal). Part of the `SessionState` reset list via `reloadRules`.


### confidence demotion

The mechanism that demotes the first-layer verdict when the confidence floor (`classifierMinConfidence`, ADR-0004 amendment) is triggered: when a jev verdict's confidence is strictly below the floor, **allow/ask/deny all demote**—cascade to the fallback classifier if configured, otherwise route to a human ask (non-interactive mode degrades to deny). At or above the floor, the first layer acts autonomously. The floor can be used independently (without a second layer); an LLM first layer has no numeric confidence, so the floor is inert for it.

### fallback classifier

The second layer of the cascade (`classifierFallbackModel` configuration), involved only during confidence demotion or first-layer fail-closed. In `enforce` mode (default), the second layer re-adjudicates; if it would change a first-layer `ask` or `deny` caused by confidence demotion to allow, the result becomes a human ask. `shadow` only records the second layer's opinion and does not change the cascade result; confidence demotion still becomes a human ask, and a fail-closed deny remains. If the fallback call fails or cannot be parsed, the cascade call becomes a human ask (non-interactive mode degrades to deny). A demoted record's top-level verdict preserves the first-layer semantics, with the effective result in `fallback.effective`; when `enforce` rescues a fail-closed result, the top-level record contains the effective verdict and the source remains fail-closed, while a `shadow` rescue preserves deny. `degraded` marks only ask degradation that actually occurs on the early fail-closed path. Confidence from jev is mandatory (guaranteed by contract; missing confidence means fail-closed).

### subagent gate

omp only: subagent sessions have no UI of their own, and `subagentGate` determines where their asks go—`normal` (default) presents them in the root session UI with a subagent label; if no one responds within `subagentAskTimeoutMs` or the root has no UI, there is "no verdict"; `auto` always yields no verdict; `off` means subagent tool calls skip the rule layer, floor, and classifier. In the no-verdict case, only classifier-generated asks consult the fallback classifier, and only an explicit allow from the second layer in `enforce` mode can possibly permit the action; protected-path asks, `.omp` gate asks, and asks produced solely by `autoDeny:false` are always denied.
