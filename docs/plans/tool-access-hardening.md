# Tool access + input hardening — execution plan

Slug: `tool-access-hardening-plan`

**Status: approved by the user on 2026-10-05, not yet executed.** Revision 3, nine commits, release
held by default.
Revision 2 (2026-10-05) folds the Claude review of the draft
(`.scratch/reviews/2026-10-05-tool-access-hardening-plan-review.md`: findings F1–F19; its executed
evidence and nine decision points, all recommended defaults adopted). Revision 3 folds the scoped
re-review of revision 2 (findings R2-1–R2-14, all applied) and the 2026-10-05 Claude re-review of
revision 3 (the opaque narrowing + four minors, all applied).

**Basis:** `docs/plans/input-coverage-hardening.md` (the 2026-10-04 proposal; items re-triaged against
HEAD `c7f9d2e`, `v0.17.0` — two of its items already landed with the probe-apparatus round, see the
disposition table). Gate-side facts below were re-verified against `extensions/pi-verdict.ts` at
`c7f9d2e` (= `889c57a` + the AGENTS.md package-name fix) by symbol, not by the proposal's now-stale
line numbers. Host-side tool shapes were pinned
2026-10-05 from the installed sources (omp 18.5.1 `src/…`, pi 0.84.3 `dist/…`) and are cited inline
per fact in Phase 2.
ADRs: 0002 (denyPaths), 0004 (cascade), 0005 (self-protection), 0006 (project overrides), 0007
(monotone floor), 0008 (simple-command allow). New: 0009, 0010.

## Context

The proposal's common cause stands: the gate decides from its own model of each host tool's input
shape, and where that model is incomplete the call can fall to a silent `allow` instead of to the
classifier or an ask. The probe-apparatus round closed the shell-tokeniser, kernel-path, XDG and
`denyPaths`-tier defects; it did not touch how the gate parses tool *inputs*. This round extends the
input-keyed discipline (the layer-0 R3 model) to the other layers, and lands the proposal's remaining
items in the order its "Suggested order" section implies, adjusted for what has already shipped.

Verified defects this round closes (evidence at HEAD `889c57a`):

1. **Multi-file omp `edit` is a silent rule allow (proposal item 1, critical).** omp's
   `normalizeToolEventInput` hands extensions `{input, paths}` — no `path` — for a multi-header
   hashline patch. The gate reads `input.path` only: `classifyByRules` calls
   `classifyPath(String(input.path ?? ""))`, `userRuleTargets` returns `[]` for a pathless file tool,
   and `denyPathCandidates` returns `[]`. `classifyPath("")` resolves to the cwd, which passes the
   in-project write allowance → `allow/rule`, zero model calls, for a patch that may write
   `~/.bashrc`, `.git/hooks/` or any `denyPaths` entry. `input.paths` appears nowhere in the gate.
2. **A trusted project override can widen the gate (item 3, important).** The override merge switch
   narrows `deny`/`denyPaths`/`allow`/`tools`/`ignoreTools`/`builtinDenyFloor`, but its `default`
   arm copies `gateOmpDir`, `notifyAllows`, `footer`, `classifierFallbackMode`, `subagentGate` and
   `subagentAskTimeoutMs` verbatim — a cloned repo's `.omp/pi-verdict.json` with
   `{"subagentGate":"off","footer":"off"}` ungates every subagent call and hides the badge that
   flags it, contradicting ADR-0006 R7 and the trust-prompt text.
3. **Past tool calls leak protected paths into the classifier transcript (item 6b).**
   `collectTranscriptParts` sends every prior `toolCall` block to the classifier provider unfiltered —
   a protected read the user approved leaks its path on later verdicts, against ADR-0002's
   zero-plaintext commitment.
4. **The action line is truncated before the classifier sees it (item 6a).** `transcriptSafe` caps
   every line — including the action under review — at 1000 characters (head 600 / tail 400). A
   payload in the middle of a long command or patch is invisible to the classifier; the danger floor
   separately stops reading at `BASH_MAX_MATCH_LEN` = 8192.

Already landed since the proposal (do **not** re-do): item 2 — `allowAdmits` guards the user allow
loop (commit `a3c7071`, ADR-0008); item 5's core — the monotone floor (tripwire decides hits, the
sound-gated word view only clears; commit `7ad1014`, ADR-0007); item 8's package-name staleness
(commit `c7f9d2e`) and CONTEXT's kernel-true tier (commit `6594ebd`).

## Universal-plugin constraints (binding for every phase)

This plugin ships to anyone's omp (and pi) install; it must never depend on anything of the
development host:

1. **Zero runtime dependencies** (repo law): only `node:` builtins; TypeScript shipped as-is.
2. **No dependence on the development host**: behavior keys on capability ("does this API exist") or
   on payload shape by default. The one sanctioned exception: behavior may **target a specific
   omp/pi version or similar documented fact** where that fact requires handling — the existing
   omp-18 compat seam is the precedent — and any such version-targeted branch must cite the fact
   that forces it. What stays forbidden in all cases: depending on the development host's own state
   (its install layout, local tools, configs, or unshared files).
3. **Payload conventions are implemented self-contained**: the hashline grammar (file headers, tags,
   op lines) is the plugin's own parser with its own constants — no import from `@oh-my-pi/pi-tui` or
   any host-internal module, and no reading of host source files at runtime. Grammar drift is caught
   by the adapter tests and the probe cases, never by a runtime lookup.
4. **No development-host state in behavior or tests**: no hard-coded dev paths, tools, or configs;
   fixtures are runtime-built payload snapshots under `os.tmpdir()` (probe convention). The only
   dev-host touchpoint is the local smoke test — verification, never a release gate.
5. **Host-source citations in this plan are design-time evidence only**: the file:line references
   justify decisions; nothing at runtime may depend on them or on the inspected install's layout.

## Phase 0 — the ask-source seam (size S; commit 1; no behavior change)

Land the seam **first**, on its own, with zero behavior change (Claude-review F14 — otherwise every
later ask-producing phase improvises the contract):

1. `RuleResult` carries `askSource`; `adjudicate` maps it to `Verdict.source` (today every rule-layer
   ask hardcodes `"protected-path"` in both the interactive branch `:3044-3067` and the headless
   branch `:3063`). Every existing ask (`denyPaths`, the `.omp` gate) explicitly sets
   `askSource: "protected-path"` — verdicts are unchanged, bit for bit. **Contract for later
   phases** (Claude-review R2-9): every new ask producer names its source (Phase 4's over-cap ask →
   `"rule"`; Phase 6's degraded asks — first layer, cascade, subagent second model — state their
   value at implementation); an **unset** `askSource` maps to `"protected-path"`, preserving
   today's label for anything the seam does not yet know about.
2. `AuditRecord.source` gains `"rule"` (it is `"model" | "fail-closed" | "protected-path"` today,
   `:2641`).
3. The probe gains the `rule-ask` layer in `Layer` (`probe/cases.ts:16`), the coverage renderer
   (`tools/coverage.ts`) and `assertLayer` (`probe/probe.ts:101-131`); run A additionally asserts
   `degraded === true` so a rule deny cannot pass as a degraded ask.
4. Verified only by: existing suites + probe stay green unchanged, and a throwaway check that the
   two ask paths still report `protected-path`.

## Phase 1 — project overrides narrow by direction (item 3; size S; commit 2)

1. Replace the merge switch's verbatim `default` arm with a **direction table**: each overridable key
   carries its narrowing merge function, so a new key cannot be added without choosing one.
   - `subagentGate` — a project may set only `"normal"` (the interactive value; `"off"` ungates and
     `"auto"` skips the human); any other project value is ignored with the standard skipped-note.
   - `subagentAskTimeoutMs` — a project value applies only when strictly greater than the user's
     **effective** value (the merge runs on raw values, `:1219-1246`, before normalisation —
     compare against the user's effective value, which defaults to 60000 when absent or invalid;
     Claude-review F12), and is capped at 2^31−1 ms for both user and project configs (a larger
     value overflows `setTimeout`-family timers on Bun and would make `AbortSignal.timeout`
     (`:4773`) fire almost immediately, acting like `"auto"` — F12).
   - `classifierFallbackMode` — a project may set only `"shadow"` (the second layer may record, never
     allow).
   - `gateOmpDir` — a project may set only `true`.
   - `notifyAllows` — a project may set only `true` (F12: a project `false` hides classifier allows —
     the same class as `footer`).
   - `footer` — **removed** from `PROJECT_OVERRIDABLE_KEYS` (user-only): `footer: "off"` hides the
     `subagent off` warning badge that exists to expose the widened state.
2. Tests: extend the R7 regression to **every** overridable key — a widening project value is ignored
   (user value survives + skipped-note), a narrowing value applies. BREAKING for project configs that
   relied on the widened values; CHANGELOG entry.
3. Docs: ADR-0006 amendment (the direction table); `docs/configuration.md` records the narrowing
   directions for the overridable set (the affected keys: `footer`, `notifyAllows`, the subagent
   keys, `gateOmpDir`) **and fixes its stale overridable list** (F12: `docs/configuration.md:58`
   still lists `autoDeny`, `audit`, `classifierMinConfidence` and `classifierFallbackModel` as
   overridable, which the code forbids at `:1073-1093`); the config template `_hint` copy changes
   only if the trust-prompt text names the set. The trust prompt itself is unchanged — it finally
   reads true for every key.

## Phase 2 — the tool-access adapter (item 1; size M; commit 3)

1. **`toolAccess(toolName, input): ToolAccess`** — one pure, exported, **host-agnostic** model of what
   a call touches:
   `{ direction: "observing" | "mutating" | "unknown", kind: "command" | "file" | "code" | null, reads: string[], writes: string[], command: string | null, opaque: boolean, scope: boolean }`.
   It is a function of the call's own payload by default; the one permitted exception is a
   version-targeted branch citing a specific documented host fact (constraint 2) — never a dependence
   on the development host's own state:
   - **`direction` makes the grading split mechanically expressible** (Claude-review R2-2): `observing`
     for the known observing names (`read`, `grep`, `find`, `ls`, `glob`, `ast_grep`), `mutating`
     for the known mutating names (`write`, `edit`, `ast_edit`), `unknown` for everything else —
     with `kind: null` for an unknown tool, so the null branch hosts its deny-side grading and gray
     fall-through. An unknown tool is **never opaque and never mutating-by-shape**: whatever targets
     its payload yields go through the deny-side layers, otherwise it stays gray exactly as today
     (this makes the MCP name-prefix carve-out of revision 2 unnecessary). A shape-inferred
     `command` (e.g. `debug`'s DAP request) **never enters `classifyBash`**; step 3's consumers are
     scoped to known names. Disclosed as BREAKING: an unknown tool's extracted targets now hit the
     deny-side layers (user `deny`, the `denyPaths` ask) where today nothing grades them.
   - **Exemption ordering, stated once** (Claude-review R2-3): the `tools` exemption is checked **after
     the deny-side layers** (floor denies, user `deny`, the `denyPaths` ask, the `.omp` gate) and
     **before the opaque ask and the gray fall-through**. A listed tool carrying a protected-path
     target therefore faces the deterministic ask — the silent allow is gone; that is the disclosed
     BREAKING for listed tools.
   - **Shape-keyed extraction** from the input object itself: singular path-like fields (`path`,
     `_path`); plural path fields (`paths: string[]`); **patch text** — a string field
     (`input`/`_input`) is **always parsed, whether or not `path`/`paths` are present**. The
     grammar (Claude-review F3: omp's `edit` has five modes; the draft covered one) recognises:
     hashline file headers (`[PATH]`/`[PATH#TAG]`, legacy `¶PATH`; trim both ends, strip a trailing
     `#`+4-hex tag and matching quotes), op lines `MV DEST`, and the apply-patch lines
     `*** Add File:`, `*** Update File:`, `*** Delete File:` and `*** Move to:` — the move
     destination is a write and **the source stays a target** (the move deletes it there; Claude-review
     R2-5). Patch-mode `edits[].rename` values are also targets. A host-derived or model-supplied
     `path`/`paths` is added to the target set but **never makes a call non-opaque** — a payload in
     an unrecognized grammar (`sloppy`) stays opaque. A `code` field → kind `code`; a `command`
     field → kind `command`; a hashline-wrapped `path` value (`[path#TAG]`) is unwrapped first.
   - **List-splitting targets (Claude-review F6, a pre-existing bypass):** an observing tool's `path`
     is extracted as the whole string **plus each part** split on `;`, `,` and whitespace — omp's
     `read` splits such lists and opens each file separately while the gate grades the string as one
     in-cwd path (`read {path:"README.md;~/.bashrc"}` with `denyPaths` set is `allow/rule` today).
     Over-extraction is the safe direction on both sides.
   - **Self-contained grammar** (constraint 3): the header/op-line constants and their parser live in
     the plugin; the only imports are `node:` builtins; no host-internal module is read at runtime.
   - **Opaque rule** (Claude-review F1 supersedes the draft's R3 reading; narrowed by the 2026-10-05
     Claude re-review): `opaque` — deterministic **ask**, headless → deny — applies **only to the
     known mutating names (`write`, `edit`, `ast_edit`) with no extractable target**. An unknown
     tool is never opaque: whatever targets its payload yields go through the deny-side layers,
     otherwise it stays gray as today. The opaque ask exists to catch file writes whose target
     cannot be found — an unknown tool that names no file is not that case. This makes the MCP
     name-prefix exemption unnecessary, removes the BREAKING change for unlisted tools (omp's own
     `retain {content}` and any third-party tool with a content field keep today's gray), and stops
     relying on omp's `mcp__` naming.
   - **Field evidence (motivation and fixture source — not contract; design-time only, constraint 5):**
     verified 2026-10-05 against the omp 18.5.1 and pi 0.84.3 source trees; fixtures snapshot these
     observed payloads, cited file:line:
     - omp normalizes `edit` only (`tool-event-input.ts:69-91`): raw patch from `input`/`_input`;
       zero headers → unchanged; one → `{input, path, paths}`; **two or more → `{input, paths}` with
       no `path`** (the defect); `_path` promoted when `input` is absent (:87-88).
     - Hashline grammar (omp's `extractHashlinePaths` :48-66, `normalizeHashlineHeaderPath` :36-46):
       `[PATH#TAG]` header lines and legacy `¶PATH` lines; the path text is otherwise unrestricted
       (relative, `~`, absolute — resolved later by the host). omp's bracket constants live in a
       `@oh-my-pi/pi-tui` module that was not materialized in the inspected tree (values inferred
       `[`/`]` from three local sources) — which is exactly why constraint 3 applies: the adapter
       implements the grammar with its own constants, and the probe cases pin them.
     - Move destinations live in the patch text (`hashline-compact.md:17` `MV DEST`; apply-patch
       `*** Move to:` `edit/index.ts:133`); there is no MV tool on either host.
     - `write` may carry a hashline-wrapped `path` (`write.ts` approval/resolution via
       `unwrapHashlineHeaderPath`, `plan-mode-guard.ts:55-70`); `write = {path, content?}` (content
       optional), `read = {path}`; no derived fields for either.
     - `eval` = `{language: 'py' | 'js', code, title?, timeout?, reset?}` (`eval.ts:104-119`);
       `ast_edit` = `{ops: [{pat, out}], paths: string[]}` (`ast-edit.ts:40-52`); omp `glob` =
       `{path?, hidden?, gitignore?, limit?}` (`glob.ts:39-44`) — the pattern IS `path`.
     - pi 0.84.3 `edit` is single-file `{path, edits: [{oldText, newText}]}` (`edit.js:19-26`) — the
       multi-file silent-allow risk is observed on omp today, but the contract above is what closes
       it on every host, including hosts that do not exist yet.
2. **`classifyWrites(targets, cwd, floorOn)`** replaces the `classifyPath` call for write/edit tools:
   grade every target through the existing S-tiers (S0/S1/S3/S2, `kernelWalk` per target, the
   unresolved-write fail-closed branch per target); deny on the first tier hit; the in-cwd allowance
   fires only when at least one target exists and **every** target sits in-cwd. Single-target inputs
   behave bit-for-bit as today (`input.path` maps to a one-element target list) — the existing suites
   and probe cases must stay green unchanged.
3. **Consumer migration (same commit):** `userRuleTargets` collects the lexical + kernel forms of
   **every** read/write target of a **known** file/command tool — the user-allow loop and
   `allowAdmits` never see an unknown tool's shape-inferred fields (Claude-review R2-2; pin with a
   test: an unlisted tool whose `path`/`command` field matches a user allow regex stays gray).
   Deny = any, allow = every — semantics unchanged, more targets.
   `denyPathCandidates` returns all targets; the ask dialog names a multi-target edit (count + targets
   — dialog plaintext is local per ADR-0002; block reasons stay path-free); the transcript action line
   names the target set. **Layer 0 consumes the adapter too (Claude-review F7, today's gap):**
   `selfProtectCheck` additionally tests every adapter `writes`/`reads` target — an apply-patch
   `*** Update File: <agentDir>/config/pi-verdict.json` bypasses layer 0 today because it treats each
   whole input string as a path — and kind `code` runs layer 0's command-direction substring
   signatures over the code text (`eval` writing the gate's own files bypasses `bashPatterns`
   today). Probe/test cases pin both routes.
4. **Scope tools and pathless inputs (Claude-review F1/F5):** `toolAccess` carries `scope: boolean` —
   true for `grep`, `find`, `ls`, `glob`, `ast_grep` **and `ast_edit`** (their `path`/`paths`
   accept directories and globs; an omitted path means the workspace root/cwd — today's #48 shape):
   a pathless scope/read call yields the cwd as its effective target. **The `scope` flag drives
   `hitDenyPaths`/`hitOmpDir`** — the bidirectional subtree compare must not silently lose the new
   scope families (Claude-review F5: `ast_grep {path:"."}` and `ast_edit {paths:["."]}` would become
   `allow/rule` and skip any `denyPaths` base inside the project). **Precedence (Claude-review R2-4):**
   for a mutating scope tool, an omitted path never yields a cwd target — the call is opaque (ask);
   the cwd-as-effective-target rule applies to observing scope tools only. Probe case: `ast_edit`
   with no `paths` → `rule-ask`. A pathless `read`/scope call keeps today's grading (cwd →
   gray/allow); a pathless `write`/`edit` deliberately changes **silent in-cwd allow → deterministic
   ask** (the opaque rule) — disclosed as BREAKING.
5. **Ask provenance (Claude-review F14; the seam itself is Phase 0):** `classifyByRules` sets
   `askSource: "rule"` on the new asks and `adjudicate` maps it to
   `Verdict.source` — the seam's plumbing landed in Phase 0; the new asks (`rule`) ride it.
   `docs/layers.md` (the layer map the probe asserts) gains the new ask kinds, the README
   pipeline diagram gains the adapter, and CONTEXT.md gains the `tool-access adapter` + `opaque
   call` terms — all in this commit's docs sync (the commit that introduces them, Claude-review R2-8).
6. **ADR-0009** ("one model of what a tool call touches"): the adapter contract, the opaque-write
   fail-closed rule, why the host's derived fields are evidence and not authority, and the
   universal-plugin constraints it implements (shape-keyed extraction, self-contained grammar, the
   direction rule).
7. **Probe:** new family `tool-access` — (a) omp-shaped multi-header `edit` whose second header
   targets `~/.ssh/authorized_keys` → rule deny (S0 via the per-target grading), `kernelOpens` not
   applicable; (b) multi-header in-cwd edit → `allow`; (c) a pathless edit with no parseable header →
   the opaque ask (`rule-ask`); (d) `grep` with an omitted path and a declared base inside the cwd →
   `protected-path` (the #48 bidirectional subtree case, pinned at probe level for the first time);
   (e) an apply-patch multi-file payload (`*** Update File:` ×2, one targeting
   `~/.ssh/authorized_keys` — a tier-hitting path, so the deny is a floor hit) → rule deny
   (Claude-review F3); (f) an `Update File` + `Move to:` payload whose move target is in-cwd but the
   update target
   is not → rule deny — extraction of the move destination alone must not allow the call
   (Claude-review F3's consequence 1); (g) a `paths` spoof (`{input: "<apply_patch>", paths: ["src/a.ts"]}`) stays
   opaque/ask (Claude-review F3's consequence 2); (h) patch-mode `edit {edits:[{rename:"~/.bashrc"}]}` with
   `denyPaths` → `protected-path` (Claude-review F3's consequence 3); (i) `read {path:"README.md;~/.bashrc"}` with
   `denyPaths` → `protected-path` (Claude-review F6); (j) `ast_edit {paths:["."]}` with an in-cwd base →
   `protected-path` (Claude-review F5); (k) `ast_edit` with no `paths` → `rule-ask` (Claude-review R2-4).
   The runner feeds `{toolName, input}` verbatim, so the omp shapes need no
   new fixture machinery; the `rule-ask` layer machinery (enum, renderer, `assertLayer` support)
   landed in Phase 0 — this phase adds the cases and the run-A `degraded === true` assertion
   (Claude-review R2-6), documented in `probe/README.md`.
8. **omp-side approval semantics are answered from source**: one `edit` call applies EVERY header, and
   approval is ONE decision per tool call — `strictestApproval` across all payload paths and move
   destinations (`edit/index.ts:386-393`, `wrapper.ts:250`) — under `tools.approvalMode`, **default
   `yolo`** (`tools/settings.ts:312`, `tools/approval.ts:80`): a multi-file hashline edit is
   auto-approved by default. The gate's silent allow therefore composes with omp's default
   auto-approval — the writes simply happen, with no human and no model in the loop. The headless
   smoke test (AGENTS.md procedure adapted — `--tools read,bash,edit`, since the recorded command
   enables no `edit`; one two-header `edit` payload whose second header targets a file **inside the
   throwaway temp dir**, declared in the test config's `denyPaths` — never a real home path, which
   `yolo` would actually write if the gate were broken) stays as end-to-end confirmation of the
   gate-side verdict; record it in the execution record.
   (Citation namespaces: "Claude-review F*" are the findings of the 2026-10-05 Claude review
   (`.scratch/reviews/2026-10-05-tool-access-hardening-plan-review.md`); "Claude-review R2-*" are the
   plan-critic re-review of revision 2
   (`.scratch/reviews/2026-10-05-tool-access-hardening-plan-review-r2.md`); "PC-review F*" are the
   draft's own plan-critic pass, which lives in this session only. None of these lists is cited from
   tracked docs at execution time.)

## Phase 3 — tool families + session-start coverage report (item 4 + the policy-lint bullet; size S/M; commit 4)

1. The shape-keyed adapter already covers the extra families by payload — `eval`'s `code` field,
   `ast_edit`'s `paths`, `glob`/`ast_grep`'s `path`, a future tool's patch text — so no per-tool
   mapping is added. What remains is the `eval` semantics (Claude-review F4 corrects the draft, and
   its trace found a new silent allow: the starter `^ls\b` matches Python `ls = …`):
   - kind `code` (eval): user `deny` regexes, `denyPaths` extraction and the `.omp` word check apply;
     **user `allow` regexes never apply to kind `code`** — a code call always reaches the classifier
     unless something denies or asks first. `BASH_DANGER_RULES`, the tripwire and `allowAdmits` do
     not apply to the whole code text.
   - **The bash floor DOES apply to the extracted shell lines of `language: "py"` code** (F13
     corrects the draft's "floor is shell machinery" rationale): omp's Python eval translates `!cmd`
     into `__omp_shell(cmd)` and `%%bash` into a cell magic, so a Python cell can run shell
     commands. The command channel — danger regexes included — runs on the extracted `!`, `%sh`,
     `%%bash`/`%%sh` lines; not a regression (eval is gray today), recorded in ADR-0009.
   - Disclosed consequence: `eval` leaves the `tools` exemption family — its documented scope is
     `toolKind() === null` tools, so a user who listed `eval` there loses that exemption; marked
     **BREAKING** in the CHANGELOG entry.
2. **Coverage report at `session_start`** (:4172 insertion point), computed from schemas, not
   payloads (Claude-review F15: the adapter is payload-keyed and `session_start` has no payload): for
   each **active** tool (`getActiveTools()` — present on both hosts, `omp types.ts:1609`, pi
   `types.d.ts:978`) not in the user's `tools` list and outside the adapter's known names, inspect
   `parameters.properties` for `path`/`paths`/`input`/`_input`/`code`/`command`/`content` — kept in
   lockstep with the adapter's mutation triggers (Claude-review R2-14). Report once — as a
   debug-channel note, not noise — the tools whose schema exposes none of those fields (they will
   stay gray, classifier-only) and the tools whose fields the adapter cannot type. A future host tool
   then surfaces as a warning instead of a silent gap.
3. **Side-effecting `tools` warning:** when the user's `tools` list names a known side-effecting tool
   (the starter-list rationale already excludes persistent-memory tools: `learn`, `memory_edit`,
   `retain` — keep the set explicit in code), warn once at session_start. The consumer's choice stays
   the user's; the gate just stops being silent about it.
4. Tests: `eval` payloads under a user deny (denied via the code text) and — under the starter
   template — still classified (the `^ls\b` allow must NOT admit a Python cell; F4); a py code cell
   with a `!`-line matching a danger regex → floor deny (F13); the coverage-report and
   side-effecting-tool warnings.
5. Docs: README pipeline diagram (the eval/coverage change). (The `tool-access adapter` glossary
   term lands with Phase 2, which introduces it — Claude-review R2-8.)

## Phase 4 — transcript integrity: never elide the action (item 6a; size M; commit 5)

1. **First verify the jev decisions input limit** (OpenRouter alpha decisions endpoint and the
   TypeSafe systemone endpoint) — the raised caps must fit the backend that receives them. **From
   vendor documentation first; live probe calls only with the user's explicit go-ahead** (they need
   API keys, network and money, against the offline convention — Claude-review F17). Record the
   found limits in the execution record before changing anything. If a measured transport limit is
   below the new action cap, that transport's cap becomes `min(8192, limit)` with the same over-cap
   ask semantics — the classifier call must never be sent a payload beyond the measured limit
   (Claude-review R2-7 corrected the draft's miscite of this fallback).
2. The action line is exempt from `transcriptSafe`'s 1000-character line cap; it gets its own larger
   cap aligned with the floor's reading horizon (`BASH_MAX_MATCH_LEN` = 8192), **counted precisely**
   (Claude-review F8): toward the cap count the tool name, **every adapter target**, and the full
   `command` (bash/powershell) or `code` (eval); **not counted**: the write/patch content excerpt
   (step 3) and the JSON arguments of gray tools (truncated to a named constant alongside
   `EXCERPT_CHARS`, with an explicit marker — Claude-review R2-12). An over-cap action → a
   deterministic **ask** (headless → deny) **before** the classifier runs — **BREAKING for commands
   and code only**. The user `allow` check must never run before the over-cap check (today a simple
   command over 8192 chars can be rule-allowed while the floor read only its prefix — F8's ordering
   gap). No system-prompt line is added — a "truncated action means ask" instruction would be dead
   code for actions (they never reach the classifier over-cap) and would silently convert every
   session containing one long past line into classifier-ask pressure if aimed at past-line
   truncation markers (PC-review F4 — the draft's own plan-critic pass; dropped deliberately).
3. Write/edit actions include a **bounded content excerpt** — a fixed `EXCERPT_CHARS` window of the
   write `content` / the patch text, behind an explicit `[excerpt: N of M chars]` marker — so the
   classifier judges payload, not just path. The excerpt never counts toward the cap (Claude-review
   F8: the draft's "first N chars inside the action cap" contradicted the refuse-what-cannot-be-shown
   principle).
4. The danger floor's 8192 cap already grades only a prefix; verify (test) that a beyond-cap command
   never mechanical-allows on the unread tail — bash no-hit is gray today; pin it.
5. Docs + disclosure: `docs/configuration.md` (the caps, the over-cap ask semantics); CHANGELOG with
   **BREAKING** weight (Claude-review F18 extended to this phase: actions over 8192 chars move from
   classifier-adjudicable to a deterministic ask). The proposal's "past the floor's cap, mark the
   call gray with a floor incomplete reason" idea is **superseded** by the over-cap ask; the
   beyond-cap never-mechanically-allows behavior of step 4 stays pinned (Claude-review F8).

## Phase 5 — redact protected paths in the transcript (item 6b; size S/M; commit 6)

1. **Plumbing (Claude-review F10):** `buildTranscript(host, actionLine, redact)` takes a predicate
   built from `env.cwd` and the anchored `denyPaths` bases, and **every caller passes it** —
   `collectTranscriptParts` has neither cwd nor bases today (`:2237`), and its callers are the
   classifier paths **plus `explainGate`** (`:3324`), whose transcript also goes to a model
   provider. The predicate runs on the structured `block.arguments` **before** `toolCallLine`, and
   redacts on a structured hit **or** when the raw JSON of the arguments contains any base
   spelling: absolute, `~/`, `$HOME`/`${HOME}` (the tokeniser knows only `$HOME` — F10), or the
   home-relative tail (e.g. `.ssh/`); it also covers the fields of unknown tools (F10). It runs
   **before** `transcriptSafe` truncates (redact-then-truncate — a protected path cut at the
   600/400 boundary would otherwise evade every base form; the order is pinned by a test,
   PC-review F5a). Over-redaction is transcript-only and harmless; under-redaction is a leak, so
   the conservative direction is wholesale, and over-redaction is explicitly accepted. A redacted
   line becomes the fixed marker `<protected-path>` — exact text pinned in the test; a neutral
   privacy marker, not an injection framing (PC-review F9). **Recorded residual** (goes into the
   ADR-0002 amendment this commit lands, PC-review F5b): detection inherits the extractor's
   documented obfuscation holes (command substitution, base64, archiving — ADR-0002), so a
   protected path hidden behind `$(echo …)` is not redacted; the classifier's existence hint remains
   the backstop for those calls. User-message lines are deliberately not redacted — the user's own
   disclosure in their own message is theirs (recorded choice, PC-review F5c).
2. Pin with the proposal's test: approve a protected read, inspect the next classifier prompt — no
   base plaintext may appear, including across the truncation boundary. Add the EXPLAIN-GATE prompt
   test (Claude-review F10). Audit records stay local + full-fidelity (ADR-0002 boundary note).
3. The existence hint already tells the classifier protected paths exist; no prompt change needed.

## Phase 6 — policyDegraded (item 6c; size S; commit 7, ADR-0010)

1. **What sets it (Claude-review F11 — `reset()` alone misses the `/verdict` reload path
   (`:4347`), a load exception (`:1346-1354`), a trusted-project failure and skipped entries):**
   `LoadedRules` gains `degraded: boolean`, set on a user config **parse failure**, a **load
   exception**, a **trusted-project parse or shape failure**, or **any skipped `deny`/`denyPaths`
   entry**. `reloadRules` copies it to the session state (`reset()` keeps its own reset-list entry).
   While set:
   - **every model-originated allow becomes an ask** (headless → deny, unchanged): the first layer,
     the cascade's effective verdict and the subagent's second model — each such ask carries
     `askSource: "degraded-policy"` through the Phase 0 seam (Claude-review R2-9). The value is
     added to **`Verdict.source` and `AuditRecord.source` alongside `"rule"`**, named in the
     `presentVerdict` message templates, `docs/layers.md`, and the probe's `Layer` list;
   - the footer badge and every block reason name the degraded state;
   - the session-start warning stays the primary signal (it already fires).
   The built-in floor is intact under `EMPTY_RULES`, so denies are unaffected. The proposal's
   "suspend user `allow`/`tools`" is recorded as **moot for the parse case** (they are already
   empty) and **applied for the skipped-entry case** (F11). This closes the fail-open direction
   where a broken policy silently removes the user's declarations and classifier allows sail
   through; marked **BREAKING** (a fail-direction change, F18).
2. `/automode` status names the state. ADR-0010 records the fail-direction change for configuration
   errors (proposal: "changes the fail direction for configuration errors").
3. Docs: README pipeline diagram (the policyDegraded branch); AGENTS.md's fail-direction paragraph
   ("Config errors ⇒ empty rules … plus a notification") is rewritten; CONTEXT.md gains
   `policyDegraded`; `docs/configuration.md`'s stale overridable-keys list (F12, below) is fixed in
   Phase 1's docs sync, not here.

## Phase 7 — end-to-end adjudication deadline (item 7; size S/M; commit 8)

1. `adjudicate` gains one end-to-end deadline below the host's `tool_call` bound — pinned: omp
   `extensionHandlers.toolCallTimeoutMs`, default 30 000 ms, per handler call, invalid values fall
   back to 30 s, and time awaiting omp-owned dialogs does not count toward the bound
   (`extensibility/settings.ts:151-162`). **Adaptive budget**
   (Claude-review F9 corrects the draft's fixed 15 s/7 s/5 s split, which would roughly triple
   fail-closed denies on the documented gateway — its p90 is 19.8 s — and waste the reserve when no
   fallback exists): each attempt gets `min(per-attempt cap, deadline − now − reserve)`;
   **fallback time is reserved only when `classifierFallbackModel` is configured**; without one,
   attempt 1 keeps its full 25 s. Attempt 2 retries only after a **contract violation** — a timeout
   goes straight to the fallback (retrying a slow model inside a tight budget wastes the remainder).
   The plumbing exists: `callClassifierOnce` composes `AbortSignal.any([timeout, signal])`
   (`:2450-2460`) and `env.signal` is wired (`:4702`); omp's handler timeout counts active work only
   (dialogs pause it — `runner.ts:1806-1809`, `:192-238`), so an interactive ask does not eat the
   budget. Today's worst case is 25 + 25 + 15 + 15 s against a 30 s bound — the cascade the ADR-0004
   budget exists for cannot run on the path it exists for.
2. The measured p90 = 19.8 s means a tighter first-attempt cap false-denies more on slow models; the
   honest trade — a working cascade instead of a host-kill — is recorded in `docs/configuration.md`
   next to the 25 s history. Raising the host bound protects the **subagent ask path** only
   (cross-reference step 4); the cascade budget's only lever is the hardcoded constant.
3. Tests: the deadline fires before the host bound; a slow first layer still reaches the fallback;
   a timeout is never retried; with no fallback configured, attempt 1 keeps 25 s;
   `docs/configuration.md` sync (restating the measured trade-off). Marked **BREAKING** (the
   adjudication-timeout contract changes, F18).
4. Boundary (Claude-review F9): the deadline covers the root-session cascade path only. The subagent
   ask path (`resolveAskWithoutHuman` — second model plus the `subagentAskTimeoutMs` dialog wait)
   runs in the handler outside it and keeps its documented guidance: raise
   `extensionHandlers.toolCallTimeoutMs` to `subagentAskTimeoutMs + 60000` (`docs/configuration.md`
   already says so). The ~27 s budget is a **hardcoded constant**, not derived from the host's
   configured bound: the extension cannot reliably read that setting (capability unverified), and
   27 s sits below every sensible bound — raising the host bound helps the subagent path, not this
   one.

## Phase 8 — docs + supply-chain sync (item 8 residual; size S; commit 9)

1. **AGENTS.md staleness:** `gateOmpDir` default (off), `classifierFallbackMode` default (`enforce`),
   the removed shadow cache, and the ADR-0001-removal framing (ADR-0005 restored the layer) — the
   lint/biome and package-name points are already fixed (Phase 1 commit and `c7f9d2e`).
2. **ADR-0002**'s 2026-09-25 amendment gains its pointer to ADR-0005.
3. **`publish.yml`** still publishes `@frapetti-dev/pi-verdict`; the package is
   `@jonatsu/pi-verdict`. **Decision point (user):** fix the workflow's scope + registry block to
   `@jonatsu` (recommendation — it keeps the documented GitHub Packages install path true), or remove
   the workflow and switch the README's install section to the git-spec install. The v0.17.0 GitHub
   Release (TODO.md) must not be created before this is settled: with the current workflow a Release
   publication would target the old scope.
4. **README** install references + `~/.npmrc` scope example follow the same decision.
5. **Supply chain:** pin the GitHub Actions by commit SHA and pin the Bun version in both workflows
   (implementation reads the current `ci.yml`/`publish.yml` first).

## Delivery (nine commits; release held by default)

Approving this plan authorizes **exactly these commits** (Claude-review F17); anything beyond them
needs its own authorization.

1. `refactor(gate): ask-source seam — RuleResult.askSource → Verdict.source (no behavior change)`
   — verified by Phase 0's own step 4 (suites + probe unchanged + the throwaway check), not by
   failing-before tests.
2. `feat(rules): project overrides narrow by direction (item 3)` — BREAKING note.
3. `feat(gate): tool-access adapter — multi-file edit fails closed (item 1, ADR-0009)`.
4. `feat(gate): eval semantics + session-start tool coverage report (item 4)`.
5. `feat(classifier): transcript integrity — never elide the action (item 6a)`.
6. `feat(classifier): redact protected paths in the transcript (item 6b)`.
7. `feat(gate): policyDegraded — broken policy fail-closed (item 6c, ADR-0010)`.
8. `feat(gate): end-to-end adjudication deadline (item 7)`.
9. `docs: sync AGENTS/ADR pointers + supply chain (item 8 residual)`.

No version bump, no tag, no push by default — `v0.17.0` shipped today; the user owns the next release
decision. Every behavior-changing commit (2–9) carries its failing-before regression tests
(temp-copy proven), its CHANGELOG entry,
its docs sync, and regenerated `docs/coverage.md`; CONTEXT.md's glossary gains each new term
(`tool-access adapter`, `opaque call`, ask provenance, `policyDegraded`) in the commit that
introduces it.

## Interaction with the allow-operands plan

`docs/plans/allow-operands-and-floor-gaps.md` (a sibling round, independent of this one) amends
ADR-0008 and changes the same user allow loop: `allowAdmits(command)` becomes
`allowAdmits(command, cwd)` with operand grading. Whichever round lands second rebases onto the
other — there is no logical conflict (operand grading is orthogonal to this plan's target
extraction). Follow-up recorded there: once this plan's adapter exists, operand extraction could
read bash operands from it instead of from `bashPathTokens`.

**Ordering rule for that plan's fast path (2026-10-05 Claude re-review, minor 3):** its built-in
fast-path admission sits at the same pipeline point as the user allow loop, so it inherits the same
ordering constraint this plan imposes on user allows — **the over-cap "too long to judge" check
must run before any allow path, built-in or user**; an over-cap command is never fast-path-allowed.
Record it in that plan when the two rounds land.

## Shared verification set (every commit)

`bun run typecheck`; `mise exec -- biome ci .`; `bun test` (expect only additions to pass counts);
`bun run probe` (existing 79 cases must never regress; new families add cases);
`bun run coverage && git diff --exit-code docs/coverage.md`. **Failing-before** is proven per new
test against a temp copy of `git show HEAD:extensions/pi-verdict.ts` (worktree copy + pointed
imports), never by stashing the shared working tree (Claude-review F19). Never put a dangerous
literal on a command line (concatenate in test files; use `bun test -t` / probe filters). Stage
explicit paths; never `git add -A`/`.`. Sequential-thinking MCP is mandatory for design decisions
during execution. Phases 4, 6 and 7 all edit `adjudicate` — expect textual conflicts between their
commits (rebase discipline), no logical ones.

## Disposition of proposal items

| Proposal item | Where addressed |
|---|---|
| 1 multi-file omp edit silent allow | Phase 2 (adapter + classifyWrites + opaque-write ask; ADR-0009); its "Unverified: does omp perform the second write without its own approval" — answered: `yolo` default auto-approves (Phase 2 step 8) |
| 2 user allow matches raw command text | **done** — commit `a3c7071` (`allowAdmits`, ADR-0008, probe user-allow family) |
| 3 trusted override can widen the gate | Phase 1 (direction table; ADR-0006 amendment) |
| 4 tools outside pi's eight names skip declarations | Phase 3 (shape-keyed coverage by payload + `getActiveTools` report) |
| 5 floor monotone instead of tokeniser-dependent | **core done** — commit `7ad1014` (tripwire + sound-gated word view, ADR-0007); residual lexer consolidation deferred with the path service |
| 6a truncated actions / protected-path leakage / broken policy | Phase 4 (over-cap ask, precise cap counting — superseding the proposal's gray-mark idea; the beyond-cap no-allow pin stays), Phase 5, Phase 6 respectively |
| 7 timeout budget | Phase 7 (adaptive budget) |
| 8 path service / file split / supply chain / stale AGENTS.md / policy lint | Phase 8 (docs + supply chain) and the policy-lint bullet in Phase 3; **path service and file split deferred** (below) |

## Deferred (recorded, not scheduled)

- **One path-resolution service** (`resolveTarget(raw, cwd)` returning every tier once): the
  kernel-true walk consolidation already landed (`kernelWalk` feeds `classifyPath`, the protected-path
  helpers, `denyPathForms` and `userRuleTargets`); a full re-unification re-touches layers that just
  stabilized, for no behavioral gap. Revisit after this round.
- **Splitting the 4,788-line file:** size L; whether omp's loader follows pi's every-`.ts`-file rule
  for subdirectory extensions is unverified; provenance must hash the whole `files` list. Land only
  along the seams above, in its own round, after the loader question is settled.
- **A bash AST library:** rejected by the proposal itself (precision, not soundness; measured to
  absorb zero gray calls; breaks zero-dependency packaging). Revisit only if tripwire false positives
  become the main complaint.

## Decision points

The 2026-10-05 Claude review left nine decisions with recommended defaults (its "Decisions for the
user" list). **This revision adopts every recommended default**; any of them is reversible at your
review, before execution:

1. **An opaque ask applies only to the known mutating names (`write`, `edit`, `ast_edit`) with no
   extractable target; every unknown tool stays gray** (Claude-review F1, refined by
   R2-1/R2-2/R2-3, narrowed by the 2026-10-05 re-review) — the opaque ask exists to catch a file
   write whose target can't be found, which an unknown tool naming no file is not; the MCP/`task`
   carve-out of revision 2 is therefore unnecessary, and the BREAKING change for unlisted tools
   (e.g. omp's own `retain`) is gone.
2. **User `allow` regexes never apply to `eval` code** (Claude-review F4) — deny-side layers only.
3. **Over-cap ask scope: commands and code only** (Claude-review F8) — write/patch content and
   gray-tool JSON arguments are excerpted behind a marker.
4. **Phase 7 budget: adaptive** (Claude-review F9) — attempt 1 keeps its full time when no fallback
   is configured; a timeout is never retried.
5. **`policyDegraded` triggers: user parse failure, load exception, trusted-project failure, skipped
   `deny`/`denyPaths` entry** (Claude-review F11).
6. **`notifyAllows` from a project: only `true`** (Claude-review F12).
7. **omp's `;`-delimited paths: fixed in Phase 2, not deferred** (Claude-review F6).
8. **`publish.yml`: fix the scope to `@jonatsu`** (Phase 8.3) — blocks the v0.17.0 GitHub Release
   (TODO.md) either way; fix-vs-remove remains yours to overrule.
9. **Phase 4.1's jev limits: vendor documentation first; live calls only with your go-ahead**
   (Claude-review F17).

And the standing scope decision: the nine phases above are the recommendation; you may strike phases
(the proposal marks items 1/3 critical+important, 4/6 important, 7/8 suggested) — the plan is
executable in any prefix order that respects the dependencies: 0 first, then 2 → 3, 2 → 4,
5 depends on 2; the rest are independent (Claude-review F2: Phase 4 builds on Phase 2's patch
parsing and reworks the same action-line seam).

## Disposition of review findings

**Claude review (2026-10-05, F1–F19):** all 19 applied. Blockers — F1 (opaque only for mutating
calls; MCP/`task` never ask), F2 (unknown-tool targets deny-side only; the `tools` exemption survives
them), F3 (full grammar: apply_patch lines, `edits[].rename`, sloppy opaque; 4 probe cases), F4
(user allow never on code; the contradicting test text fixed) — reworked Phase 2's contract.
Majors — F5 (scope drives the bidirectional compare), F6 (`;`-list splitting, fixed not deferred),
F7 (layer 0 consumes the adapter), F8 (precise cap counting + the allow/cap ordering), F9 (adaptive
budget), F10 (redaction plumbing incl. EXPLAIN-GATE + raw-JSON spelling coverage), F11
(`LoadedRules.degraded` on four triggers). Minors — F12 (effective compare, timer cap,
notifyAllows-true-only, stale docs), F13 (bash floor on py shell lines), F14 (the Phase 0 seam
commit), F15 (schema-keyed report via `getActiveTools`), F16 (smoke payload to a throwaway dir),
F17 (vendor-docs-first; commits = the approved list), F18 (BREAKING disclosure extended; commit 4
retitled), F19 (citations fixed; failing-before via temp copy).

**Plan-critic re-review of revision 2 (R2-1–R2-14):** all 14 applied. Material — R2-1 (the MCP/`task`
carve-out; narrowed further by the 2026-10-05 short re-review: opaque now applies only to the known
mutating names, so the carve-out itself became unnecessary), R2-2 (`direction` in the contract;
consumers scoped; `classifyBash` closed to unknown tools), R2-3 (exemption ordering stated once),
R2-4 (mutating-scope precedence + probe (k)). Minors —
R2-5 (move source stays a target), R2-6 (probe machinery lives in Phase 0), R2-7 (citation
namespaces + miscites + eval range), R2-8 (glossary terms in Phase 2), R2-9 (askSource contract for
every producer + the unset mapping), R2-10 (delivery sentence scoped), R2-11 (host-bound advice
reworded), R2-12 (gray-tool truncation constant), R2-13 (probe (e) uses a tier-hitting target),
R2-14 (`content` in the report's field list).

## Open questions (each has an owner and a settle point)

1. ~~Does omp apply its own approval per written file?~~ — answered from source (Phase 2 step 8): one
   approval per call, strictest across targets; default `tools.approvalMode: "yolo"` auto-approves a
   multi-file edit. The smoke test confirms the gate-side verdict end to end.
2. jev decisions input limits (both transports) — from vendor documentation first; live probe calls
   only with the user's explicit go-ahead (Phase 4 step 1, decision 9).
3. ~~`getAllTools()` availability~~ — answered: present on both hosts (`omp types.ts:1611`, pi
   `types.d.ts:980`), `getAllTools(): ToolInfo[]`.
4. ~~Exact tool-input shapes~~ — answered; the fixture table cites the sources inline (Phase 2). The
   one medium-confidence item is the exact `HL_FILE_PREFIX`/`HL_FILE_SUFFIX` constant values
   (inferred `[`/`]` from three local sources; the constants module is not materialized in this
   install) — the probe cases pin the grammar the adapter ships.

## Round outcome (appended at execution close)

Not yet written — the plan is a draft pending user approval.