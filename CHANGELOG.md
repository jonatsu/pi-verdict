# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/lang/zh-CN/).

## [Unreleased]

Fork changes on top of `v0.16.0` (frapetti-dev), for the omp deployment. Diff range `frapetti/main..v0.16.0-fork.3`.

### Added

- **Self-protection layer restored** (ADR-0005): pipeline layer 0, a hard, config-exempt deny over the gate's own files — `<agentDir>/config/pi-verdict.json`, `<agentDir>/config/pi-verdict-trust.json`, the installed extension copy (when `import.meta.url` sits under a recognized install root; dev checkouts are not protected) and `<agentDir>/verdicts/`; the audit directory additionally denies reads (raw model output must not reach agent context). `builtinDenyFloor: false`, user `allow` rules and `autoDeny: false` cannot lift it. Deliberately **snapshot-free** — no in-memory tamper baseline, so concurrent sessions never revert one another's legitimate edits. Bash-side matching is substring and obfuscatable (ADR-0001 caveat).
- `ignoreTools` accepted as a deprecated alias for `tools`, merged and deduplicated with a one-shot warning, so an unmigrated policy keeps its exemption (`#pi-verdict local patch`).
- Reads of the project trust store are denied (R6), alongside the audit dir.
- Built-in S0 gains the dotless XDG credential homes (fork): `~/.config/gnupg`, `~/.config/age` and `~/.config/sops` now hard-deny on read and write like `~/.ssh/**`. A GnuPG home at `~/.config/gnupg` (the XDG default; `~/.gnupg` need not exist), an unlocked age private key at `~/.config/age/key.txt` and the SOPS age key under `~/.config/sops` previously sat outside the floor, while only the dot forms (`~/.gnupg`) were covered; with these three the built-in floor alone covers what the deployment had declared as `denyPaths` asks, so the overlapping policy rules can be dropped instead of stacked. Pinned by the `S0 credential inventory` tests.
- Host contract documented (R2, [`docs/host-contract.md`](docs/host-contract.md)): the extensions' bare host imports (`@earendil-works/pi-ai`, its `/compat` subpath, `pi-coding-agent`, `pi-tui`) are declared as optional peers and devDependencies, and omp's `legacy-pi-compat` resolution path is recorded.

### Changed

- **BREAKING**: `gateOmpDir` default flipped `true` → `false` (ADR-0006). The forced `.omp` terminal ask broke ordinary `.omp` work and could not be allowed by rule; the self-protection layer carries the protection. The footer no longer renders a `.omp gate off` warning badge; it now flags `subagent off` as the fail-open deviation, and shows `subagent auto` as an info badge.
- **BREAKING**: `subagentGate` default raised `"off"` → `"normal"` (ADR-0006). `"off"` returned from the `tool_call` hook before `adjudicate`, so every subagent tool call skipped the rule layer, the floor and the classifier; `"normal"` adjudicates subagent calls and routes their asks to the root UI.
- `classifierFallbackMode` default flipped `"shadow"` → `"enforce"`, matching upstream (`8bcd08a`); a shadow-mode fallback may no longer resolve a subagent ask without a human — the `autoResolve: "allow"` shortcut now requires `enforce` (ADR-0004 amendment, ADR-0006).
- Project-config overrides are restricted to an explicit allowlist (ADR-0006): `classifierModel`, `explainGateModel`, `explainGatePrompt`, the free-text `rules` and `toggleShortcut` are user-only, ignored with a warning; the trust prompt now names the overridable set. Project trust is bound to a sha256 of the approved override content, so a trusted root whose override changes re-prompts instead of applying silently (TOCTOU guard); legacy trust entries without a hash re-prompt once.
- `loadUserRules`' outer catch now surfaces an unexpected failure through the warning channel instead of returning empty rules silently.
- Ported upstream hardening: linear `denyPaths` bash token extraction (`bb05e33`, no 8192-char cap) and the macOS per-user temp-tree S1 exemption (`bb6922a`, `/var/folders/...` reads no longer gray, writes no longer denied).
- Ported upstream cascade semantics (`0d87e99`, `1c06365`): the ask-relaxation carve-out covers a demoted `ask` as well as a demoted `deny`; enforce fail-closed rescue rows carry the applied ruling at the top-level audit verdict (source stays `fail-closed`); the `degraded` flag marks only genuine ask-degradation on the early fail-closed path.
- Rich approve dialog: `DynamicBorder`, `keyHint` and `rawKeyHint` are no longer destructured from the host namespace (omp 18.5 does not export them there, which silently degraded every ask to a plain confirm with no code preview, no jev bar and EXPLAIN-GATE unreachable); local theme-aware substitutes keep the rich dialog working on pi and omp.
- jev adapter: corrected the stale header/doc claim that omp has no `registerProvider`, and dropped the ignored third `registerProvider` argument.
- Tooling: Biome (lint + formatter + import sorting) pinned via `mise.toml`/`mise.lock`, with `bun run lint` / `bun run format` scripts; formatting is applied across `extensions/` and `tests/` and CI runs `biome ci .`, so lint, format and import order are enforced by one command.
- Self-protection keys on the call's inputs, not a switch over tool names (R3): every string value in the tool input is resolved and tested for a protected path, so `ast_edit`, an MCP filesystem tool or a later-added name gets the same hard deny; the tool name only selects write/read/command direction, and an unenumerated tool is treated as a write.
- The read-deny is ancestry-aware and closes the bash/directory routes (R4): `grep`/`find`/`ls` over `<agentDir>` deny rather than ask, and `cd`/`pushd` targets are resolved so `cd <agentDir> && cat verdicts/*.jsonl` is caught; the honest residual (command text built at runtime) is recorded in ADR-0005.
- The gate's enablement surface is write-protected (R5): the plugin workspace `omp-plugins.lock.json`/`package.json` and any project `.omp`/`.pi` `plugin-overrides.json` — which can disable the gate for later sessions with no verdict.
- **BREAKING**: project overrides narrow only (R7) — `deny`/`denyPaths` union with the user's, `allow`/`tools`/`ignoreTools` intersect, `builtinDenyFloor` may only be set `true`, and `autoDeny`/`audit`/`classifierMinConfidence`/`classifierFallbackModel` leave the overridable set; the trust prompt states the project cannot widen the gate.
- `task` removed from the starter `tools` allowlist (R8): it spawns a subagent, so the exemption was a fail-open relative to the subagent gate; `checkpoint`/`rewind` stay (in-memory session context only).
- Unknown keys in the user config now warn (R9) instead of silently dropping a protection.

### Removed

- **BREAKING**: the shadow cache (dual-key LRU probe, `/automode` stats line, debug annotation, audit `shadow` field) — upstream retired it in `0.12.0` after measurements put its would-be hit rate near 3%; it never changed a verdict.

### Fixed

- `git-push-force` denied `git push --force-with-lease` (fork): `--force\b` has its word boundary before the hyphen, so it also matched the longer flag — the safe spelling of the operation the rule exists to refuse was hard-denied. The pattern now anchors on `(^|[\s;&|])git\s+push` and matches `--force(?![-\w])`, which accepts the bare flag only (`-f` is unchanged; in `--force` its next character is a word character). `git push --force-with-lease origin main` and `git push --force-with-lease=main origin main` reach the classifier; `git push --force origin main` and `git push -f origin main` stay floor denies, pinned by the `git push force-flag precision` tests.

## [0.16.0] - 2026-10-02

### Added

- Footer status redesign and `footer` config key (`"full"` default | `"compact"` | `"off"`; editable from `/verdict`, project-overridable, invalid values warn and fall back to `"full"`): the footer used to show only `auto mode on`/`auto mode off`. `"full"` now renders Nerd Font powerline blocks — gate state, risky settings (`floor off`, `.omp gate off`), the classifier model (`↺` inherited session model, `⚠ ↺` configured model unavailable so the session model is used, `↳ <id>·shadow|enforce` fallback model), per-session verdict counters (final pipeline verdicts of root-session calls; reset by `SessionState.reset()`, kept across `/verdict` saves; subagent calls and calls while the master switch is off are not counted), and info badges (`≥N%`, `autoDeny off`, `subagent normal|auto`); `"compact"` is one plain text line without counters, also used when the host theme lacks `bg`/`getBgAnsi` (e.g. omp). The footer refreshes after every adjudicated tool call, on `/verdict` saves and on `model_select`, and never contains command or path text (ADR-0002). Pure renderer exported as `renderFooter`.
- Live classifier status: while a gray-zone model call runs (the primary classifier or the `classifierFallbackModel` cascade), the `tool_call` handler shows one widget row above the editor (`ui.setWidget("verdict", …)`, e.g. `🛡️ verdict: classifying bash via <model>…`) and clears it before the verdict is presented, so it never sits next to the confirm dialog; the text is phase + tool name + model id only (never command or path text, ADR-0002), rule-layer verdicts show nothing, root sessions with a UI only (subagent and headless calls never set it), always on with no config key; the pipeline exposes it as the UI-free `AdjudicateEnv.onPhase` hook.
- Ask dialog mouse clicks: the rich approve dialog now handles left-clicks when the host forwards SGR mouse input (`ESC [ < b ; x ; y M`) to the focused component — a click highlights an option row, a second click on the same row confirms it, but only if that row was highlighted by the immediately preceding mouse click (the initial `Yes` highlight and keyboard moves never arm a confirm, so allowing always takes two clicks on `Yes`). Releases, motion, wheel, non-left buttons, legacy X10 mouse sequences, and clicks outside the option rows are ignored; the row is mapped from the host's `children`/`terminal.rows`/`viewportTop` and clicks are ignored when the host exposes none. The dialog never enables terminal mouse tracking itself, and the key-hint line is unchanged: pi 0.84.3 consumes mouse events before components, so this takes effect only on hosts that forward them.

### Fixed

- Windows path matching: the path sensitivity floor (S0–S3) and the in-cwd write allowance now match against a POSIX-form spelling of every canonical path form (backslashes → `/`, drive letter dropped), so `C:\proj\.ssh\id_rsa`, `C:\proj\.git\hooks\x`, and `~\.npmrc` hit their S-rules instead of silently passing the floor; the in-cwd base is now `path.resolve`d before dual-form expansion. User `allow`/`deny` regexes see the same POSIX form for file-tool path targets on win32 (a `^/proj/` rule matches `C:\proj\a.ts`), and bash command strings have backslashes unified to `/` before denyPaths token extraction so `cat C:\dir\file` is extracted. POSIX hosts are unchanged. The `read via project-local symlink to /etc` test is skipped on win32 (no `/etc` to link to).

## [0.15.0] - 2026-10-02

### Added

- Rich approve dialog: a thin blue confidence bar under the jev allow/ask/deny bar fills to jev's `confidence` and marks the `classifierMinConfidence` floor with a `┃` tick (no tick when the floor is `null`); the legend reads `confidence N% · min M%`. `renderJevBar` now takes `minConfidence` as its second argument and returns three lines.

## [0.14.0] - 2026-10-02

### Added

- Subagent gate (omp only; pi behavior is unchanged): omp runs subagents in-process with no UI, so every `ask` inside a subagent used to degrade to deny. New config keys `subagentGate` (`"off"` default | `"normal"` | `"auto"`) and `subagentAskTimeoutMs` (positive integer ms, default `60000`) route subagent asks to the root session's UI. `"normal"` shows the usual confirmation dialog on the root UI, prefixed with a `[subagent <id> (<name>)]` label; if nobody answers before `subagentAskTimeoutMs` (counted from enqueue, queue wait included) or the root has no UI, the ask is resolved without a human. `"auto"` never prompts and always resolves without a human. `"off"` (the default) makes the gate inert in subagents: **no rule, floor or classifier check runs on a subagent's tool calls** — opt in with `"normal"` or `"auto"` to gate them. Resolving without a human consults `classifierFallbackModel` only for asks the classifier raised, and only an explicit `allow` from it permits the call — anything else denies, with block tag `subagent-auto`; protected-path / `.omp` asks and asks that exist only because of `autoDeny: false` always deny (ADR-0002: no path plaintext reaches notifications or the agent), and a demoted first-layer deny is never auto-allowed (ADR-0004). A cancelled subagent run closes its pending root dialog and blocks with `subagent-cancelled` without consulting the second model. Root dialogs are now serialized process-wide (omp queues `confirm` but not `custom`). With `audit: true`, subagent asks record `subagent: { id, name, resolution: "human" | "timeout" | "auto" }`, and second-model resolutions record `fallback.triggeredBy: "subagent-ask"`. Set omp's `extensionHandlers.toolCallTimeoutMs` to at least `subagentAskTimeoutMs + 60000` — a subagent waiting on the root UI does not pause its handler budget.

- The first-run config template pre-fills a starter `tools` allowlist (`ask`, `todo`, `wait`, `task`, `yield`, `think`, `checkpoint`, `rewind`, `recall`, `reflect`): omp tools with no side effect of their own, or whose effects are gated elsewhere, skip the classifier from the first session after the initial run. Tools that read paths outside the file-tool family (`glob`, `ast_grep`, `lsp`), send data off-machine (`web_search`), persist memory, execute code or mutate state are deliberately left out. A pre-filled user declaration, not a built-in allowlist; existing configs are never rewritten.
- `gateOmpDir` (default `true`): **forced `.omp` gate**. Any file-tool path or bash command that touches a `.omp` directory (path segment `.omp`, matched on the lexical and symlink-resolved forms; bash also matches `.omp` as a bare word, e.g. `cd .omp`) is a terminal ask — non-interactive sessions degrade to deny. Pipeline position: after the built-in floor and user `deny`, before `denyPaths` and user `allow` (an `allow` regex cannot skip it). The ask reason carries no path (UI-only detail). `grep`/`find`/`ls` are checked on their own target only. Set `false` to disable; `/verdict` now has a `gateOmpDir` on/off switch (project files can also unset it to inherit the global value).
- `/verdict [user|local]` command: edit the list keys of `pi-verdict.json` (`allow`, `deny`, `denyPaths`, `tools`, `rules`) from the TUI — add, edit, and remove entries. `user` targets `<agentDir>/config/pi-verdict.json`, `local` the project config (`<project>/.pi/pi-verdict.json`, `.omp/…` on omp); a bare call asks which. Regex entries (`allow`/`deny`) are validated before saving. Each save rewrites only the edited key (other keys, key order, and `_hint` are preserved), reloads the rules into the running session immediately without clearing shadow-cache or fallback session stats, and never auto-trusts a project. The first project-level edit of a key offers to start from a copy of the global list (a project list replaces, not extends, the global one); `× Unset` removes the override so the project inherits the global list again. Other scalar keys (`builtinDenyFloor`, `classifierModel`, `toggleShortcut`, …) are out of scope. Requires an interactive UI.
- Rich approve dialog in the interactive TUI: the code under review (bash `command`, write `content`, edit `newText` blocks) is rendered with the chat's Markdown renderer as a syntax-highlighted fenced block (capped at 40 lines / 4000 characters; control and bidi characters shown as `\uXXXX` escapes). When the ask comes straight from jev, a colored bar graphs its allow/ask/deny distribution with a confidence legend, plus a `concern:` line. RPC mode and hosts without `ui.custom` keep the plain-text confirm unchanged.
- jev backend: each decisions request now also carries a typed `concern` question (deletion, write outside the project, network, package install, environment change, credentials, untrusted code execution, other, none); the answer is appended to the reason as ` — concern: <label>` (cosmetic — a missing or malformed answer is ignored, only the verdict stays fail-closed).
- **EXPLAIN-GATE role** and two new options on the interactive ask dialog (rich TUI dialog only; RPC mode and hosts without `ui.custom` keep the plain Yes/No confirm unchanged). **Explain…** takes an optional free-text question and calls the EXPLAIN-GATE role — a model call (session model by default) whose system prompt is fixed and whose default task is `Explain what this action does and why the gate held it for confirmation.`; a non-empty question replaces the default task. The model sees the transcript (same sanitized window as the classifier), the full code under review and the gate's stated reason; its answer is rendered in the re-opened dialog, labelled advisory, and never reaches the agent, the verdict, the audit log or the classifier. It can be asked repeatedly before deciding. **No, with explanation…** declines and forwards the user's text (single line, sanitized, ≤1000 characters) to the agent in the block reason (`user declined, saying: "…"`); plain **No** and Escape are unchanged, and Escape in either follow-up prompt returns to the dialog. Explain is not offered for protected-path asks (`denyPaths` hits and the `.omp` gate): their path plaintext is UI-only and must not reach a model provider (ADR-0002); **No, with explanation…** is available there. New config keys `explainGateModel` (`provider/id[:thinking]`, default: session model; unavailable → session model with a one-time warning) and `explainGatePrompt` (replaces the default task); both can be set per project.

### Changed

- **BREAKING**: `trustedProjects` in `pi-verdict.json` is replaced by an interactive project trust prompt plus a gate-owned trust file, `<agentDir>/config/pi-verdict-trust.json` (`{ "trusted": [...], "untrusted": [...] }`). A project config (`<dir>/.pi/pi-verdict.json`, `.omp/…` on omp) is applied only when its project root is trusted; an interactive session starting in an undecided project asks **Trust** / **Not now** / **Never**. Headless sessions and subagents never prompt and ignore undecided project configs. Existing `trustedProjects` entries are no longer read, so affected projects prompt once.

### Fixed

- jev adapter on pi 0.84: host detection no longer relies on `registerProvider.length` (pi's wrapper is now `(providerOrName, config)`, arity 2, so pi was routed into the omp registration branch and every jev classifier call failed closed with `No API provider registered for api: jev-decisions`). omp is now recognized by its API object carrying `logger` and `typebox`; behavior on omp is unchanged.

## [0.13.0] - 2026-09-25

### Removed

- `README.zh-CN.md` (Simplified Chinese README) and its language-switch link in `README.md`; `README.md` is the only README and is no longer published under `files`.
- **BREAKING**: Self-protection layer (ADR-0001, superseded — see its final revision): the rule-layer hard deny on agent writes to `<agentDir>/config/pi-verdict.json` and the installed extension copies is gone, along with the `#54` verdicts audit directory's read/write blocking that shared the same module. Agent-initiated writes to the gate's own files and to `<agentDir>/verdicts/` are now graded like any other path, by the ordinary rule layer and classifier — no special exemption and no special block. Removal followed the 2026-09-24 removal of the layer's runtime tamper-detection backstop, which had already narrowed the layer's real guarantee to "blocks writes made through a tool call" (a direct rewrite of the installed file outside any tool call was already unaffected). Users who want these paths protected can declare them via `denyPaths` (ask-terminal, not hard deny). `trustedProjects` project-override config loading is unaffected; only the write-protection wiring on its candidate files is gone.

### Fixed

- README / README.zh-CN.md install instructions: `pi install`/`omp plugin install` now reference the scoped `@frapetti-dev/pi-verdict` package, and note that GitHub Packages requires an authenticated npm client (`.npmrc` scope mapping + a `read:packages` token) even for public packages, unlike npmjs.com.

## [0.12.1] - 2026-09-25

### Changed

- Package renamed to `@frapetti-dev/pi-verdict` and publish target switched from the npm registry to the GitHub Package Registry (`npm.pkg.github.com`), authenticated via the workflow's own `GITHUB_TOKEN` instead of npm trusted publishing. The npm package name `pi-verdict` is owned by a separate, unrelated account (upstream `jesset/pi-verdict`); this repository is not a fork of it and has no publish rights there, which made every release fail at the `npm publish` step (`404` on `PUT .../pi-verdict`). `repository`/`homepage`/`bugs` in `package.json` now point at this repository.
- `v0.12.0`'s tag is protected and could not be moved to carry this fix, so it ships as `v0.12.1` instead; `v0.12.0` remains tagged but was never actually published anywhere.

## [0.12.0] - 2026-09-25

### Added

- `autoDeny` config key (default `true`): `false` converts every auto-review deny (danger floor, `deny` rules, classifier deny, fail-closed) into an interactive confirmation; the self-protection layer stays a hard deny and non-interactive sessions still deny. The confirm dialog labels the source (`Rule` / `Fail-closed` / `Classifier opinion`).
- `rules` config key (default `[]`): user-authored free-text rules appended to the classifier system prompt and forwarded to the jev decisions adapter as extra verdict instructions; applicable rules take precedence over default criteria.
- `trustedProjects` config key (default `[]`): lists project roots allowed to override the global config per-session. A trusted root's `<root>/.pi/pi-verdict.json` (`.omp/…` on omp) is discovered by walking up from cwd and shallow-merged over the global config (all keys except `trustedProjects`/`toggleShortcut`); both the candidate and resolved project files join the self-protection write-deny set for the session, and untrusted project files are ignored with a skip warning.
- `tools` config key (default `[]`): exact tool-name allowlist for the MCP/custom family (`toolKind() === null`, e.g. `ask`, `propose_commit`, `propose_changelog`, `todo`) — a case-sensitive exact match on the tool's registered name bypasses the classifier and returns allow directly for that family. Does not touch the self-protection layer, the built-in floor, or `denyPaths` (none of those cover this family either). Empty (default) leaves the family fully classifier-routed, unchanged from before.

### Removed

- Runtime change-detection backstop (ADR-0001 §4, `IntegrityWatch`): the session-start snapshot + per-verdict re-verification that auto-restored a tampered extension copy or asked to keep/restore a changed config is gone. A shared installed copy across concurrent sessions made the in-memory snapshot revert a legitimate manual edit made by another session and permanently fail-close a session that never touched the file — the hard write-deny (agent writes to the gate's own files always deny; ADR-0001 §1–3) remains and is unaffected. See the ADR-0001 amendment for the full rationale.

### Fixed

- oh-my-pi 18.3.0 compatibility: agentDir self-anchoring normalizes Windows backslash paths before matching (the gate no longer falls back to `~/.pi/agent` on Windows); the compat completion bridge forwards credentials from `modelRegistry.getApiKeyAndHeaders` (fixes `MissingApiKeyError` on OAuth-backed sessions); the jev adapter registers through omp's `registerProvider(name, config, sourceId)` signature (arity-detected) without `createProvider`, and jev classifier calls on omp go directly through `streamDecisions`.
- `@earendil-works/pi-ai` `0.84.3` type shape drift (CI typecheck): `createJevProvider` builds `getModels()`/top-level `stream`/`streamSimple` per the current `Provider` interface (no more `models`/`api` wrapper fields); `completeForClassifier`'s direct `streamDecisions()` path narrows the `AssistantMessage` result to the `CompletionFn` text-content contract. Removed stale `watchBases`/tamper-detection test coverage left over from the runtime change-detection backstop removal above (tests never updated when the feature was dropped).

## [0.11.0] - 2026-09-21

### Changed

- Confidence floor semantics (#67, [ADR-0004 amendment](docs/adr/0004-classifier-fallback-cascade.md)): the cascade gate becomes an **autonomy floor**. `classifierFallbackConfidence` is renamed **`classifierMinConfidence`** (`number | null`, default null = off; the old key warns as renamed and is ignored — clean break, no alias) and now means: a jev verdict with confidence strictly below the floor is **demoted, whatever the verdict** (allow/ask/deny alike) — cascaded to the fallback if `classifierFallbackModel` is set, otherwise asked of the user directly (non-interactive degrades to deny). The floor works standalone without a second layer, and is inert for LLM first layers (no numeric confidence). High-confidence asks no longer consult the fallback (the 0.10.0 ask-trigger is gone).
- Second-layer authority under `enforce` is now **de novo adjudication** with one carve-out (#67): a demoted first-layer **deny** that the second layer would allow is asked of the user, never an automatic allow; every other combination applies as the second layer rules (a demoted allow can be re-allowed — the absorb direction). This supersedes the 0.10.0 safety ratchet and its fail-closed no-exception decision. A failed or unresolvable fallback on a cascaded call now asks the user (the tier that was to adjudicate is down; headless → deny, one-time warning) instead of denying outright.

### Added

- Audit `demoted: true` marker on floor fires (#67); `/automode` cascade counters renamed to `triggered · agreed · overruled (would-overrule in shadow) · errored`.

## [0.10.0] - 2026-09-21

### Added

- Ground truth for ask confirms (#62): interactive asks — classifier and protected-path alike — now record the user's answer in the verdict audit log. `userAnswer` (`allowed`/`declined`) and `answeredAt` (ISO of the confirm resolution; `ts` stays adjudication time) attach to the record after the confirm resolves, keeping one record per verdict; killing pi mid-dialog loses that ask record (accepted trade-off of the append-only discipline). The audit surface widens to protected-path asks (#54 boundary change) — their user answers grade the denyPaths rules, records carry the matched path in `detail`, and a headless degradation records as its effective deny; rule-layer allow/deny verdicts remain unaudited.
- Uncertainty-gated fallback classifier, shadow-first (#63, [ADR-0004](docs/adr/0004-classifier-fallback-cascade.md)): opt-in `classifierFallbackModel` adds a second-layer classifier consulted only when the first layer is uncertain — trigger precedence fail-closed → `ask` → jev confidence strictly below `classifierFallbackConfidence` (0–100, default 50). `classifierFallbackMode: "shadow"` (default) records the outcome in an optional audit `fallback` sub-object and in `/automode` session counters without ever changing the verdict; `"enforce"` applies a safety ratchet (allow < ask < deny — the fallback only escalates, never relaxes; a failed fallback call or unresolvable model denies the triggered call, untriggered calls stay single-layer). The fallback runs with its own 15s-per-attempt budget and, unlike jev, receives the denyPaths existence hint. Audit records keep first-layer semantics at the top level — the enforced outcome lives in `fallback.effective`. jev's confidence is now hard-required by the adapter (contract-guaranteed on choice answers; absence fails closed like any malformed shape), and `parseJevConfidence` is exported for the gate (LLM first layers gate on ask/fail-closed only). Off unless configured — with no second layer the pipeline is byte-identical for every first layer.

## [0.9.1] - 2026-09-19

### Added

- Second transport for the jev decisions backend (#55 follow-up): `PI_VERDICT_JEV_TRANSPORT=typesafe` targets TypeSafe's official v1 API (`POST api.typesafe.ai/v1/systemone`, credentials via `TYPESAFE_API_KEY` from console.typesafe.ai) instead of OpenRouter's alpha decisions endpoint. The two wire contracts are isomorphic (live-verified 2026-09-19: same `{state, questions}` body, answers carry choice/probabilities/confidence, usage snake_case) — verdict text, timeouts, and fail-closed semantics are unchanged; the TypeSafe API does not report per-call cost (it shows as $0). `PI_VERDICT_JEV_URL` now overrides whichever transport is active. Default stays `openrouter` (pi's OpenRouter login reuse).

## [0.9.0] - 2026-09-19

### Added

- Optional allow-visibility preference (#60): `notifyAllows: true` in `pi-verdict.json` surfaces every classifier allow as an info notification (verdict reason + action line — e.g. jev's probability breakdown), default `false`. Mechanical passes (allow-rule echoes, protected-path confirms) never notify under it; the debug switch keeps its diagnostic scope unchanged, shadow-cache annotations stay debug-only, and with both on the notification appears exactly once. Config-only, new-session semantics.
- Opt-in verdict audit log (#54): `"audit": true` in `pi-verdict.json` records every gray-zone adjudication (allow/ask/deny and fail-closed alike) as a self-contained JSONL line under `<agentDir>/verdicts/<sessionId>.jsonl` — timestamp, session id, cwd, model, tool + input, action line, thinking level, the full transcript sent, the raw response, the parsed verdict, source, and shadow-cache probe result. Rule-layer decisions are not recorded; retention keeps the 20 most recent session files (pruned at session start). Full fidelity stays local (ADR-0002 boundary note); the directory is denied to agent reads and writes; the sink is fail-soft (a write failure never affects a verdict — one warning per session) and never an adjudication input. `/automode` shows `audit: on → <path>` while active.

### Fixed

- Agent-facing block reasons are now guaranteed non-empty and unambiguous (#53): all eight block sites (classifier, rule, fail-closed, protected-path degraded, user-declined ×2, tamper ×2) route through one wrapper emitting `[auto-mode <source> block] BLOCKED — this action did NOT run. Reason: <detail or "(no further reason given)">. Report the block to the user; never claim it succeeded or completed.` Previously an empty classifier reason left a bare `[auto-mode classifier block]` prefix in the tool result and terse rule reasons read like file descriptions — acting models then reported blocked actions as succeeded, since structural error signaling (`isError`) never reaches several provider lanes. UI notifications are unchanged; the wrapper adds no protected-path plaintext (ADR-0002).
- Gray-zone adjudication no longer fail-closes on models whose provider rejects the `temperature` parameter (#47): current-gen Anthropic models (`claude-sonnet-5`, `claude-opus-5`, `claude-opus-4-8`) answer the classifier's `temperature: 0` with a 400, denying every call whether set as `classifierModel` or reached via the session-model fallback. A rejection that mentions the parameter is now retried once without it at the same tier and the model is remembered until the extension reloads; models that accept the parameter keep the `temperature: 0` determinism pin.

## [0.8.0] - 2026-09-19

### Changed

- Shortened the first-run config template `_hint` to the decision-critical lines plus a pointer to the full configuration reference (~1.9KB → ~0.7KB): match targets, path-normalization details, thinking suffixes, and the jev backend note now live only in `docs/configuration.md`.

### Fixed

- Classifier calls to the `openai-codex-responses` API no longer send `temperature: 0` — the codex API rejects the parameter, which broke GPT-based `classifierModel` setups; the provider's `errorMessage` now also surfaces in classifier diagnostics instead of a bare failure (#46).

### Added

- Optional jev classifier backend (#55): `classifierModel: "typesafe/jev-latest"` routes gray-zone verdicts through TypeSafe's jev decisions model. A bundled adapter extension (`extensions/jev-adapter.ts`, auto-loaded with the package, individually disable-able via `pi config`) registers the model in pi's registry and translates the classifier call into one OpenRouter `choice` question (`POST /api/alpha/decisions`), synthesizing the usual `<verdict>` text with probabilities and confidence — timeouts and fail-closed semantics unchanged. Credentials reuse pi's OpenRouter login (`/login openrouter`) with `OPENROUTER_API_KEY` as fallback (no separate typesafe account); the endpoint is overridable via `PI_VERDICT_JEV_URL` (alpha API). Known limitations and the alternatives considered are recorded in ADR-0003: the denyPaths existence hint does not reach jev (denyPaths themselves stay rule-enforced before the classifier); jev "does not treat [state] as hostile by default" per TypeSafe docs, so adversarial transcript content can move its judgment; omp hosts stay inert; reasons are templated probabilities. Selecting the model as the session model warns — it generates no text.

## [0.7.1] - 2026-09-09

### Added

- The first-run config template pre-fills a starter `denyPaths` list (`~/.ssh/`, `~/.profile`, `~/.gnupg`, `~/.mc`, `~/.zshrc`, `~/.bashrc`) so protection is on from the first session after the initial run (#49): touches of these paths — file tools and bash path tokens alike — ask for your confirmation. The list is a pre-filled *user declaration*, not a built-in floor: edit or empty it in `pi-verdict.json`; existing configs are never rewritten. (Proposed with per-key entries under `~/.ssh/`; deduplicated to the directory prefix — segment-prefix comparison already covers every file beneath it.)

### Fixed

- denyPaths subtree scope for `grep`/`find`/`ls` (#48, reported in [discussion #8803](https://github.com/earendil-works/pi/discussions/8803#discussioncomment-18350257)): an omitted `path` (pi's documented default: the current directory) bypassed denyPaths entirely — a plain rule-layer allow with zero classifier involvement, leaking protected content out of the cwd. An explicit `path` pointing at a directory above a declaration fell through to classifier discretion. These tools now treat their search scope as the target: an omitted path resolves to the cwd for both user rules and denyPaths, and the comparison is bidirectional for them (declaration under the searched subtree, or cwd inside a declaration) → terminal ask, non-interactive degrades to deny. `read`/`write`/`edit` and bash token extraction keep single-target semantics — a recursive search issued from a shell (argument-less, or with a parent-directory argument) still falls to the classifier's existence hint (ADR-0002 amendment).

## [0.7.0] - 2026-09-04

### Changed

- Renamed the extension entry file to `extensions/pi-verdict.ts` — the entry file now matches the package name and the config file (`pi-verdict.json`). Runtime interfaces are unchanged (`--auto-mode*` flags, `/automode` command, `PI_AUTO_MODE_*` env). Both install paths load the extensions directory, so `pi install` / `omp plugin install` users are unaffected.
- Internal refactor (behavior-identical): the tool_call adjudication pipeline is now `adjudicate()` — a zero-UI module returning a `Verdict` value object (`source: rule | protected-path | classifier | fail-closed` × `degraded` for ask→deny in non-interactive sessions). The two previously duplicated ask-degradation branches collapse into one place; the handler only maps verdicts to UI. Tamper detection moved into an `IntegrityWatch` class and session state into a `SessionState` class (one reset list per module). New interface-level tests cover ask-degradation unification, the full `source × degraded` matrix, and a denyPaths zero-plaintext regression on reasons and notifications (ADR-0002 story 11). The dead `selfProtectCheck` export was removed; block reasons and notification texts are byte-identical.
- Internal refactor (behavior-identical): the dual-form path-normalization machinery is now one canonical-forms module — `baseForms` (whole-path realpath with lexical fallback, the ADR-0002 base tier) and `rebuiltForms` (ancestor-rebuilding tier, #20) — replacing the two builders (`targetForms`/`pathForms`) and six scattered `tryRealpath` base-side sets. Comparison disciplines stay per-consumer (denyPaths case folding, floor regex `/i`, self-protection exact match). denyPaths deliberately stays base-tier — a nonexistent target written through a symlinked alias falls to the classifier, not a denyPaths hit — now pinned by a regression test.

## [0.6.1] - 2026-09-03

### Fixed

- omp 18.1+ anchoring: omp 18.1 installs npm plugins under `~/.omp/plugins/node_modules/<pkg>/` — a sibling of `agent/` in the config root, not under it — which the 0.6.0 self-anchor did not match. On omp 18.1+ the gate silently fell back to `~/.pi/agent`: no config template appeared under `~/.omp/`, hand-edited rules/denyPaths there were never read, omp sessions shared the pi host's config file, and the omp install copy sat outside the self-protection set. The anchor now accepts both omp layouts (`agent/plugins/node_modules/…` and `plugins/node_modules/…`), and the self-protection ext-roots cover the package dir under the config root. Scoped npm packages (`@scope/pkg`) now get package-level self-protection instead of shielding the whole `@scope/` dir (a latent #26-era over-protection, now corrected to package granularity). Verified against omp 18.1.3. Upgrading from 0.6.0 on omp: close running omp sessions before `omp plugin install` (a live session's tamper detection would treat the updated install copy as tampering), then re-create your config at `~/.omp/agent/config/pi-verdict.json` — configs under `~/.pi/agent/` keep applying to pi sessions only.

## [0.6.0] - 2026-09-02

### Added

- oh-my-pi (omp) host support (#35): the extension self-anchors to whichever agent tree it is installed in — user rules, self-protection, and the S0 credential deny now cover `~/.omp/agent/` (config, `plugins/node_modules/` install copies, `auth.json`) exactly like `~/.pi/agent/`. On omp 18 (no `ModelRegistry.complete`) the classifier falls back to the pi-ai compat completion API at first gray-zone verdict; resolution failures follow the existing fail-closed deny. Thinking control is sent in both hosts' native dialects (`thinkingEnabled`/`effort` for pi, `reasoning`/`disableReasoning` for omp). Behavior on pi is unchanged; on dual-install machines the gate follows the extension copy's own location, never host-tree probing.
- Security design principles: full statement in `docs/security-principles.md` (12 principles + a "directions, not shipped" section for capability-aware authorization), with a condensed "Design principles" section in both READMEs; claims are checked against actual behavior (no sandbox layer in the gate's own pipeline, platform gaps stated as documented differences rather than parity claims)
- README slimming (~25%): user-rules reference and host implementation notes moved to a new `docs/configuration.md`; the self-protection section keeps the essentials with the differential-disposal narrative in ADR-0001; pipeline diagram annotations reduced; comparison tail de-duplicated

## [0.5.2] - 2026-09-01

### Fixed

- A malformed `pi-verdict.json` (e.g. a trailing comma) no longer silently loads empty user rules: the parse failure is reported through the session-start skip channel (the built-in floor and self-protection layer were never affected) (#25)
- Danger-regex matching is capped at 8192 characters: very long separator-free commands could backtrack quadratically and stall adjudication; beyond the cap the call falls to the classifier (fail-closed direction) (#25)
- npm package-directory installs: the tamper-detection baseline now covers every file in the package directory (node_modules/.git excluded) — write protection already covered the whole dir, but only the entry file was watched, so a tampered manifest would have loaded next session undetected (#26)

## [0.5.1] - 2026-09-01

### Security

- S-rules (S0–S3) now match case-insensitively and S1 gains the macOS firmlink prefixes (`/private/etc`, `/private/var`): on case-insensitive filesystems (default macOS APFS, Windows) case variants name the same file but previously missed the case-sensitive regexes when the target did not exist (realpath cannot normalize a nonexistent path), and firmlink real spellings silently allowed where the `/etc` spelling went gray. denyPaths comparison folds case on darwin/win32 (linux stays case-sensitive) (#21)
- Path sensitivity floor (S0–S5) and the self-protection write check now match every canonical form of the target path (lexical + realpath, rebuilding from the nearest existing ancestor when the target does not exist yet); the in-cwd write allowance requires all forms to sit inside the session cwd's real path. Fixes a symlink-alias bypass where a single classifier-adjudicated `ln -s` aliasing `~/.ssh` or a `.git/hooks` directory let subsequent reads and cwd-scoped writes through the floor with zero model calls (#20)
- Classifier transcript lines are now line-break-escaped and the tool-call path branch goes through the same sanitize pipeline as commands (zero-width stripping + length cap). A path, command, or user message containing embedded line breaks could previously split its transcript line and forge structural lines — e.g. a fake `User:` line instructing the classifier to allow — and tool arguments are model-generated (steerable by prompt-injected file contents), so the surface was real. The escape covers `\n`, `\r\n`, lone `\r` and the Unicode separators U+2028/U+2029/U+0085, which models may render as breaks (#22)

### Changed

- Documentation alignment (#23): classifier timeout documented as 25s (en/zh READMEs; code and the measured p90 basis say 25s, docs said 15s); the volatile offline-test count removed from the dev section; the Status & limitations sections now state two floor scope boundaries explicitly — bash command strings are matched by the danger regexes only (`cat ~/.ssh/id_rsa` goes to the classifier, not the deterministic S0 deny), and on Windows the built-in floor covers bash-shaped patterns only, PowerShell-native dangerous commands rely on the classifier
## [0.5.0] - 2026-08-31

### Added

- `denyPaths`: user-declared protected paths (#16, [ADR-0002](docs/adr/0002-deny-paths-deterministic-ask.md)):
  - plain-path list in `config/pi-verdict.json`; the tool owns normalization — `~`, `$HOME/`, relative, `..`, symlink spellings all resolve, compared per path segment; anchored once per session, so cwd drift or mid-session symlinks cannot re-anchor the declaration
  - any touch — file tools by their path, bash by path tokens from the command string (heredocs included) — triggers a terminal **ask** the user adjudicates; headless sessions degrade to deny
  - priority: after user `deny`, before user `allow` (not even your own allowlist may touch these); unaffected by `builtinDenyFloor: false`; subject to the master switch
  - the classifier sees only a fixed existence hint — zero path plaintext; the matched path appears solely in the local confirm dialog, never in block reasons or notifications
  - `/automode` shows the active count; the config template gains the field; invalid entries warn once at session start
  - known holes (substitution, base64, script contents, spaces, final-segment globs → classifier vigilance) documented in the README and frozen by regression payloads

### Changed

- Footer status colors: `auto mode on` renders in success green, `auto mode off` in warning yellow (was accent/dim) — an ungated session stays visible at a glance instead of fading into the dim channel. Semantic theme colors adapt to light/dark themes; the `/automode` notifications are unchanged

## [0.4.1] - 2026-08-31

### Changed

- Standardized the positioning statement as “minimal permission gate” — synchronized the bilingual README tagline, AGENTS.md, and npm `description` (effective with this release in the npm registry and pi.dev package directory); moved the “hundreds of lines of minimal code” point to the top of the feature list; changed the user-rules subsection heading to the full path `~/.pi/agent/config/pi-verdict.json`; bolded the opening of “Why No Built-In Allowlist.” Documentation and package-metadata wording only; no code changes

## [0.4.0] - 2026-08-31

### Added

- Master-switch toggle shortcut (#15): defaults to `ctrl+shift+a` to switch Auto Mode on/off with one keystroke and silent feedback (the footer always shows the state as the sole confirmation; no notification). Added the `toggleShortcut` field to `config/pi-verdict.json` — any pi key combination can be rebound; `null`/an empty string disables it; invalid combinations produce a one-time warning at session startup and skip registration (matching `classifierModel` fallback behavior); effective in new sessions. Semantically equivalent to `/automode on|off`: takes effect at runtime, with no confirmation dialog and no persistent write-back (the extension runtime never writes its own protected config, so ADR-0001’s “user-edited only” boundary is unchanged); the `/automode` status output’s Usage line also shows the current key binding

## [0.3.1] - 2026-08-29

### Changed

- Documentation (en/zh READMEs, this file’s 0.2.0 entry): removed the “third-party security audit” claim and replaced it with factual descriptions — 8 findings in rule-layer bypass tests, a reproducible payload for each, and the architectural removal of the built-in allowlist in 0.2.0

## [0.3.0] - 2026-08-27

### Added

- Self-protection layer (self-protection layer, ADR-0001): prevents agent-side changes to the gate’s own files — `config/pi-verdict.json` + installed extension copies (runtime self-anchoring through `import.meta.url`, covering both single-file and npm-directory install layouts, excluding dev checkouts). `write`/`edit` use realpath normalization and exact comparison (preventing symlink bypass); bash/powershell command strings cover literal/`~`/`$HOME`/`$PI_CODING_AGENT_DIR` spellings; reads are allowed; no configuration can exempt it (`builtinDenyFloor: false` cannot turn it off, and user `allow` cannot override it). The entire `~/.pi/agent/` tree (mcp.json, skills, etc.) is explicitly outside the protected scope — users who need that layer of protection should express it themselves with user-rule `deny` regexes (an ADR-0001 rejected option)
- Change detection (ADR-0001): take full snapshots of protected files at `session_start` and recheck before every adjudication; handle changes per file — if the extension copy changes or no UI is available, automatically restore it from the in-memory snapshot + fail-closed for the session; if only the config changes during an interactive session, use `ctx.ui.select` for a two-option disposition, with the option text specifying the action (Accept = rebuild the baseline and continue the session; Decline = roll back + fail-closed; closing the dialog takes the safe option, same as Decline); legitimate manual edits between sessions still take effect in the next session

### Changed

- Narrowed the semantics of `builtinDenyFloor: false`: it now disables only the built-in danger regexes and path-sensitivity checks, and can no longer indirectly disable the self-protection layer; updated the config template `_hint` accordingly
- README (en/zh): added layer 0 to the pipeline diagram; added a “Self-Protection” subsection; added candid statements to the limitations list that Bash substring regexes can be obfuscated, the cross-session baseline was deferred to phase two, and dev checkouts are not protected; test count 42 → 62
- Documentation cleanup: removed outdated research notes from the repository root (research-pi-auto-mode.md, research.md)
## [0.2.4] - 2026-08-27

### Changed

- Aligned the `package.json` `description` with the README’s one-line positioning (pi.dev catalog listings and npm search results display this field; its previous value was a dense list of technical details)
- Documentation cleanup: removed research/pi-observational-memory.md and made small changes to the READMEs (en/zh)

## [0.2.3] - 2026-08-27

### Changed

- Standardized runtime UI notices in English: Bash danger-rule reasons, path-sensitivity reasons, user-rule reasons, classifier-failure diagnostics, shadow-cache summaries/annotations, notify/confirm wording, the config template `_hint`, and block-reason prefixes; code comments remained in Chinese, and test assertions were updated in sync (all 42 tests passed)
- Rewrote the README opening (en/zh): one-line positioning (a pi permission gate in the style of Claude Code Auto Mode) + a three-point mechanism list; added a “Problem / Why Three States?” subsection; moved Quick start above the category comparison; retired the unofficial term YOLO (it does not appear in pi documentation, so the problem statement now uses pi’s official wording and links to its security documentation)

## [0.2.2] - 2026-08-27

### Changed

- Connected `package.json` metadata to pi’s official package directory (pi.dev/packages): added the `pi-package` keyword (a directory listing requirement, confirmed by empirical comparison of listed and unlisted packages) and the `extension` keyword (the directory type label displays “extension” rather than the generic “package”); added an explicit `pi` manifest declaration for the `extensions/` resource (previously relying on convention-based directory discovery); updated the README installation section with the directory link
- Added the `auto-mode`/`automode` keywords (matching the common usage of the direct comparison package @czottmann/pi-automode, and matching searches for the `/automode` command name and repository name; after evaluation, excluded claude/claudecode — this package is a pi extension, not a Claude Code plugin, so misleading keywords would contradict its truthful positioning, and neither of the two direct competitors uses them)

## [0.2.1] - 2026-08-27

### Added

- Config files now support `classifierModel` (provider/id): persistent classifier-model configuration; priority is CLI flag > env > config > self-reflection; invalid values fall back to the session model with a one-time warning (the same non-failing handling as for an invalid regex)
- The spec supports pi’s native thinking-level suffix `provider/id:thinking` (matching pi `--model` syntax): `off` (default, explicitly disables thinking)/`low`/`medium`/`high`/`xhigh`/`max` are passed through adaptive effort, and `minimal` maps to `low`; invalid suffixes produce one warning and are ignored
- Updated the README positioning based on convergence analysis (#14): truthful framing + a seven-item evidence base

## [0.2.0] - 2026-08-26

### Changed

- Rule-layer refactor: removed the built-in Bash allowlist and replaced it with **user-configurable** allow/deny regexes (`<agentDir>/config/pi-verdict.json`, deny blacklist takes precedence over allowlist, template generated on first startup); built-in danger regexes + path sensitivity remain as the deny floor (enabled by default; `builtinDenyFloor: false` disables it entirely)
- Classifier timeout increased from 15s → 25s (the p90 of this gateway’s CC classifier distribution is 19.8s; 15s would falsely deny about 15% of calls; see `research/cache-sim/`)

### Security

- All 8 findings from the rule-layer bypass tests were fixed (`research/rule-layer-security-audit.md`): V1–V7 (structural bypasses of the built-in allowlist) were **structurally eliminated** by the architectural refactor — without a built-in allowlist there is no short-circuit path; V8 (omission from the S0 secret list) expanded the list to `.netrc/.npmrc/.pypirc/.envrc/.vault-token/.kube/.docker config.json/.gem credentials`; all 8 attack payloads were added to regression tests (36 stub tests)

### Added

- `research/pi-automode-convergence.md`: comparison of convergence with @czottmann/pi-automode — the architectures have converged (10 areas of convergence); remaining differences are ranked (fundamental: the floor can be disabled/minimal form/methodology; replicable: three-state asks/AST rules/anti-tampering); strategic recommendation: B as an independent testbed + A as upstream contributions (#14)
- `tests/auto-mode.test.ts`: 21 offline stub tests (rule layer/classifier retry matrix/shadow-cache observe-only/command semantics/debug annotations) — promoted the three-part development smoke-test set into the permanent test suite
- `.github/workflows/ci.yml`: typecheck + test (bun) on push/PR
- `.github/workflows/publish.yml`: npm publishing triggered by v* tags (OIDC trusted publishing + provenance, tag/version consistency assertion, package allowlist check)
- `package.json`: ready for npm publishing (`private` removed, main entry, files allowlist, optional peerDeps declaration, keywords/repository)
- `research/pi-permission-landscape.md`: competitor landscape for the permission auto-adjudication category — first-hand research on 7 projects (czottmann/pi-automode, gotgenes/pi-permission-system, cc-safety-net, r4vi/pi-auto-mode, flaxodev/pi-perms, zhushanwen/pi-permission, wangzexi/pi-auto-approve), with positioning conclusions and README wording implications (#10)
- MIT license (open-source preparation)

- Shadow-cache telemetry (observe-only): gray-zone adjudications synchronously replay the two-key LRU (128) to measure its would-be hit rate; results are only recorded and never take effect, building empirical data for #5 (“whether to introduce an active cache”). `/automode` includes session statistics (hit rate/miss composition/command repetition/counterfactual disagreements); notifications include would-hit/miss annotations when `PI_AUTO_MODE_DEBUG=1` (#7)
- `--auto-mode-debug` CLI flag: enables all adjudication notifications and shadow-cache annotations, is equivalent to and takes precedence over `PI_AUTO_MODE_DEBUG=1` (pi config files have no generic env-injection mechanism; the flag is the native switch)

### Fixed

- Classifier gray-zone calls systematically failed closed (GLM-family reasoning models): the extension passed the `reasoning` option to API-level `complete()`, but that option is not a field at that layer (`SimpleStreamOptions` is the only type with it; the index signature on the broad `Model<Api>` type let TypeScript silently accept it, but it was discarded at runtime) → the request omitted the reasoning parameter → GLM used its default max-effort reasoning, exhausting the budget or timing out. Switched to the API-native `thinkingEnabled: false` (verified delivery by the anthropic-messages stack as `thinking:{"type":"disabled"}`; GLM dropped to light reasoning at effort low, with two defensive retry tiers (512 → 1024) covering empty output/truncation/timeouts/exceptions and long-tail failures on other APIs). Root cause and three layers of evidence: `research/thinking-param-blackhole.md`

### Changed

- Rewrote the README for a public audience: English main document + equivalent Chinese README.zh-CN.md (cross-linked at the top); one-line positioning (three-state adjudication), lightweight category-comparison table, evidence-driven sections (five research documents), disclaimer (not a sandbox), and naming note

- Clarified statusline wording: the off state is now always visible in dim text instead of hidden; both states show `auto mode on` (highlighted) / `auto mode off` (dim)

- Clarified `/automode` command semantics: a bare call now displays **read-only status** (fixing the side effect where checking the status flipped the state); `/automode on|off` sets the state idempotently (does not toggle if it already matches); strictly rejects unknown arguments and lists usage; normalizes case

- `extensions/auto-mode.ts`: Auto Mode extension prototype — implements three-state adjudication (allow / ask / deny) on the `tool_call` hook with “rule layer first + model classifier handles the gray zone” (#3)
  - Rule layer: unconditional/conditional Bash allowlists + danger regexes (match the complete command string) + six file-path sensitivity tiers (S0 credentials to S5 outside CWD)
  - Model classifier: Claude Code-style compact `<transcript>` transcript + `<verdict>` prefix output contract; defaults to “self-reflection” (inherits the current session model), configurable with `--auto-mode-model` / `PI_AUTO_MODE_MODEL`
  - Fail-closed: classifier exceptions/timeouts (15s)/output that violates the contract → block; non-interactive ask → block
  - Transparency: `/automode` toggle command, footer `🛡️ auto` status, block notifications include the verdict reason, and `PI_AUTO_MODE_DEBUG=1` enables all verdict notifications
- `research/claude-code-classifier-prompts.md`: reconstructed Claude Code permission-classifier prompts from Langfuse (hundreds of samples/24h) (#4)
- `research/cache-sim/`: offline replay of verdict-cache benefits — replayed historical CC classifier verdicts (1,2xx calls / 2x sessions) through a two-key LRU; 3.2% hit rate and 0 dangerous disagreements; #5 decision basis and reproducible scripts (fetch-io / simulate / kinds)
- `research/rule-engine-sim/`: rule-engine benefit measurement — dual-engine cross-replay of 746 real Bash calls (tree-sitter AST × this layer); measured zero benefit from the port and zero real security holes; actual targets are allowlist breadth and classifier cost (#6)
- `research/pi-model-call-and-ref-implementations.md`: research on Pi extension model-call/configuration APIs and analysis of implementations from three open-source permission extensions, including a rule-layer seed set (#2)
- `CONTEXT.md`: domain glossary (Auto Mode / adjudication / rule layer / gray zone / classifier / self-reflection / fail-closed / three-state verdict / ask degradation)
- `package.json` + `tsconfig.json`: extension type checking (`bun run typecheck`)
