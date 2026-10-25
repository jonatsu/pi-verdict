# Repository Guidelines

## Project Overview

**pi-verdict** (`@jonatsu/pi-verdict`) is a minimal permission-gate extension for [Pi](https://github.com/earendil-works/pi-coding-agent) and oh-my-pi (`omp`): a deterministic **rule layer** plus a **model classifier** for the gray zone. Every tool call is adjudicated to one of three states: `allow` / `ask` / `deny`. Default posture is allow-unless-intercepted ("Auto Mode"), the reverse of Claude Code.

Use the glossary terms exactly (e.g. adjudication pipeline, dual-form matching, gray zone, `denyPaths`, always plural).

## Goals

Judge every change by these goals, set by the user; work that serves none of them is scope drift.

- **Usable every day.** The agent works on its own, and the gate stops only the calls that matter: destructive commands, secrets and protected paths, code-loading writes, and the gate's own files. A needless ask is a defect, because a user who learns to click through asks is no longer protected.
- **Fast path in code, slow path through the model.** Decide trivial calls deterministically, and send only calls that need judgement to the classifier. Soundness sets the cutoff: a static rule may allow a call only when it can show the call is harmless. Bash has no built-in allow; user allows grade a command's operands (ADR-0008), and the read-only command fast path built on that grading is TODO item 6.
- **Fail closed.** No error, timeout, missing UI or degraded policy ever becomes an allow.
- **Efficient, and maintainable by humans.** Small modules with one concern each, short functions, why-only comments, no needless model calls or repeated work per call. Refactoring serves this goal and the shared reading of each call (TODO item 5); it is not a goal in itself.
- **Harden 80/20.** Fix plausible spellings of a path or command; record exotic ones as residuals (ADR-0009). The OS sandbox is the backstop.

## Where to Read

- Read before starting new work: [TODO.md](TODO.md) (ranked open work); plans: [docs/plans/](docs/plans/), finished ones in `docs/plans/archive/`.
- Read when naming a concept or term: [CONTEXT.md](CONTEXT.md).
- Read before changing the control flow, a module's role or the design direction: [docs/architecture.md](docs/architecture.md), with diagrams; update it in the same change.
- Read before changing a layer's order or decision: [docs/layers.md](docs/layers.md); the probe asserts it.
- Read before adding or changing a config key or default: [docs/configuration.md](docs/configuration.md).
- Read before changing behavior, or to learn why it is so: [docs/adr/README.md](docs/adr/README.md), the decision index.
- Read before changing a security property: [docs/security-principles.md](docs/security-principles.md).
- Read before changing host imports, dialog mouse handling or the status widget: [docs/host-contract.md](docs/host-contract.md).
- Read before adding a probe case: [probe/README.md](probe/README.md); [docs/coverage.md](docs/coverage.md) is generated from it.
- Read before filing or triaging an issue: [issue tracker](docs/agents/issue-tracker.md), [triage labels](docs/agents/triage-labels.md), [domain docs](docs/agents/domain.md).
- Read when tracing a claim made before v0.17.0: [docs/verification-2026-10-04.md](docs/verification-2026-10-04.md), a dated record.

## Agent Rules (YOU MUST)

Before writing or changing code, read the repository rules in `.agents/rules/` (symlinked into `.claude/rules/`):

- `pv-typescript.md` for any `.ts` file: modules, types, the fail-closed error rule, architecture limits, and the checks that define done.
- `pv-comments.md` before writing or editing a comment: why-only comments, and references limited to ADRs, issues, test names and one host citation. Plan and finding ids stay out of code.
- `pv-tests.md` for `tests/` and `probe/`: the harness, failing-before proof, pinned security tests, and probe case rules.

They condense the global `coding-standards` skill for this repository and win where the two differ. `biome ci .` enforces their mechanical half; review enforces the rest.

## Architecture & Data Flow

Two independent extensions in `extensions/` (no `src/`, no build step; TypeScript is shipped as-is). `package.json` → `"pi": {"extensions": ["./extensions"]}` makes the host auto-load **both**: it scans one level and loads `jev-adapter.ts` and `pi-verdict/index.ts`, never a sibling module. The gate is split into sibling modules under `extensions/pi-verdict/`, one concern each (the module map below). Never add `extensions/index.ts` or a `package.json` inside `extensions/pi-verdict/`.

- `extensions/pi-verdict/index.ts`. Default export `autoMode(pi, deps: AutoModeDeps = {})` (flags, hook wiring) and explicit re-exports of the public names (never `export *`).
- Modules, leaves first (each imports only modules above it, never `index.ts`): `shell` (bash rule layer), `paths` (canonical forms), `agent-dir` (anchor), `trust`, `config` (user rules and template), `floor` (path sensitivity), `git-reach` (whether an allowed git call stays in the project), `allow-operands` (what a user allow may admit), `home-guard` (whether the session may have reassigned `HOME`), `access` (host path spelling, tool-access adapter), `action-line` (a call as a transcript line), `deny-paths`, `redaction` (protected-path redactor), `code-loading`, `self-protection`, `completion` (host completion binding), `model-call` (one model call, temperature policy), `classifier` (prompts, transcript, classify loop), `rules` (`classifyByRules`), `audit`, `state` (`SessionState`), `adjudicate`, `explain`, `subagent`, `model-roles`, `runtime`, `root-ui`, `ui/` (`dialog`, `footer`, `status`), `present`, `session-start`, `master-switch`, `ui/config-editor`, `tool-call`. `agent-dir.ts` names the gate's install location (`OWN_FILE_PATH`), so it MUST stay directly in `extensions/pi-verdict/` beside `index.ts`; a test pins that.
- `extensions/jev-adapter.ts`. Default export `jevAdapter(pi)`. Registers provider `typesafe` / model `typesafe/jev-latest` (non-generative "typed decision" classifier backend, ADR-0003). Inert without `pi.registerProvider`. Gate modules value-import its helpers, never the extension.

**Host hooks**: flags `auto-mode` (default on), `auto-mode-model`, `auto-mode-debug` (or `PI_AUTO_MODE_DEBUG=1`); `session_start` → `session-start.ts` (trust prompt, `SessionState.reset()`, audit prune); `tool_call` → `tool-call.ts`; `/automode` (on|off|status) and toggle shortcut (default `ctrl+shift+a`) → `master-switch.ts`; `/verdict` (needs UI) → `ui/config-editor.ts`.

**Pipeline** — pure, UI-free `adjudicate(state, call, env) → Verdict`, called from the `tool_call` handler; change it together with `docs/layers.md`.

1. `classifyByRules` → `RuleResult{allow|deny|gray|ask}`. Every file-tool layer reads its targets from the tool-access adapter `toolAccess` (ADR-0009), graded in every form the host can resolve the path to (`hostPathForms`), worst grade winning. Order: self-protection (ADR-0005: a hard, config-exempt deny over the gate's own files) → built-in deny floor (`BASH_DANGER_RULES`, path sensitivity S0–S5 via `classifyPath`; off with `builtinDenyFloor:false`) → user `deny` regexes → forced `.omp` gate (`gateOmpDir`, default off) ask → `denyPaths` ask (also a call the strict redactor matches) → code-loading ask (ADR-0011: a write where the host loads code in later sessions; off with `builtinDenyFloor:false`) → over-cap action ask → user `allow` regexes / `tools` exact-name exemption → opaque-call ask → gray. Deny beats allow. There is **no built-in allowlist** (`research/rule-layer-security-audit.md`).
2. Gray zone → `classifyWithModel` (per-attempt cap `CLASSIFIER_TIMEOUT_MS`, inside the end-to-end budget `ADJUDICATION_BUDGET_MS`; a timed-out attempt is never retried). Response MUST start with `<verdict>allow|ask|deny</verdict>` (verdict prefix contract) or it fails closed.
3. Post-classifier: `confidenceDemotion` (`classifierMinConfidence`, jev only) → `runConfidenceCascade` to `classifierFallbackModel` (`enforce` default | `shadow`; a demoted deny can never become an auto allow; ADR-0004).
4. Presentation: single point `presentVerdict` (`present.ts`). Block text via `blockReason(state, tag, detail)` → `[auto-mode <tag> block] BLOCKED — ...`. `Verdict.detail` is UI-only; protected-path plaintext MUST NOT reach the agent, notifications, or any model (ADR-0002 existence hint only). Asks go through `confirmAsk` (rich dialog → `AskDecision`): Yes / No / "No, with explanation…" (user text → `declineDetail` → block reason) / "Explain…" (EXPLAIN-GATE role, `explainGate`; display-only output, **never offered for protected-path asks** — same ADR-0002 rule).

**Fail direction**: closed. Classifier error / timeout / no model / malformed output ⇒ deny (`source:"fail-closed"`). No UI (`pi -p`, json, rpc) ⇒ every `ask` degrades to deny with `degraded:true`. Config errors ⇒ empty rules with the floor ON plus a notification, **and `policyDegraded` (ADR-0010): a config parse/load failure, a trusted-project parse/shape failure, or any skipped `deny`/`denyPaths` entry withholds every model-originated allow — first layer + cascade → ask (`source:"degraded-policy"`), subagent second model → denied outright — and suspends user `allow`/`tools` for the session; named in the footer badge, `/automode`, every block reason, and a session-start warning**. The extension is never disabled. Audit write failures are fail-soft.

**Subagents** (omp): a subagent session's ask goes to the root session's UI (`root-ui.ts`); with no root UI, or `subagentGate: "auto"`, it resolves without a human through `resolveAskWithoutHuman`, which consults `classifierFallbackModel` and denies everything else. omp does not pause its per-handler budget for a dialog on the root UI, so a subagent's ask closes before that budget ends (`readHostHandlerBudget`, `subagentAskWindow`; `docs/host-contract.md`).

**State**: `SessionState` (fallback stats, `userRules`, audit log, `policyDegraded`, `denyPathBases`) inside one instance's `GateRuntime`. Module-level: root UI and dialog queue (`root-ui.ts`); caches `completionCache`, `TEMPERATURE_REJECTED_MODELS`, `dialogModules`.

**Dual host**: real pi and omp. Adapter detects omp by `"logger" in pi && "typebox" in pi`. Model calls go through `ctx.modelRegistry.complete` when present, else the `compatLoader` fallback (omp 18 shape). The omp host source for path and loader behavior is cloned under `.scratch/research/oh-my-pi` (git-ignored); check its version against the installed `omp --version` before citing it.

**Config**: `<agentDir>/config/pi-verdict.json` (user), written from `USER_CONFIG_TEMPLATE` on first run; project override `<project>/.omp|.pi/pi-verdict.json`, applied only if trusted (`<agentDir>/config/pi-verdict-trust.json`), and only in the narrowing direction (ADR-0006). `agentDir` = `PI_CODING_AGENT_DIR` if set, else self-anchored from the install path (`resolveAgentDir`), fallback `~/.pi/agent`; never probe the host dir tree. Defaults live in `EMPTY_RULES`. Audit (opt-in): `<agentDir>/verdicts/<sessionId>.jsonl`.

## Key Directories

| Path | Purpose |
| --- | --- |
| `extensions/` | Shipped runtime code (the two extensions above) |
| `tests/` | `bun:test` suites, one per extension file |
| `probe/` | The shared gate-testing contract: `cases.ts` (the case table), `probe.ts` (three-run runner), `fixtures.ts`, `consumer-policy.json`, `README.md`. Dev artifact; not shipped |
| `tools/` | `provenance.ts`, `coverage.ts` (generates `docs/coverage.md`), `release-check.ts`. Dev artifacts; not shipped |
| `docs/` | Reference docs, plans and ADRs (routed in "Where to Read"); `agents/` is skill config, not product docs |
| `.agents/rules/` | Repository rules for agents (`pv-*.md`); `.claude/rules/` holds symlinks to them |
| `research/` | Evidence notes + offline sims (`cache-sim/`, `rule-engine-sim/`); not part of tests/typecheck |
| `scripts/` | `demo.tape` (vhs recording of `docs/demo.gif`; macOS/zsh/RamDisk-specific) |
| `.github/workflows/` | `ci.yml`, `publish.yml` |

## Development Commands

```bash
bun install                 # use --frozen-lockfile in CI; bun.lock must match package.json
bun run typecheck           # tsc --noEmit -p tsconfig.json (extensions/, probe/, tools/)
bun test                    # all tests
bun test tests/pi-verdict.test.ts
bun test -t "<substring>"   # filter by test name
bun run probe               # the shared case-table contract; --filter "<label>" runs a subset
bun run coverage            # regenerate docs/coverage.md from probe/cases.ts
bun run provenance          # sha256 of the committed extension blobs at HEAD
bun run release-check       # package.json version == annotated tag v<version> (local pre-tag gate)
```

`lint`/`format` scripts exist (`mise exec -- biome …`) and `biome.json` is the config; CI runs `biome ci .` over `extensions/`, `tests/`, `probe/` and `tools/` (`tests/` alone may use `any`). Run the full set in `pv-typescript.md`'s "Done" after any change to `extensions/`, `probe/`, or `tools/`. For headless smoke-testing of a build, see "Smoke-testing" below.

## Domain Conventions

- Language: comments, docs, CHANGELOG, release notes, README in English. Technical writing uses standard terminology; no invented colloquial metaphors (annotate a short form with its precise meaning on first use).
- Path matching is **dual-form**: lexical + realpath (`baseForms`; `rebuiltForms` additionally rebuilds from the nearest existing ancestor and is used by the path-sensitivity floor only). `denyPaths` MUST NOT use ancestor rebuild (pinned by a test). Compare case-folded on win32/darwin via `fold`.
- Host path spellings are graded through `hostPathForms` (raw form plus omp's `expandPath`, read selectors, `?q=` image questions, shell-escaped spaces, WSL drive aliases); ADR-0009 records the accepted residual spellings. Add a spelling there, not in a single layer.
- Scope tools (`SCOPE_TOOL_NAMES`: `grep`, `find`, `ls`, `glob`, `ast_grep`, `ast_edit`) have subtree semantics; an empty path is the cwd. A target holding a glob metacharacter never yields a rule allow, except an in-project `glob` listing.
- Regexes in rules are capped at `BASH_MAX_MATCH_LEN=8192`; longer commands fall through to the over-cap ask.
- DI seams beyond `AdjudicateEnv`: `autoMode(pi, {compatLoader, hostHandlerBudget})`; `streamDecisions(…, fetcher = fetch)` and `createJevProvider(keyResolver, fetcher)` inject `fetch`.
- Notifications: deny/ask always notify; a classifier allow only with `notifyAllows`; mechanical allows are silent.

## Important Files

- `extensions/pi-verdict/` — gate: `runtime.ts` (`GateRuntime`, `AutoModeDeps`), `present.ts` (`presentVerdict`), `adjudicate.ts` (`adjudicate`), `rules.ts` (`classifyByRules`), `access.ts` (`toolAccess`, `hostPathForms`), `state.ts` (`SessionState`), `config.ts` (`USER_CONFIG_TEMPLATE`, `DEFAULT_ALLOWED_TOOLS`).
- `extensions/jev-adapter.ts` — jev provider/transport (env `PI_VERDICT_JEV_TRANSPORT` = `openrouter|typesafe`, `PI_VERDICT_JEV_URL`, keys `OPENROUTER_API_KEY` / `TYPESAFE_API_KEY`).
- `package.json` — `files` whitelist (a new runtime file under `extensions/` MUST be added or it won't publish), version, peer dep `@earendil-works/pi-coding-agent >=0.84.0` (optional; dev-pinned 0.84.3).
- `tsconfig.json` — `paths` maps the pi package to `node_modules/.../dist/index.d.ts`.

## Runtime/Tooling Preferences

- **Bun** is the package manager and test runner (`bun.lock` committed; it records no package version, so a version bump leaves it unchanged). **TypeScript** (`tsc`) for typechecking only. Node 22 is used only in `publish.yml` for `npm pack/publish`.
- Zero runtime dependencies; the pi package is an optional peer dep. Don't add runtime deps without a strong reason.
- Package name is `@jonatsu/pi-verdict` (renamed from `@frapetti-dev/pi-verdict`). The deployment installs via the git spec; GitHub Packages publishing requires the scope to match `@jonatsu`.
- CI (`ci.yml`): `bun install --frozen-lockfile` → `bun run typecheck` → `biome ci .` → `bun test` → `bun run probe` → `bun run coverage && git diff --exit-code docs/coverage.md`. Publish (`publish.yml`, on GitHub Release): tag must equal `v` + `package.json` version and HEAD must be the tag commit, then typecheck + test + publish.
- Keep `PI_CODING_AGENT_DIR` and home-relative fixtures cross-platform; Windows path separators are handled in code. The dev host is native Linux and CI runs only `ubuntu-latest`, so the win32 and darwin branches (fixed at module load from `process.platform`) are untested; their tests skip. WSL drive aliases are tested by setting `WSL_DISTRO_NAME`.

## Testing & QA

- Runner `bun:test`. `tests/` is **not** typechecked; `probe/` and `tools/` are (they are `tsc`-included and biome-strict). No coverage threshold. Harness, fixtures and test-writing rules: `.agents/rules/pv-tests.md`.
- `bun run probe` is the shared case-table contract (see `probe/README.md`): one case asserts the layer that decides a call, across three runs (A headless, B interactive, C consumer policy). `docs/coverage.md` is generated from the case table and CI checks it fresh.
- `research/` sims need external data (a private Langfuse instance / local session logs) and aren't reproducible offline; don't run them as part of QA.

## Documentation Sync (YOU MUST)

Keep docs in sync with functional changes:

| Change | Update |
| --- | --- |
| Any user-visible change | `CHANGELOG.md` `## [Unreleased]` (Keep a Changelog; sections Added/Changed/Removed/Fixed; long single-line English bullets, identifiers in backticks, issue/ADR refs inline; breaking → `- **BREAKING**: …`; describe behavior, pipeline position, defaults, migration impact) |
| Usage / behavior | `README.md` (keep the ASCII "Pipeline" diagram in sync) |
| A layer's order or decision | `docs/layers.md` and the probe cases that assert it |
| Config key, host, or transport | `docs/configuration.md` and the config template `_hint` copy (`USER_CONFIG_TEMPLATE`) |
| Terminology | `CONTEXT.md` (terms only — no implementation detail or decisions) |
| Architectural decision | new `docs/adr/NNNN-title.md` (next number; `status:` and `date:` block, then Context) |
| A security principle changes | `docs/security-principles.md` |

`CHANGELOG.md` and `docs/adr/` may cite plan item and finding ids that a tracked plan defines; code may not (`pv-comments.md`).

## Installed Copies (ADR-0005)

- Never write `<agentDir>/config/pi-verdict.json` or an installed copy: they are the user's live gate, and the gate itself denies those writes.
- On omp, the live gate is the git-spec install in `~/.omp/plugins`, pinned by commit in the user's agent-setup repository (`~/src/agent-setup`, `agents/omp/pi-verdict-pin.json`), which also deploys the policy file. A release reaches the user only through a pin bump there; coordinate it with that repository's session.
- On pi, the user tests a build by copying the `extensions/pi-verdict/` directory and `extensions/jev-adapter.ts` into `~/.pi/agent/extensions/` and restarting pi. Delete a stale `~/.pi/agent/extensions/pi-verdict.ts` first, or two gates load.

## Smoke-testing a build without touching the installed copy

Spawn a sub-instance that loads only the repo copy, against a throwaway agent dir (never the live `~/.omp/agent`):

- Create a temp agent dir containing `config/pi-verdict.json` (test config) plus copies of `agent.db`, `config.yml`, `models.db` and `models.yml` from `~/.omp/agent`; `models.yml` fetches the OpenRouter key from OpenBao (`bao kv get`), so the key reaches only the omp process.
- Run from a throwaway project dir: `PI_CODING_AGENT_DIR=<tmp> omp -p --no-session --no-title --no-extensions -e <repo>/extensions/pi-verdict/index.ts --tools read,bash --no-lsp "<prompt>"`. `-p` has no UI, so asks degrade to deny — this exercises the headless path only; interactive dialogs and `/verdict` are covered by the stub tests.
- Delete the temp dir afterwards.

## Release

- Sequence: `chore(release): bump version` commit (bump `package.json` version; move `## [Unreleased]` to `## [X.Y.Z] - <date>`) + annotated tag `vX.Y.Z` + `bun run release-check` + push + GitHub Release. `gh release` commands are blocked by the built-in deny floor, so the user runs them from their own terminal.
- This checkout has three remotes (`origin` = `jonatsu/pi-verdict`, `frapetti` = `frapetti-dev/pi-verdict`, `upstream` = the original `jesset/pi-verdict`). `gh` defaults to `jonatsu/pi-verdict` through `gh repo set-default`, which is local git config; in a fresh clone, run `gh repo set-default jonatsu/pi-verdict` first, because otherwise `gh` may query the original repository.
- Publishing is automated: Release published → `.github/workflows/publish.yml` (tag/version double-check + typecheck + tests + publish to GitHub Package Registry). The workflow runs as it stands at the tagged commit.

## Git & Workflow Conventions

- Feature branches: `feat/description-with-dash-separated-and-MAY-contains-issue-number`.
- [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) for messages. Commit verified work without asking; push only with the user's authorization.
- Update CHANGELOG before merging to main.
- Issues are GitHub issues managed via `gh`; the issue and triage docs are routed in "Where to Read".
- To inspect another GitHub project's source, use `gh api`. Clone an open-source project for research under `.scratch/research/` (git-ignored), never `/tmp`.
