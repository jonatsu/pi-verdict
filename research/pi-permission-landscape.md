# Research: Competitive Landscape of Automatic Permission Adjudication for Pi Tool Calls (pi-verdict Positioning Baseline)

> ⚠️ This is a pre-0.2.0 snapshot (pi-verdict still had a built-in allowlist). For comparison with the current state, see `pi-automode-convergence.md` (2026-08-27, including architecture convergence conclusions and classification of remaining differences).

> Related issues: #9 (README rewrite) / #1
> Research date: 2026-08-26. All data were collected firsthand that day from the npm registry API, GitHub API / READMEs / source, and locally unpacked source.
> Baseline: this repository's pi-verdict (`extensions/auto-mode.ts`, ~590-line single file, zero runtime dependencies, three-state verdicts, fail-closed, shadow-cache telemetry) — existing facts are not repeated per the task agreement and are used only for comparison.

## TL;DR

1. **The category has split into three schools, and the leaders do not use "model adjudication"**: (a) deterministic permission engines — `@gotgenes/pi-permission-system` (29.0K monthly downloads, v27.0.1, pure rules with no built-in classifier) and `cc-safety-net` (20.6K monthly downloads, 1,505 stars, an LLM-free semantic parsing interceptor supporting 11 CLIs); (b) two-stage model adjudication descended from CC auto mode — `@czottmann/pi-automode` (2.7K monthly downloads, 96 stars, 3 releases in a month, highest activity and engineering maturity) and the stalled `r4vi/pi-auto-mode`; (c) hybrid pipelines — `@zhushanwen/pi-permission` (AST + rules + single-round classifier) and the defunct `wangzexi/pi-auto-approve`.
2. **pi-verdict's differentiated combination holds**: three-state classifier semantics (competitor classifiers are almost all binary allow/block, with ask only in the rule layer), CC-style transcript context (`<verdict>` prefix contract), fail-closed + non-interactive ask→deny, `thinkingEnabled: false` (supported by this repository's thinking-param-blackhole research; in contrast to czottmann explicitly requesting a reasoning tier), a zero-dependency single file, and observe-only shadow-cache telemetry. No other implementation in the category has this **combination**.
3. **But each individual feature has precedents, so the README must avoid "first/only" claims**: two-stage classifiers (czottmann/r4vi), AST-level bash analysis (tree-sitter in zhushanwen/gotgenes, a custom parser in cc-safety-net), path-sensitivity tiers (gotgenes' directional path surfaces), and rejection-budget circuit breaking (r4vi pauses the session after 3 consecutive / 20 total rejections). pi-verdict's truly unique assets are its **evidence-driven narrative** (three live-measurement studies) and the combination of three-state verdicts × context × fail-closed behavior; position it by combination, not individual features.

---

## 2. Landscape comparison matrix

Download window: 2026-07-27 → 2026-08-25 (api.npmjs.org). The "Classifier" column refers to LLM adjudication of the gray zone.

### Table A: Adjudication design

| Project | Verdict semantics | Pipeline stages | Failure direction | Classifier context | Output contract | Model selection |
|---|---|---|---|---|---|---|
| **pi-verdict** (baseline) | Three-state allow/ask/deny | Rules (78 allowlist entries + 13 dangerous patterns + path sensitivity S0-S5) → gray-zone classifier | **closed** (exception → deny; non-interactive ask → deny) | CC-style transcript (most recent 5 user messages + 10 tool calls) | `<verdict>` prefix, two retry tiers 512→1024 | Self-reflection by default (inherits session model), overridable with `--auto-mode-model` |
| @czottmann/pi-automode | Three-state rule layer; **binary classifier** allow/block | Deny rules → ask rules → deterministic hard deny → path rejection → three allow tiers → one-token conservative filter → structured review | **closed** (model/parse failure → block) | Token-budgeted transcript selection | One token (0/1) → structured JSON; two tiers 512/1200 | Dedicated classifier model (`/automode model`), can request a reasoning tier |
| @gotgenes/pi-permission-system | Three-state allow/ask/deny (**purely deterministic**) | Path surfaces → CWD-boundary surfaces → per-tool → bash modes; strictest wins | **closed** (internal gate error → block; unparseable bash → ask) | **No classifier** (LLM can only be optionally attached via `authorizerChain`) | No LLM contract; authorizer-chain contract allow/deny/defer | Optional attached chain, e.g. pi-permission-model-judge |
| cc-safety-net | block / allow (parser) | Semantic command analysis (10 nested wrapper levels, single-line interpreter) → secret-path protection → rulebook | **closed** (malformed input → block; Strict mode blocks unparseable input) | No LLM | None | None |
| r4vi/pi-auto-mode | Binary (YES/NO → shouldBlock); interactive three-way choice after rejection | Read-only allowlist → hard deny → two-stage classifier | **Configurable `failOpen`, default true (fail-open!)** | Session branch carried in `<transcript>` | Stage 1 YES/NO; stage 2 `{"shouldBlock","reason","thinking"}` | Dedicated model (`/auto-mode model` selector) |
| flaxodev/pi-perms | No verdict (mode switching) | Dangerous-bash regex confirmation table (by mode) | None (unblocked calls pass) | No LLM | None | None |
| @zhushanwen/pi-permission | Three-state (outcome includes ask) | tree-sitter AST → rules → classifier (races human approval) | **closed** (exception → ask; headless ask → deny) | **Single round, no context** | Four-field JSON `{outcome,risk_level,reasoning,confidence}` | `classifier.model:"auto"` (first scoped model with credentials) or explicit specification |
| wangzexi/pi-auto-approve | Binary allow/block | 15 allow regexes → 7 block regexes → self-review | **open** (timeout/error/parse failure → allow) | Full conversation context (strips toolCall/toolResult, wraps command in CDATA) | Exactly two keys `{"verdict","reason"}` | Self-reflection (same session model), reuses the main session's prefix cache |

### Table B: Engineering and operations

| Project | Rule-layer capabilities | Mode/UX | Configuration surface | Dependencies/size | Tests | Cache/telemetry | Monthly downloads | Activity (as of 08-26) | License |
|---|---|---|---|---|---|---|---|---|---|
| **pi-verdict** | 78 allowlist entries + 13 dangerous regexes + path sensitivity S0-S5 | /automode on\|off; footer; --auto-mode-debug | CLI flag + JSON (see repository) | **0 runtime dependencies**; ~590-line single file | Repository tests | Shadow-cache telemetry (observe-only) + three live-measurement studies | Not published to npm | This repository | MIT |
| @czottmann/pi-automode | CC permissions.deny/ask/allow + hard deny + deniedPaths glob (resolves symlinks, recursively checks grep/find scope) | 8 `/automode` subcommands; status line `AM● a: d: ca: cd:`; read-only agent tool `automode_inspect` + companion skill; ADR docs | Global + project local (after trust) + env; **shared project files cannot weaken policy (tamper-resistant)** | 1 dependency (unbash); 262KB | 10 test files (including classifier routing/staged parsing and caching/symlinks) | Classifier cache; rejection counter; observable logs | 2,725 | v1.13.0 (08-25); first release 6-14, 17 releases; pushed that day | MIT |
| @gotgenes/pi-permission-system | tree-sitter bash gate; **directional path surfaces** (read/write split); MCP/skill-granular gates; hides disabled tools; subagent integration | Inline hotkey approval dialog (y/s/n/r, double-click confirmation); session-level approval; event broadcast | Global + project (trust-gated) + per-agent frontmatter; last matching rule wins | 3 dependencies (tree-sitter×2 + zod); 1.37MB; 144 src files | **147 test files** | review-log audit (gate_error, etc.) | **28,976** | v27.0.1 (08-24); first release 5-03, 186 releases | MIT |
| cc-safety-net | Semantic parsing (detects reordered flags/wrappers/single-line interpreter escapes); secret protection (SSH/.env/.aws/credential stores across tools); SHA-256-locked rulebook | Standard/Strict/Paranoid presets; status/doctor/explain/logs/gui CLI; Web GUI | Rulebook (user/project) + presets | 1 dependency (zod); 1.76MB; supports 11 CLIs | CI + codecov (README badge) | **Local JSONL audit log (redacted, 30-day default retention)** | 20,563 | v2.2.2 (08-25, 3 releases that day); first release 2026-01, 37 releases | MIT |
| r4vi/pi-auto-mode | Read-only allowlist (merges .claude settings allowlists) + hard deny; **rejection budget** (3 consecutive / 20 total rejections → pause session) | Footer; rejection-history widget; three choices after rejection (block/allow once/turn off auto mode and allow); system-prompt injection | auto-mode.example.json | 0 dependencies (but peer locks old @mariozechner/* namespace); 50KB; 1,171-line single file | CI exists (publish.yml); no tests seen | Rejection count/history | 6x | v0.1.2 (**2026-05-16, stalled for 3 months**) | MIT |
| flaxodev/pi-perms | Hard-coded dangerous-bash regex list (rm -rf/sudo/git push/curl\|sh/DDL, etc.) | **Shift+Tab cycles through four modes** (normal/accept edits/plan/bypass) + footer indicator; persists across restarts; /perms | No configuration file | 0 dependencies; single file extensions/index.ts | None seen | None | Not published to npm (npm `pi-perms` belongs to Mearman) | Repository had a push on 08-25, but no npm release channel | MIT |
| @zhushanwen/pi-permission | tree-sitter AST (11-node allowlist, port of Codex bash.rs) + 50 unconditional/9 conditional safe commands + 12 dangerous regexes + **TUI rule editor** | Four modes: yolo/auto/approve/strict; statusline coloring | `<agentDir>/config/permission-ext-config.json` (generated on first run) | 4 dependencies + 3 peers; 568KB | **25 test files** (local `find` count) | No cache | 1,326 | v1.3.3 (08-24); 3 releases in August | MIT |
| wangzexi/pi-auto-approve | 15 allow + 7 block regexes | /autoapprove toggle; toast shows cache hit rate | Env debug variable only | Single file; depends on old pi-ai package-root export (**pi-ai@0.84.3 no longer exports it; live test returned undefined**) | None seen | Cache hit-rate toast | Not on npm (404) | No repository push after 06-20; **runtime is broken** | Unmarked (no LICENSE found in repository) |

---

## 3. Project-by-project details (core mechanisms + sources)

### 3.1 @czottmann/pi-automode (specifically requested by the user)

- Independent reimplementation of CC auto mode; explicit disclaimer: "It is not a sandbox" and "does not protect the user's `!`/`!!` commands." The README acknowledges that CC's actual classifier is private and that this package implements "the documented priority and configuration behavior." (Source: github.com/czottmann/pi-automode README)
- Fifteen-step adjudication flow: deny rules → ask rules (after acceptance, **must pass through the classifier**) → deterministic hard denies (shell profile/authorized_keys/cron/TLS weakening/self-modification) → path rejection (including symlink aliases and recursive search scope) → three allow tiers (inside CWD/permissions.allow/read-only tools) → **one-token conservative filter** (pass if safe, block if malformed) → structured review. **Fail-closed by default.** (Source: docs/automode-classifier-flow.md)
- Three direct comparisons with pi-verdict: (1) binary vs. three-state classifier; (2) `classifierReasoningLevel` explicitly **requests** reasoning (low ≈ Codex Auto Review), while pi-verdict explicitly disables thinking with `thinkingEnabled:false` (backed by thinking-param-blackhole research); (3) its tamper-resistant configuration is ahead (shared project files can only tighten, not loosen, policy).
- Engineering-maturity benchmark: read-only agent tool `automode_inspect` + companion diagnostic skill, status-line telemetry, 8 subcommands, ADRs, npm Trusted Publishing + provenance, and 10 test files. One runtime dependency (unbash, bash AST parsing).
- Maintenance activity: first release 6-14; 2.7K monthly downloads in August, 96 stars, v1.13.0 (08-25), pushed that day. (Source: npm API, GitHub API)

### 3.2 @gotgenes/pi-permission-system (category leader by downloads)

- A deep fork of MasuRii/pi-permission-system; a **purely deterministic permission engine with no built-in LLM classifier**. LLM adjudication can only be optionally attached through `authorizerChain` (first-party reference implementation pi-permission-model-judge, a "deny-first reviewer"; third-party pi-permission-ai-guard uses this hook too). (Source: gotgenes/pi-packages packages/pi-permission-system README)
- Four layers, with the strictest decision winning: path surfaces (read/write-separated `path_read`/`path_write`) → `external_directory` (directional CWD boundary) → per-tool modes → bash modes (tree-sitter parsing; indirect wrappers such as `bash -c`/`eval`/`sudo`/`env`/`xargs`/`find -exec` always ask). Since v16, the bash gate is fail-closed; an internal gate error → block and `gate_error` audit record.
- Distinctive capabilities: **hide disabled tools** before the agent starts; gate MCP servers/tools and skills by name; native integration with pi-subagents (subagent asks bubble up to the parent session); event-bus broadcasts.
- Scale: 144 src files / 147 test files / 3 dependencies / 1.37MB / 186 releases (since 5-03). Project config loads only after the project is trusted (an untrusted repository cannot weaken global policy).
- One-sentence difference from pi-verdict: it is "the strictest gate without a model," while pi-verdict "lets the model adjudicate with context where the rules do not reach" — the former wins on determinism and coverage; the latter on gray-zone resolution.

### 3.3 cc-safety-net (cross-CLI ecosystem, not Pi-native)

- Positioning: a PreToolUse interceptor across 11 coding CLIs (Claude Code/Codex/Cursor/Gemini CLI/OpenCode/Pi, etc.); **no LLM**. Semantic command parsing prevents escapes through flag reordering, shell wrappers (10 nested levels), and interpreter one-liners (`os.system("rm -rf /")` inside `python -c`); it distinguishes `git checkout -b` (allow) from `git checkout --` (block). (Source: github.com/kenryu42/cc-safety-net README)
- **Pi integration runs as an in-process extension** (`pi install npm:cc-safety-net`), not a hook subprocess. However, the Pi adapter analyzes only the built-in `bash` tool as a shell command; other tools get protected-path checks only, and custom Shell tools are unsupported — narrower coverage than a Pi-native extension. (Source: Pi section of ccsafetynet.com/docs/installation)
- Fail-closed: malformed hook input blocks; unparseable input blocks in Strict mode; **corrupt configuration does not block** (falls back to protective defaults and reports the issue) — aligned with pi-verdict's direction but tolerant of configuration errors.
- Heaviest operations footprint: three presets, SHA-256-locked rulebook, local redacted JSONL audit (30-day default), full doctor/explain/logs/gui CLI, and a trilingual Chinese/Japanese/English documentation site. 1,505 stars; first released 2026-01 (earliest in the category).
- One-sentence difference from pi-verdict: it is a "model-free cross-CLI interception net," complementary to rather than in the same category as gray-zone model adjudication; its secret protection and audit log are productization examples that pi-verdict's shadow-cache telemetry can be compared with.

### 3.4 r4vi/pi-auto-mode (npm: pi-auto-mode — placeholder for this repository's former name)

- Pi port of lghupan/cc-automode: read-only allowlist (also merges `.claude/settings*.json` allowlists) → deterministic hard deny → **two-stage classifier** (stage 1: conservative YES/NO filter, "Err toward YES if uncertain"; stage 2: `{"shouldBlock","reason","thinking"}` JSON). Both stages carry `<transcript>` from `sessionManager.getBranch`. (Source: github.com/r4vi/pi-auto-mode README + extensions/auto-mode.ts:585-658)
- **`failOpen` defaults to true** (source :53, exception paths :1085-1096) — the only active implementation in the category that defaults to allowing; the README does not state this default.
- Rejection budget: 3 consecutive / 20 total rejections → automatically pause the session (source :828-832); after rejection, interactive choices are block / allow once / turn off auto mode and allow.
- Status: stalled after v0.1.2 (05-16), 61 monthly downloads, and peer dependencies remain locked to the old `@mariozechner/*` namespace. **The naming collision is a real issue the repository's README must address**: npm's `pi-auto-mode` has the same name as this repository's former name but belongs to someone else.

### 3.5 flaxodev/pi-perms (note the naming collision with Mearman/pi-perms)

- CC-style permission-mode switcher: Shift+Tab cycles through normal/accept edits/plan/bypass; colored footer indicator; persists across restarts; `/perms` selector. "Dangerous bash" is a hard-coded regex list (rm -rf, sudo, git push, npm publish, curl|sh, DDL, etc.), with no AST, no LLM, and no failure semantics. (Source: github.com/flaxodev/pi-perms README)
- **The npm package `pi-perms` is unrelated**: that package belongs to Joseph Mearman (Mearman/pi-perms, Apache-2.0, v2.1.0, stalled after 05-12); it is a separate project that loads cross-agent policy from `.agents/permissions.json`, evaluates deny→ask→allow, and provides a pure-rule thin wrapper around the agent-perms library. (Source: `npm view pi-perms maintainers/repository`; github.com/Mearman/pi-perms README)
- One-sentence difference from pi-verdict: mode switching and automatic adjudication are orthogonal (plan/bypass are session postures, not per-call verdicts), so they can coexist; it fills Pi's missing CC-style keyboard-shortcut experience.

### 3.6 @zhushanwen/pi-permission@1.3.3 (verified against local source)

- Four modes (yolo/auto/approve/strict) × three pipeline layers: tree-sitter AST (11-node allowlist, faithful port of Codex bash.rs; >65536 characters or parse failure → fail-closed) → rules (50 unconditional + 9 conditional safe commands, 12 dangerous regexes, user rules + TUI editor) → classifier (**single round, no context**, four-field JSON contract; `autoDenyHighRisk` can force high+allow to deny; **races** human approval, and the user's response first aborts the AI). (Source: local unpacked `~/tmp/pi-permission-pkg/package` and this repository's `research/pi-model-call-and-ref-implementations.md` §3.1)
- Fail-closed: any exception → ask; headless ask → deny. No cache.
- Local verification supplement: 4 runtime dependencies (tree-sitter-bash, web-tree-sitter, @zhushanwen/pi-extension-logger, @zhushanwen/pi-llm-shared) + 3 peers; **25 `*.test.*` files** counted live (15 in src/__tests__ + 10 in subdirectories).
- One-sentence difference from pi-verdict: it is a hybrid with "the heaviest AST and lightest model" (the classifier judges one round blindly), while pi-verdict is the opposite (light rules, context-heavy classifier) — their pipeline emphases are mirror images.

### 3.7 wangzexi/pi-auto-approve (reusing this repository's existing extraction)

- Three tiers: 15 allow regexes → 7 block regexes → self-review (same session model + full conversation context; strips toolCall/toolResult to prevent format interference; wraps commands in CDATA; reuses the main-session prefix cache with `cacheRetention:"short"` + sessionId; toast shows hit rate). Contract has exactly two keys, `{"verdict","reason"}`. (Source: `research/pi-model-call-and-ref-implementations.md` §3.3; github.com/wangzexi/pi-auto-approve)
- **Fail-open**: a 30s timeout/error/parse failure always allows (blocks only with no UI or no model) — the opposite of pi-verdict.
- Defunct: not on npm (404), no repository push after 06-20, and the `completeSimple` import no longer exists at the pi-ai@0.84.3 package root (verified in the existing extraction).
- One-sentence difference from pi-verdict: the category's only fail-open experiment and only classifier experiment to reuse the main-session prefix cache; these respectively serve as a cautionary example and a cache-design reference for pi-verdict.

---

## 4. Implications for README issue #9

**Positioning language**

1. Avoid the main keyword "auto mode": npm's `pi-auto-mode` is r4vi's stalled package, and `@czottmann/pi-automode` is an active leader, so both SEO and mindshare are occupied; "permission" is occupied by pi-permission/pi-permission-system. **Verdict is an unoccupied name, and its three-state semantics explain themselves** — #9's naming section is on the right track and should become the main positioning axis: "Most competitors' classifiers only do binary allow/block; a verdict is a judgment, not a switch."
2. Suggested one-sentence positioning skeleton: "Pi defaults to YOLO. verdict gives every tool call a three-state judgment: allow / ask / deny — rules first, with the gray zone handed to a classifier with full context, and every failure handled fail-closed." (Consistent with #9 requirement 1; verified not to collide with competitor wording.)
3. Borrow two mature disclaimers: czottmann's "It is not a sandbox" and cc-safety-net's "Why not just use a sandbox?" — the category leaders explicitly state that they do not define a security boundary. pi-verdict's README should do the same; it is category consensus, not a sign of weakness.

**What to emphasize** (ordered by strength of evidence)

4. Combination, not individual features: the package "three-state × transcript context × fail-closed × zero-dependency single file" has no second implementation — Table A can be trimmed into a lightweight README comparison table (recommended columns: three-state? / carries context? / failure direction / runtime dependencies).
5. Evidence-driven brand: three live-measurement studies are unique across the category (no competitor README includes live-measurement data); cache-sim's hit-rate data, thinking-param's three-layer evidence, and rule-engine-sim's port rejection each answer "why is it configured this way by default?" in ways competitors cannot. czottmann's honest "Known limits" section is a model; pi-verdict can link research instead of making unsupported verbal admissions.
6. `thinkingEnabled: false` merits a one-line selling point: unlike czottmann explicitly requesting reasoning (its docs acknowledge that a high reasoning tier can exhaust 512/1200 tokens and cause fail-closed behavior), pi-verdict's choice is backed by blackhole research — describe it as "we measured this," rather than criticizing another project by name.

**What to avoid**

7. Avoid superlatives such as "first/only/lightest": cc-safety-net has existed since 2026-01, and gotgenes has released 186 versions since May; "zero-dependency single file" is supportable, but "lightest" is not (r4vi is smaller at 50KB).
8. Do not compare downloads/stars (the package is not published to npm, so it would lose on those figures); do not name and attack a competitor with claims such as "safer than X."
9. Do not make fail-open competitors the target: wangzexi is defunct, and r4vi's `failOpen` is configurable despite defaulting on — those attack points will go stale. State pi-verdict's own fail-closed semantics positively (including non-interactive ask→deny, a detail no competitor README emphasizes).
10. Do not imply that rule coverage leads the category: 78 allowlist entries vs. zhushanwen's 59 safe commands + AST and gotgenes' four-layer gate — rule count is not the differentiator; resolution (three-state gray-zone verdicts) is.

---

## Endnotes: Data and sources

- Collection date: 2026-08-26 (npm download window 2026-07-27 → 2026-08-25; GitHub pushed_at / stars are snapshots from that day).
- npm registry: `npm view <pkg>` and api.npmjs.org/downloads — @czottmann/pi-automode, @gotgenes/pi-permission-system, cc-safety-net, @zhushanwen/pi-permission, pi-auto-mode (r4vi), pi-perms (Mearman).
- GitHub READMEs / docs (github.com):
  - czottmann/pi-automode (README, docs/automode-classifier-flow.md, docs/configuration.md)
  - gotgenes/pi-packages (packages/pi-permission-system/README.md, git-tree counts)
  - kenryu42/cc-safety-net (README) + ccsafetynet.com/docs/installation (Pi integration section)
  - r4vi/pi-auto-mode (README, extensions/auto-mode.ts@master source, 1,171 lines)
  - flaxodev/pi-perms, Mearman/pi-perms, wangzexi/pi-auto-approve (READMEs)
- Local source: `~/tmp/pi-permission-pkg/package` (@zhushanwen/pi-permission@1.3.3 unpacked from npm tarball; dependencies and test count rechecked that day).
- Reused material from this repository: research/pi-model-call-and-ref-implementations.md §3.1 (zhushanwen), §3.3 (wangzexi), §3.4 (gotgenes Authorizer-chain hook).
