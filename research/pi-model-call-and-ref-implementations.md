# Research: Model-Call APIs and Configuration Access in Pi Extensions, with Extracted Implementations from Three Permission Extensions

> Related issue: #2 (Part of #1)
> Research date: 2026-08 (based on the locally installed versions: `@earendil-works/pi-coding-agent` + `@earendil-works/pi-ai@0.84.3`)
> All conclusions were verified against primary sources: locally installed official Pi documentation and dist types/implementation; the npm-package source of three extensions (unpacked with `npm pack`); and GitHub repository clones (at `/Volumes/RamDisk/pi-research/`).

## TL;DR

1. **Model calls**: The official helper already exists — `ctx.modelRegistry.complete(model, context, options)` (automatically resolves credentials internally); pass `ctx.signal` directly as `options.signal`. For **self-reflection** (inherit session model + credentials), pass `ctx.model` as `model`; `ctx.modelRegistry.getApiKeyAndHeaders(ctx.model)` can retrieve credentials explicitly. There is no need to fetch a provider API yourself.
2. **Configuration reading**: `settings.json` has **no API for reading extension-specific custom keys** (`ExtensionContext` has no settings accessor). Official options: the extension's own config file (under global `getAgentDir()`, or under project `.pi/` with `CONFIG_DIR_NAME` to construct the path + `ctx.isProjectTrusted()` gating), CLI flags via `pi.registerFlag()/pi.getFlag()`, and environment variables (`process.env`). All three reference extensions use their own JSON config files.
3. **Reference implementations**: The prompts, rule sets, caching/circuit breaking, and verdict contracts of all three extensions were extracted file by file (see Section 3); a directly reusable "rule-layer seed set" appears at the end.

---

## 1. Model-call mechanism (subquestion 1)

### 1.1 Official helper: `ctx.modelRegistry.complete()` — no need to fetch yourself

`ExtensionContext.modelRegistry` is an instance of the `ModelRegistry` class; its type declaration is in the locally installed `node_modules/@earendil-works/pi-coding-agent/dist/core/model-registry.d.ts:33`:

```typescript
complete<TApi extends Api>(model: Model<TApi>, context: Context, options?: ModelsApiStreamOptions<TApi>): Promise<AssistantMessage>;
```

The same file also declares credential-resolution methods:

- `getApiKeyAndHeaders(model)` → `Promise<ResolvedRequestAuth>` (`{ ok: true; apiKey?; headers?; baseUrl?; env? } | { ok: false; error }`) (`model-registry.d.ts:11-16, 29`)
- `getProviderAuth(provider)` → `Promise<AuthResult | undefined>` ("resolves its current API key, headers, base URL, and provider-scoped environment without requiring a loaded model") (`model-registry.d.ts:35`; docs `docs/extensions.md:995-997`)
- `find(provider, modelId)`, `hasConfiguredAuth(model)`, `getProvider(provider)` (`model-registry.d.ts:27-34`)

**Credentials are resolved automatically inside Pi; extensions do not need to touch API keys.** Call chain: `ModelRegistry.complete()` → `ModelRuntime.complete()` → `stream()` → `prepareRequest()` (`dist/core/model-runtime.js:422-451`); the latter calls `this.getAuth(model, ...)` to resolve `apiKey/headers/baseUrl/env` and inject them into the provider request. Credential lookup order (auth.json → environment variables → custom provider in models.json) is documented in `docs/sdk.md:445-448`.

`options` (through `ModelsApiStreamOptions` → `StreamOptions` → `ProviderRequestOptions`) supports:

- `signal?: AbortSignal` (`@earendil-works/pi-ai/dist/types.d.ts:53`) — pass `ctx.signal` directly; Esc then cancels the nested model call (the docs explicitly list "model calls that accept `signal`" at `docs/extensions.md:1001-1011`).
- `cacheRetention?: "none" | "short" | "long"`, `sessionId?: string` (`pi-ai/dist/types.d.ts:128-137`) — prefix caching and session affinity.
- `reasoningEffort`, `maxTokens`, `temperature`, `timeoutMs`, etc.

**Official example**: `examples/extensions/summarize.ts:163-187` fully demonstrates an independent model call inside an extension:

```typescript
const model = ctx.modelRegistry.find("openai", "gpt-5.2");
if (!ctx.modelRegistry.hasConfiguredAuth(model)) { /* fallback */ }
const response = await ctx.modelRegistry.complete(
  model,
  { messages: summaryMessages },
  { reasoningEffort: "high", cacheRetention: "none", sessionId: uuidv7() },
);
// extract blocks where type === "text" from response.content
```

### 1.2 Implementing "self-reflection" (inherit current session provider/model + credentials)

`ctx.model` is the active model for the current session (`docs/extensions.md:995-997`; "`ctx.model` is the active model"). The simplest self-reflection call is therefore:

```typescript
pi.on("tool_call", async (event, ctx) => {
  if (!ctx.model) return { block: true, reason: "no active model" };
  const response = await ctx.modelRegistry.complete(
    ctx.model,                                   // inherit the session's current provider/model
    { messages: [/* adjudication prompt */] },
    { signal: ctx.signal, cacheRetention: "short",
      sessionId: ctx.sessionManager.getSessionId(),
      temperature: 0, maxTokens: 80 },
  );
  // credentials are resolved internally by ModelRuntime.prepareRequest; no need to read the API key
});
```

To retrieve credentials explicitly (for example, when bypassing the registry to call a provider directly), use `await ctx.modelRegistry.getApiKeyAndHeaders(ctx.model)` — this is a discriminated union; narrow it with `if (!auth.ok)` before accessing `apiKey/headers/env` (as in pi-llm-shared `src/call.ts:95-99`).

### 1.3 Alternative paths used by the three reference extensions

| Path | User | Notes |
|---|---|---|
| `ctx.modelRegistry.complete()` | Official summarize.ts example | **Recommended**. Credentials resolved internally; stable API (class method, not deprecated). |
| `ctx.modelRegistry.getProvider(id).streamSimple(model, ctx, opts).result()` | pi-permission-ai-guard `src/model-review.ts:78-88` (`createCompleteSimple`) | Not deprecated; the caller must inject `apiKey/headers` from `getApiKeyAndHeaders`. |
| `completeSimple` from `@earendil-works/pi-ai/compat` | @zhushanwen/pi-llm-shared `src/call.ts:17` | compat is a "temporary compatibility entry point" (`pi-ai/dist/compat.d.ts:1-10` header comment: "This module is deleted with the coding-agent ModelManager migration"); `completeSimple`/`streamSimple` are declared in `compat.d.ts:65-66`. |
| `completeSimple` from `@earendil-works/pi-ai` (package root) | wangzexi/pi-auto-approve `auto-approve.ts:18` | **Compatibility risk**: pi-ai@0.84.3 no longer exports `completeSimple` at the package root (live `import()` test returned `typeof === "undefined"`); the extension was written for an older pi-ai. Do not use in new code. |

Accounting for nested calls: if a nested LLM call is made from a **custom tool**, its `usage` can be reported in the tool result (`docs/extensions.md:1995`); the `tool_call` hook has no such channel, so this is only a note.

Parallel tool calls: when `tool_call` fires, `ctx.sessionManager` is synchronized through the current assistant message, but is not guaranteed to include sibling tool results from the same batch (`docs/extensions.md:764-766`). If a `tool_call` handler throws, that tool is blocked fail-safe (`docs/extensions.md:2904`).

---

## 2. Configuration reading (subquestion 2)

### 2.1 No extension-specific custom-key API in settings.json

The full `ExtensionContext` field list (`dist/core/extensions/types.d.ts:209-249`) is `ui / mode / hasUI / cwd / sessionManager / modelRegistry / model / scopedModels / thinkingLevel / isIdle() / isProjectTrusted() / signal / abort() / hasPendingMessages() / shutdown() / getContextUsage() / compact() / getSystemPrompt()` — **there is no settings accessor**. The full "All Settings" table in `docs/settings.md` also has no mechanism for extension-specific custom keys. Conclusion: settings.json applies only to Pi's built-in keys; extensions should not add custom configuration to it.

### 2.2 Four officially supported options

1. **Extension-owned JSON config file (project-level)** — the only approach explicitly demonstrated in the docs (`docs/extensions.md:958-973`):

   ```typescript
   import { CONFIG_DIR_NAME, type ExtensionAPI } from "@earendil-works/pi-coding-agent";
   const projectConfigPath = join(ctx.cwd, CONFIG_DIR_NAME, "my-extension.json");
   ```

   Gate project-level config reads with `ctx.isProjectTrusted()` (`docs/extensions.md:976-980`: "Use this before reading project-local extension configuration that should only be honored for trusted projects").

2. **Extension-owned config file (global)** — `getAgentDir()` is an official export (`dist/index.d.ts:2` re-export; `dist/config.d.ts:77`) that returns the Pi agent directory (default `~/.pi/agent`, honoring the `PI_CODING_AGENT_DIR` environment variable). Extensions can create their own config subpath there.

3. **CLI flags** — `pi.registerFlag(name, { description, type, default })` + `pi.getFlag(name)` (`docs/extensions.md:1633-1648`), suitable for toggle-style configuration (such as plan-mode's `--plan`).

4. **Environment variables** — extensions run as in-process Node code and can use `process.env` directly (official examples: `examples/extensions/interactive-shell.ts:102,105` use `INTERACTIVE_COMMANDS` / `INTERACTIVE_EXCLUDE`).

### 2.3 Practices used by the reference extensions (all verified)

| Extension | Config location | Mechanism |
|---|---|---|
| @zhushanwen/pi-permission | `<agentDir>/config/permission-ext-config.json` | Derived from `getAgentDir()`; creates default config on first run; fields: `mode(yolo/auto/approve/strict)`, `enabled`, `classifier.{enabled,model,timeout,autoApproveLowRisk,autoDenyHighRisk,thinkingLevel}`, `userRules[]` (`src/config.ts:6-14, 44-46`; README). |
| pi-permission-ai-guard | Global `<agentDir>/extensions/pi-permission-ai-guard/config.json` + project `<cwd>/.pi/extensions/pi-permission-ai-guard/config.json` | Two-layer read and deep merge (project overrides global), zod validation; skips the project layer when `trustedProject: false` (`src/config-loader.ts:50-58, 111-145`); invalid config → does not register the adjudication chain (fail-safe degradation to no automatic review, never a wrong decision). |
| wangzexi/pi-auto-approve | No config file | `/autoapprove` command toggles an in-memory switch + `PI_AUTO_APPROVE_DEBUG_REVIEW` environment variable (`auto-approve.ts:69-71, 224-230`). |

---

## 3. Reference implementation extractions (subquestion 3)

Research clones: `/Volumes/RamDisk/pi-research/{pi-permission, pi-llm-shared, pi-permission-ai-guard, pi-auto-approve, pi-packages}`.

### 3.1 `@zhushanwen/pi-permission@1.3.3` — three-layer pipeline (AST + rules + AI classifier)

**Architecture**: `checkPermission()` is the pure-function entry point (`src/pipeline.ts:411`), with four modes:

- `yolo`: allow everything; `strict`: require human approval for everything.
- `approve`: layer 1 AST → layer 2 rules (allow → allow / deny → deny / ask → human, no AI).
- `auto`: layer 1 AST → layer 2 rules → on ask, enter layer 3, where the **AI classifier races human approval** (`runLayer3WithRacing`, `pipeline.ts:229`).

**Fail-closed general rule**: any exceptional path → ask (auto mode) or human; never silently allow. In headless (json/print) modes, an AI ask → fail-closed deny (`pipeline.ts:267-281`).

**Layer 1 — AST structural analysis** (`src/ast/analyzer.ts`): uses web-tree-sitter to faithfully port Codex `bash.rs`'s `try_parse_word_only_commands_sequence`. The 11-node allowlist is program/list/pipeline/command/command_name/word/string/string_content/raw_string/number/concatenation + 6 punctuation tokens (`&&` `||` `;` `|` `"` `'`); any other structure (command_substitution/file_redirect/subshell/backtick/redirection, etc.) → `clean: false` and passes directly downstream. Input over 65536 characters or a parse failure → fail-closed (`analyzer.ts:31-57`). Produces `commands: string[][]` (splits compound commands into individual argv arrays).

**Layer 2 — Rule matching** (`src/rules/`):

- **Allowlist = function-based checks, not regexes**: `isKnownSafeCommand(argv)` (`builtins.ts:535`) = 50 unconditional safe commands (`BUILTIN_UNCONDITIONAL_SAFE`, `builtins.ts:37-89`: cat/ls/grep/find (note: find is actually in the conditional group)/head/tail/wc/jq, etc.) + 9 conditional commands with argv-level flag checks (`builtins.ts:91-101`: base64 forbids `-o/--output` and combined short-flag clusters containing `o`; find forbids `-exec/-delete/-fprint*`; rg forbids `--pre/--hostname-bin/-z`; git permits only read-only `status/log/diff/show/branch` subcommands and forbids global options such as `-C/-c/--exec-path`; sed permits only `sed -n {N|M,N}p`; sort/iconv/shuf forbid `-o`; date forbids `-s`). Ported from codex-rs `is_safe_command.rs`.
- **Danger rules = 12 regexes** (`BUILTIN_DANGER_RULES`, `builtins.ts:552-666`): bd-001 `rm` with recursive flag; bd-002 `sudo`; bd-003 `chmod 777/a+rwx/ugo+rwx`; bd-004 raw-device writes (`> /dev/sd*` / `dd of=/dev/*`); bd-005 `git push --force`; bd-006 `git reset --hard`; bd-007 `git clean -f`; bd-008 `git checkout .`; bd-009 `git restore`; bd-010 `curl|wget ... | sh/bash`; bd-011 `gh repo create/delete/rename/archive`; bd-012 `gh release create/delete/edit`. All use `action: "deny"` and are compiled with `new RegExp(pattern, "i")`.
- **Aggregation semantics** (`runLayer2`, `pipeline.ts:130-166`): match each argv; any deny → overall deny; all allow → allow; otherwise ask. **C1 addition**: run a deny check over the full command string too, covering `curl x | sh` (bd-010), which individual argv arrays cannot see after the AST splits the pipeline. For non-bash tools, wildcard-match the `tool` field against toolName and the `pattern` field against path (`matchNonBashTool`, `pipeline.ts:85-107`).
- User-defined rules: OpenCode wildcard syntax, last-match-wins.

**Layer 3 — AI classifier** (`src/classifier/`):

- **Classifier prompt** (`prompt.ts:23-38`, full text):

  ```
  You are a security risk classifier for tool invocations in an AI coding agent.
  Evaluate the given tool invocation for destructive or unsafe operations.

  Reply with ONLY a JSON object (no markdown, no prose before/after):
  {"outcome": "allow" | "deny" | "ask", "risk_level": "low" | "medium" | "high", "reasoning": "one short sentence", "confidence": 0.0-1.0}

  Rules:
  - allow: safe operations (read-only commands, writing to project directory, git status/diff/log, ls, cat, echo, grep, find)
  - deny: clearly destructive AND irreversible (rm -rf /, mkfs, force push to main, drop database, format disk)
  - ask: potentially dangerous or system-wide changes (rm with recursion, sudo, writing to system dirs like /etc, network operations, deleting multiple files)
  - For file writes: allow if writing to user's project/cwd directory; ask if writing to system dirs or sensitive paths (~/.ssh, /etc)
  - confidence = your certainty in the outcome (0.0 = guessing, 1.0 = certain)
  ```

  The comment says it is deliberately kept to ~80 tokens to reduce first-call latency. The user prompt is four or five key-value lines for `tool/command/path/cwd(/agent)` (`prompt.ts:41-52`).
- **Risk-tier contract**: `ClassifierResult { outcome: allow|deny|ask, risk_level: low|medium|high, reasoning: string, confidence: 0-1 }`. **Bias correction** (`applyAutoApproveOverrides`, `pipeline.ts:181-201`): `high + allow + autoDenyHighRisk=true` → force deny; `low + allow + autoApproveLowRisk=false` → force ask. In other words, the AI's allow is not trusted at high risk.
- **Model resolution**: `classifier.model: "auto"` selects the first available model with credentials from the session's scopedModels; otherwise, specify `provider/model-id` exactly. Uses `ctx.modelRegistry` (`find` + `hasConfiguredAuth`), and does not read models.json itself (`src/classifier/model-resolver.ts:12-26, 60-97`; README).
- **LLM call**: Uses @zhushanwen/pi-llm-shared `callLLM` (`pi-llm-shared/src/call.ts:88-132`): `completeSimple` (compat subpath) + `getApiKeyAndHeaders` to inject credentials; normalizes `stopReason: error/aborted` to `{ok:false, stopReason}`; an outer timeout + signal race prevents a hang (`classifier.ts:92-130`). All failures → fail-closed `{outcome:"ask", risk_level:"medium", confidence:0}`.
- **Parsing tolerance**: Three stages — greedy regex extracts JSON → `JSON.parse` → field-enum validation (clamp confidence to [0,1]); any failure → fallback ask (`src/classifier/json-parser.ts:1-26`).
- **Race semantics** (`pipeline.ts:229-403`): AI and user approval start simultaneously; if the user responds first → abort AI; if AI returns allow/deny first → close the dialog with the AI result; if AI returns ask → switch to human approval (5-minute timeout fallback, fail-closed deny).

### 3.2 `pi-permission-ai-guard@0.7.0` (kuoruan) — context minimization against injection, verdict cache, circuit breaker

**Positioning**: A non-terminal link in the Authorizer chain of `@gotgenes/pi-permission-system` (`src/review-pipeline.ts`; chain contract `AuthorizerVerdict = allow | deny(reason?) | defer`, see pi-packages `pi-permission-system/src/authority/authorizer.ts:20-41`). It runs only when the deterministic rule engine returns "ask"; if the engine already returns allow/deny, it returns defer directly (`review-pipeline.ts:92-103`). All failures → defer (pass to the next link/human), not deny.

**Context minimization (core injection defense)** (`src/transcript-stripper.ts:171-249`, `stripTranscript`): session entries are handled by trust level:

- **Keep (trusted)**: `user` messages; `ask_user_question` tool results (the user's structured answers).
- **Delete (untrusted)**: assistant text (extract tool-call names + arguments only), ordinary toolResult (injection entry point and heaviest in tokens), compaction/branch_summary (derived context, not user authorization signals), custom messages.
- **Limits**: most recent 5 user messages, 10 tool calls, 1000 characters each (truncate to first 60% + last 40%) (defaults, `src/config-schema.ts:15-19`).
- **Cleaning** (`src/utils.ts`): `normalizeText` removes zero-width characters (U+200B-200D/2060/FEFF) + collapses all whitespace to single spaces (prevents newlines from forging prompt-section headings, `utils.ts:116-118`); `redactSecrets` redacts ~20 secret patterns (AWS/Anthropic/OpenAI/GitHub/GitLab/Slack/Google/Stripe/PEM private-key blocks/Bearer, etc., `utils.ts:20-69`) + key-value pairs such as `password|token|api_key|...` (`utils.ts:76-77`); action text uses `encodeActionTextForPrompt` = JSON.stringify-escaped inline text (`utils.ts:150-152`), preserving shell whitespace without letting it create new prompt sections.

**Verdict prompt** (`src/prompt.ts`):

- system = `SAFETY_RULES` (prompt.ts:34-176) + fixed `VERDICT_SECTION` (prompt.ts:179-193; custom instructions can replace only the rules section, not the output contract).
- `SAFETY_RULES` has three tiers based on **dependence on intent**: `DENY — Always` (regardless of intent: reading secrets/credentials, irreversible destruction, exfiltrating sensitive data, system tampering and security weakening, persistent system changes, external code execution via `curl|bash`/remote package installation, exposing external listeners, destructive VCS operations, resource abuse); `DENY — Unless` (allow only with clearly matching intent: writes outside CWD, environment changes, deletion, network/browser interaction, external publishing, MCP/skill side effects); `ALLOW` (matches the current task: read-only within CWD, limited project writes, project toolchain, non-destructive local VCS). Evaluate compound commands segment by segment and use the strictest tier; if an encoded/obfuscated payload's effect cannot be determined → defer.
- **Verdict JSON contract** (`VERDICT_SECTION`):

  ```json
  {"verdict":"allow"}
  {"verdict":"deny","reason":"<risk; safer alternative if useful>","riskLevel":"low|medium|high|critical"}
  {"verdict":"defer","reason":"<what needs clarification>"}
  ```

  Parse failure/invalid fields → defer (`src/verdict.ts:100-126`).

**Verdict cache** (`src/session-state.ts:114-164`, `VerdictCache`): LRU (128 entries by default); key = `commandHash` (request snapshot: action context + cwd + policy path boundaries), value carries `contextHash` (hash of the trusted-intent chain). **A hit requires both hashes to match** — when the contextHash changes as the conversation progresses, the same command misses and is reviewed again, preventing verdicts from being reused across contexts; miss reasons (disabled/no-entry/context-changed) are recorded in telemetry. Defer is not cached (`review-pipeline.ts:137-152, 168-174`).

**Circuit breaker** (`src/session-state.ts:49-99`, `CircuitBreaker`): counts only **real model adjudications** (cache hits and breaker short-circuits do not count): deny → increment consecutive and total counts; allow → reset consecutive count; defer → unchanged. Two tiers: 3 consecutive denies trigger a recoverable tier (reset after triggering to give the model another chance) + 20 cumulative session denies trigger a hard limit (never resets); the default on trigger is `deny` (configurable to defer). Defaults are in `src/config-schema.ts:42-46`.

**Model call** (`src/model-review.ts`): `provider.streamSimple(...).result()`; `AbortSignal.timeout(timeoutMs)` is the only cancellation source (the Authorizer callback does not receive `ctx.signal`, `model-review.ts:205`); `maxTokens: 512` (`model-review.ts:64`); defaults: `timeoutMs: 15000`, model `anthropic/claude-haiku-4-5`, `reasoning: "off"` (`config/config.example.json`). A live-test pitfall: after catching abort, the Anthropic provider resolves an empty message (`stopReason="aborted"`) rather than rejecting, so empty replies must distinguish `timeout` from `empty-reply` (`model-review.ts:146-172`).

### 3.3 `wangzexi/pi-auto-approve@1.1.0` — self-reflection call path, verdict JSON contract

**Three tiers** (`auto-approve.ts`):

1. **Tier 1 automatic allow** (15 regexes, `auto-approve.ts:23-40`): `ls/dir/tree`, `cd`, `cat/head/tail/less/more`, `file/stat/wc/du/df`, `grep/rg/ag/ack`, `find/locate/which/whereis/type`, git read-only subcommands (status/log/diff/show/branch/tag/stash list/remote/ls-remote/rev-parse/rev-list/describe/whatchanged/shortlog/blame/grep/config --get), read-only docker, read-only npm/yarn/pnpm (list/info/view/outdated/audit/why), read-only pip, `echo/printenv/env/whoami/hostname/uname/uptime/id/groups/pwd/date`, `<cmd> --version/--help`.
2. **Tier 2 automatic block** (7 regexes, `auto-approve.ts:42-50`): `rm -rf /`, `rm -rf /etc|/usr|/var`, fork bomb `:(){ }`, `dd of=/dev/*` (non-null), `mkfs.*`.
3. **Tier 3 self-review**: same model + full conversation context.

**Self-reflection call path** (`auto-approve.ts:255-291`):

```typescript
const reviewModel = resolveReviewModel(ctx.modelRegistry, ctx.model);      // ctx.model is re-resolved via registry.find (lines 214-218)
const { systemPrompt, messages } = buildReviewContext(
  ctx.sessionManager, ctx.getSystemPrompt(), command);                      // reuse the main session system prompt + branch messages (line 260)
const auth = await ctx.modelRegistry.getApiKeyAndHeaders(reviewModel);      // credentials (line 261)
completeSimple(reviewModel, { systemPrompt, messages }, {
  apiKey: auth?.apiKey, env: auth?.env, headers: auth?.headers,
  cacheRetention: "short",                    // prefix cache
  sessionId: ctx.sessionManager.getSessionId(),// session affinity, reuse the main session cache prefix
  signal: ctx.signal,
  temperature: 0, maxTokens: 80,
});
```

`buildReviewContext` (lines 122-144) clones messages from `sessionManager.getBranch()` and **removes toolResult entries and assistant toolCall parts** (keeps only text/thinking), preventing an unclosed tool-call format from being fed back to the model and causing it to continue with DSML/tool-call output. It appends a user-role review request at the end (fixed rules first, dynamic command afterward, to support prefix caching). The comment states the goal: "same model/prefix segments, favoring cache hit rates" (file-header comment, lines 5-14). The UI toast also shows the cache-hit rate `CH = cacheRead/(cacheRead+input)` (lines 55-67).

**Review prompt** (`buildReviewPrompt`, lines 96-120): wrapped in `<safety_review>` XML — instruction (complete only this review, act as an internal security reviewer, do not continue the task) / rules (`<allow>` read-only low-risk actions or explicitly user-requested actions, plus user-requested public-network diagnostics; `<block>` destructive actions, secrets, credential/private-file exfiltration, state changes without clear authorization, or ambiguity) / output_contract / examples; the command is placed inside `<command><![CDATA[...]]></command>` (CDATA prevents injection; `toCdata` escapes `]]>`, lines 84-86).

**Verdict JSON contract** (lines 106-109, 146-176): **exactly two keys**, `{"verdict":"allow"|"block","reason":"..."}` (strictly checks the key set with `keys.length===2`); `extractFirstJsonObject` scans with brace balancing to extract the first JSON object (tolerates ```json fences); an empty reason or non-enumerated verdict → invalid.

**Failure policy = fail-OPEN (opposite to the other two extensions)**: a 30-second timeout → allow + toast warning (lines 293-296); `stopReason==="error"` → allow (lines 300-303); parse failure → allow (lines 308-315); catch fallback → allow (lines 317-320). It blocks only in non-interactive mode (`!ctx.hasUI`) or when there is no model/no credentials (lines 250-252, 261-265).

**Compatibility note**: `import { completeSimple } from "@earendil-works/pi-ai"` (line 18) no longer exists at the pi-ai@0.84.3 package root (live test returned undefined); the extension depends on an older pi-ai package-root export. New implementations should use `ctx.modelRegistry.complete()` or the compat subpath.

### 3.4 Appendix: Authorizer-chain hook (`gotgenes/pi-permission-system`)

For a "permission system + chain link" ecosystem rather than an independent `tool_call` hook: `@gotgenes/pi-permission-system` defines `Authorizer.authorize(details, query, log) → Promise<allow|deny|defer>` (`pi-packages/packages/pi-permission-system/src/authority/authorizer.ts:20-41`); defer = pass to the next chain link; terminal links (such as LocalUserAuthorizer) cannot defer. Third-party extensions register links with `getPermissionsService().registerAuthorizer(name, fn)` (ai-guard `src/extension.ts:136`); `query.checkPermission(...)` provides the deterministic engine's current decision (gate parity). This is the integration chosen by ai-guard, as an alternative to the independent `tool_call` hook used by pi-permission / pi-auto-approve.

---

## 4. Rule-layer seed set (ready for direct use in a prototype)

The following list merges items extracted from the three extensions and can be used directly as the initial rule layer for a pi-verdict prototype.

### 4.1 Unconditional Bash allowlist (read-only/no side effects, allow directly)

Based on pi-permission's `BUILTIN_UNCONDITIONAL_SAFE` (50 entries) + additions from pi-auto-approve Tier 1:

```
arch basename cat cd cksum cmp column comm cut diff dirname du df echo expand
expr false file fold grep groups head id jq ls md5sum nl paste printenv ps pwd
readlink realpath rev seq sha256sum shasum stat tail tr true tsort uniq uname
uptime wc whereis who whoami which
```

Additional command-prefix regexes: `tree`, `less/more`, `rg/ag/ack`, `locate/type`, `hostname/env`, `date` (forbid `-s/--set`), `<any command> --help|-h`, `<python|node|uv|tsx|npx> --version|-v`.

### 4.2 Conditional Bash allowlist (argv-level flag checks)

| Command | Allow condition | Forbidden flags |
|---|---|---|
| `git` | Only `status/log/diff/show/branch`, with read-only arguments | Global: `-C -c -p --config-env --exec-path --git-dir --namespace --paginate --super-prefix --work-tree`; subcommands: `--output --ext-diff --textconv --exec`; `branch` permits only `--list/-l/--show-current/-a/-r/-v*/--format=` |
| `find` | Default | `-exec -execdir -ok -okdir -delete -fls -fprint -fprint0 -fprintf` |
| `rg` | Default | `--pre --hostname-bin --search-zip -z` |
| `base64` `sort` `iconv` `shuf` | Default | `-o/--output` (including `o` in combined short-flag groups such as `-fo`) |
| `sed` | Only `sed -n {N|M,N}p [file]` (argv≤4) | All other forms |
| `date` | Default | `-s/--set` (including `s` in a short-flag group) |
| `npm/yarn/pnpm` | Only `list/info/view/outdated/audit/why/config list` | Other subcommands |
| `pip/pip3` | Only `list/show/freeze/search` | Other subcommands |
| `docker/podman` | Only `ps/images/inspect/logs/stats/info/version/history/top/diff` | Other subcommands |

### 4.3 Dangerous Bash patterns (deny directly, regexes, `i` flag)

Extracted from pi-permission's `BUILTIN_DANGER_RULES` (12 entries) + pi-auto-approve Tier 2 (7 entries), grouped by topic:

1. **Recursive deletion**: `\brm\b.*(\s-(?:[a-zA-Z]*r)|--recursive)`; root/system-directory specialization: `\brm\s+(-rf?|--recursive)\s+(/|/etc|/usr|/var)(?:\s|$)` (the latter is "catastrophic" and should never be configurable down to a weaker action).
2. **Privilege escalation**: `\bsudo\b`
3. **Permission weakening**: `\bchmod\b.*(777|a\+rwx|ugo\+rwx|ugo=rwx)`; optionally add chmod setuid: `\bchmod\b.*\b[ug]\+s\b`.
4. **Raw-device writes**: `(>\s*/dev/(sd|hd|nvme|mmcblk|vd|xvd)[a-z0-9]+|of=/dev/(sd|hd|nvme|mmcblk|vd|xvd)[a-z0-9]+)`; `\bmkfs\.`
5. **Destructive VCS operations**: `\bgit\s+push\s+.*(-f\b|--force\b)`; `\bgit\s+reset\s+--hard\b`; `\bgit\s+clean\b.*(\s-(?:[a-zA-Z]*f)|--force)`; `\bgit\s+checkout\s+(--\s+)?\.\s*($|[;&|])`; `\bgit\s+restore\b`
6. **Remote code execution**: `\b(curl|wget)\b.*\|\s*(ba)?sh\b`
7. **Remote GitHub changes**: `\bgh\s+repo\s+(create|delete|rename|archive)\b`; `\bgh\s+release\s+(create|delete|edit)\b`
8. **Fork bomb**: `:\(\)\s*\{`

Two engineering details to note (from pi-permission comments): anchor short-flag clusters with whitespace (`\s-`), otherwise `.*` backtracking can mistake letters in long options such as `--verbose` for short flags; pipeline patterns (`curl|sh`) must be checked against the **full command string**, because individual argv arrays cannot see `|` after AST splitting.

### 4.4 File-path sensitivity tiers (path matching for read/write/edit tools)

Synthesized from pi-permission prompt rules and ai-guard `SAFETY_RULES`:

| Tier | Paths | Default action |
|---|---|---|
| S0 Secrets/credentials (high risk even to read) | `~/.ssh/**`, `~/.aws/**`, `~/.gnupg/**`, `~/.config/gnupg/**`, `~/.config/age/**`, `~/.config/sops/**` (the last three are the fork addition for XDG dotless credential homes), `**/.env*`, `**/*credentials*`, `**/id_rsa*`, `**/*.pem`, `**/*_history`, `~/.config/gh/**`, `~/.pi/agent/auth.json` | deny (read) / deny (write) |
| S1 System configuration | `/etc/**`, `/usr/**`, `/var/**`, `/System/**`, `/etc/sudoers*`, `**/authorized_keys` | deny (write); reading → ask/AI |
| S2 User configuration (persistence entry points) | `~/.bashrc` `~/.zshrc` `~/.profile`, shell RC, `~/.gitconfig`, `crontab`, `~/Library/LaunchAgents/**`, `~/.config/systemd/**` | writing → ask/deny; reading allowed (non-secret parts) |
| S3 Repository metadata | `.git/hooks/**`, `.git/config`, `.gitmodules` | deny writes (executable-code entry points) |
| S4 Inside project (CWD) | `join(ctx.cwd, "**")` | writes allowed (bounded, matching task intent); `..`/symlink escapes count as outside CWD |
| S5 Ordinary files outside CWD | Other | writing → ask; reading non-secret files → ask or AI defer |

### 4.5 Directly reusable components of the AI adjudication layer

- **Adjudication contract**: three-state `{outcome|verdict: allow, deny|block, ask|defer}` + `risk_level` + brief `reason`, strict JSON; three-layer fault-tolerant parsing (extract JSON → parse → enum validation), on parse failure fail-closed(pi-permission) or fail-open(pi-auto-approve)——**prototype recommends fail-closed to ask**.
- **Cache**: (commandHash, contextHash) two-key LRU; defer is not cached.
- **Circuit breaker**: N consecutive denies trigger a recoverable tier + a session cumulative hard cap of M; triggering returns deny.
- **Deviation patch**: when high risk, AI's allow is untrustworthy(high+allow → deny), when low risk but automatic approval is not allowed(low+allow → ask).
- **Prompt injection defense**: separate trusted/untrusted content; untrusted text: strip zero-width characters, collapse whitespace, redact keys, inline JSON escaping; commands in CDATA; system prompt remains concise (cost/latency) but the output contract cannot be overridden by custom instructions.

---

## 5. Evidence list (primary sources)

Local installation (`~/.bun/install/global/node_modules/`):

- `@earendil-works/pi-coding-agent/docs/extensions.md` —— tool_call(70-73, 760-776), ctx.modelRegistry(995-999), ctx.signal(1001-1011), ctx.cwd project configuration(958-973), ctx.isProjectTrusted(976-980), registerFlag/getFlag(1633-1648), error handling(2904)
- `@earendil-works/pi-coding-agent/docs/settings.md` —— all built-in settings keys (no extension custom keys)
- `@earendil-works/pi-coding-agent/docs/sdk.md:445-448` —— credential lookup order
- `dist/core/model-registry.d.ts:11-35` —— `complete` / `getApiKeyAndHeaders` / `getProviderAuth` types
- `dist/core/model-runtime.js:422-451` —— `prepareRequest` credential injection implementation
- `dist/core/extensions/types.d.ts:209-249` —— ExtensionContext full fields (no settings accessor)
- `dist/config.d.ts:77` + `dist/index.d.ts:2` —— `getAgentDir()` official export
- `@earendil-works/pi-ai/dist/types.d.ts:53, 128-137` —— StreamOptions's signal/cacheRetention/sessionId
- `@earendil-works/pi-ai/dist/compat.d.ts:1-10, 65-66` —— compat temporary entry and completeSimple declaration
- `examples/extensions/summarize.ts:163-187` —— official `modelRegistry.complete` example
- `examples/extensions/interactive-shell.ts:102-105` —— environment variable configuration example

Reference extensions (research copies in `/Volumes/RamDisk/pi-research/`):

- `@zhushanwen/pi-permission@1.3.3`(npm pack):`src/pipeline.ts`、`src/rules/builtins.ts`、`src/ast/analyzer.ts`、`src/classifier/{prompt,classifier,json-parser,model-resolver}.ts`、`src/config.ts`、README
- `@zhushanwen/pi-llm-shared@0.4.1`(npm pack):`src/call.ts`、`src/resolve.ts`
- `pi-permission-ai-guard@0.7.0`(npm pack):`src/{review-pipeline,transcript-stripper,prompt,session-state,model-review,verdict,config-loader,config-schema,utils,extension}.ts`、`config/config.example.json`
- `wangzexi/pi-auto-approve@1.1.0`(github clone):`auto-approve.ts`、README.md
- `gotgenes/pi-packages`(github clone):`packages/pi-permission-system/src/authority/authorizer.ts`
