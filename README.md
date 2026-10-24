# pi-verdict

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![pi extension](https://img.shields.io/badge/pi-extension-blueviolet)](https://pi.dev)

**pi-verdict is a minimal permission gate for [pi](https://pi.dev) in the style of Claude Code's auto mode: every tool call gets checked before it runs — allow, deny, or ask you first.**

- Minimal — zero runtime dependencies
- Built-in danger rules and your own allow/deny rules settle the clear cases first, at zero latency
- Everything else goes to a model classifier that sees the conversation context
- Any uncertainty or failure fails closed; nothing ever runs silently

## The problem

pi has no built-in permission prompts — every tool call executes with the permissions of the pi process ([pi security docs](https://pi.dev/docs/latest/security)).

pi-verdict adds the missing gate: a model decides whether each call should run, based on the conversation context and your intent.

## Why three states

**verdict is an adjudication, not a switch.** Most classifiers in this space output a binary allow/block. Three states matter: `ask` routes genuinely ambiguous actions to a human (and degrades to `deny` in non-interactive sessions), so "not sure" never silently becomes "go ahead" — the goal is safe automation, not maximum automation: both approval fatigue and silent unsafe execution lose.

## Design principles

- **Fail closed** — uncertainty produces friction, never permission.
- **Deterministic floor before AI** — hard denies are never overridden by the classifier or user allow rules.
- **Semantics over syntax** — the classifier judges what an action *does*, not how long it is. The one length rule is a safety limit: an action longer than the rule layer can read (8192 characters) is asked about before any user `allow` rule can admit it.
- **Judgments, not proofs** — a classifier `allow` is an informed opinion; the floor exists because that is all it is.
- **Minimal trusted input** — no tool results in the transcript (#22), zero path plaintext to the classifier (ADR-0002).
- **Canonical identity** — dual-form matching (lexical + realpath, plus the kernel-true form of a spelling a host may open verbatim); a workspace-*looking* path is not trusted as one (#20/#21).
- **A permission gate, not a sandbox** — stack OS isolation on top; this gate never replaces it.

Full statement in [docs/security-principles.md](docs/security-principles.md).

## Screenshots

![Demo: protected-path ask declined](docs/demo.gif)

![Automode Status](docs/images/status.png)
![Ask Permission](docs/images/asked.png)

## Quick start

Published on the GitHub Package Registry as `@jonatsu/pi-verdict` (not npmjs.com). GitHub Packages requires an authenticated npm client even for public packages, so first point the scope at it and supply a token with `read:packages` — add to `~/.npmrc`:

```
@jonatsu:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```

(`GITHUB_TOKEN` here is a personal access token — classic or fine-grained with `read:packages` — exported in your shell, or hardcode it in `~/.npmrc` instead of the env-var form.)

```bash
# install from GitHub Packages (pi):
pi install npm:@jonatsu/pi-verdict

# install from GitHub Packages (oh-my-pi / omp):
omp plugin install npm:@jonatsu/pi-verdict

# or directly from git — try it once
pi --extension ./extensions/pi-verdict/index.ts

```

### Hosts

pi-verdict runs on both [pi](https://github.com/badlogic/pi-mono) and [oh-my-pi](https://github.com/can1357/oh-my-pi) (omp) — it self-anchors to whichever agent tree it is installed in, and follows the extension copy's own location on dual-install machines. On omp 18 the classifier's completion call falls back to the pi-ai compat API (still fail-closed). Details: [docs/configuration.md](docs/configuration.md#host-notes-pi-and-oh-my-pi).

| | pi | omp |
|---|---|---|
| install | `pi install npm:@jonatsu/pi-verdict` | `omp plugin install npm:@jonatsu/pi-verdict` |
| extension copy | `~/.pi/agent/extensions/` | `~/.omp/plugins/node_modules/@jonatsu/pi-verdict/` (omp 18.1+; ≤18.0: under `agent/`) |
| user rules | `~/.pi/agent/config/pi-verdict.json` | `~/.omp/agent/config/pi-verdict.json` |
| credential file (S0 hard deny) | `~/.pi/agent/auth.json` | `~/.omp/agent/auth.json` |

- `/automode` — show the current Auto Mode status
- `/automode on`
- `/automode off`
- `ctrl+shift+a` — toggle the master switch silently (the always-on footer is the only feedback; rebind or disable via `toggleShortcut`)
- `/verdict [user|local]` — edit the list rules (`allow`, `deny`, `denyPaths`, `tools`, `rules`) of the global (`user`) or project (`local`) config interactively: add / edit / remove entries, saved to disk and applied to the running session at once; also hosts the `gateOmpDir` on/off switch and the `footer` style. Other scalar keys stay hand-edited
- footer status (`footer` key): `full` = Nerd Font powerline blocks (gate state, risky settings, classifier model, verdict counters, badges), `compact` = one plain line, `off` = none; a switched-off gate always shows as `AUTO OFF · ungated`

| Option | Default | Description |
|---|---|---|
| `--auto-mode` / `--no-auto-mode` | on | master switch |
| `--auto-mode-model provider/id` | session model | classifier model ("self-reflection" by default) |
| `--auto-mode-debug` | off | full verdict notifications |
| `PI_AUTO_MODE_MODEL` | — | env form of the model flag |
| `PI_AUTO_MODE_DEBUG=1` | off | env form of debug (flag wins) |

### User rules (`~/.pi/agent/config/pi-verdict.json`)

The first run writes this file from a template that holds every key with its default (`~/.omp/agent/config/pi-verdict.json` on omp). The full reference for each key, its default, and the direction in which a trusted project file may override it is [docs/configuration.md](docs/configuration.md#user-rules). This excerpt shows the three list keys with example values:

```json
{
  "allow": ["^ls\\b", "^git (status|log|diff)\\b"],
  "deny":  ["rm ", "docker ", "^/etc/"],
  "denyPaths": ["~/.ssh/", "~/Documents/private"]
}
```

- `allow`/`deny` are JS regex arrays; **`deny` wins over `allow`**, and both beat the classifier. An `allow` regex admits **one simple command**: a compound command, a redirection, a re-parser, or a write-shaped `git` invocation reaches the classifier instead ([ADR-0008](docs/adr/0008-simple-command-allow.md)). The regexes see bash commands and the targets of known file tools; the payload of an MCP or custom tool never feeds them.
- `tools` is an exact-name list of tools that skip the classifier (`ignoreTools` is its deprecated alias). It is checked after every deny-side layer, so a listed tool whose payload names a protected path still asks.
- `denyPaths` are plain paths you declare **protected**: a touch triggers a terminal ask you adjudicate (non-interactive → deny), and the classifier learns only that protected paths exist, never the paths. Scope tools (`grep`, `find`, `ls`, `glob`, `ast_grep`, `ast_edit`) compare their whole **search scope**. A fresh install pre-fills a **starter list** (`~/.ssh/`, `~/.gnupg`, `~/.mc`, shell rc/profile files) as a user declaration, not a built-in floor.
- `builtinDenyFloor: false` turns off the built-in danger and path floor, but not the self-protection layer.
- `gateOmpDir` (default `false`) forces a terminal ask for `.omp` directory accesses; it runs after the built-in floor and your `deny` rules and before `denyPaths` and `allow`, so an `allow` regex cannot skip it.
- `classifierModel` pins the classifier model (default: the session model with thinking off); `"typesafe/jev-latest"` selects the bundled jev decisions adapter described below.
- `explainGateModel` / `explainGatePrompt` configure the **EXPLAIN-GATE role** behind the **Explain…** option of the ask dialog. It is never offered for protected-path asks, because their path plaintext must not reach a model provider ([ADR-0002](docs/adr/0002-deny-paths-deterministic-ask.md)). The dialog's **No, with explanation…** option declines and tells the agent why.
- `audit: true` records every gray-zone adjudication, and protected-path asks, as local JSONL under `<agentDir>/verdicts/`; the agent can neither read nor write that directory.
- `notifyAllows: true` notifies on every classifier allow; the default keeps passes silent.
- `classifierMinConfidence`, `classifierFallbackModel` and `classifierFallbackMode` set the **confidence floor** and the second-layer classifier it cascades to ([ADR-0004](docs/adr/0004-classifier-fallback-cascade.md)). A natural pairing is jev first and a haiku-class fallback.
- `subagentGate` and `subagentAskTimeoutMs` (omp only) decide how asks raised inside subagents are answered: on the root session's UI, or without a human through `classifierFallbackModel`. Without a human, a subagent ask is allowed only when an `enforce`-mode second model explicitly allows it; a `shadow`-mode opinion is recorded but never decides, and an ask the confidence cascade already ruled on is denied.

No built-in allowlist — every "always allow" claim is yours ([why](docs/configuration.md#why-no-built-in-allowlist)). Full reference: [docs/configuration.md](docs/configuration.md).

### Jev decisions backend (experimental — [ADR-0003](docs/adr/0003-jev-decisions-adapter.md))

1. Install a version that ships the adapter (v0.8+): `pi install npm:@jonatsu/pi-verdict`
2. Pick a transport (both serve the same decisions wire contract):
   - **OpenRouter (default)**: reuse the host's OpenRouter credential (`/login openrouter` inside pi), or `export OPENROUTER_API_KEY=sk-or-v1...` in your shell
   - **TypeSafe direct (official v1 API)**: grab a self-service key at console.typesafe.ai, then `export TYPESAFE_API_KEY=apikey_...` and `export PI_VERDICT_JEV_TRANSPORT=typesafe`
3. Point the classifier at jev (applies to new sessions)
   - persistent: edit `~/.pi/agent/config/pi-verdict.json` (`~/.omp/agent/config/pi-verdict.json` on omp) outside the agent and set `{ "classifierModel": "typesafe/jev-latest" }`
   - or try it once: `PI_AUTO_MODE_MODEL=typesafe/jev-latest pi`

**Limits**:
- **Transports**: OpenRouter decisions (default) or TypeSafe direct — on the TypeSafe transport per-call cost shows $0 (its API does not report it)
- **Hosts**: pi and omp. On pi the host dispatches to the registered provider. On omp the adapter registers `typesafe/jev-latest` so the setting resolves, and the classifier calls the decisions API directly, with the key taken from the host's OpenRouter credential or from `OPENROUTER_API_KEY` (`TYPESAFE_API_KEY` on the TypeSafe transport). It must never be selected as the session model (no text generation — selecting it warns)
- **Escape hatch**: `PI_VERDICT_JEV_URL` overrides the active transport's endpoint (OpenRouter's is an alpha API)
- **Approve dialog**: in the interactive TUI the ask prompt shows the code under review (bash command, write content, edit blocks) as a syntax-highlighted block, and — when the ask comes straight from jev — a colored allow/ask/deny probability bar, a thin blue confidence bar beneath it (tick at the `classifierMinConfidence` floor), and a `concern:` line (jev's risk category for the action, from a second `concern` question sent in the same request). Other hosts and RPC mode fall back to the plain-text confirm

jev's calibrated confidence is exactly what the confidence floor keys on — pair it with a second layer (`"classifierMinConfidence": 50, "classifierFallbackModel": "anthropic/claude-haiku-4-5"`) so its low-confidence calls go to a deeper model instead of standing ([ADR-0004](docs/adr/0004-classifier-fallback-cascade.md)).

Requires pi ≥ 0.84. Works in interactive and non-interactive (`-p`/json/rpc) sessions; in non-interactive modes `ask` degrades to `deny`.

## How it compares

| | three-state verdict | classifier sees context | fail direction | runtime deps |
|---|---|---|---|---|
| **pi-verdict** | ✅ allow / ask / deny | ✅ recent user intent + tool calls | **closed** (errors/timeout/bad output → deny; headless ask → deny) | **0** |
| [@czottmann/pi-automode](https://github.com/czottmann/pi-automode) | rules 3-state, classifier 2-state | ✅ budgeted transcript | closed | 1 |
| [@zhushanwen/pi-permission](https://www.npmjs.com/package/@zhushanwen/pi-permission) | ✅ (outcome) | ❌ single-turn, no context | closed (→ ask) | 4 |
| [@gotgenes/pi-permission-system](https://github.com/gotgenes/pi-packages) | ✅ deterministic only | — (no built-in classifier) | closed | 3 |

Full landscape: [`research/pi-permission-landscape.md`](research/pi-permission-landscape.md) · convergence analysis with the closest architectural relative: [`research/pi-automode-convergence.md`](research/pi-automode-convergence.md).

Honest framing: pi-automode and pi-verdict have **converged on the same architecture** (deny floor → user rules → classifier, fail-closed — see the convergence analysis). What remains distinct here: a classifier that can say `ask` (runtime human-in-the-loop, not just rule-declared), a built-in floor you can turn off (`builtinDenyFloor` — user sovereignty), zero runtime dependencies, and the measurement habit — every design decision in this repo is backed by shipped research.

## Pipeline

The authoritative layer order is [docs/layers.md](docs/layers.md), and the probe asserts it. The diagram below follows that order.

```
tool_call
  │
  ├─ 0. Self-protection (snapshot-free, config-exempt hard deny)
  │     ├─ writes to gate policy, trust store, installed copy → deny
  │     ├─ reads of the policy file pass; reads of the trust store → deny
  │     └─ <agentDir>/verdicts/ reads and writes → deny
  │
  ├─ 1. Rule layer (deterministic, zero latency), in this order
  │     ├─ tool-access adapter (ADR-0009): one model of what a call touches —
  │     │   every target a payload names (path/paths, or the hashline/apply-patch
  │     │   headers inside a patch), not just input.path; each target is graded in
  │     │   every form the host can resolve it to
  │     ├─ built-in deny floor: bash danger regexes + path sensitivity S0–S5,
  │     │   graded over every adapter target, worst grade wins; a write whose kernel
  │     │   target is unresolvable (symlink loop) fails closed → deny
  │     ├─ your deny rules: any matching target form denies; deny beats allow
  │     ├─ optional gateOmpDir (default off): .omp access → terminal ask
  │     ├─ denyPaths (ADR-0002): protected paths → terminal ask,
  │     │   before user allow; classifier sees an existence hint only; a call the
  │     │   redactor matches by a spelling the tokeniser misses (${HOME}) asks here too;
  │     │   an unknown tool's path/paths and patch text count as targets
  │     ├─ an action whose counted text exceeds 8192 chars → ask, before user allow
  │     ├─ your allow rules, then the tools exemption → allow; neither applies to
  │     │   a globbed path, a mutating call with no target, a read of a relative
  │     │   path that does not exist, an internal URL (ssh://, vault://), or eval's code
  │     ├─ a mutating call naming no target at all → opaque ask (ADR-0009)
  │     ├─ otherwise the floor's own grade stands: a read no sensitivity rule flags,
  │     │   a write inside the project, or an in-project glob listing → allow
  │     ├─ note: a scope tool's glob path is graded as spelled and by its literal prefix
  │     ├─ note: eval's code text: deny/denyPaths/.omp apply to the whole text, user
  │     │   allow never does; the bash floor covers a py cell's shell-out lines only
  │     └─ note: no built-in command allowlist — a bash command the floor does not deny
  │         and no rule of yours covers goes to the classifier
  │
  ├─ 2. Gray zone → model classifier (defaults to session model — "self-reflection")
  │     ├─ input: CC-style <transcript> — recent user intent + tool calls,
  │     │        action under review always last
  │     ├─ output contract: <verdict>allow|ask|deny</verdict> prefix-anchored
  │     └─ jev confidence below classifierMinConfidence, or a fail-closed first layer
  │           → classifierFallbackModel (ADR-0004)
  │
  ├─ 2a. policy degraded (your own rules failed to load — ADR-0010)
  │     ├─ first-layer / cascade allow → ask (source "degraded-policy"; headless → deny),
  │     │   subagent second-model allow → denied outright
  │     └─ user allow / tools exemption suspended; floor + deny side unchanged
  │
  └─ 3. Three-state adjudication
        ├─ allow → pass
        ├─ deny  → block, reason returned to the agent
        └─ ask   → human confirm; non-interactive modes degrade to deny
```

**fail-closed**: classifier exception / timeout (each attempt capped inside one end-to-end adjudication budget) / contract violation → deny. Never silently allow.

At `session_start`, a schema-driven coverage report (debug-channel, `--auto-mode-debug`) names any
active tool the adapter and your `tools` list both leave ungraded, and a one-time warning flags a
side-effecting tool (`learn`, `memory_edit`, `retain`) if you've listed it in `tools`.

## Evidence-driven, not vibes-driven

Design decisions here are settled by measurement, and the lab notes ship with the repo:

- [`research/cache-sim`](research/cache-sim/README.md) — replayed 1.2k+ real classifier verdicts and measured a **3.2%** would-be verdict-cache hit rate; this fork ships no cache or cache telemetry
- [`research/thinking-param-blackhole.md`](research/thinking-param-blackhole.md) — three-layer forensic root-cause of thinking models burning the classifier budget; why the fix is `thinkingEnabled: false`
- [`research/rule-engine-sim`](research/rule-engine-sim/README.md) — measured a tree-sitter rule-engine port against 746 real bash calls (**absorbs 0 gray calls**) and rejected it
- [`research/pi-permission-landscape.md`](research/pi-permission-landscape.md) — the competitive landscape this README's positioning is checked against
- [`research/rule-layer-security-audit.md`](research/rule-layer-security-audit.md) — rule-layer bypass testing (8/8 reproduced → fixed architecturally in 0.2.0)
- [`research/pi-automode-convergence.md`](research/pi-automode-convergence.md) — where this project genuinely converges with pi-automode, and what remains distinct
- [`research/claude-code-classifier-prompts.md`](research/claude-code-classifier-prompts.md) — structural reconstruction of Claude Code's classifier design (via self-hosted Langfuse observations) that this extension's transcript contract descends from

## Status & limitations

- no built-in command allowlist by design (see the [bypass writeup](research/rule-layer-security-audit.md)); with an empty `allow` config most commands go to the classifier — point `--auto-mode-model` at a fast model if per-call latency matters
- the path sensitivity floor applies to file tools only: bash command strings are matched by the danger regexes alone, so e.g. `cat ~/.ssh/id_rsa` goes to the classifier rather than the deterministic S0 deny (the file-tool spelling `read ~/.ssh/id_rsa` does deny)
- on Windows the built-in floor covers bash-shaped patterns only — PowerShell-native dangerous commands (`Remove-Item -Recurse -Force`, `Invoke-Expression`, `Set-ExecutionPolicy`, …) rely on the classifier (fail-closed)
- On macOS, the per-user temp tree under `/var/folders/...` is exempt from S1 system-path treatment: reads there do not go gray, and writes are not denied by S1
- AGENTS.md is not passed to the classifier as downweighted intent evidence (Claude Code does this)
- interactive ask dialogs are shown one at a time across the whole process; the extension adds no queue around classifier calls
- self-reflection means the session model adjudicates — point `--auto-mode-model` at a lighter model if verdict latency/cost matters (open question tracked in the issue tracker)
- `denyPaths` bash extraction uses a linear token scan with no fixed input-length cap ([ADR-0002](docs/adr/0002-deny-paths-deterministic-ask.md)): command substitution, base64-embedded paths and external script contents produce no hit signal, so those calls fall back to the classifier's existence-hint vigilance. MCP and custom tools are covered through the targets the adapter extracts from their `path`, `paths` and patch-text fields, and through any payload text that spells a declared path (the redactor match); a field that names a declared path in a way neither sees produces no hit, and the call falls to the classifier with the hint. Path normalization is base-tier plus the kernel-true spelling for `..`-spellings (ADR-0002 amendment): a nonexistent target written through a symlinked directory rebuilds no real form and produces no hit, which also falls to the hint. The deterministic layer remains obfuscatable, which is why a hit routes to *you* rather than silently deciding
- `denyPaths` bash tokens contain no spaces, so a *declared* path containing spaces is found in a bash command only through the redactor match on its literal spelling: `cat "/path with space/x"` asks, while the shell-escaped spelling `cat /path\ with\ space/x` produces no hit (file tools always hit, their path is not tokenized). A glob covering the final segment of a base (`cat /proj/pers*` against `denyPaths: ["/proj/personal"]`) also misses — the base's own name never appears literally. A recursive search issued from a shell misses in both spellings — no path argument (defaults to the cwd, e.g. a bare `rg foo`) or a parent-directory argument (`rg foo <parent-of-a-declared-path>`): an argument-less command contributes no token at all and bash tokens otherwise compare one-directionally, while the file tools' bidirectional subtree compare covers the same shapes issued through `grep`/`find`/`ls`. All of these holes fall back to the classifier's existence hint, alongside substitution/base64 above
- The snapshot-free self-protection layer hard-denies agent-side writes to `<agentDir>/config/pi-verdict.json`, `<agentDir>/config/pi-verdict-trust.json`, and the installed extension copy when it resolves under a recognized pi/omp install root; development checkouts are not protected. Reads of the policy file pass; reads of the trust store are denied, and `<agentDir>/verdicts/` denies reads and writes. `builtinDenyFloor: false`, user `allow` rules, and `autoDeny: false` cannot lift these denies. There is no in-memory snapshot or automatic restore. Bash matching uses substrings and is obfuscatable; direct rewrites outside gated tool calls are not covered

**verdict is not a sandbox.** It runs inside the pi process and adjudicates tool calls; it does not contain malicious code, protect against a compromised process, or guard manual `!` shell escapes. For isolation, use an OS-level sandbox.

The name: the three-state **verdict** is the core concept. The UX keeps `/automode` — the mode concept traces back to Claude Code's auto mode, which this project borrows its transcript design from.

## Development

```bash
bun install
bun run typecheck
bun test          # offline stub tests: deny floor, user rules, denyPaths, bypass regression, classifier retry, commands, toggle shortcut
```

Issue tracker and decision records live in the GitHub issues ("map" issue #1 indexes them).

## License

[MIT](LICENSE)
