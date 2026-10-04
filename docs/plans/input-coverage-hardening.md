# Input coverage hardening — proposals

**Status: proposed, not scheduled.** Items 1-3 are recommended as the next round, after the probe-apparatus round
(`docs/plans/probe-apparatus.md`) lands. None of these items is accepted yet. Each one needs a decision before it
becomes a plan.

Written 2026-10-04 from an architecture review of HEAD `6136aa0` (`v0.16.0-fork.6`). The review read this
repository and the omp 18.5.1 host source (`@oh-my-pi/pi-coding-agent`, installed under mise). The four findings
marked *verified* below were also checked against the code in the main session. Line references are to
`extensions/pi-verdict.ts` at that commit, unless a file is named.

## The common cause

The gate decides from its own model of each host tool's input shape and of shell syntax. Where that model is
incomplete, several paths fall back to `allow`, so the call never reaches the classifier or an ask. The
self-protection layer (layer 0, ADR-0005 R3) already avoids this class of defect: it reads every input string and
treats an unknown tool as a write. Most of the proposals below extend that input-keyed discipline to the other
layers.

The probe-apparatus round covers the shell tokeniser escapes, the kernel path walker, the XDG roots and the
`denyPaths` kernel tier, and this document does not repeat them. Proposal 5 changes how the floor uses the tokeniser.
Coordinate it with the probe cases, which assert the source of each verdict.

## Recommended next round

### 1. A multi-file omp `edit` is a silent rule allow (critical; verified on the gate side)

omp 18.5.1 defaults `edit.mode` to `hashline`, and one hashline edit may carry several file headers.
`normalizeToolEventInput` (`src/extensibility/tool-event-input.ts:70-90` in omp) hands extensions:

- `{ input, path, paths }` when the patch has one header;
- `{ input, paths }`, with no `path`, when it has several;
- no path field at all for an input without hashline headers.

pi-verdict reads only `input.path` (`:1784`), and no code reads `paths`. `classifyPath("")` resolves to the cwd, which
passes the in-project write allowance (`:1237-1239`). `userRuleTarget` returns `null`, so the user-rule block
(`:1801-1822`) is skipped. `denyPaths` sees no candidates. The result is `allow/rule`, with no classifier call.

```mermaid
sequenceDiagram
  participant Model as Agent model
  participant Omp as omp tool wrapper
  participant Gate as pi-verdict tool_call
  participant Tool as omp edit tool
  Model->>Omp: edit { input: "[a.ts#…] … [~/.bashrc#…] …" }
  Omp->>Omp: normalizeToolEventInput → { input, paths: [a.ts, ~/.bashrc] } (no path)
  Omp->>Gate: tool_call edit
  Gate->>Gate: classifyPath("") = cwd → in-project write → allow
  Gate-->>Omp: allow (silent)
  Omp->>Tool: execute
  Tool->>Tool: writes a.ts and ~/.bashrc
```

**Consequence:** a second file header turns any write into a rule allow. That includes a write to `~/.bashrc`
(normally classifier), `.git/hooks/` (normally a floor deny) or any `denyPaths` entry. Layer 0 still holds, because it
scans every input string. This contradicts ADR-0002's invariant that an incomplete tool enumeration degrades to
classifier scrutiny, never to a silent allow. The tests missed it because they build invented tool shapes; for
example, `tests/pi-verdict.test.ts:3134` gives `ast_edit` a `path`, but omp's real `ast_edit` takes `paths`.

**Unverified:** whether omp then performs the second write without its own approval prompt. That depends on omp's
approval settings. A headless smoke test (see `AGENTS.md`) settles it.

**Proposal (size M):** add one host tool-access adapter, `toolAccess(toolName, input)`. It returns
`{ kind, reads[], writes[], command?, code?, opaque }` and knows both hosts' shapes:

- pi's `path`;
- omp's `path` and `paths`;
- hashline headers, parsed from `input.input` directly rather than trusting the derived fields;
- `MV` destinations;
- `ast_edit.paths` and `glob`;
- `eval.code`.

A write tool with no target the adapter can extract is `opaque`, and it becomes a deterministic ask (deny when
headless). The in-project allowance fires only when every write target is present and inside the cwd. Layer 0, the
floor, user rules, `denyPaths`, the `.omp` gate and the transcript builder all read the adapter's output instead of
re-deriving it. Pin it with fixtures copied from the host schemas, not invented.

The first failing test: `edit { input: "[a.ts#…]\n…\n[~/.ssh/authorized_keys#…]\n…" }` must not return `allow/rule`.

### 2. User `allow` regexes match the raw command text (critical; verified)

The user allow loop (`:1819-1821`) tests the whole command string, and a match ends adjudication before the
classifier. The starter template ships `allow: ["^ls\\b"]`, and the deployed consumer policy carries `^ls(\s|$)`,
`^pwd$` and `^git (status|log|diff|show|branch|remote -v)(\s|$)`. All of the following match one of those rules and
run with no model judgment:

- `ls` + newline + `bash /tmp/evil.sh`;
- `ls; python3 -c '…'`;
- `git status && curl x | python3`;
- `git log --output=<path>`, which writes to an arbitrary path (security audit V7).

This is security-audit finding V3. It was fixed in 0.2.0 by removing the built-in allowlist, but the same mechanism
lives on in the user layer and in the shipped template. The regression suite only checks the audit payloads against an
empty policy (`tests/pi-verdict.test.ts:635-653`), so it pins the property only for a configuration nobody deploys.

**Proposal (size S):** an allow rule may fire only on a single simple command. Add `isSimpleCommand(command)` next to
`shellWords`. It returns false on any of these:

- an operator, or a newline;
- `$(`, a backtick, `<(` or `>(`;
- a redirection other than to `/dev/null`, or a here-document;
- a backslash-newline continuation;
- a re-parser in command position: `eval`, `env -S`, a shell with `-c`, `xargs`, `find … -exec`.

A non-simple command skips the allow rules and goes to the classifier. The check only has to recognise "not simple",
which is much easier than parsing fully. Add the audit payloads under the starter template and under the consumer's
allow list, expecting a classifier call. This narrows what existing rules admit, so mark it **BREAKING** in
`CHANGELOG.md` and record it in an ADR. The cost is one classifier call for commands that used to be allowed silently.
No allow can become a deny.

### 3. A trusted project override can widen the gate (important; verified)

`PROJECT_OVERRIDABLE_KEYS` (`:812-825`) includes `subagentGate`, `subagentAskTimeoutMs`, `classifierFallbackMode`,
`gateOmpDir` and `footer`. The merge copies those keys verbatim (`default: merged[k] = v`, `:976`). The trust dialog
says that a project "cannot widen the gate" (`:3845`), and ADR-0006 R7 says overrides narrow only. The R7 test covers
none of these five keys.

**Consequence:** a cloned repository ships `.omp/pi-verdict.json` with `{"subagentGate":"off","footer":"off"}`. Its
trust prompt reads accurately, so the user trusts it. The file then ungates every subagent tool call and hides the
footer badge that exists to flag that state. These values widen the gate in the same way:

- `subagentAskTimeoutMs: 1` hands every subagent ask to the second model;
- `classifierFallbackMode: "enforce"` lets the second model allow;
- `gateOmpDir: false` removes an ask the user chose.

**Proposal (size S):** give each overridable key a declared narrowing direction in a `(key, merge function)` table, so
that a new key cannot be added without choosing one:

- `subagentGate` may only move toward `normal`;
- `subagentAskTimeoutMs` may only increase;
- `classifierFallbackMode` may only become `shadow`;
- `gateOmpDir` may only become `true`;
- `footer` becomes user-only.

Extend the R7 test to every overridable key, and amend ADR-0006.

## Worth scheduling later

### 4. Tools outside pi's eight names skip every user declaration (important)

`toolKind` (`:1247-1262`) knows `bash`, `powershell`, `read`, `write`, `edit`, `grep`, `find` and `ls`. omp also ships
`eval` (JavaScript or Python execution), `ast_edit`, `glob`, `ast_grep`, `browser` and others. For these, the user
deny regexes, `denyPaths` and the path floor never run. The classifier still fails closed, so this is not a silent
allow, but every deterministic declaration is inert for exactly the tools that run code or rewrite files. The consumer
handover assumes that layer 3 covers `eval`, which is wrong.

**Proposal (size S, after item 1):** fold these tools into the adapter. Route `eval.code` through the command channel,
and map `ast_edit.paths` and `glob` to writes and reads. At `session_start`, call `pi.getAllTools()`, which both hosts
expose, and report once any active tool that neither the adapter nor the user's `tools` list covers. A new host tool
then shows up as a warning instead of a silent gap.

### 5. Make the floor monotone instead of tokeniser-dependent (important)

fork.6 put the tokeniser in the *detection* path of `git-push-force`. Wherever the tokeniser models the shell less
faithfully than the old regex over-approximated it, a deny turns into a classifier call. This is why the escape stream
keeps coming: it is structural, not a run of separate bugs. Five independent lexers read the same command:

- the danger regexes;
- `shellWords`;
- `bashPathTokens`;
- the `.omp` matcher;
- the self-protection `cd` regex.

None of them can report that it did not understand the input.

**Proposal (size M; coordinate with the probe cases):**

- Build one `ShellView` that tokenises once and returns segments plus a `sound` flag. `sound` is false on anything it
  does not model.
- Restore a raw-text tripwire as the detector, and let a sound parse only *clear* a hit, as in the commit-message case.
- Reuse `ShellView` for item 2 and for path extraction.
- Record the principle in an ADR: a floor change may never turn a raw-text hit into a non-hit on an unsound parse.

**Do not adopt a bash AST library for now.** An AST adds precision, not soundness, because it still cannot resolve
`eval "$x"`. ADR-0002 measured tree-sitter-bash absorbing no extra gray-zone calls. A WebAssembly parser would also
break the zero-dependency, ship-TypeScript-as-is packaging. Revisit if tripwire false positives become the main
complaint.

### 6. Classifier input integrity and privacy (important)

- **Truncated actions.** The action under review goes through the transcript sanitizer, which keeps the first 600 and
  last 400 characters (`:1861-1871`). A `write` or `edit` is shown to the classifier as its path only, with no content.
  The floor stops reading after 8192 characters (`:316`).
  - **Consequence:** a payload in the middle of a long command is invisible to both the floor and the classifier.
  - **Proposal:** never elide the action itself. Allow a larger, separate cap, and make an over-cap action a
    deterministic ask. Include a bounded content excerpt for writes, and tell the classifier that a truncation marker
    means `ask`. Past the floor's cap, mark the call gray with a "floor incomplete" reason. Check the jev input limit
    before raising the caps.
- **Protected-path leakage.** `collectTranscriptParts` (`:1897-1919`) sends earlier tool calls to the classifier
  provider with no filter.
  - **Consequence:** a protected read the user approved leaks its path on the next calls, which breaks ADR-0002's
    "no path plaintext, ever".
  - **Proposal:** redact `denyPaths` hits in transcript lines to a fixed `<protected-path>` marker, using the item 1
    adapter. Pin it with a test that approves a protected read and inspects the next classifier prompt.
- **Broken policy file.** A JSON error in `pi-verdict.json` falls back to `EMPTY_RULES` (`:896-907`). Every user deny
  and `denyPaths` entry disappears, and the only signal is a notification, which headless sessions never show.
  - **Proposal:** add a `policyDegraded` state. While it is set, a classifier allow becomes an ask, user allow and
    `tools` exemptions are suspended, and the footer and block reasons name the state. Record this in an ADR, because
    it changes the fail direction for configuration errors.

### 7. Timeout budget (suggested)

One classifier attempt may take 25 s (`CLASSIFIER_TIMEOUT_MS`), with a retry, and the fallback model adds 15 s per
attempt. omp bounds each `tool_call` handler to 30 s by default. On a slow model, the host blocks the call with its own
timeout before the retry, the fallback cascade (ADR-0004) or the audit append can run. The result is still fail-closed,
but the cascade cannot run on the path it exists for.

**Proposal:** give `adjudicate` one end-to-end deadline below the host budget, about 27 s, split across the attempts
and the fallback. Document the root-session interaction in `docs/configuration.md`.

### 8. Structure and hygiene (suggested)

- **One path-resolution service.** Each layer builds its own path forms, with its own `~` and `$HOME` expansion, which
  is why the walker and dangling-link fixes had to land in several places. Add one `resolveTarget(raw, cwd)` that
  returns every tier once. Each consumer then names the tiers it uses, so the base tier of `denyPaths` (ADR-0002)
  becomes an explicit, test-pinned parameter. Size M, after items 1 and 5.
- **Split the 4,450-line file.** Split only along the seams that items 1, 5 and the path service create.
  - pi loads every `.ts` file directly inside `extensions/` as an extension, so the split needs
    `extensions/pi-verdict/index.ts` plus modules, or a `lib/` directory.
  - Whether omp's loader follows the same rule is unverified.
  - The split changes the `files` whitelist and the consumer's single-file provenance hash, so provenance has to hash
    the whole `files` list.
  - Size L, in M-sized steps.
- **Supply chain.**
  - Pin GitHub Actions by commit SHA, and pin the Bun version instead of `latest`.
  - `publish.yml` still publishes `@frapetti-dev/pi-verdict`, but the package is now `@jonatsu/pi-verdict`. Fix or
    remove the workflow, since deployment goes through the git spec.
- **Stale agent instructions.** `AGENTS.md` contradicts the code on several load-bearing points:
  - the `gateOmpDir` default (it is off);
  - the `classifierFallbackMode` default (it is `enforce`);
  - a shadow cache, which was removed;
  - a self-protection removal, which ADR-0005 reversed;
  - the absence of lint and biome, which both exist;
  - the package name.

  ADR-0002's 2026-09-25 amendment also needs a pointer to ADR-0005. `CONTEXT.md` lacks the kernel path tier.
- **Consumer policy lint.** The deployed policy exempts `learn`, `memory_edit` and `retain` from the classifier. This
  repository's own starter-list rationale (`:761-765`) excludes them, because they persist content into future
  prompts. That is the user's choice to make, but a `session_start` warning when `tools` names a side-effecting tool
  costs little.

## What to keep

- **`adjudicate`'s seam.** It is pure and UI-free, takes its dependencies by injection, and gives every verdict a
  `source`. Keep it that way; probing by layer depends on it.
- **The closed fail direction.** Classifier errors, timeouts, contract violations, a missing model and headless asks
  all end in deny. Items 1 and 2 are failures to *reach* that machinery, not failures of it.
- **Layer 0's design.** It is keyed on inputs and holds no snapshot (ADR-0005). It is the model the other layers
  should follow.

## Suggested order

Items 3 and 2 are small and independent, so take them first. Item 1 is the critical one and carries item 4 with it.
After those come the item 6 fixes, which depend on the adapter, then the timeout budget, then item 5, which should
follow the probe round. The path service and the file split come last. Each item lands as its own commit, with a
failing-before regression test, the `CHANGELOG.md` entry and the documentation sync that `AGENTS.md` requires.
