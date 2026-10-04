# Probe apparatus + path-layer open items — execution plan

Slug: `probe-apparatus-plan`

**Revision 3 (2026-10-04):** folds two findings of the architecture audit
(`.scratch/reviews/2026-10-04-pi-verdict-architecture-review.md`) into this round — F4's monotone floor (a raw
tripwire decides every hit; the tokenised word view may only clear) replaces revision 2's tokeniser-per-spelling
Phase 2, and F2's simple-command allow guard (BREAKING) becomes commit 3. The release is held: no bump, tag or push
this round; the follow-up `gate-architecture-fixes` round owns the single bump/tag/push.

**Revision 2 (2026-10-04):** incorporates the external review of revision 1
(`.scratch/reviews/2026-10-04-probe-apparatus-plan-review.md`: findings F1–F24, the nits, and the four user
decisions recorded there). Revision 1 was never executed. The disposition table near the end maps every finding to
the section that addresses it. Review evidence for F4/F5/F8/F24 was re-executed against HEAD `6136aa0` in this
session and reproduces exactly.

## Context

This plan moves the shared gate-testing contract into this repository: one case table both sides run, replacing
prose hand-backs, because three rounds of hand-backs lost information in translation (anchor round, tokeniser
round, path round). The source handover — written by the consumer session, untracked in the repo root — listed 11
open defects that the case table must close, and the review adds the adjacent tokeniser regressions and the `+`
refspec force push to that scope (user decision 3). **The handover file has been deleted** (user decision,
2026-10-04): everything this round needs from it is transcribed into the case table below (item numbers, the
payloads, the §3.4 notes), so no archive copy is kept.

User decisions (recorded in the review, revision 2):

1. **Commits are authorized as sliced commits** (F13). **The release is held (user decision, 2026-10-04): this
   round lands commits only — no version bump, no tag, no push.** The follow-up `gate-architecture-fixes` round
   (the architecture audit's remaining items) owns the single bump to `0.16.0-fork.7` in its last fix commit, the
   annotated tag and `git push main --follow-tags`; the GitHub Release stays the user's (the built-in floor blocks
   `gh release`). `release-check.ts` and `provenance.ts` are still built here and used then.
2. **Regression tests live in `tests/`** as AGENTS.md requires (F12); `probe/` does not replace them. Each fix
   commit carries its own failing-before/passing-after tests.
3. **The adjacent tokeniser regressions (backticks, `bash -o … -c`, `-f>file`) and the `+` refspec force push are
   in scope this round** (F8, F24), as `rule` cases marked open, fixed in the tokeniser commit.
4. **The unresolved-symlink write deny honours `builtinDenyFloor: false`** via `D(...)` (F20).
5. **The floor becomes monotone (architecture audit F4, folded in):** a broadened raw-text tripwire decides every
   `git-push-force` hit; the tokenised word view may only **clear** a hit when its parse is sound — never be the
   sole path to one. Detection items 1–5 collapse into unsound markers; the plan-review's F21 own-reason plumbing
   is superseded (a tripwire deny's `git push --force` reason is accurate — the raw text really contains it).
6. **Architecture audit F2 is in scope as commit 3:** the user `allow` layer admits only simple commands;
   BREAKING, with a new ADR and the audit's V3/V7 payloads pinned.

End state: `bun run probe` is green with **N pass, 0 fail, 0 open** — the GNUPGHOME limitation stays recorded as a
normal case carrying `deliberate`, not as an open one (F10); `bun run provenance` prints the hashes the consumer's
staged check compares (committed blobs, F22); `docs/coverage.md` is generated from the case table and CI proves it
fresh; CI runs the probe.

## Deliverable layout

```
probe/
  cases.ts          # the contract: buildCases(fx) → Case[]; every payload family, expected layer per case
  probe.ts          # runner: three runs per case, table output, --filter, exit 1 on mismatch
  fixtures.ts       # builds the real symlink/dangling/backslash/loop/xdg tree in a temp dir per run
  README.md         # how to run, the run table, case schema, layer vocabulary, override chain, provenance hand-back
  consumer-policy.json   # minimal synthetic fixture of the deployed policy + _meta (exercised entries only)
tools/
  provenance.ts     # sha256 of the committed blobs of extensions/pi-verdict.ts + extensions/jev-adapter.ts
  coverage.ts       # derives docs/coverage.md from probe/cases.ts (stable fields, placeholder fixture)
  release-check.ts  # package.json version == annotated tag v<version>, tag commit carries the bump
docs/
  plans/
    probe-apparatus.md   # this plan, tracked; the round's outcome is appended after the release
  layers.md         # the layer map + three consequences (the former handover §1), as the contract
  coverage.md       # generated, committed
```

probe/ and tools/ are dev artifacts: **do not** add them to package.json `files`. The consumer session's
`testing-handover.md` is deleted, not archived — its content lives in this plan's case table.

## Phase 0 — tooling deltas

0. Track this plan at `docs/plans/probe-apparatus.md`: the execution's first action writes this revision-3 text
   there (plan mode locked the tracked copy). The round's outcome (probe summary, provenance hashes, pin) is
   appended there at round end — the tag ships with the architecture round, not here.
1. `tsconfig.json`: `include` becomes `["extensions/**/*.ts", "probe/**/*.ts", "tools/**/*.ts"]`; add
   `"allowImportingTsExtensions": true` (valid with `noEmit`) so probe/tools can import `../extensions/pi-verdict.ts`.
   Probe/ and tools/ use **`node:` APIs only** (fs/os/path/child_process/crypto); no `@types/bun` is added (it would
   change `bun.lock` and CI installs `--frozen-lockfile`). JSON is read via `fs` + `JSON.parse` (no
   `resolveJsonModule`). (F19)
2. `biome.json`: `files.includes` becomes `["extensions/**/*.ts", "tests/**/*.ts", "probe/**/*.ts", "tools/**/*.ts"]`.
   The tests override (noExplicitAny off) stays; probe/tools keep the strict default. Verify with
   `mise exec -- biome ci .` once the new directories exist. (F19)
3. `package.json` scripts (bun runs `.ts` directly, so tools are `.ts` for uniform typecheck+lint):
   `"probe": "bun run probe/probe.ts"`, `"coverage": "bun run tools/coverage.ts"`,
   `"provenance": "bun run tools/provenance.ts"`, `"release-check": "bun run tools/release-check.ts"`.
4. `.github/workflows/ci.yml`: after the Test step add `- name: Probe` / `run: bun run probe` and
   `- name: Coverage freshness` / `run: bun run coverage && git diff --exit-code docs/coverage.md`.
   `release-check` is deliberately **not** in CI: ci.yml pushes are untagged (checkout fetch-depth 1) and would fail;
   publish.yml already double-checks tag == version. It is a local pre-tag gate.
5. `.gitignore`: add `probe/consumer-policy.real.json` — this is the documented default location for the consumer's
   real policy file (resolution order below), so the entry is justified, not speculative.
6. `testing-handover.md` is deleted in the apparatus commit (user decision, 2026-10-04): the case table below is
   the single source for the defect items, so no archive copy is tracked. `git rm` the untracked file or remove it
   from the working tree; nothing in commit 1 depends on it.

## Phase 1 — the apparatus

### `probe/fixtures.ts` — real trees, temp-dir anchored (F17, F9)

`buildFixtures(agentDir: string): FixtureTree` creates the tree under
`fs.mkdtempSync(path.join(os.tmpdir(), ".pv-probe-"))` — never a relative prefix (a crash would otherwise leave
symlinks-to-`/` inside the repo checkout). Assert the root starts with `os.tmpdir()`. Cleanup is only
`fs.rmSync(root, { recursive: true, force: true })` (unlinks symlinks without following them), registered so it runs
on both normal exit and error. Committed trees are deliberately avoided (symlink fixtures break Windows checkouts).

| member | content |
|---|---|
| `root` | the mkdtemp dir |
| `work` | `<root>/work`, the per-case cwd (must exist) |
| `escapeLink` | `<root>/escape/link` → symlink to `/` (the kernel-escape link) |
| `subLink` | `<root>/subLink` → symlink to `<root>/protected/sub` (an **existing** directory, F9) |
| `backslashLink` | `<root>/link\name` → symlink to `/` (a filename containing a backslash, legal on POSIX) |
| `dangling` | `<root>/dangling` → symlink to `<agentDir>/config/pi-verdict-trust.json` (protected **and** missing) |
| `loop` | `<root>/loop` → symlink to `loop` (self) |
| `xdg` | `<root>/xdg` with `age/key.txt`, `gnupg/pubring.kbx`, `sops/age/keys.txt`, `glab-cli/config.yml`, `gh/config.yml` |
| plain files/dirs | `repo/.config/age/data`, `foo.config/age/data`, `repo/.git/hooks/`, `protected/secret`, `protected/sub`, `gnupghome/pubring.kbx`, `escape/` |

Symlink members are created on POSIX only; on win32 the case table is identical but the `skipOn: "win32"` cases are
skipped (reported `- skipped`, never counted as fail).

### `probe/cases.ts` — schema (F2, F3, F10)

```ts
type Layer = "rule" | "allow" | "classifier" | "protected-path";
type Expectation = {
  layer: Layer;
  ruleId?: string;         // floor rule id substring, e.g. "git-push-force"
  reasonIncludes?: string; // e.g. "S0", "self-protection", "unresolved symlink", "reparse depth exhausted"
  deliberate?: string;     // one-line reason when the expectation is a choice, not a hazard
  known?: "open";         // strict expected failure until the fix lands
};
type Case = {
  label: string;           // named for the behaviour, never the implementation
  family: "force-push" | "path-tier" | "kernel-path" | "self-protection" | "deny-paths" | "user-rules" | "user-allow";
  tool: string;            // "bash" | "read" | "write"
  input: Record<string, unknown>;
  policy?: "consumer";     // additionally asserted under the consumer-policy fixture config (run C)
  config?: Record<string, unknown>; // exact config written for this case (deny-paths/user-rules families); mutually exclusive with policy
  kernelOpens?: string;    // runner-side kernel truth check: readFile(raw spelling) content == readFile(kernelOpens) content
  skipOn?: "win32";        // symlink + /etc families (POSIX-only)
  item?: number;           // defect item number (from the source handover's ledger); markers removed per item as fixes land
  ref?: string;            // review finding reference, e.g. "arch-F2"; same open-marker mechanics
  expected: Expectation;
};
export function buildCases(fx: FixtureTree): Case[];   // fixtures first, then cases
```

- **`"allow"` means a deterministic rule-layer allow** (A and B both `allow/rule`) — the layer the code actually
  returns for non-S0/S1 reads; it is distinct from a classifier allow and `probe/README.md` states that. (F2)
- **`known: "open"` is a strict expected failure**: the case carries the *desired* expectation, must fail today, and
  is excluded from the pass count; if an open case **passes**, the runner exits 1 with
  `open case now passes — remove the marker`. This makes the failing-before discipline mechanical — no marker
  stripping. (F10)
- **Every case of an open item carries the marker and its `item` tag**, not only the first. (F10)

### `probe/probe.ts` — runner (F3, F16, F17, F23)

- Before importing `../extensions/pi-verdict.ts`: set `process.env.PI_CODING_AGENT_DIR` to a fresh
  `fs.mkdtempSync(...)` and `process.env.XDG_CONFIG_HOME = <fx.xdg>` (module-load time for `HOME_RULE_ROOTS`). The
  import is **dynamic** (`await import(...)`); `cases.ts` and `fixtures.ts` import only *types* from the extension,
  because static imports are hoisted above the env setup. (F16)
- Per case: write `<agentDir>/config/pi-verdict.json` (`case.config` when present, else `{}`) before constructing the
  session state; construct `new SessionState()`; then call `state.reloadRules(<fx.work>)` and **fail the case when
  `report.skipped.length > 0`** (the constructor's default load discards the skipped report). (F16)
- `AdjudicateEnv` per run: `cwd: <fx.work>` (must exist), `host: { getBranch: () => [], getSessionId: () => "probe" }`,
  `signal: undefined`, `getFallbackModel: undefined`. (F16)
- **Three runs per case** (A and B under the same config; C only for `policy: "consumer"` cases):

  | Run | Config | Model | Applies to |
  |---|---|---|---|
  | A | `case.config ?? {}` | `hasUI: false`, `getModel: () => null`, `complete` throws if reached | every case |
  | B | same as A | `hasUI: true`, stub `complete` returns `<verdict>allow</verdict> probe stub` | every case |
  | C | consumer-policy fixture (or the override) | `hasUI: false`, no model | `policy: "consumer"` only |

  Run C asserts **the same layer as run A**: a `rule` expectation must still deny with the floor `ruleId` — a
  `user deny rule` reason fails C, because it would mean the floor stopped covering the case and the policy covered
  it instead; a `classifier` expectation must still be `deny/fail-closed`, proving the policy does not claim the
  lease or if-includes forms. (F3)
- Assertion per expectation `layer` (the layer that must decide the call — assert the source, not the verdict):
  - `"rule"` → A: `deny/rule`; B: `deny/rule`; C (when run): `deny/rule`. `ruleId` / `reasonIncludes` must be a
    substring of the reason.
  - `"allow"` → A: `allow/rule`; B: `allow/rule`; C (when run): `allow/rule`.
  - `"classifier"` → A: `deny/fail-closed`; B: `allow/classifier`; C (when run): `deny/fail-closed`.
  - `"protected-path"` → A: `deny/protected-path` (headless ask degradation); B: `ask/protected-path`; C: not run.
- `kernelOpens`: readFile the case's raw spelling and assert its content equals `readFile(kernelOpens)` — the
  "compare against what the kernel actually opened" pattern (§2.5).
- Output: one line per case `✓/✗/~ <label> [family] item=<n> A=<source>/<verdict> B=… C=… expected=…`; summary
  `N pass, M fail, K open`; exit 1 on any fail **or on an open case passing**; `known: "open"` cases print `~`.
  `--filter <substring>` runs a subset (used for verification and debugging).
- Config for a `policy: "consumer"` case is the consumer-policy fixture: resolution order
  `PI_VERDICT_PROBE_POLICY` → `probe/consumer-policy.real.json` (gitignored) → `probe/consumer-policy.json`
  (synthetic); `_meta` is stripped before loading. `config` and `policy` are mutually exclusive.

### `probe/consumer-policy.json` — synthetic fixture (nits)

Minimal and exercised-only, so no entry is dead fixture data:

```json
{
  "_meta": { "synthetic": true,
    "note": "representative of agents/omp/pi-verdict.json; the real policy stays consumer-side. Override with PI_VERDICT_PROBE_POLICY=<path> or probe/consumer-policy.real.json." },
  "deny": [ "git push[^\\n]*--force(?![\\-\\w])" ],
  "builtinDenyFloor": true,
  "autoDeny": true
}
```

The substring force rule (no left anchor) is **load-bearing for run C**: it catches the four escapes and the
commit-message case exactly like the deployed rule, while the lookahead keeps the lease forms and
`--force-if-includes` out — so if the floor stops covering a case, C reports `user deny rule` and the case fails.
The `printenv` regex and the `tools` allowlist from revision 1 are dropped (they traced to no case), as is the
unexercised `denyPaths` pair; the deployed policy's other entries enter only through the real-file override, which
is documented in `probe/README.md`.

### `probe/README.md`

How to run; the run table A/B/C; the layer vocabulary including `allow` vs a classifier allow; open semantics;
the override chain; the fixtures are runtime-built and POSIX-only; `kernelOpens`; the provenance hand-back
(`bun run provenance` output + SHA, no payload tables in prose).

### `tools/`

- `provenance.ts` (F22): hash the **committed blobs** (`git cat-file blob HEAD:<path>`) with sha256 via
  `node:crypto`, print the full HEAD sha and one `<sha256>  <path>` line per extension file, and warn when the
  working tree differs from the HEAD blob (dirty tree / CRLF). This matches the consumer's
  `git show <sha>:<path> | sha256sum` comparison exactly; exit 0 (warning on stderr).
- `coverage.ts` (F18): calls `buildCases` with a **placeholder `FixtureTree` of constant strings** (never creates
  real symlinks) and renders only stable fields in a stable order (`family`, `label`, `tool`, `expected.layer`,
  `ruleId`, `reasonIncludes`, `deliberate`, `known`, `item`) into `docs/coverage.md`, so
  `git diff --exit-code docs/coverage.md` is deterministic.
- `release-check.ts`: `package.json` version == annotated tag `v<version>`; the tag is annotated; the tag commit
  carries the bump (`git show v<version>:package.json` == version and `git rev-parse v<version>^{commit}` == the
  bump commit).

## Case table (the contract)

Expectations below are the **final** state. Cases tagged `item` (or `ref`) enter as `known: "open"` and lose the
marker as their fix lands (each fix commit removes its own). §2.4 payloads are transcribed 1:1; this table is
authoritative for expectations.

**force-push** (all `tool: "bash"`, `policy: "consumer"` except the two pins noted; `layer: "rule"`,
`ruleId: "git-push-force"` unless stated):

|label|command|expectation|
|---|---|---|
|force before remote|`git push --force origin main`|rule|
|force after remote|`git push origin main --force`|rule|
|short flag|`git push -f origin main`|rule|
|bundle f not last|`git push -fu origin main`|rule|
|bundle f last|`git push -uf origin main`|rule|
|-c global option|`git -c key=value push --force origin main`|rule|
|-C global option|`git -C /tmp/repo push -f origin main`|rule|
|--git-dir|`git --git-dir=/tmp/r push --force`|rule|
|path-qualified|`/usr/bin/git push --force origin main`|rule|
|unquoted substitution|`$(git push --force origin main)`|rule|
|subshell|`(git push --force origin main)`|rule|
|command in a string|`sh -c 'git push --force origin main'`|rule|
|quoted separator in a legal ref|`git push origin 'a&b' --force`|rule|
|uppercase|`GIT PUSH --FORCE`|rule|
|invented spelling|`git push --force-something origin main`|rule, `deliberate: "invented --force-* form: deny, audit boundary"`|
|force + if-includes|`git push --force --force-if-includes origin main`|rule|
|five-deep unquoted substitution|`$($($($($(git push --force origin main)))))`|rule (F5 anti-regression pin; passes today)|
|escaped backslash + newline|`echo a\\` + newline + `git push --force origin main`|rule (F4 anti-bypass pin; passes today)|
|substitution in double quotes|`echo "$(git push --force origin main)"`|rule — **item 1**, open|
|eval re-parser|`eval 'git push --force origin main'`|rule — **item 2**, open|
|eval joins its arguments|`eval 'git push' --force origin main`|rule — **item 2** (F7), open|
|env -S re-parser|`env -S 'git push --force origin main'`|rule — **item 3**, open|
|env -S with trailing args|`env -S 'git push' --force origin main`|rule — **item 3** (F7), open|
|env --split-string=|`env --split-string='git push --force origin main'`|rule — **item 3** (F7), open|
|env -S attached|`env -S'git push --force origin main'`|rule — **item 3** (F7), open|
|env -iS bundle|`env -iS 'git push --force origin main'`|rule — **item 3** (F7), open|
|positional operand|`sh -c '$1' _ 'git push --force origin main'`|rule — **item 4**, open|
|positional $0|`sh -c '$0' 'git push --force origin main'`|rule — **item 4** (F6), open|
|positional ${1}|`sh -c '${1}' _ 'git push --force origin main'`|rule — **item 4** (F6), open|
|positional "$@"|`sh -c '"$@"' _ 'git push --force origin main'`|rule — **item 4** (F6), open|
|depth exhaustion|`sh -c "sh -c \"sh -c \\\"sh -c 'git push --force origin main'\\\"\""`|rule — **item 5**, open|
|line continuation|`git push --for\` + newline + `ce origin main`|rule — **item 11**, open|
|backtick substitution|`` `git push --force origin main` ``|rule — **F8**, open|
|bash -o pipefail -c|`bash -o pipefail -c 'git push --force origin main'`|rule — **F8**, open|
|-f with redirection|`git push -f>/dev/null origin main`|rule — **F8**, open|
|plus refspec|`git push origin +main`|rule — **F24**, open|
|plus refspec with dst|`git push origin +HEAD:main`|rule — **F24**, open|
|plus refspec after --|`git push -- origin +main`|rule — **F24**, open|
|lease|`git push --force-with-lease origin main`|`layer: "classifier"`|
|lease with ref|`git push --force-with-lease=main origin main`|`layer: "classifier"`|
|if-includes alone|`git push --force-if-includes origin main`|`layer: "classifier"`, `deliberate: "no-op without lease; git documents it"` — **item 6**, open|
|commit message quotes pattern|`git commit -m 'note git push --force here'`|`layer: "classifier"`, **no `policy` flag** (the deployed raw-text rule denies it; consumer-side trade, §3.4)|

**path-tier** (no `policy` flag; `skipOn: "win32"` for the `/etc` case):

|label|tool/input|expectation|
|---|---|---|
|XDG age key|read `<fx.xdg>/age/key.txt`|rule, `reasonIncludes: "S0"` — **item 9**, open|
|XDG gnupg|read `<fx.xdg>/gnupg/pubring.kbx`|rule, S0 — **item 9**, open|
|XDG sops|read `<fx.xdg>/sops/age/keys.txt`|rule, S0 — **item 9**, open|
|XDG glab|read `<fx.xdg>/glab-cli/config.yml`|rule, S0 — **item 9**, open|
|XDG gh|read `<fx.xdg>/gh/config.yml`|rule, S0 — **item 9** (F15 adjacent gap), open|
|home age key still anchored with XDG set|read `~/.config/age/key.txt`|rule, S0|
|home gnupg keyring|read `~/.config/gnupg/pubring.kbx`|rule, S0|
|home sops|read `~/.config/sops/age/keys.txt`|rule, S0|
|home glab|read `~/.config/glab-cli/config.yml`|rule, S0|
|gnupg private-keys write|write `~/.config/gnupg/private-keys-v1.d/x.key`|rule, S0|
|repo .config not S0|read `<fx.root>/repo/.config/age/data`|`layer: "allow"` (fork.6 anchoring held)|
|foo.config component|read `<fx.root>/foo.config/age/data`|`layer: "allow"`|
|/etc read is gray|read `/etc/hosts`|`layer: "classifier"`|
|/etc write denies|write `/etc/hosts`|rule, `reasonIncludes: "system directory"` (the reason has no tier label)|
|bashrc write gray|write `~/.bashrc`|`layer: "classifier"`|
|git hooks write denies|write `<fx.root>/repo/.git/hooks/pre-commit`|rule, `reasonIncludes: ".git metadata"` (the reason has no tier label)|
|GNUPGHOME not anchored|read `<fx.root>/gnupghome/pubring.kbx`|`layer: "allow"`, `deliberate: "GNUPGHOME is not an anchored root"` (F10: a normal passing case)|

**kernel-path** (`skipOn: "win32"`):

|label|tool/input|expectation|kernelOpens|
|---|---|---|---|
|escape link before .. (read)|read `<fx.escapeLink>/../etc/hosts`|`layer: "classifier"`|`/etc/hosts`|
|escape link before .. (policy write)|write `<fx.escapeLink>/../<agentDir-slice>/config/pi-verdict.json`|rule, `reasonIncludes: "self-protection"`|`<agentDir>/config/pi-verdict.json`|
|backslash in a filename|read `<fx.backslashLink>/../etc/hosts`|`layer: "classifier"` — **item 7**, open|`/etc/hosts`|
|dangling link write into a protected file|write `<fx.dangling>`|rule, `reasonIncludes: "self-protection"` — **item 8**, open|—|
|symlink loop write fails closed|write `<fx.loop>`|rule, `reasonIncludes: "unresolved symlink"` — **item 8**, open|—|

**self-protection** (grounding cases so layer 0 is in the contract): write to `<agentDir>/config/pi-verdict.json`,
`<agentDir>/config/pi-verdict-trust.json`, `<agentDir>/verdicts/s.jsonl` → rule + `self-protection`; read of the
audit dir → rule + `self-protection`; read of the policy → `layer: "allow"` (reads pass; F2 relabel).

**deny-paths** (fixture-declared base; **item 10**): the family's cases carry
`config: { denyPaths: ["<fx.root>/protected"] }` with `<fx.root>/protected/secret` existing:

|label|tool/input|expectation|
|---|---|
|direct touch asks|read `<fx.root>/protected/secret`|`layer: "protected-path"`|
|symlink before .. evaded it|read `<fx.subLink>/../secret`|`layer: "protected-path"`, `kernelOpens: "<fx.root>/protected/secret"` — **item 10**, open|
|kernel-resolved base form|read `<fx.root>/protected/./secret`|`layer: "protected-path"` — **grounding case** (passes today; `path.resolve` drops the `.`)|

**user-rules** (**item 10**): the family's cases carry `config: { deny: ["protected/secret"] }`:

|label|tool/input|expectation|
|---|---|
|user deny on the lexical path|read `<fx.root>/protected/secret`|rule, `reasonIncludes: "user deny rule"`|
|user deny on the kernel path|read `<fx.subLink>/../secret`|rule, `reasonIncludes: "user deny rule"`, `kernelOpens: "<fx.root>/protected/secret"` — **item 10**, open|

**user-allow** (architecture audit F2; tool bash; each case carries its own `config`; the audit's structural
payloads under a starter-shaped allow list — today every non-`ls` row is rule-allowed, which is the defect):

|label|command|config|expectation|
|---|---|---|---|
|simple allow still allows|`ls`|`{ allow: ["^ls\\b"] }`|`layer: "allow"`, `reasonIncludes: "user allow rule"`|
|newline hides a command|`ls\nbash /tmp/evil.sh`|`{ allow: ["^ls\\b"] }`|`layer: "classifier"` — `ref: "arch-F2"`, open|
|single & hides a command|`ls & npm install evil-pkg`|`{ allow: ["^ls\\b"] }`|`layer: "classifier"` — `ref: "arch-F2"`, open|
|substitution hides a command|`ls $(bash /tmp/evil.sh)`|`{ allow: ["^ls\\b"] }`|`layer: "classifier"` — `ref: "arch-F2"`, open|
|git output flag writes|`git log --format=x --output=<fx.root>/x`|`{ allow: ["^git (log)(\\s|$)"] }`|`layer: "classifier"` — `ref: "arch-F2"` (audit V7), open|

## Phase 2 — the monotone floor (commit 2; architecture audit F4 folded in)

All in `extensions/pi-verdict.ts`; search by symbol, not line (`shellWords` block starts right after
`BASH_DANGER_RULES`). Principle (audit F4, the monotonicity rule): **a raw-text tripwire decides every
`git-push-force` hit; the tokenised word view may only clear a hit, never be the sole path to one.** Wherever the
word view models the shell less faithfully than the tripwire over-approximates, the deny stands (the safe
direction), which is what makes floor coverage monotone across releases. This subsumes revision 2's per-spelling
detection work: the tripwire already denies items 1–5, the F8 spellings and F24, so the word view's job shrinks to
soundness (clear) and confirmation (confirm). Each fix removes its own case markers and adds its `tests/`
regressions.

1. **Tripwire first (`gitPushForce`)**: before any tokenisation, test the raw command (capped at
   `BASH_MAX_MATCH_LEN`, like the other rules) against a restored-and-broadened tripwire anchored on `\bpush\b`
   with a fully flexible body (`[\s\S]*?` — the `git --git-dir=X push` and `-c/-C` gaps need no special
   handling), terminated by one of: `--force(?![-\w])` (bare `--force`); `--force-(?!with-lease)` (every other
   `--force-*` form, including the invented spelling; `--force-if-includes` trips here and is **cleared by the
   word view** after fix 4 — item 6); a bundled short flag `\s-[a-zA-Z]*f[a-zA-Z]*\b` (covers `-f`, `-fu`, `-uf`
   and `-f>/dev/null` — F8); a `+` refspec word `\s+\+` (`+main`, `+HEAD:main`, and after `--` — F24). Quoted
   content no longer breaks the match: the `a&b` refname case is a genuine force push and stays denied, and the
   commit-message case is handled by clearing (fix 3). Continuation tolerance (item 11, rev-2 F4): the tripwire
   also tests the command with unescaped backslash-newlines removed via `/(?<!\\)\\\r?\n/g`, so
   `git push --for\` + newline + `ce` matches, while the escaped-`\\`-newline pin keeps matching on the
   unstripped text (the shell splits the command there; both views hit for that input). The word view owns
   pairing precision: a non-git `push` false trip (`docker push --force`) clears back to gray/classifier —
   today's behaviour. Dry-run validated: 42/42 case rows match for this spec (2026-10-04).
2. **Unsound markers in `shellWords`**: the exported signature and word-list shape stay as today; a construct the
   scanner cannot resolve faithfully produces inert word material plus one shared sentinel token
   (`const UNSOUND = "\u0000unsound\u0000"` — cannot occur in natural output), and `gitPushInWords` treats the
   sentinel as a hit (deny stands) whenever it appears in its words. Marked unsound: `$(` inside double quotes
   (item 1); backtick spans (F8); `eval` in command position (item 2); `env` split-string forms — `-S`, bundle
   `-[a-zA-Z]*S`, `-S<attached>`, `--split-string[=<value>]` (item 3); here-documents (`<<`); process substitution
   (`<(`, `>(`); an unterminated quote. The scanner keeps the revision-2 tokenisation that makes the sound path
   faithful: line continuation consumed inside the scanner (unquoted and double-quoted `\`+`\n`/`\r\n` append
   nothing and do not flush; literal inside single quotes — never a global pre-strip, the `\\` pair is consumed
   first so an escaped backslash stays safe); unquoted `<`, `>` and `>>` are word breaks (flush, drop the char;
   not segment separators); unquoted `(` and `)` stay plain operators with no cap (five-deep unquoted `$(` must
   keep denying). In the shell-option scan, `-o`, `-O`, `+o`, `--rcfile` and `--init-file` consume their following
   word; any dash-word the scan does not model marks unsound instead of silently stopping it (covers
   `bash -o pipefail -c '…'`, `sh -O extglob -c`, `bash --rcfile x -c` — F8).
3. **Clearing gate**: `gitPushForce(command): boolean` becomes
   `if (!tripwireHit(command)) return false; return gitPushInWords(view.words, 0);` where
   `gitPushInWords` keeps its segment scan and `-c` recursion (confirmation), treats the UNSOUND sentinel as a
   hit, and additionally returns true — unsound, deny stands — when a recursed `-c` template contains a positional
   reference (`$0`, `${N}`, `$N`, `$@`, `$*`; item 4) or when the recursion depth cap is exhausted (item 5; the
   `hasReparseCandidate` nuance is unnecessary: a harmless deep nesting has no tripwire hit, so the gate never
   consults the word view). A sound view finding no force push clears the tripwire hit to the normal rule-layer
   path: the commit-message case → classifier; the `a&b` refname case confirms (the word view also finds the real
   `--force` flag). No own-reason plumbing: a tripwire deny's `rule git-push-force: git push --force` reason is
   accurate because the raw text really contains it — plan-review F21 is superseded, and `BashDangerRule.check`
   keeps returning `boolean`.
4. **`--force-if-includes` (item 6)**: in `isForceFlag`, after the lease check add
   `if (t === "--force-if-includes") return false;`. `--force` in the same segment still denies via its own token.
5. **`+` refspec in the word view (F24)**: `isForceFlag` also returns true for `/^\+./` (redundant with the
   tripwire; keeps confirm and clear consistent).

## Phase 3 — simple-command allow guard (commit 3; architecture audit F2)

The user `allow` layer tests raw command text, so `ls\nbash /tmp/evil.sh`, `ls & npm install evil-pkg` and
`ls $(bash /tmp/evil.sh)` run with no model judgment (audit V3 reopened in the user layer), and
`git log --format=x --output=<path>` is rule-allowed (audit V7). New work in `extensions/pi-verdict.ts`:

1. **`allowAdmits(command): boolean`** — the guard the allow loop must pass; false (allow skipped → classifier)
   on: any operator token (`;`, `;;`, `&`, `&&`, `|`, `||`, `(`, `)`, a newline); the ShellView UNSOUND sentinel
   (so `$(`, backticks, `eval`, `env -S`, positional `sh -c`, depth exhaustion, here-docs and process substitution
   are all caught); a redirection other than to `/dev/null`; a re-parser word in command position beyond the
   scanner's markers (`xargs`, `find … -exec`). Audit V7 rides the same guard: a `git` invocation carrying an
   attached write flag — `--output=`, `-o`, `--exec=`, `--ext-diff=`, `--textconv=`, `--git-dir=`, `--work-tree=`
   (the audit's GIT_FORBIDDEN_FLAGS attached forms; prefix match `flag === f || flag.startsWith(f + "=")`) — is
   never allowed. V2's redirection targets are only *deferred* here (redirecting commands go to the classifier);
   deterministic target grading lands with the host-adapter round — recorded as the residual limitation, not
   silently dropped.
2. **Guard the user allow loop** (`classifyByRules`, the `for (const re of user.allow)` block): skip allow when
   `!allowAdmits(command)`; deny, `denyPaths` and gate ordering unchanged. Reuse the `shellWords` view — no second
   lexer.
3. **Tests + probe family**: pin the audit payloads `ls\nbash /tmp/evil.sh`, `cat foo & npm install evil-pkg`,
   `echo $(bash /tmp/evil.sh)`, `cat <(npx -y evil-pkg)` and
   `git log --format=x --output=~/Library/LaunchAgents/x.plist` under the starter-template allow (`^ls\b`) and
   under a copy of the consumer's allow list (`^ls(\s|$)`, `^pwd$`,
   `^git (status|log|diff|show|branch|remote -v)(\s|$)`) in `tests/pi-verdict.test.ts`, expecting a classifier
   call; each fails before the change (rule-allowed today). Dangerous literals by concatenation. The probe's new
   `user-allow` family (case table) pins the same property in the shared contract.
4. **ADR + changelog**: new `docs/adr/0008-simple-command-allow.md` (allow semantics = "this regex admits one
   simple command"; the narrowing direction; the V7 flag table) and a `**BREAKING**` CHANGELOG entry.

## Phase 4 — path fixes (commits 4–6)

1. **Separator split (item 7, commit 4)**: the walker's tail split becomes separator-correct — POSIX splits on `/`
   only (a backslash is a legal filename character there), win32 keeps `/[\\/]+/`.
2. **`kernelWalk` + dangling/loop fail-closed (item 8, commit 4, F1, F20)**: replace `kernelForms(rawPath, cwd)` with
   a shared `kernelWalk(rawPath, cwd): { resolved: string | null; unresolved: boolean }` plus three thin consumers
   (no equivalent exists today):
   - `kernelForms` → `rebuiltForms(resolved)` (floor + self-protection keep the ancestor-rebuild tier); `[]` when
     skipped.
   - `kernelPath` → `resolved` only (denyPaths and user rules stay base tier on the kernel spelling); stays
     `..`-gated so every bash path token pays no syscall walk.
   - `kernelUnresolved` → the flag.

   **The walk runs when the spelling contains `..` OR when `lstatSync(path.resolve(cwd, expanded))` reports a
   symlink** — without the leaf clause neither item-8 case can close (their spellings have no `..`). Walk algorithm:
   maintain `resolved` (start: `path.parse(expanded).root` for absolute input, else `path.resolve(cwd)`) and a queue
   of remaining parts; per part: `realpathSync(resolved/part)` success → advance; failure → `lstatSync`: symlink →
   `readlinkSync`, `hops++` (budget 8; exceeding sets `unresolved` and stops), absolute target → restart from its
   root with its parts prepended, relative target → prepend its parts; not a symlink → keep the lexical candidate;
   `lstatSync` failing too (nonexistent final component) → keep the lexical candidate, `unresolved` false.
   `kernelWalk` inherits `kernelForms`' `~` expansion and 4096 length cap. `classifyPath` gains, after the S-tier
   checks and before the in-cwd allow:
   `if (isWrite && kernelUnresolved(rawPath, cwd)) return D("unresolved symlink (write fail-closed)");` —
   **through `D(...)`**, so it degrades to gray with `builtinDenyFloor: false` like every other floor branch (F20),
   pinned by a test. Reads are left alone (the kernel open fails ELOOP anyway).
3. **XDG config root (item 9, commit 5, F15)**: leave `HOME_RULE_ROOTS` unchanged; add `XDG_CONFIG_ROOTS` (lexical +
   realpath rule forms of `process.env.XDG_CONFIG_HOME`, **ignoring an empty or relative value** as the XDG spec
   requires). Because XDG replaces `~/.config` (it does not nest under it), the two anchored S0 entries become
   unions: `^(?:<homeRoots>/\.config/(?:names)|<xdgRoots>/(?:names))(/|$)` — names `gnupg|age|sops` and `glab-cli`,
   plus `gh` in the XDG alternatives (the review's adjacent gap: `gh` honours `XDG_CONFIG_HOME`; the existing
   segment-anywhere `.config/gh` entry stays for the non-XDG spelling). Add a test seam such as
   `setXdgConfigRootsForTests` that rebuilds the two regexes (mirroring `setTmpdirBasesForTests`), or compute the
   regexes lazily — module-load evaluation means `bun test` cannot otherwise exercise item 9. Keep the comment
   stating the sibling dot entries stay segment-anywhere and that app-level honouring of XDG for these homes is
   unverified (the source handover's §3.4 note; the file is deleted, so the plan's Context stands as the record).
   GNUPGHOME is not added — it stays the recorded `deliberate` case.
4. **denyPaths + user rules gain the kernel tier (item 10, commit 6, F11)** — ADR-0002 amended:
    - `denyPathForms(raw, cwd)`: append `baseForms(kernelPath(expanded, cwd))` when non-null (deduped). Callers
      `anchorDenyPaths` (bases) and `hitDenyPaths`/`hitOmpDir` (candidates) all get it through this one function —
      both sides of the comparison move together, which is why it stays sound.
    - Rename `userRuleTarget(…) : string | null` → `userRuleTargets(…) : string[]`: command → `[command]`; file with
      a path → `[toRuleForm(lexical), toRuleForm(kernelPath)]` (kernel only when the spelling contains `..`, deduped);
      file without a path + scope tool → `[toRuleForm(path.resolve(cwd))]`; else `[]`. Exactly one caller today (the
      user deny/allow block in `classifyByRules`). **Semantics: deny = any target matches; allow = every target
      matches** — an allow regex that matches only the lexical spelling must not allow the call (F11); pin it with a
      test.
    - Amend `docs/adr/0002-deny-paths-deterministic-ask.md` with a short amendment section: denyPaths compares base
      forms of **both** the lexical and the kernel-true spelling (the omp verbatim-absolute behaviour makes the
      lexical-only tier a real bypass); the no-ancestor-rebuild rule is unchanged.

## Phase 5 — verification (F23 corrections applied)

1. **Failing-before is mechanical**: the apparatus commit lands with all `known: "open"` markers; `bun run probe`
   exits 0 with the open cases reporting `~` (they must fail today — a marker that passes is an error). No marker
   stripping.
2. **After the fixes**: `bun run probe` → exit 0, summary `N pass, 0 fail, 0 open`.
3. **Spot checks**: `bun run probe/probe.ts --filter "double quotes"` → 1 pass; `--filter "dangling"` → 1 pass;
   `--filter "hides"` → 3 passes (the arch-F2 hidden-command cases, after commit 3). Do **not** put a dangerous
   literal on a command line (`bun -e '… git push --force …'` is denied by the deployed raw-text policy): use the
   probe filter or `bun test -t "<name>"`, or a script whose literals are built by concatenation.
4. **Provenance**: `bun run provenance` prints the HEAD sha and one sha256 per committed blob; the first line matches
   `git show HEAD:extensions/pi-verdict.ts | sha256sum` — the consumer's staged check compares exactly this.
5. **Coverage**: `bun run coverage && git diff --exit-code docs/coverage.md` → clean.
6. **Release gate**: `bun run release-check` → exit 0 only after the bump + tag.
7. **Existing suites**: `bun run typecheck` exit 0; `bun test` → all pass, 0 fail (baseline 359 + the new
   regressions; the S0 inventory and git-push blocks must stay green); `mise exec -- biome ci .` clean.
8. **CI parity**: `bun run probe && bun run coverage && git diff --exit-code docs/coverage.md` locally before push.

## Phase 6 — delivery (six commits, F13; release held)

1. `chore: probe apparatus + tooling` — probe/, tools/, docs/layers.md, docs/coverage.md, tsconfig/biome/package.json/
   ci.yml/.gitignore, the plan (this revision-3 text written to docs/plans/probe-apparatus.md as the execution's
   first action), the `testing-handover.md` deletion, AGENTS.md updates (Key Directories, Development Commands,
   Testing & QA, and the stale "no lint script / no biome config" statements). Probe green with open markers.
2. `fix(floor): monotone floor — tripwire + sound-gated word view (items 1–6, 11, F8, F24; audit F4)` — fixes 1–5
   above, its `tests/` regressions, `docs/adr/0007-monotone-floor.md` (a floor change may never turn a raw-text hit
   into a non-hit on an unsound parse), markers removed, CHANGELOG entry, coverage regenerated.
3. `fix(rules): simple-command allow guard (audit F2)` — `allowAdmits` + the guarded allow loop, tests, the probe
   user-allow family, `docs/adr/0008-simple-command-allow.md`, the `**BREAKING**` CHANGELOG entry, coverage
   regenerated.
4. `fix(path): kernel walker items 7–8` — kernelWalk, the write fail-closed branch, tests, README pipeline text +
   CONTEXT kernel-true form, CHANGELOG, coverage regenerated.
5. `fix(path): XDG config root (item 9)` — roots + seam + tests, CHANGELOG, coverage regenerated.
6. `fix(path): denyPaths + user rules kernel tier (item 10)` — denyPathForms/userRuleTargets, tests, ADR-0002
   amendment, README/security-principles/CONTEXT/verification-doc updates, CHANGELOG.

**No version bump, no tag, no push this round.** The follow-up `gate-architecture-fixes` round (the audit's
remaining items: F1+F3, F5, F6, F7, F8, F9, F10, F11, F12, F13, F14-optional) owns the single bump to
`0.16.0-fork.7` in its last fix commit, then the annotated tag `v0.16.0-fork.7`, `git push main --follow-tags`,
`bun run provenance` + `bun run release-check`. The GitHub Release is created by the user (the floor blocks
`gh release`). This round's hand-back: the case-file diff (markers removed per fix) + the HEAD SHA +
`bun run provenance` output — no payload tables in prose.

## Disposition of review findings

| Finding | Where addressed |
|---|---|
| plan-review F1 walk skipped without `..` | Phase 4 fix 2 (leaf-symlink clause) |
| plan-review F2 no rule-allow layer | Phase 1 schema + case table (`"allow"`) |
| plan-review F3 run C undefined / floor-only A+B | Phase 1 runner run table |
| plan-review F4 global strip bypass | Phase 2 fixes 1–2 (scanner continuation; tripwire + word view) + anti-bypass pin |
| plan-review F5 unquoted `$(` capped | Phase 2 fix 2 (uncapped unquoted; quoted `$(` is an unsound marker — no cap needed) + five-deep pin |
| plan-review F6 positional gaps | superseded by the monotone design: positional refs are an unsound marker (Phase 2 fix 3), no substitution; the `$0`/`${1}`/`"$@"` cases stay |
| plan-review F7 eval/env forms | superseded: eval and env split-string forms are unsound markers (Phase 2 fix 2); one case per spelling stays |
| plan-review F8 tokeniser regressions | Phase 2 fixes 1–2 (the tripwire hits them; option-arg scanning and word breaks keep the sound path faithful) + three cases |
| plan-review F9 fixture pinned walker artefact | Phase 1 fixtures (`subLink` → existing dir) + kernelOpens + grounding label |
| plan-review F10 open-case semantics | Phase 1 runner/schema + GNUPGHOME relabel + item/ref tags |
| plan-review F11 allow loop widening | Phase 4 fix 4 (deny any / allow every) + pinned test |
| plan-review F12 tests/ left untouched | every fix commit carries its `tests/` regressions |
| plan-review F13 one-shot commit | Phase 6 six-commit slicing |
| plan-review F14 docs omissions | Phase 6 doc list per commit |
| plan-review F15 XDG contradiction / no seam | Phase 4 fix 3 |
| plan-review F16 runner underspecified | Phase 1 runner (cwd/host/reloadRules/dynamic import) |
| plan-review F17 fixture safety/members | Phase 1 fixtures |
| plan-review F18 coverage nondeterminism | Phase 0/1 `coverage.ts` (stable fields, placeholder fixture) |
| plan-review F19 typecheck of probe/tools | Phase 0 (allowImportingTsExtensions, node:-only, fs JSON, biome ci) |
| plan-review F20 unresolved deny ignores floor flag | Phase 4 fix 2 (`D(...)`) + pinned test |
| plan-review F21 depth reason misleading | superseded by the monotone tripwire (Phase 2 fix 3): the deny is genuine, the reason accurate |
| plan-review F22 provenance vs committed blobs | Phase 0 `provenance.ts` (git cat-file + dirty warning) |
| plan-review F23 verification errors | Phase 5 (filter, no literal on the command line, baseline 359, phase numbering, step 0) |
| plan-review F24 `+` refspec missing | Phase 2 fixes 1 and 5 + three cases |
| audit F4 non-monotone floor | Phase 2 (tripwire decides hits; the sound word view only clears; ADR-0007) |
| audit F2 compound-command allow | Phase 3 (`allowAdmits` + guarded allow loop + user-allow family; ADR-0008, BREAKING) |
| release held (user decision) | Phase 6: commits only; the architecture round owns the single bump/tag/push |
| nit: fixture entries unexercised | synthetic fixture carries only exercised entries |
| nit: gitignore speculative | `probe/consumer-policy.real.json` is the documented default override |
| nit: handover archive status | moot: the handover is deleted, not archived (Context; Phase 0 step 6) |

## Assumptions & contingencies

- **omp path behaviour (Appendix B)** is treated as strong evidence, not proof; the kernel-path cases assert
  extension behaviour only, so a host-behaviour dispute does not invalidate them.
- If adding kernel forms to `anchorDenyPaths` (bases) breaks an existing denyPaths test, apply the kernel tier to
  candidates only and leave bases lexical — that fallback preserves the fix's value (the bypass is on the candidate
  side) and is recorded in the ADR amendment.
- The commit-message clearing (Phase 2 fix 3) must never clear a command-position force push: if it ever does in
  tests, restrict clearing to tripwire hits whose matched text lies entirely inside a quoted argument (track quoted
  spans in the scanner) and record the tightening.
- Redirection-target grading (audit V2) is deferred: the Phase 3 guard sends redirecting commands to the
  classifier; deterministic S0/S1/S2 grading of `>` targets lands with the host-adapter round and is recorded as a
  known limitation in ADR-0008 and the README.
- **Release hold (user decision):** nothing is pushed until the `gate-architecture-fixes` round completes. If the
  consumer needs a mid-round pin, the user requests a tag explicitly; otherwise the single bump/tag/push happens at
  that round's end.
- Windows: probe path/symlink families skip on win32 (`skipOn`), mirroring the test suite's convention; fixtures
  live under `os.tmpdir()`, never the checkout.
- The synthetic policy fixture is minimal by design; the deployed policy is exercised through
  `PI_VERDICT_PROBE_POLICY` (or `probe/consumer-policy.real.json`), and any layer conflict surfaces as a case
  failure, not a prose debate.
