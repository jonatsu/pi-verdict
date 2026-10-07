# Documentation truth audit and action plan

Status: audited on 2026-10-07 at main `7ff2750`; **no fix executed yet**. The user approved items A–P and paused the
project before execution. Q is an open investigation; R is deliberately left as is. Delete this file when every
item is done or moved to `TODO.md`.

## What was audited, and how

The surface was every reader-facing document: `README.md`, `CONTEXT.md`, `docs/*.md`, `probe/README.md`,
`docs/plans/*.md`, `docs/adr/*.md` and `CHANGELOG.md`. `AGENTS.md` and the repository rules in `.agents/rules/`
were rewritten and verified the same day (commits `0c71d4e`, `7ff2750`) and are out of scope.

Two read-only agents mapped each document's claims against the code; Claude re-verified the high-impact claims.
Items marked **verified** were re-checked by Claude against the code or by running `adjudicate`; the rest rest on
the agents' code reading, so re-check each fact while fixing it. The context-architecture checker
(`~/.config/claude/skills/context-architecture/scripts/check_context_architecture.py .`) reported 66 findings: 20
documents no trigger-keyed route reaches (item M) and 46 line-number references in plans (item R).

Line numbers below are as of `7ff2750` and drift as files change; locate by the quoted text.

## How to execute

The items touch overlapping files, so group the work by file, not by letter. Four lanes own disjoint files and can
run in parallel, each on its own branch or worktree; M and P come last because they depend on where the plans and
the ADR index land.

| Lane | Files it owns | Items |
| --- | --- | --- |
| 1 | `README.md`, `docs/security-principles.md` | A (their parts), B, E |
| 2 | `docs/configuration.md`, the `_hint` string in `USER_CONFIG_TEMPLATE` (`extensions/pi-verdict.ts`) | A (its parts), C, D, G (its parts) |
| 3 | `docs/layers.md`, `CONTEXT.md`, `probe/README.md`, `docs/host-contract.md` | A (their parts), F, G (their parts), H |
| 4 | `docs/plans/`, `docs/adr/`, `CHANGELOG.md`, `docs/verification-2026-10-04.md` | I, J, K, L, N, O, and D's CHANGELOG line |
| last | `AGENTS.md`, `TODO.md` | M, P |

Lane 2's `_hint` change is a code change: run the full check set from `.agents/rules/pv-typescript.md` ("Done"),
and give lane 4 the new wording for its `CHANGELOG.md` `### Fixed` line. Docs must follow `.agents/rules/` and the
writing rules: no plan or finding ids in reader docs (ADR refs are fine; `CHANGELOG.md` and ADRs may keep ids a
tracked plan defines). Commit each lane as `docs(<scope>): …` commits with explicit paths, no trailer.

## Action items

### A. Correct behavior claims that are now false

These describe the gate's security behavior, so they matter most.

1. **MCP and custom tools vs `denyPaths` and `tools`.** `README.md` ~:246 says MCP and custom tools "bypass the
   extractor entirely"; `docs/configuration.md` ~:35 says `tools` does not interact with `denyPaths`. Now an
   unknown tool's path-shaped payload fields reach the `denyPaths` ask (`extensions/pi-verdict.ts` ~:3016), and
   the `tools` exemption runs after the deny-side layers (~:3105), so a `tools`-listed tool carrying a protected
   target still asks. An agent confirmed `mcp_fs {path:"~/.ssh/id_rsa"}` gives `protected-path/ask` even when
   listed in `tools`; CHANGELOG 0.18.0 lists both as BREAKING. Fix: covered through the targets the adapter
   extracts; their fields never feed user `allow`/`deny` regexes.
2. **Trust-store reads are denied** (verified). `README.md` ~:180 and ~:248, `docs/configuration.md` ~:41,
   `docs/security-principles.md` ~:19 and ~:71, `docs/layers.md` ~:14 say only `verdicts/` is read-denied. Code:
   `readDenied = [...verdictsForms, ...trustForms]` (`extensions/pi-verdict.ts` ~:2786; test at
   `tests/pi-verdict.test.ts` ~:3684); a read of `pi-verdict-trust.json` is `rule/deny`, a read of
   `pi-verdict.json` is `rule/allow`. Fix: make `docs/layers.md` row 0 the one owner ("writes to config, trust
   store and installed copy; reads and writes of `verdicts/`; reads of the trust store") and point the others at
   it.
3. **The over-cap ask.** `docs/security-principles.md` ~:35 "long read-only actions can auto-allow" and `README.md`
   ~:28 "not how long it is" ignore that an action over `BASH_MAX_MATCH_LEN` (8192 chars) is asked before user
   allow (~:3080). Add the exception.
4. **Only `~`, `$HOME` and host spellings are read.** `docs/security-principles.md` ~:47 says
   "environment-variable spellings are normalized". Only `~`, `$HOME`, `${HOME}` (via the strict-redactor ask)
   and omp's own path forms (`hostPathForms`) are; other variables are not expanded.
5. **In-project `glob` still allows.** `README.md` ~:195, `docs/configuration.md` ~:37, `docs/layers.md` ~:20
   say a globbed target never gets a rule allow. An in-project `glob` listing (`globStaysInProject`, ~:3024) is
   still a floor allow; user allow and `tools` never admit a globbed target.
6. **Host spellings and withheld rule allows.** `docs/configuration.md` ~:34, `docs/layers.md` ~:20-22 and
   `CONTEXT.md` ~:49 say file tools match "the resolved absolute path". Now every target is graded in every form
   the host resolves (`hostPathForms`, `expandTargetForms`, ~:2429): user deny matches any form, user allow needs
   every form. A rule allow is also withheld for registered internal URL schemes (`ssh://`, `vault://`) and for a
   `read` of a missing relative path (~:3094, ~:3108); `docs/layers.md` row 6 omits both.
7. **Probe `rule` layer.** `probe/README.md` ~:25 describes `rule` as "(built-in floor, user rules, or an
   in-cwd/file allow)"; `assertLayer` makes `rule` a deny and a rule allow the separate `allow` layer. Remove "or
   an in-cwd/file allow".

### B. Fix the two pipeline diagrams

`README.md` ~:190-200 places "user deny beats user allow" before the `.omp` and `denyPaths` steps and omits the
`tools` step. Reorder to `docs/layers.md`: self-protection, built-in floor, user deny, `.omp` gate, `denyPaths` ask
(with the strict-redactor match), over-cap ask, user allow and `tools`, opaque-call ask, classifier, degraded-policy
withholding; add "Authoritative order: `docs/layers.md`". Replace `docs/security-principles.md` ~:84-86 ("clearly
safe → allow", no ask or user rules) with a pointer.

### C. `docs/configuration.md`

1. **Example and starter list** (verified). The example JSON (~:11) must equal `USER_CONFIG_TEMPLATE`
   (~:1115-1145) minus `_hint`. Today it lists `task` in `tools` and lacks `audit`, `notifyAllows`,
   `classifierMinConfidence`, `classifierFallbackModel` and `subagentAskTimeoutMs`. `DEFAULT_ALLOWED_TOOLS`
   (~:1088) omits `task` on purpose: listing it would let subagent launches bypass the subagent gate. Drop `task`
   from ~:11 and ~:35, and name it among the deliberately absent tools with that reason.
2. **Config errors and degraded policy** (missing). Add a section from `loadUserRules` (~:1319-1500) and ADR-0010:
   a parse or load failure leaves empty rules with the floor on plus a notification; the `policyDegraded` triggers
   and effects; a single string for `deny` or `denyPaths` is coerced to a one-element list with a skip note and
   does not degrade (~:1146); unknown keys warn (~:1349).
3. **Subagent asks.** ~:57 lists only protected-path, `.omp` and `autoDeny:false` asks as denied without a human;
   `autoResolve` also denies over-cap, opaque-call and degraded-policy asks. Complete the list from
   `resolveAskWithoutHuman`.
4. **jev works on omp.** ~:48 says omp cannot load the adapter; it registers on omp, and `completeForClassifier`
   calls `streamDecisions` directly (`extensions/jev-adapter.ts` ~:32 and ~:411; `extensions/pi-verdict.ts`
   ~:3622). State both hosts and how the key is resolved. `README.md` ~:152 has the same error (lane 1).
5. **Volatile mirrors.** Delete ~:40 "TypeSafe's state budget is 32k tokens", ~:55 "measured p90 of 19.8 s" and
   "used to be 25 + 25 + 15 + 15 s". Keep the behavior; name `ADJUDICATION_BUDGET_MS` and
   `CLASSIFIER_TIMEOUT_MS` instead of figures.

### D. Fix the `USER_CONFIG_TEMPLATE` `_hint` text (verified)

The `_hint` string (`extensions/pi-verdict.ts` ~:1118) links the upstream `jesset/pi-verdict` configuration page,
says the fallback is consulted on "ask / fail-closed / jev confidence below classifierFallbackConfidence, default
50" (that key is replaced; check `confidenceDemotion` and `runConfidenceCascade` for the real triggers), and
gives `task` as an example `tools` entry. Point the URL at `jonatsu/pi-verdict`, rewrite the fallback sentence,
drop `task`. It is user-visible text: add a `CHANGELOG.md` `### Fixed` line under a new `## [Unreleased]`, and run
the full check set.

### E. `README.md` front matter and duplication

- ~:9 "just 1k+ lines of code" (verified; `pi-verdict.ts` is 6,285 lines) and ~:171 "one file on purpose" (the
  split is `TODO.md` item 2): remove both; no line counts.
- ~:4 npm badge (verified) points at npmjs `pi-verdict`, which is not published there; the package is
  `@jonatsu/pi-verdict` on GitHub Packages (~:45). Remove it.
- ~:94-136 restate most of `docs/configuration.md` (footer text verbatim, audit, EXPLAIN-GATE, cascade,
  `subagentGate`) with a config example that differs from the template. Keep one sentence per key and link.
- ~:126 and ~:128 list scope tools as `grep`/`find`/`ls`; the set (`SCOPE_TOOL_NAMES`, ~:2086) is `grep`, `find`,
  `ls`, `glob`, `ast_grep`, `ast_edit`.

### F. `CONTEXT.md`

- ~:69 uses the three-tool scope list, and says `/verdict` edits "the one scalar key"; it also edits `footer`
  (~:5750). Define "scope tool" once here with the six names.
- ~:109 says `askSource` includes `degraded-policy`; it is `"protected-path" | "rule"` only (~:508), and
  `degraded-policy` is set in `adjudicate`.
- ~:33 and ~:85 restate audit and EXPLAIN-GATE behavior; cut each to a term definition.
- Missing terms: scope tool, over-cap ask, adjudication budget, transcript redaction, host spelling.
- It carries implementation detail (`kernelWalk`, `reloadRules`) despite its own terms-only rule; move or drop.

### G. Remove plan ids readers cannot resolve

`docs/configuration.md` ~:40 `item 6a`, ~:55 `item 7`; `docs/layers.md` ~:19 `item 6a`; `CONTEXT.md` ~:49
`items 7–8` and `item 10`, ~:109 `Phase 0 seam`. `item 7` and `Phase 0` each match several plans. Replace with the
ADR (ADR-0009's Phase 4 amendment covers the action caps) or nothing.

### H. `docs/host-contract.md`

It pins omp 18.5.1 (~:21, ~:33, ~:36-39); the installed host is 18.6.1. An agent confirmed `PI_SCOPE_ALIASES` and
`PI_SUBPATH_REMAPS` (with `pi-ai/compat`) in 18.6.1 but could not find `@oh-my-pi/pi-ai` or `pi-tui` exports, so
re-verify those. Row ~:13 says both extensions dynamically import `@earendil-works/pi-coding-agent`; only
`pi-verdict.ts` does (~:4863), `jev-adapter.ts` has a type import. Restate versions as "verified against omp
18.6.1 on <date>".

### I. Mark the finished plans and archive them

- `docs/plans/tool-access-hardening.md` ~:5 says "approved …, not yet executed". Its round outcome (~:616-694)
  records all nine commits plus a fix-forward (01260f9 … 7c5dbe9, 0f0ab53), released in v0.18.0. Replace the
  status with `**Status: COMPLETED — 2026-10-05.**` plus a pointer to the round outcome and to CHANGELOG
  `[0.18.0]` for the later review fixes and host path resolution. Its "Deferred" section (~:533) should say the
  path service and the file split moved to call-model plan items 9 and 12, and the loader question is settled
  there.
- `docs/plans/input-coverage-hardening.md` ~:3 says "proposed, not scheduled". The tool-access plan's disposition
  table (~:515-526) shows every item addressed (a3c7071, 7ad1014, the round). Mark it `SUPERSEDED` with that
  pointer.
- Archive both with `git mv` into `docs/plans/archive/` (convention: `docs/plans/archive/probe-apparatus.md`,
  commit `ba841f2`), then repoint the references in `docs/plans/call-model-and-rule-hardening.md` (~:7, ~:32,
  ~:627).

### J. Call-model plan: leftovers after decision 11

In `docs/plans/call-model-and-rule-hardening.md`: ~:29 "split the single 4,788-line file along the seams Part B
creates" and ~:573-574 (title "…along the call model's seams", "4,788 lines") contradict decision 11; ~:691
decision 6 "Item 1a, in commit 1" is now delivery step 5; ~:5 says item 9 follows "the small Part A fixes" but
delivery puts items 3-6, 1-2 and 11 first; ~:304 names `PROJECT_OVERRIDABLE_KEYS`, now `PROJECT_OVERRIDE_DIRECTION`
(~:1213); ~:296 "once the tool-access plan's Phase 4 lands" (it landed, f3b47a5) and ~:334/~:639 "reserves ADR-0009
and ADR-0010" (both exist; the next free number is 0011).

### K. ADR status and date fixes

- ADR-0001 (verified): `date: 2025-08-27` should be `2026-08-27`; `status: superseded (…fully removed)` should read
  `superseded by ADR-0005 (removed 2026-09-25; restored 2026-10-04)`.
- ADR-0001 ~:8 "Restored 2026-10-05" and ADR-0002 ~:187 "Superseded 2026-10-05 by ADR-0005": ADR-0005 is dated
  2026-10-04; use that date or say "pointer added 2026-10-05".
- ADR-0002 ~:148 cites the `toolKind` dispatch, which no longer exists; add an amendment pointing to ADR-0009
  (unknown tools' path-shaped fields now reach the `denyPaths` ask).
- ADR-0003 ~:21 says "write-deny itself no longer exists"; ADR-0005 restored it. Amend, and note that the adapter
  copy is write-protected only under the directory install (see P).

### L. Add an ADR index

Nothing lists ADR-0005 to ADR-0010. Add `docs/adr/README.md` with number, title, status and date per ADR. Statuses
are inconsistent (ADR-0004 "accepted" despite superseded decisions in its amendments); reflect amendments there.

### M. `AGENTS.md` routing index

The checker reports 20 documents no structural route reaches: the ten ADRs, `docs/agents/*.md`,
`docs/configuration.md`, `docs/coverage.md`, `docs/host-contract.md`, `docs/layers.md`,
`docs/security-principles.md`, `docs/verification-2026-10-04.md` and `CONTEXT.md`. `AGENTS.md` names them only
inline. Add a short index of trigger-keyed routes (`- Read when <condition>: [doc](path)`), route the ADRs through
the new index from L, and replace the inline mentions so the file does not grow. Do this after I and L, with the
`agents-context-docs` skill; then run both checkers.

### N. `CHANGELOG.md`

Point the Keep a Changelog and SemVer links (~:5-6) at the English pages (they use `zh-CN`); add compare links
(`[0.18.0]: https://github.com/jonatsu/pi-verdict/compare/v0.17.0...v0.18.0`); note under `[0.17.0]` that it is a
tag only, with no GitHub Release, shipped to users as 0.18.0; add `## [Unreleased]` with the next change (D's line).
The tool-access plan's residual about creating the v0.17.0 Release (~:686, decision 8 ~:562) is superseded by
0.18.0; say so in I.

### O. `docs/verification-2026-10-04.md`

A dated record pinned to `v0.16.0-fork.2` but running through 2026-10-05; it already flags its superseded claims
(~:274-292). Add one line under the title: dated record, not current guidance; later behavior is in `CHANGELOG.md`.
Route it from M.

### P. Code: the copy install leaves `jev-adapter.ts` unprotected (verified)

`buildProtectedSet(agentDir, <agentDir>/extensions/pi-verdict.ts)` protects `pi-verdict.ts` but not
`jev-adapter.ts`: `isProtectedWritePath` returned `true` for the first and `false` for the second. `pi-verdict.ts`
imports the adapter, so an agent could change the gate by rewriting it. Only the documented single-file copy
install (`cp extensions/pi-verdict.ts extensions/jev-adapter.ts ~/.pi/agent/extensions/`) is affected; the git-spec
directory install is protected by prefix. Add it to `TODO.md` under "Security and correctness"; the file split
(item 12) widens protection to the module directory and could close it there, but it needs its own pinned test.

### Q. Investigation, no change yet

- `README.md` ~:244 "parallel gray-zone calls are adjudicated serially": only dialogs are serialized
  (`serializeDialog`, ~:5189); no classifier queue was found.
- `README.md` ~:233 says eight bypasses were fixed in 0.2.0; `research/rule-layer-security-audit.md` ~:5 says all
  eight remain unfixed. Decide which is current.
- `README.md` ~:162-167 competitor dependency counts are external and volatile; verify or drop.
- `README.md` ~:247 says declared paths with spaces never match in bash; the new shell-escape handling applies to
  `read` only, so this likely still holds. Confirm.

### R. Left as is

46 line-number references in plans (mostly in finished plans, which are records). Fix only those in the active
call-model plan if they mislead, during J.

## Next steps

1. Run lanes 1-4 (A-L, N, O); review each lane's diff against this file; merge.
2. Then M (`AGENTS.md` routing) and P (`TODO.md` entry); run both checkers.
3. Then resume `TODO.md` from the top: the silent subagent blocks, then the file split.
4. Q stays here (or moves to `TODO.md`) until someone settles it.
