# Review of `docs/plans/probe-apparatus.md` (2026-10-04)

> **Provenance.** Produced by an external reviewer on 2026-10-04 against HEAD `6136aa0`
> (`v0.16.0-fork.6`) and preserved here so its numbered findings (F1–F24, and the re-review's
> N1–N14) stay citable from tracked documents (`docs/plans/probe-apparatus.md`). Findings are
> historical evidence at that revision, not current behaviour: verify against the tree before
> relying on any line number or claim.
>
> **Note on sources.** This review repeatedly cites a source `testing-handover.md` (section and item
> numbers) that the consumer session wrote and that was deleted after this round absorbed its
> contents into the case table and this plan. Those citations are kept as historical references to
> the reviewed artifact; the underlying defects are now tracked by the plan's item numbers.

**Revision 3 (2026-10-04): re-review of plan revision 2 (506 lines).** **Verdict: proceed after the changes
below.** Revision 2 resolves F1-F4, F9, F10, F14 and F16-F23 completely, and it reflects all four user decisions.
One new defect would keep the probe permanently red (N1), and two leave the security gate open (N2, N3). The rest are
cheap fixes to the plan text. The re-review findings come first; the revision 1 findings follow unchanged, for
reference.

## Re-review of plan revision 2

The citation conventions are the same as below. EXECUTED means the claim was run against `gitPushForce` at HEAD
`6136aa0`:

| Input | `gitPushForce` today | Finding |
| --- | --- | --- |
| `bash -euo pipefail -c 'git push --force origin main'` | **`false`** | N3 |
| `bash +x -c 'git push --force origin main'` | **`false`** | N3 |
| `git push origin main 2>&1 --force` | **`false`** | N4 |
| `sh -c '"$@"' _ git push --force origin main` (separate operands) | `true` | N1: a pin that passes today |

### N1 (major). The positional `"$@"` case can never pass, so the probe never reaches green (CONFIRMED)

- **Plan:** l.262 is the case `sh -c '"$@"' _ 'git push --force origin main'`. l.355 maps `"$@"` to
  `rest.slice(1).join(" ")`.
- **Evidence:** text substitution yields `"git push --force origin main"`, with the quotes kept. `shellWords` turns
  that into a single word (`:182-195`), and its `wordBasename` is not `git`. The case therefore still misses after
  the fix, and under the strict open semantics (l.137-140) its marker can never be removed.
- **It is also not a hazard.** With one operand, `"$@"` expands to a single word, so sh looks for a command literally
  named `git push --force origin main` and fails with "command not found". The case came from revision 1's F6, which
  was wrong about this spelling.
- **Fix:** replace the l.262 row with:

  ``positional $@ unquoted | `sh -c '$@' _ 'git push --force origin main'` | rule — item 4, open``

  Unquoted `$@` is word-split, so this spelling does run a push. Also add the passing pin
  `sh -c '"$@"' _ git push --force origin main`, with separate operands (EXECUTED: `true`). The direct scan already
  catches it (`:270-279`).

### N2 (major). "Allow = every target" allows by vacuous truth when there are no targets (PLAUSIBLE: the plan does not say how to iterate)

- **Plan:** l.413-418. `userRuleTargets` returns `[]` for a file tool with no path that is not a scope tool, and for
  MCP or custom tools.
- **Evidence:** today the whole user-rule block sits under `if (target !== null)` (`:1801-1802`). Suppose that guard
  is dropped and the allow check becomes `targets.every((t) => re.test(t))`. On an empty array it returns `true`, so
  every MCP or custom tool call is allowed whenever any allow regex exists. The classifier is bypassed, and the
  `tools` allowlist stops being the only exemption.
- **Fix:** add to l.416: "When `targets` is empty, skip the whole user deny/allow block, exactly as the
  `target !== null` guard does today." Pin it with a test: with `allow: [".*"]`, an MCP tool call still reaches the
  classifier.

### N3 (major). The shell-option skip still misses `-euo pipefail` and `+x`, and the `+o` skip is unreachable (CONFIRMED + EXECUTED)

- **Plan:** l.370-372 lists `-o`, `-O`, `+o`, `--rcfile` and `--init-file`.
- **Evidence:** the option scan stops at `if (!opt.startsWith("-")) break;` (`:285`).
  - `+o`, `+x` and `+e` never start with `-`, so the scan stops before any skip logic runs.
    `bash +x -c 'git push --force …'` stays a bypass (EXECUTED: `false`).
  - `bash -euo pipefail -c '…'` is a very common spelling. The bundle `-euo` is not exactly `-o`, so `pipefail` ends
    the scan (EXECUTED: `false`).
- **Fix:** replace l.370-372 with:
  - An option word matches `^[-+]`.
  - A short-option bundle (`^[-+][a-zA-Z]+$`) whose last letter is `o` or `O` consumes the next word.
  - `--rcfile` and `--init-file` consume the next word.
  - Only a word that does not start with `-` or `+` ends the scan.
- **Cases:** add `bash -euo pipefail -c 'git push --force origin main'` and
  `bash +x -c 'git push --force origin main'` as F8 rows, both marked open.

### N4 (minor). Redirections containing `&` still split the segment (CONFIRMED + EXECUTED; pre-existing, not a regression)

- **Plan:** l.344-345 treats `<` and `>` as word breaks, but `&` stays a command operator (`:151`, `:208`).
- **Evidence:** in `git push origin main 2>&1 --force`, the `&` starts a new segment, so `--force` falls outside the
  push segment (EXECUTED: `false`). The d5a8115 regex's `[^;|&]*` missed this too.
- **Fix:**
  - Consume `>&`, `<&`, `&>`, `&>>`, `>|` and `<>`, together with any leading file-descriptor digits, as a single
    redirection, and do not emit them as operators.
  - Add `git push origin main 2>&1 --force` as an F8 row marked open.
  - This joins the round only if the user agrees; see "Decisions for the user (revision 3)".

### N5 (minor). The `)` that closes a double-quoted `$(` must be found quote-aware (PLAUSIBLE: the wording is ambiguous)

- **Plan:** l.338-340: "recursively scans the substring up to the depth-matched `)`".
- **Risk:** if the closing `)` is found by counting parentheses before the substring is scanned, then
  `echo "$(echo ')' ; git push --force origin main)"` closes at the quoted `)`. The rest becomes inert double-quoted
  text, and the call is missed.
- **Fix:** write it as "the recursive scanner consumes input until its own unquoted, unmatched `)` and returns that
  index; there is no separate parenthesis counting". Add the case above as an item 1 row marked open.

### N6 (minor). The `env` split-string detection is underspecified (PLAUSIBLE)

- **Plan:** l.349-351.
- **Gaps:**
  - `-S` must be searched for across env's leading options. `env -u HOME -S '…'` and `env -C /tmp -S '…'` only work
    if the arguments of `-u` and `-C` are skipped.
  - The bundle and attached forms need one anchored regex, because `-vS'git push…'` arrives as a single word.
- **Fix:** write it as follows:
  - Scan env's options left to right.
  - `-u`, `-C`, `--unset` and `--chdir` take the next word as their argument.
  - A word matching `^-[a-zA-Z]*S(.*)$`, or `--split-string(=…)?`, is the split-string form.
  - The string is its attached remainder, or the next word if there is no remainder.

### N7 (minor). The release commands are wrong and in the wrong order (CONFIRMED)

- **Wrong command:** plan l.23 and l.455 say `git push main --follow-tags`. Git reads `main` as the remote, so the
  push fails. Use `git push origin main --follow-tags`. Revision 2 of this file carried the same error, and it is now
  corrected.
- **Wrong order:** l.455 runs `release-check` after the push. A failing check would then sit behind a tag the consumer
  can already see.
- **Fix:** run the steps in this order:
  1. the annotated tag;
  2. `bun run release-check`;
  3. `bun run provenance`;
  4. the push.

### N8 (minor). Commit 5 does not regenerate coverage, so CI fails on that commit (CONFIRMED)

Plan l.451-453 leave "coverage regenerated" out of commit 5. That commit removes the item 10 markers, and
`docs/coverage.md` renders `known` and `item` (l.216), so the freshness check fails. Add "coverage regenerated" to
commit 5, and check every other commit that removes markers for the same step.

### N9 (minor). Provenance verification contradicts the tool's output format (CONFIRMED)

l.211 makes the HEAD SHA the first output line, but l.433-434 say "the first line matches
`git show HEAD:extensions/pi-verdict.ts | sha256sum`". Change it to "the `extensions/pi-verdict.ts` line matches".

### N10 (minor). The `+` refspec check has false positives, all in the deny direction (CONFIRMED by code reading)

- **Plan:** l.368-369: after `push` has been seen, any word matching `^\+.` counts as a force refspec.
- **Evidence:** the push scan (`:274-278`) checks every later word in the segment. It does not tell options, option
  values, the remote and refspecs apart.
- **False positives:**
  - an option value in a separate word, such as `git push -o +x origin main`, `--push-option +x`,
    `--receive-pack +x` or `--repo +x`;
  - `git stash push -- +file`, because the push check fires on any `push` word after `git` (`:276`).
- **Not affected:**
  - `--push-option=+x`, because that word starts with `--`;
  - `+:main`, a forced delete, which is caught, correctly.
- **Fix:** add the sentence "the word after `-o`, `--push-option`, `--receive-pack`, `--exec` or `--repo` is an
  option value, not a refspec". Alternatively, record the false positives as accepted in the code comment and the
  CHANGELOG. This is the user's choice; see the decisions below.

### N11 (minor). The dangling-link case fails on macOS and with a symlinked agentDir (PLAUSIBLE; pre-existing, next to F1)

- **Evidence:** `buildProtectedSet` adds the missing trust file through `baseForms` (`:1550`), which yields only the
  lexical form. The walker rebuilds the target through the realpath of its parent, for example `/private/var/…`
  instead of `/var/…`, and `rebuiltForms` (`:353-369`) never yields the lexical form. The two sides never compare
  equal.
- **Consequence:**
  - The item 8 dangling case fails on macOS.
  - Today, a direct write to the real path of a missing trust file is missed whenever the agentDir path contains a
    symlink.
- **Fix:**
  - Build `exact` and `prefixes` with `rebuiltForms` for missing files, or compare the rebuilt forms of both sides.
  - Pin it with a test that uses a symlinked agentDir.
  - This touches the self-protection layer (ADR-0005), so it joins the round only if the user agrees.

### N12 (minor). The XDG test seam cannot simply "rebuild the two regexes" (CONFIRMED)

`S0_SECRET` is a `const` array of regexes compiled at module load (`:1127-1159`, entries at `:1138` and `:1148`).
Specify the mechanism: either the seam replaces those two entries in place, or `S0_SECRET` reads the anchored entries
through a getter.

### N13 (nit). Two pieces of plan text are ambiguous

- l.228 says "except the two pins noted", but only the commit-message row is marked "no policy". Name both rows.
- Define "an open case passes" as "every applicable run matches": runs A and B, plus run C when it applies.

### N14 (nit). A dangling leaf symlink into a `denyPaths` directory stays uncovered

`kernelPath` is still gated on `..` (l.383-384), and the base-tier rule is pinned (`tests/pi-verdict.test.ts:1472`).
State this in the ADR-0002 amendment, so that nobody reads item 8 as covering it.

### F12 still needs a concrete test list

The plan states the rule but lists no tests. Add a minimum list per commit, so that `tests/` covers what the probe
cannot rather than duplicating it:

- **Commit 2 (tokeniser):**
  - `shellWords` token pins for a backtick, a redirection and a continuation inside double quotes;
  - `gitPushForce` for each new spelling (literals built by concatenation), plus the escaped-backslash pin from F4;
  - the `$0` mapping;
  - the depth-exhaustion reason.
- **Commit 3 (path walker):**
  - the dangling and loop cases through `adjudicate`;
  - the `D(...)` pin under `builtinDenyFloor: false`;
  - the POSIX backslash split.
- **Commit 4 (XDG):** XDG through the seam, plus an ignored relative or empty `XDG_CONFIG_HOME`.
- **Commit 5 (denyPaths and user rules):**
  - denyPaths and user deny on the kernel spelling;
  - the allow-every pin from F11;
  - the empty-targets pin from N2;
  - the unchanged pin at `tests/pi-verdict.test.ts:1472`.

### Status of the revision 1 findings

| Finding | Status | Where resolved (plan revision 2) | Remaining |
| --- | --- | --- | --- |
| F1: walk skipped without `..` | resolved | l.387-388 | N11 on macOS or a symlinked agentDir |
| F2: no rule-allow layer | resolved | l.112, l.135-136, l.290-296, l.310 | none |
| F3: run C undefined | resolved | l.154-171 | N13 wording |
| F4: the global strip's bypass | resolved | l.334-337, pin at l.250 | none |
| F5: unquoted `$(` was capped | partial | l.338-342, pin at l.249 | N5 |
| F6: positional gaps | partial | l.353-357, l.259-262 | N1 |
| F7: eval and env forms | partial | l.348-352, l.253-258 | N6 |
| F8: adjacent tokeniser regressions | partial | l.343-345, l.370-372, l.265-267 | N3, N4 |
| F9: the walker-artefact fixture | resolved | l.99, l.318-319, l.326 | none |
| F10: open-case semantics | resolved | l.137-141, l.296 | N13 |
| F11: the allow loop widening | partial | l.416-418 | N2 |
| F12: `tests/` untouched | partial | l.25-26, l.331 | the test list above |
| F13: one commit, no permission | partial | l.441-455 | N7, N8 |
| F14: missing documentation updates | resolved | l.443-453 | none |
| F15: the XDG contradiction and seam | partial | l.399-408 | N12 |
| F16: runner underspecified | resolved | l.145-153 | none |
| F17: fixture safety and members | resolved | l.88-104 | none |
| F18: coverage nondeterminism | resolved | l.214-217 | N8 uses the same mechanism |
| F19: typecheck of probe and tools | resolved | l.64-71 | none |
| F20: floor flag ignored | resolved | l.396-398 | none |
| F21: misleading depth reason | resolved | l.358-365 | none |
| F22: provenance hashed the working tree | resolved | l.210-213 | N9 |
| F23: verification errors | resolved | l.423-439 | N9 |
| F24: the `+` refspec | resolved | l.368-369, l.268-270 | N10 |
| The three nits | resolved | l.79-82, l.177-200 | none |

### Decisions for the user (revision 3)

These do not block the work. If the user does not answer, OMP applies the default given for each one.

1. **N10:** accept the `+` refspec false positives and document them, or skip push-option values? Default: skip the
   option values. That is one sentence in the plan, and it avoids false denies on `git push -o`.
2. **N4:** fix `2>&1` splitting this round? Default: yes. It belongs in the tokeniser commit, which already rewrites
   redirection handling.
3. **N11:** fix the self-protection comparison for a symlinked agentDir this round? Default: no. Record it as an open
   case, because it touches ADR-0005, it predates this round, and it does not affect the user's Linux host unless
   their agentDir path contains a symlink.

---

**Revision 2 (2026-10-04):** the user has answered the four open questions. The answers are recorded in the last
section, "Decisions taken by the user", and in F8, F12, F13, F20 and F24. The findings themselves are unchanged.

Reviewed 2026-10-04 against HEAD `6136aa0` (tag `v0.16.0-fork.6`, `bun test` 359 pass). The review was done by an
adversarial plan reviewer and the claims were independently re-run. Plan line numbers refer to
`docs/plans/probe-apparatus.md`, and code line numbers refer to `extensions/pi-verdict.ts` at HEAD.

**Verdict: the plan needs rework before it is built.** As written, it cannot reach its own end state ("N pass, 0 fail").
Neither item 8 case can pass under the item 8 design. Four case expectations name a layer that the code never returns.
Run "C" is used but never defined. Several of the planned fixes either open a new bypass or leave a simple variant
open.

## How the findings were verified

- **CONFIRMED** means the finding was traced deterministically through the cited code.
- **EXECUTED** means the claim was also run against `gitPushForce` at HEAD. Dangerous literals
  were built by concatenation. The results are below, and every one matches the review:

  | Input | `gitPushForce` today | Finding |
  | --- | --- | --- |
  | `echo a\\` + newline + `git push --force origin main` | `true` | F4, baseline |
  | the same input after the plan's `replace(/\\\r?\n/g, "")` | **`false`** | F4, the new bypass |
  | `$($($($($(git push --force origin main)))))` | `true` | F5: must stay true |
  | `` `git push --force origin main` `` | **`false`** | F8 |
  | `bash -o pipefail -c 'git push --force origin main'` | **`false`** | F8 |
  | `git push -f>/dev/null origin main` | **`false`** | F8 |
  | `git push origin +main` | **`false`** | F24 |

- **PLAUSIBLE** means the finding is reasoned from the design or from semantics, but was not run.
- Language-server references were unavailable (TypeScript 7.0.2 in `node_modules` ships no
  `tsserver.js`), so references were found by repository-wide search instead:
  - `kernelForms` is called at `:1216`, `:1649` and `:1665`.
  - `userRuleTarget` has one caller, at `:1801`.
  - `denyPathForms` is called at `:1432`, `:1467` and `:1492`.
  - `HOME_CONFIG_ROOT` is used at `:1138` and `:1148`.

---

## Blockers

### F1. Item 8 cannot close either of its cases, because the walk is skipped when the path has no `..` (CONFIRMED)

- **Plan:** l.286-287 makes `kernelWalk` return `null` (skipped) when the spelling has no `..`. Its consumers are
  `kernelForms`, `kernelPath` and `kernelUnresolved`. The cases at l.217-218 are `write <fx.dangling>` and
  `write <fx.loop>`. Neither spelling contains `..`.
- **Evidence:** `kernelForms` returns `[]` when there is no `..` (`:381`).
  - For `<root>/dangling`, `rebuiltForms` (`:353-369`) fails `realpath`, climbs to `<root>` and yields
    `<root>/dangling`. That form never equals `<agentDir>/config/pi-verdict-trust.json`, so `isProtectedWritePath`
    (`:1647-1657`) misses.
  - For `<root>/loop`, the walk never runs, so `unresolved` is never set.
- **Consequence:** both cases stay red after the fix, so verification step 2 is unreachable. The dangling-link write
  into a protected file, which is the actual defect, stays open.
- **Fix:** make the leaf readlink resolution independent of `..`. Plan wording:
  > "`kernelWalk` runs when the spelling contains `..` OR when `lstatSync(path.resolve(cwd, expanded))` reports a
  > symlink (one extra `lstat` per call)."

  An equivalent alternative is to add a readlink step for a missing final symlink to `rebuiltForms` itself. That
  matches the handover's wording, "resolve via readlink even when the target is missing". Keep the `..` gate on
  `kernelPath` (the denyPaths and bash-token path), so that every bash path token does not pay a syscall walk.

### F2. The layer model has no "rule allow", so four expectations are wrong (CONFIRMED)

- **Plan:** l.96 defines `type Layer = "rule" | "classifier" | "protected-path"`. Four cases expect `classifier`:
  - l.202, "repo .config not S0";
  - l.203, "foo.config component";
  - l.208, GNUPGHOME;
  - l.222, "read of the policy → classifier (reads pass)".
- **Evidence:** `classifyPath` returns `{ verdict: "allow" }` for any read that is neither S0 nor S1 (`:1227-1229`).
  `classifyByRules` returns that result (`:1823`), and `adjudicate` maps it to `allow`/`rule` (`:2673`). The
  classifier is never reached. All four paths are non-S0, non-S1 reads.
- **Consequence:**
  - Run A yields `allow/rule`, not `deny/fail-closed`, so all four cases fail.
  - The contract also cannot express the pre-fix state of the handover's sharpest defect, which is a missed read
    returning the base `allow` (handover §3.4).
- **Fix:**
  - Add `"allow"` to `Layer`, meaning a deterministic rule-layer allow. It asserts A = `allow/rule` and
    B = `allow/rule`.
  - Re-label the four cases `layer: "allow"`.
  - State in `probe/README.md` that `allow` is a rule-layer verdict and distinct from a classifier allow.
  - Re-check the "pre-fix" notes on the kernel-path and item 10 cases (l.214, l.231, l.239). They already say "silent
    allow", which is the `allow` layer and not `classifier`.

### F3. Run "C" is used but never defined, and the runs contradict the handover's floor-only rule (CONFIRMED, plan text)

- **Plan:**
  - Run C appears at l.89 (`C=…` in the output line), at l.146 ("makes run C meaningful") and at l.375 ("run C then
    asserts").
  - l.74 says "Runs per case (two, under the same config)".
  - l.72-73 makes the consumer policy the config of a `policy: "consumer"` case for runs A and B.
- **Consequence:**
  - Runs A and B stop being floor-only, which contradicts handover §2.1 and §4.2: "one with empty user rules".
  - The synthetic raw-text `git push…--force` regex catches every floor miss as "user deny rule". The case can then
    only discriminate through `ruleId`.
  - The implementer has to guess what C is.
- **Fix:** define three runs explicitly.

  | Run | Config | Model | Applies to |
  | --- | --- | --- | --- |
  | A | `case.config ?? {}` | `hasUI: false`, no model | every case |
  | B | same as A | `hasUI: true`, stub allow | every case |
  | C | the consumer-policy fixture, or `PI_VERDICT_PROBE_POLICY` | `hasUI: false`, no model | `policy: "consumer"` only |

  Run C asserts the same layer as run A.
  - A `rule` expectation must still carry the floor `ruleId`. A "user deny rule" reason fails C, because it would mean
    the floor stopped covering the case and the policy covered it instead.
  - A `classifier` expectation must still be `deny/fail-closed`. That proves the policy does not claim the lease or
    if-includes forms.

  Delete the l.72-73 wording that substitutes the consumer policy into runs A and B.

---

## Major

### F4. Item 11's global strip of backslash-newline adds a bypass (CONFIRMED + EXECUTED)

- **Plan:** l.275-279 adds `command.replace(/\\\r?\n/g, "")` as the first line of `gitPushForce`.
- **Evidence:** take an escaped backslash at end of line, followed by a real newline:
  `echo a\\` + newline + `git push --force origin main`.
  - Today, `shellWords` turns `\\` into `\` (`:197-201`). The newline then acts as a separator (`:208`), and the next
    segment denies. EXECUTED: `true`.
  - After the strip, the regex consumes the second backslash and the newline, giving `echo a\git push --force …`.
    `\g` becomes `g`, the word is `agit`, and no `git` word remains. EXECUTED: `false`.
- **Fix:** handle line continuation inside the scanner, not as a pre-strip.
  - Unquoted: `\` followed by `\n` (or `\r\n`) consumes both and appends nothing.
  - Inside double quotes: the same.
  - Inside single quotes: literal.

  Because the scanner consumes the `\\` pair first, an escaped backslash stays safe. This also removes the accepted
  single-quote false positive. Pin it with a test: `echo a\\` + newline + `git push --force origin main` → deny.

### F5. Item 1's depth cap weakens unquoted `$(`, which denies at any depth today (CONFIRMED + EXECUTED)

- **Plan:** l.248-253 unifies quoted and unquoted `$(` on one code path with a cap of 4. Beyond the cap, and on an
  unterminated `$(`, the content becomes "inert word material".
- **Evidence:** an unquoted `(` is always an operator today (`:151`, `:208-218`), so the input
  `$($($($($(git push --force origin main)))))` denies at any nesting. EXECUTED: `true`.
- **Consequence:** this unquoted case becomes a silent miss. It also contradicts item 5's own principle that depth
  exhaustion should deny.
- **Fix:**
  - Keep unquoted `(` and `)` as plain operators with no cap.
  - Cap only the double-quote re-entry, and report cap exhaustion to `gitPushInWords` as a hit, for example through a
    sentinel token or a returned flag.
  - Do not treat an escaped `\$(` inside double quotes as a substitution.
  - Add the five-deep unquoted case to the table as `rule`. It passes today and must keep passing.

### F6. Item 4's positional substitution misses `$0`, `${N}`, `$@` and `$*` (CONFIRMED against sh semantics)

- **Plan:** l.261-266. With `rest.length >= 2`, the first operand becomes `$0`, and `/\$(\d+)/g` is replaced with
  `args[n-1]`. With no args, the template is recursed unchanged.
- **Evidence:**
  - `sh -c '$0' 'git push --force origin main'` has `rest.length` 1, so the template is recursed unchanged and the call
    is missed.
  - With two operands, `$0` maps to `args[-1]`, which is `""`.
  - `sh -c '${1}' _ '…'` and `sh -c 'eval "$@"' _ '…'` are missed as well.
- **Fix:**
  - Map `$0` and `${0}` to `rest[0]`, and map `$N` and `${N}` to `rest[N]`.
  - Map `$@`, `$*`, `"$@"` and `"$*"` to `rest.slice(1).join(" ")`.
  - Apply the mapping whenever `rest.length >= 1`.
  - Add cases for `$0`, `${1}` and `"$@"`.

### F7. Items 2 and 3 recurse only into the next token and accept only the exact `-S` (CONFIRMED against shell and env semantics)

- **Plan:** l.256-260.
- **eval:** `eval` joins all of its arguments before parsing. `eval 'git push' --force origin main` tokenises to
  `[eval, "git push", "--force", …]`.
  - The direct scan finds no `git` word, because `wordBasename("git push")` is not `git`.
  - The next-token recursion sees only `git push`.
- **env -S:** env splits the string and appends the remaining arguments, so `env -S 'git push' --force origin main`
  is missed the same way. Three more spellings are also missed:
  - `env --split-string='git push --force origin main'`;
  - `env -S'git push --force origin main'`, which tokenises to the single word `-Sgit push…`;
  - `env -iS '…'`.
- **Fix:**
  - eval: recurse on `seg.slice(i + 1).join(" ")`.
  - env: detect `-S`, a bundle matching `-[a-zA-Z]*S`, `-S<attached>` and `--split-string[=…]`. Recurse on the split
    string joined with the remaining words.
  - Add one case per spelling.

### F8. Other tokeniser regressions in the same class appear in neither the handover nor the plan (CONFIRMED + EXECUTED)

The `d5a8115` regex was
`/\bgit\b(?:\s+-[cC]\s+\S+)*\s+push\b[^;|&]*(\s-[a-zA-Z]*f[a-zA-Z]*\b|--force(?![-\w]))/i` (see
`git show d5a8115:extensions/pi-verdict.ts`, l.127). It denied all three spellings below; the fork.6 tokeniser misses
each one. EXECUTED: all three return `false` today.

- **Backtick substitution:** `` `git push --force origin main` `` tokenises to `` `git ``, and `wordBasename`
  (`:143-146`) does not strip the backtick.
- **`bash -o pipefail -c '…'`:** the shell-option loop stops at `pipefail`, a word without a dash (`:285`). The same
  happens with `sh -O extglob -c` and `bash --rcfile x -c`.
- **`git push -f>/dev/null origin main`:** `>` is not an operator (`:151`), so the word is `-f>/dev/null`, which fails
  `^-[a-z]*f[a-z]*$` (`:234`).

**Fix:** item 1 already restructures the scanner, so add these there:

- Treat backticks like `$(`.
- Treat `<`, `>` and `>>` as word breaks.
- In the shell-option scan, skip the argument of `-o`, `-O`, `+o`, `--rcfile` and `--init-file` instead of stopping.
- Add the three cases.

**Decided:** these fixes are in scope for this round. Each spelling enters as an open case under the F10 semantics
and loses its marker in the tokeniser commit.

### F9. The item 10 fixture pins a walker artefact, not kernel truth (CONFIRMED against POSIX path resolution)

- **Plan:** l.125 points `subLink` at `<root>/protected/x`, and `x` is never created. l.231 and l.239 claim that the
  kernel spelling resolves to `<root>/protected/secret`.
- **Evidence:** the kernel follows a non-final symlink. Resolving `subLink/..` goes through the dangling
  `<root>/protected/x`, so `open` returns ENOENT. Only the plan's walker produces `<root>/protected/secret`, because
  it keeps the lexical candidate on failure.
- **Consequence:** the two item 10 cases pin walker behaviour rather than the real bypass. `kernelOpens` cannot be
  added to them, because `readFile` throws.
- **Fix:**
  - Point `subLink` at an existing directory, `<root>/protected/sub`.
  - Add `kernelOpens: "<root>/protected/secret"` to both item 10 cases.
  - Before the fix, the lexical form is `<root>/secret` and the read returns `allow/rule`, so both cases still fail
    beforehand.
- **Separately:** "kernel-resolved base form" (l.232, `<root>/protected/./secret`) already passes today, because
  `path.resolve` drops the `.`. It cannot fail before the fix, so label it a grounding case, not an item 10 case.

### F10. `known: "open"` can never fail, and GNUPGHOME is deliberate rather than open (CONFIRMED, plan text)

- **Plan:** l.90 says open cases "never affect the exit code". l.208 gives the GNUPGHOME case both `known: "open"` and
  `deliberate`. Its expectation describes current behaviour, and that expectation is itself wrong (see F2).
- **Consequence:**
  - A case that starts passing is invisible, and so is a stale expectation.
  - The failing-before discipline stays manual (verification step 1 says to "temporarily remove markers").
  - The marker on GNUPGHOME records today's behaviour, not the desired one.
- **Fix:**
  - An open case carries the *desired* expectation and is a strict expected failure. It must fail today. When it
    starts passing, the runner exits 1 with "open case now passes — remove the marker". This makes failing-before
    mechanical, so verification step 1 no longer needs manual marker stripping.
  - Make GNUPGHOME a normal passing case: `layer: "allow"`,
    `deliberate: "GNUPGHOME is not an anchored root"`. The end state becomes "N pass, 0 fail, 0 open".
  - Mark every case of each item as open, not only the first:
    - all four item 9 XDG cases (l.193-196);
    - both item 8 cases;
    - both item 10 cases.
  - Tag each case with its item number, for example `item: 9`. Replace "the 11 §6 cases" (l.340) with "the cases
    tagged item 1-11".

### F11. With multiple targets, the user `allow` loop can widen (PLAUSIBLE; the wording is ambiguous, the risk is concrete)

- **Plan:** l.314-318 says "iterate the targets for both the deny and the allow loops".
- **Evidence:** today, `allow` tests only the lexical target (`:1819-1821`). If any one target may trigger an allow,
  then an allow regex that matches only one of the two spellings now allows the call. Compare the in-cwd write
  allowance, which requires every form to match (`:1239`).
- **Fix:** write it as "deny = any target matches; allow = every target matches". Add a pinned test: an allow regex
  matches the lexical spelling, the kernel spelling falls outside it, and the call is not allowed.

### F12. The plan leaves `tests/` untouched, against AGENTS.md (CONFIRMED; plan l.331-332, AGENTS.md "Testing & QA")

- **Rule:** AGENTS.md says "Bug fixes: add a failing-before/passing-after regression test. Security-relevant behavior
  … needs a pinned test."
- **What the probe cannot pin:**
  - exact `shellWords` token output;
  - the `$0` mapping;
  - behaviour skipped on win32;
  - unit-level `kernelWalk` outcomes.
- **Fix:** add one `describe("… (2026-10-04 handover items)")` block per fix family to `tests/pi-verdict.test.ts`.
  - Build dangerous literals by concatenation, following the convention at test l.431-444.
  - Build symlink fixtures with `withTempDir` and `.pv-` home fixtures, following the pattern at test l.1481-1499.

  **Decided:** the tests go in `tests/`, and `probe/` does not replace them.

### F13. Phase 5 commits everything at once, then tags and pushes without user permission (CONFIRMED; plan l.359-362, AGENTS.md)

- **Rules:** AGENTS.md says "Do not run `git commit` without the user's permission". Pushing reaches the shared
  remote, which the consumer pins.
- **History problem:** with one commit, no commit in history contains the probe without the fixes. The consumer's
  failing-before method, which checks out the previous pin, then cannot be reproduced.
- **Fix:** slice the work into commits.
  1. Tooling and the probe, with the open markers in place. The probe is green.
  2. The floor tokeniser fixes and their tests.
  3. The path walker (items 7 and 8).
  4. XDG (item 9).
  5. denyPaths and user rules, plus the ADR-0002 amendment (item 10). The `0.16.0-fork.7` bump goes in this last fix
     commit.

  Each commit removes the markers it closes and adds its `tests/` regressions. **Decided:** the user has authorized
  the sliced commits, the tag and `git push --follow-tags`. Publishing also needs a GitHub Release, which the user
  creates, because the floor blocks `gh release`.

### F14. The plan omits the documentation updates that AGENTS.md requires (CONFIRMED)

- **Plan:** the only documentation change is the ADR-0002 amendment (l.319-321, l.334).
- **Text that becomes stale:**
  - `CHANGELOG.md` `## [Unreleased]` needs entries for the tokeniser changes, `--force-if-includes`, the
    unresolved-symlink write deny, the XDG root and the denyPaths kernel tier.
  - `README.md:225` and `docs/security-principles.md:47` say "`denyPaths` uses base-tier matching only".
  - `CONTEXT.md:41` (dual-form matching) describes two tiers and calls denyPaths base tier. The kernel-true form,
    which fork.6 already added, is absent.
  - `AGENTS.md:62`, plus the Key Directories and Development Commands sections, which need `probe/`, `tools/` and the
    new scripts. Several existing statements are already stale: AGENTS.md says there is no lint script and no biome
    config, but both exist, and CI runs `biome ci .`.
  - `docs/verification-2026-10-04.md:263` says that denyPaths "is not changed".
- **Fix:**
  - Add a documentation step that updates each of these files.
  - Add a `CONTEXT.md` entry for the kernel-true form and the expected layer, with definitions only.
  - Add the unresolved-symlink write deny, a new floor branch, to the README pipeline text.

### F15. Item 9 contradicts itself and has no test seam (CONFIRMED; plan text, `:1109-1120`)

- **Contradiction:** l.303 says `HOME_RULE_ROOTS` gains the forms of `XDG_CONFIG_HOME`, but l.306 builds a separate
  `XDG_CONFIG_ROOTS`. Adding XDG to `HOME_RULE_ROOTS` would yield `^<xdg>/\.config/…`, which is wrong.
- **Fix:**
  - Leave `HOME_RULE_ROOTS` unchanged and add only `XDG_CONFIG_ROOTS`.
  - Ignore an empty or relative `XDG_CONFIG_HOME`, as the XDG spec requires. Otherwise `path.resolve` at module load
    anchors it to an arbitrary process cwd.
  - Add a test seam. Module-load evaluation means that `bun test`, which imports statically in one process, cannot
    exercise item 9. Add a function such as `setXdgConfigRootsForTests` that rebuilds the two regexes, mirroring
    `setTmpdirBasesForTests` (`:1194`), or compute the regexes lazily.
- **Adjacent gap (PLAUSIBLE):** `gh` honours `XDG_CONFIG_HOME`, but the `.config/gh` entry (`:1144`) requires a
  literal `.config` segment. Consider adding `gh` to the XDG name list.

---

## Minor

### F16. The runner environment is underspecified (CONFIRMED)

- **Missing env fields:** the plan never sets `env.cwd` or `env.host`. Run B reaches `buildTranscript`, which calls
  `host.getBranch()` (`:2182`, via `classifyWithModel`).
- **Lost load errors:** `new SessionState()` loads rules through a default parameter (`:2399`) and discards the
  `skipped` report. An invalid regex or an unknown key in the policy fixture would be dropped silently.
- **Fix:**
  - Set cwd to `<fx.root>/work`, which must exist.
  - Set host to `{ getBranch: () => [], getSessionId: () => "probe" }`.
  - After constructing the state, call `state.reloadRules(cwd)` (`:2413`, public). Fail the case when
    `report.skipped.length > 0`.
  - Import `pi-verdict.ts` dynamically (`await import(...)`). `cases.ts` and `fixtures.ts` may import only types from
    it, because static imports are hoisted above the env setup.

### F17. The fixture tree is unsafe and incomplete (CONFIRMED / PLAUSIBLE)

- **Location:** l.118 calls `mkdtemp(".pv-probe-")`. The prefix is relative, so the tree is created in the process
  cwd, which is the repo root. The tree holds two symlinks to `/`, and no `.gitignore` entry covers it, so a crash
  leaves a link to `/` inside the repo.
  - Use `path.join(os.tmpdir(), ".pv-probe-")`.
- **Cleanup:** clean up only with `fs.rmSync(root, { recursive: true, force: true })`, which unlinks symlinks without
  following them. Never write a custom walker for it. Assert that `root` starts with `os.tmpdir()`.
- **Missing members:** the l.121-129 table omits these, though cases depend on them:
  - `repo/.config/age/data`;
  - `foo.config/age/data`;
  - `repo/.git/hooks/`;
  - `protected/secret`;
  - `protected/sub` (F9);
  - `gnupghome/pubring.kbx`;
  - the `escape/` parent directory.

### F18. The coverage freshness check is nondeterministic as designed (PLAUSIBLE)

- **Cause:** `buildCases(fx)` embeds random mkdtemp paths, agentDir slices and the runner's home directory. If
  `docs/coverage.md` renders inputs, `git diff --exit-code` fails on every CI run.
- **Fix:**
  - Render only stable fields, in a stable sort order: `family`, `label`, `tool`, `expected.layer`, `ruleId`,
    `reasonIncludes`, `deliberate` and `known`.
  - Have `coverage.ts` call `buildCases` with a placeholder `FixtureTree` of constant strings, so that it never
    creates real symlinks.

### F19. probe/ and tools/ will likely fail typecheck under the expanded include (PLAUSIBLE, not run)

- **`.ts` specifiers:** importing `"../extensions/pi-verdict.ts"` needs `allowImportingTsExtensions: true`.
  `extensions/` imports `"./jev-adapter"` without the extension, so `tsconfig.json` has never needed the option. Add
  the option, which is valid with `noEmit`, or drop `.ts` from the probe and tools specifiers. AGENTS.md says that
  relative imports carry `.ts`, but the code does not, so check which convention wins.
- **Bun types:** devDependencies include `@types/node` but not `@types/bun`, so any `Bun.*` API will not typecheck.
  Either state "node: APIs only", or add `@types/bun`, which changes `bun.lock`, and CI installs with
  `--frozen-lockfile`.
- **JSON:** read `consumer-policy.json` through `fs`, because `resolveJsonModule` is not set.
- **Biome:** run `mise exec -- biome ci .` locally once probe/ and tools/ are included.

### F20. The unresolved-symlink deny ignores `builtinDenyFloor: false` (CONFIRMED; plan l.301, `:1220-1222`)

The plan returns a literal `{ verdict: "deny" }`. Every other floor branch goes through `D(...)`, which degrades to
gray when the floor is off. **Decided:** use `D("unresolved symlink (write fail-closed)")`, so this deny honours
`builtinDenyFloor: false` like every other floor branch.

### F21. Depth exhaustion is reported as a `git push --force` (CONFIRMED; plan l.267-272, `:129`, `:319`)

When `hasReparseCandidate` returns `true`, any harmless four-deep `sh -c` becomes a hard deny, with the misleading
reason "rule git-push-force: git push --force". Either accept that and say so in the code comment and the CHANGELOG,
or let the check return its own reason, such as `reparse depth exhausted (fail-closed)`.

### F22. Provenance can disagree with the consumer's hash (PLAUSIBLE)

`provenance.ts` hashes the working-tree files, but the consumer hashes `git show <sha>:<file>` (handover §2.2). A
dirty tree, or CRLF line endings on the Windows workstation, produces a different hash; the repo has no
`.gitattributes`. Hash the committed blobs with `git cat-file blob HEAD:<path>`, print the HEAD SHA next to them, and
warn when the tree is dirty.

### F23. The verification section has several errors (CONFIRMED, plan text)

- **Filter:** step 3's `--filter "double-quotes"` matches nothing, because the label at l.177 is "substitution in
  double quotes". Use `"double quotes"`.
- **Blocked command:** step 3's `bun -e '…git push --force…'` is itself denied in a session running the consumer's
  raw-text policy (handover §3.4). Use the probe filter or `bun test -t` instead, or build the literal by
  concatenation inside a script file.
- **Baseline count:** "358+ baseline" should be 359.
- **Phase numbers:** l.340 refers to phases 2 and 3, which the plan never defines. Number the phases consistently,
  or drop the numbers.
- **Step 0:** l.45 copies the plan to the path it already occupies. Reword it as "track the existing file".

### F24. A force-push family is missing from the contract (CONFIRMED + EXECUTED)

The floor does not detect `git push origin +main`, a force refspec that is a force push (EXECUTED: `false`).
**Decided:** fix it this round. Add an open `rule` case, and remove its marker in the tokeniser commit. Add cases for
`+main`, `+HEAD:main` and a `+` refspec after `--`.

---

## Nits

- The consumer-policy fixture's `tools` list and its `printenv` regex (l.137-140) are exercised by no case. Add cases
  for them, or drop them.
- The `.gitignore` entry `probe/consumer-policy.real.json` (l.59) is speculative, because the override can be any
  path passed through `PI_VERDICT_PROBE_POLICY`. Either drop it or make that path the documented default.
- The archived handover (l.40) still marks the §6 items as open. Add a one-line header saying which items closed in
  fork.7.

---

## Traceability

The criteria come from handover §4 and §6 and from the user's decisions.

| Planned item | Criterion | Status |
| --- | --- | --- |
| `cases.ts`, `probe.ts`, `known`, `deliberate` | §4.1, §4.3, §5 | mapped, with defects in F2, F3 and F10 |
| Two or three runs per case | §4.2, §4.4 | **gap**: run C is undefined (F3) |
| `fixtures.ts`, `kernelOpens` | §4.5 | mapped, with defects in F9 and F17 |
| `consumer-policy.json` | §4.4, user decision | mapped. The `tools` and `printenv` entries trace to no case |
| provenance, coverage, release-check | §4.6, §4.7 | mapped. release-check is rightly outside CI |
| `docs/layers.md` | §4 | mapped |
| Fixes 1-11 | §6 | mapped. Items 1, 2, 3, 4, 8 and 11 have design defects (F1, F4-F7) |
| Regression tests in `tests/` | AGENTS.md | **gap** (F12) |
| CHANGELOG, README, CONTEXT, security-principles | AGENTS.md | **gap** (F14) |
| Moving the handover, the `.gitignore` entry | none | traces to no criterion, but harmless |

## What the plan gets right, to keep

- It asserts the source and layer, not only the verdict, and uses `ruleId` and `reasonIncludes` to tell rules apart.
- It builds real fixtures at run time and commits no symlinks.
- It leaves `probe/` and `tools/` out of `package.json` `files`.
- It keeps `release-check` out of CI, for the right reason: CI checks out untagged with fetch depth 1.
- Item 5 keeps sibling segments scanned after a depth hit (`continue`, not a bare `return`).
- denyPaths bases and candidates move together through `denyPathForms`, which is what keeps item 10 sound.
- It has a fallback contingency at l.369-371.
- It keeps ADR-0002's no-ancestor-rebuild rule. The pinned test at `tests/pi-verdict.test.ts:1472` is unaffected,
  because its path has no `..`.
- It isolates `PI_CODING_AGENT_DIR` and `XDG_CONFIG_HOME` before the import.
- It writes the config before constructing `SessionState`. `loadUserRules` writes a template when the config is
  missing (`:863-870`).
- These expectations are correct:
  - the A/B shapes for `rule` and `protected-path`;
  - the classifier shape, A = `deny/fail-closed` and B = `allow/classifier` (`:2732-2772`, `:2846`);
  - the reason substrings "S0" (`:1224`), "system directory" (`:1231`), ".git metadata" (`:1232`), "self-protection"
    (`:1724`, `:1736`, `:1748`) and "user deny rule" (`:1804`).

## Decisions taken by the user (revision 2)

The user answered all four open questions on 2026-10-04. Each answer is now part of the plan's scope.

1. **Commits, tag and push are authorized, as sliced commits.** Use the five-commit slicing in F13. The bump goes in
   the last fix commit, followed by the annotated tag `v0.16.0-fork.7` and `git push origin main --follow-tags`
   (corrected in revision 3; see N7). The user
   still creates the GitHub Release, because the floor blocks `gh release`.
2. **Regression tests go in `tests/`, as AGENTS.md requires (F12).** Each fix commit carries its own
   failing-before/passing-after tests alongside its probe cases. `probe/` does not replace `tests/`.
3. **The adjacent tokeniser regressions and the `+refspec` force push join this round (F8, F24).** Add each of them
   as a `rule` case marked open under the F10 semantics. Fix them in the floor tokeniser commit (slice 2) and remove
   the markers there. The `+refspec` fix needs a design line in the plan: a push refspec word that starts with `+`
   (for example `+main` or `+HEAD:main`) counts as a force flag. Remember that `git push` also accepts `+` refspecs
   after `--`.
4. **The unresolved-symlink write deny honours `builtinDenyFloor: false` (F20).** Use
   `D("unresolved symlink (write fail-closed)")`, so the deny degrades to gray when the floor is off. Pin that with a
   test.
