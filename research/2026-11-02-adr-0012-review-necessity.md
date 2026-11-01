# ADR-0012 review: necessity, simplicity and cost

Reviewed on 2026-11-02 against `main` at `e5f8709` ("docs(todo): record the merged shell-state guard"), with
`docs/adr/0012-shared-shell-reading.md` untracked in the working tree (status `proposed`). The lens is the owner's five
goals in `AGENTS.md` "Goals", read by a skeptical second architect: is the change needed, is it the smallest change that
works, and does it pay for its code. Sizes come from `wc -l`; behaviour claims cite the file and line read. Claims
marked "inferred" were reasoned from the code, not run.

## Verdict

**Do a reduced version.** The ADR identifies one real defect, the loss of quoting and expansion facts in `shellWords`,
but the gaps it cites close with four small local edits to the floor. Most of the rest adds code, keeps every old
reader, and two decisions would weaken today's verdicts. Build the typed word together with the read-only fast path
(TODO item 6), the first consumer that needs it, and after the replay tool (TODO item 4) exists to measure the change.

## Answers to the five questions

### 1. Is the problem real and large enough?

The problem is real but smaller than the ADR states, and the cost of leaving it is a classifier call rather than an
allow.

The open expansion gaps in `TODO.md` item 3 all have the same outcome: a force push that the floor should deny reaches
the classifier instead (TODO.md line 17: "which clear a force push to the classifier today"). None of them reaches an
allow. The user-allow path already refuses each of these spellings, because `expandOperand` returns null for any `$` or
brace expansion (`allow-operands.ts:200`) and `allowAdmits` refuses any operator or unsound word (`shell.ts:337-341`).
So the gaps downgrade a hard deny to a model judgement; they do not open the gate.

The ADR's main claim is divergence: "Review rounds keep finding a spelling that one reader understands and another does
not". The git history supports this for **paths**, not for shell words. Of the 40 `fix(...)` commits that touched the
shell and rule modules (`git log` over `shell-words.ts`, `shell.ts`, `allow-operands.ts`, `deny-paths.ts`,
`shell-state.ts`, `git-reach.ts`, `self-protection.ts`, `code-loading.ts`), my reading of their subjects puts about four
in the provenance class: `f3bc1b3` (an expansion before git's subcommand), `717979c` (an unreadable git option before a
push word), `e47df5f` (code-loading's own `$(pwd)` expansion) and `05c6779` (self-protection's own
`$PI_CODING_AGENT_DIR` expansion). The last two sit in raw-text readers that the ADR keeps as nets. The other 36 fix
option semantics (`env -S`, `zip -TT`, `rsync -e`, `grep -d`, `find -fprint`, push option values), redirection forms
(`2>&1`, `{name}>`, fd digits), floor tables, pipe filters and session state. A shared reader would carry those
semantics forward unchanged, so it would not have prevented them.

The four readers of `shellWords` already share one tokenizer: the floor (`shell-words.ts:584`), `allowAdmits`
(`shell.ts:336`), the allow operands (`allow-operands.ts:99`) and the shell-state scan (`shell-state.ts:286`). Where they
diverge, they diverge in small post-processing helpers. The clearest case is the assignment regex, defined three times
with two meanings: `shell-words.ts:498` does not accept `NAME+=value`, while `allow-operands.ts:17` and
`shell-state.ts:114` do. `MIN_LONG_PREFIX` is also defined twice (`shell.ts:299`, `allow-operands.ts:64`). Both
divergences fail in the safe direction today (inferred: `X+=1 echo …` keeps the floor's deny), and both are fixed by
sharing a constant, not by a new module.

The ADR is also the wrong size in the other direction. The architecture's named weakness is path re-reading
(`docs/architecture.md:155-162`), and plan item 9 put a single path resolver (`resolveTarget`) and differential tests
against omp's `path-utils` at its centre (`docs/plans/call-model-and-rule-hardening.md:418-421`). ADR-0012 drops both
without saying so, so it is not the TODO item 5 that the plan and the architecture describe.

### 2. Is this the simplest design?

No. A smaller design closes the same gaps with far less code.

| | ADR-0012 as written | Reduced alternative |
| --- | --- | --- |
| New code | New `shell-reading.ts` with a 5-field `Word`, a 6-field `SimpleCommand`, here-document bodies, a `LIMITS` table, a work counter, a fuzz generator, union code in three layers | Four edits in `shell-words.ts` and `shell.ts`, two shared constants, residual probe cases |
| Readers after the change | Same seven, plus `shellWords` kept as an exported view (ADR line 143); three layers gain a second extraction | Same seven, two duplicated constants removed |
| Item 3 gaps | Closed through word provenance (step 4) | Closed directly by marking more constructs unsound and widening git's unreadable-subcommand test, as `TODO.md` item 3 already proposes |
| Behaviour risk | Here-document and limit changes can weaken verdicts (findings F1, F2) | Each edit only adds unsound marks or hits, so the floor can only deny more |
| Size | Inferred 350-550 new lines in the reader alone, before tests; no net reduction, since every raw net stays | Inferred under 40 lines of code plus tests |

The specific edits:

1. An unquoted `$(` emits the unsound word and leaves the `(` to the existing operator branch, so the shell-state scan
   still sees the same segments (`shell-words.ts:189`). Closes `git push origin $(:) +main`.
2. An unquoted `<(` or `>(` emits the unsound word before the redirection branch (`shell-words.ts:167`). Closes process
   substitution.
3. In the git push rule, `mayBeSubcommand` tests for `push` as a substring of a later word instead of equality
   (`shell.ts:103`). Closes `git {push,} origin +main` and `git push$NOPE origin +main`, both of which already make
   `gitSubcommandIndex` return `undefined` through `mayExpand` (`shell-words.ts:301`).
4. `gitSubcommandIndex` treats a `-c alias.…` value as unreadable and returns `undefined` (`shell-words.ts:305-307`).
   With edit 3, the alias value word that holds `push` then counts as a hit. Without this edit, the alias name (`x`)
   reads as a literal subcommand and the substring test never runs.
5. Export one `ASSIGNMENT` regex and one `MIN_LONG_PREFIX` from `shell-words.ts`, accepting `+=`, and import them in the
   three modules.

The suggested middle path in the brief, provenance flags on `shellWords` output plus memoizing, is worth having later,
but not now. A `quoted` and `literal` flag per word lets `allow-operands.ts` drop its string guesses (`HOME_VARIABLE`,
`BRACE_EXPANSION`, `GLOB_CHARS`, `OPTION_EXPANSION`, lines 19-25) and stop expanding a single-quoted `'$HOME'`
(`allow-operands.ts:187-188`). Today those guesses fail toward the classifier, so the gain is fewer needless classifier
calls, not safety. The memo buys nothing measurable (finding F5).

### 3. Which parts are worth doing?

Ranked by value per cost, highest first:

| Rank | Part | Value | Cost | Recommendation |
| --- | --- | --- | --- | --- |
| 1 | Decision 6 / step 6: one probe case per accepted residual | Catches a silent regression to allow; independent of everything else | Low | Do now |
| 2 | Step 4 goal: close the item 3 expansion gaps | Restores the floor denies | Low, through edits 1-4 above | Do now, without the new reader |
| 3 | Shared `ASSIGNMENT` and `MIN_LONG_PREFIX` | Removes the only shell-word divergence found | Very low | Do now |
| 4 | Decision 1 reduced: `quoted` and `literal` per word | Sound basis for item 6's static allow; fewer refusals | Medium | Build with item 6, not before |
| 5 | Decision 6: seeded fuzz with invariants | Finds tokenizer disagreements before a review round does | Medium, one test file | Do when the tokenizer next changes shape |
| 6 | Decision 6: work-unit counter | Proves linearity of a single forward pass that is already evidently linear | Instrumentation inside shipped code | Cut; use a growth-ratio test (research note recommendation 6) |
| 7 | Step 5: union targets in `denyPaths`, code-loading, self-protection | Small; see F4 | Medium, a second extraction in three layers | Defer until replay data shows a missed spelling |
| 8 | Decision 2 / step 2: memo per call | None measurable; see F5 | Medium, touches every consumer | Cut |
| 9 | Decision 5 / step 3: `LIMITS` with one breach path | Negative as written; see F2 | Low | Cut the breach path; co-locating constants is optional |
| 10 | Decision 1 in full: `expansions` set of eight kinds, `grouped`, `end`, `redirects` | No named consumer for most fields | Medium | Cut fields until a consumer exists |

### 4. Does it grow the static layer the wrong way?

Yes, mildly by itself, and strongly by what it enables. The ADR adopts cc-safety-net's data model (raw, quoted,
provenance, redirects, bodies) while it says that project's parser "serves a model-free design with more static rules
than pi-verdict wants" (ADR line 159), and the research note says its exemptions show "how static rules grow when no
model handles the gray zone" (`research/2026-11-02-cc-safety-net.md:47`). A structure with eight expansion kinds and
typed redirects invites rules written against each field. The decisions themselves route toward the classifier, which
is the right direction, but none of them carries a guard against later growth. Item 6 (a static allow) and item 7
(follow written code) are the natural consumers, and each should justify its own fields.

### 5. What would make it measurably better for a maintainer?

Measure four things before and after, and state the targets in the ADR:

- **Lines in the shell modules.** Today: `shell-words.ts` 604, `shell.ts` 433, `allow-operands.ts` 253,
  `shell-state.ts` 440, total 1,730. Target: no net growth for the reduced version; a net reduction for any later
  reader, since a reader that adds code without removing any fails the "maintainable by humans" goal.
- **Modules that tokenize command text.** Today seven (the ADR's own table). The ADR as written leaves seven and adds
  a second extraction to three layers. Target: fewer, or the same with no duplicated helper.
- **Duplicated shell constants and expansion guesses.** Today: `ASSIGNMENT` three times with two meanings,
  `MIN_LONG_PREFIX` twice, four expansion regexes in `allow-operands.ts`. Target: one definition each.
- **Probe coverage of residuals.** Today residuals are prose in ADR-0007, ADR-0008 and ADR-0009. Target: one probe
  case per residual, counted in `docs/coverage.md`.

The proof that the change worked is behavioural: the next review round of the shell layer lands each fix in one
module, and the replay tool (TODO item 4) shows no verdict moved toward allow and no growth in asks.

## Findings

### F1 (Important): here-document bodies as data can turn today's floor deny into a classifier call

Symptom: today any `<<` emits the unsound word (`shell-words.ts:169-173`), so a tripwire hit anywhere in a command with
a here-document keeps its deny. Decision 1 keeps bodies "as data" and marks the reading `partial` only for "a
here-document fed to a shell" (ADR line 69). Decision 3 then lets a `sound` reading clear a raw-text hit.

Consequence (inferred): `ssh host <<'EOF'` followed by a force-push line, or `python3 <<EOF` calling `os.system`, feeds
the body to a program that runs it but is not a shell by name. The reading would be `sound`, the body is not a word,
`mentions` never sees it, and the floor clears the deny. That breaks the ADR's own promise that "no layer can grade less
than it does today" (ADR line 86), and deciding which programs run their stdin is a new static rule set.

Remedy: keep every here-document `partial` for the floor, as today. Expose bodies only to the shell-state scan, which
already strips them (`shell-state.ts:238-276`). This also removes the "fed to a shell" judgement from the design.

### F2 (Important): one breach path for every limit changes verdicts in both directions

Symptom: decision 5 says a breach "raises one typed result that leads to the over-cap ask" (ADR line 99). Today the caps
fail differently on purpose. Past `SHELL_RECURSION_DEPTH` the floor counts a hit, so the deny stands
(`shell-words.ts:596`). Past `MAX_GRADED_OPERANDS` the allow is refused and the call reaches the classifier
(`allow-operands.ts:112`).

Consequence: the recursion breach weakens from deny to ask, which violates the monotone rule. The operand breach
strengthens from a classifier call to a human ask, which is a needless ask under "usable every day". The ADR's
migration calls step 3 "No behaviour change", which is not true of decision 5 as written.

Remedy: cut the single breach path. Keep each cap's fail direction. Co-locating the constants in one table is optional
and cosmetic; `ACTION_LINE_MAX_CHARS` is already defined as `BASH_MAX_MATCH_LEN` (`action-line.ts:56`).

### F3 (Important): the item 3 gaps do not need the new reader

Symptom: decision 4 and step 4 present word provenance as the way to close the expansion gaps "in one place" (ADR
line 93). Edits 1-4 under question 2 close all five listed spellings, and `TODO.md` item 3 already proposes the
substring test.

Consequence: tying a low-cost fix for a real floor gap to a medium refactor delays the fix by the whole migration, and
adds the risk of F1 and F2 to it.

Remedy: land edits 1-4 as their own `fix(floor)` commits with probe cases, now. Remove step 4 from the ADR or reduce it
to "consumers of the typed word drop their string guesses".

### F4 (Suggested): the union targets in step 5 add little over the strict redactor

Symptom: step 5 promises that "more spellings reach the `denyPaths` ask". The plan named bare names such as `cat .env`
as the example (`docs/plans/call-model-and-rule-hardening.md:448-450`). The protected-spelling ask already matches a
cwd-relative bare name with path-word boundaries (`redaction.ts:66-67`, `redaction.ts:89`, `mentionsSpelling` at
`redaction.ts:112-138`), and it runs right after the `denyPaths` ask (`rules.ts:79-80`).

Consequence (inferred): what the union adds is mostly quote-split spellings (`.e'n'v`), which the 80/20 rule records as
residuals. It costs a second extraction in three layers.

Remedy: defer step 5 until the replay tool or a review finds a plausible spelling both current readers miss.

### F5 (Suggested): the memo solves no measured problem

Symptom: the ADR states the rule layer costs 0.1-0.2 ms per typical call (ADR line 22). The floor tokenizes only when a
tripwire has already hit (`shell.ts:234-235`), the allow path tokenizes only when a user allow regex matched
(`rules.ts:249-250`), and the shell-state scan runs in `ShellStateLedger.observe` (`adjudicate.ts:501`,
`tool-call.ts:141`), outside `classifyByRules`, on text with here-document bodies removed (`shell-state.ts:285`).

Consequence: a memo on `readCall` in `rules.ts` would not reach the shell-state scan without moving it, and saves at most
two tokenizer passes on a sub-millisecond path. It still threads a new object through every consumer.

Remedy: cut decision 2. If a typed word is built later, have each consumer call one function; consistency comes from
one function, not from one cached object.

### F6 (Suggested): the word model carries fields no consumer needs

Symptom: `Word.expansions` has eight kinds; `SimpleCommand` has `grouped`, `end` and `redirects`. The ADR names
consumers only for `literal`, `quoted` and the expansion check on a command or subcommand word (decision 4).

Consequence: unused fields are code to test and keep correct, and an invitation for new static rules (question 4).

Remedy: start with `text`, `quoted` and `literal`. Add a field in the same change as its first consumer.

### F7 (Suggested): the ADR inverts the agreed order and narrows item 5 silently

Symptom: `TODO.md` lists the replay tool (item 4) as "the safety net for item 9", ahead of item 5. The ADR does not
mention the replay tool, and it drops the path resolver and the omp differential tests that plan item 9 and
`docs/architecture.md:288-292` describe as the point of item 5.

Consequence: the riskiest refactor would run without its regression net, and a reader of the architecture would think
item 5's path half is covered.

Remedy: state in the ADR that it covers shell words only, and record where the path half went (deferred, or dropped
because `hostPathForms` closed the largest class). Sequence any reader change after item 4.

### F8 (Informational): decision 4's wording reads as a weakening for the floor

Symptom: "A non-literal word in a position whose meaning matters … sends the call to the classifier" (ADR line 91).
For the floor, today's rule is that such a word keeps the deny (`gitRunsIn`, `shell-words.ts:332-334`). Step 4's text
("some calls that cleared a tripwire now deny") shows the intent is a deny.

Remedy: say "keeps the floor's deny and refuses a user allow".

## What is already right

The ADR measures before it argues, and it says plainly that speed is not the motive. It keeps every raw-text net and
extends ADR-0007's monotone rule instead of replacing tripwires with parsing, which is the right safety shape. It rejects
a full bash parser and a port of cc-safety-net's 1,816-line parser for reasons that hold under the zero-dependency rule.
Pinning each accepted residual with a probe case and testing linearity without wall-clock limits are both cheap and
worth keeping. The `partial`/`unreadable` status mapping to today's unsound sentinel preserves the fail direction.

## Implementation brief

Each task lands as one commit with its probe case and passes the full "Done" set in `.agents/rules/pv-typescript.md`.
Tasks 1-6 are independent of each other; task 7 follows task 6, and task 8 follows TODO item 4.

1. Add one probe case per accepted residual in ADR-0007, ADR-0008 and ADR-0009, asserting today's route (deny, ask or
   classifier). Regenerate `docs/coverage.md`.
2. `fix(floor)`: mark an unquoted `$(` unsound in `shellWords` while still emitting `(` as an operator. Pin
   `git push origin $(:) +main` as a floor deny, and confirm the shell-state tests pass unchanged.
3. `fix(floor)`: mark an unquoted `<(` or `>(` unsound. Pin a process-substitution force push as a floor deny.
4. `fix(floor)`: make the push rule's `mayBeSubcommand` test for `push` as a substring. Pin `git {push,} origin +main`
   and `git push$NOPE origin +main` as floor denies.
5. `fix(floor)`: make `gitSubcommandIndex` return `undefined` for a `-c alias.…` value. Pin
   `git -c alias.x=push x origin +main` as a floor deny (needs task 4 for the hit).
6. `refactor(shell)`: export one `ASSIGNMENT` (accepting `+=`) and one `MIN_LONG_PREFIX` from `shell-words.ts`; delete
   the copies in `shell.ts`, `allow-operands.ts` and `shell-state.ts`. Run the probe to show no verdict moved except
   toward deny.
7. Update `TODO.md` item 3 to drop the closed gaps, and revise ADR-0012 to the reduced scope: decisions 1 (three
   fields), 3 and 6 only, here-documents always `partial` for the floor, no memo, no single breach path, an explicit
   statement that the path half of item 5 is out of scope, and the maintainability targets from question 5.
8. After TODO item 4 lands: build the typed word as part of TODO item 6, migrating `allow-operands.ts` off its
   expansion regexes in the same change, with the seeded fuzz test.

## Unverified

- The size estimates for the new reader (350-550 lines) and for the reduced fix (under 40 lines) are inferences from
  the current tokenizer's size, not measurements.
- F1's weakening path (`ssh host <<'EOF'` with a force-push body clearing the floor) is reasoned from decisions 1 and 3
  and `anyCommandIn` (`shell-words.ts:583-604`); no test was run.
- That edits 1-4 close every listed spelling, and that the `$(` edit leaves the shell-state scan unchanged, is reasoned
  from the code; neither was executed.
- F4 assumes the strict redactor catches `cat .env` for a `denyPaths` entry at `<cwd>/.env`; this was read in
  `redaction.ts`, not tested.
- The classification of the 40 fix commits is by subject line, not by reading each diff.
