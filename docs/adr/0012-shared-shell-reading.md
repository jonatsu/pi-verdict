# 0012 - Shell reading: close the gaps locally, defer a shared reader

---
status: proposed
date: 2026-11-02
---

## Context

A bash call reaches seven readers of its command text, and each reads it its own way:

| Reader | Module | How it reads the text |
| --- | --- | --- |
| Self-protection | `self-protection.ts` | substring signatures, plus its own `cd` parser (`bashDirectoryTargets`) |
| Floor | `shell.ts`, `shell-words.ts` | raw-text tripwires (ADR-0007), then `shellWords` to clear a hit, recursing into `sh -c` |
| `denyPaths` and the `.omp` gate | `deny-paths.ts` | `bashPathTokens`, a path-shaped token scanner, and the `.omp` regex |
| Code-loading ask | `code-loading.ts` | its own variable expansion, then `bashPathTokens` again |
| User `allow` | `shell.ts`, `allow-operands.ts`, `git-reach.ts` | `shellWords` in `allowAdmits`, and `shellWords` again for the operands |
| Session shell state | `shell-state.ts` | `shellWords` once per command, here-document bodies stripped first (ADR-0008) |
| Transcript redaction | `redaction.ts` | `bashPathTokens` over past calls |

The rule layer takes 0.1 to 0.2 ms for a typical call and about 1 ms at the 8,192-character cap (measured
2026-11-02 on v0.23.0), so cost is not the problem. `shellWords` returns plain strings, and the open gaps in
`TODO.md` item 3 come from that: an unquoted `$(…)` splits a command, process substitution `<(…)` is not marked
unsound, and brace expansion (`git {push,} origin +main`), `git push$NOPE` and a `-c alias.x=push` alias read as
harmless words. Each of them sends a force push to the classifier instead of the floor deny; none reaches an allow,
because the user-allow path refuses every such spelling (`allow-operands.ts`).

[cc-safety-net](https://github.com/kenryu42/cc-safety-net) 2.7.1 by kenryu42 (MIT), the source of this record's
ideas, parses each command once into words that keep their raw spelling, a quoted flag and their
provenance, gives the whole program one parse status, caches the parse for every check, and holds every analysis cap
in one table (`research/2026-11-02-cc-safety-net.md`). A first draft of this record adopted all of that as one
shared reader with a six-step migration. Two independent architecture reviews rejected that draft as written
(`research/2026-11-02-adr-0012-review-soundness.md`, `research/2026-11-02-adr-0012-review-necessity.md`):

- Treating here-document bodies as data would have widened what counts as sound, so `python3 - <<'EOF'`,
  `bash <<< '…'` and `ssh host <<'EOF'` with a destructive body would move from a floor deny to the classifier.
- One breach path for every cap would have turned the `sh -c` depth cap's deny into an ask, and the operand cap's
  classifier call into a needless ask.
- Nothing in the migration proved verdict equivalence: the planned probe check missed a gray call becoming a rule
  allow. The replay tool in `TODO.md` item 4 is that proof, and the TODO orders it before this work.
- The gaps the draft cited close with four local edits, and by commit subject only about four of forty recent shell
  and rule fixes concerned expansion. The divergence the reviewers found in shell-word handling is one assignment
  pattern defined three times with two meanings, and one constant defined twice.

## Decision

1. Close the item 3 gaps in place, one floor commit each, with failing-before tests and a probe case: mark an
   unquoted `$(` unsound in `shellWords` while still emitting its operator; mark an unquoted `<(` or `>(` unsound;
   let the push rule find `push` as a substring of a later word; and treat a `-c alias.…` value as making git's
   subcommand unreadable.
2. Define the assignment pattern (accepting `+=`) and `MIN_LONG_PREFIX` once in `shell-words.ts`, and delete their
   copies. The probe shows that no verdict moves, except toward deny.
3. Pin every accepted residual in ADR-0007, ADR-0008 and ADR-0009 with a probe case that asserts today's route (deny,
   ask or classifier), so a silent regression to allow fails the probe.
4. Keep here-documents unsound for the floor and the allow path. Keep each cap's own outcome: the depth cap denies,
   the operand cap sends the call to the classifier, the length cap asks.
5. Defer the shared reader. Word provenance (raw spelling, quoted, expansion kinds) and a parse status are built
   when a consumer needs them, first the read-only fast path in `TODO.md` item 6, and only after the replay tool in
   item 4 can show that a migration moves no verdict toward allow. That change also moves `allow-operands.ts` off its
   own expansion patterns and adds a seeded fuzz test with invariants: no word holding an unquoted `$`, backtick,
   glob, brace or tilde is literal, and every floor rule is reached.

The path half of item 5 (one resolver for every path spelling) is not decided here.

## Consequences

The item 3 gaps close with small, reviewable floor changes, and the residual cases make every accepted gap a tested
fact. Two readers stop disagreeing about assignments. No new module enters the gate now.

The readers still tokenize a command up to three times and keep their own path extraction, which costs well under a
millisecond. The structural fix waits for the replay tool, so a later shared reader starts with a proof of
equivalence instead of a promise.

Rejected for now: the shared reader with per-call memo and target union (no measured gain, and the strict redactor
already catches bare names); one breach path for every cap. Rejected outright: a full bash parser such as
tree-sitter-bash or mvdan/sh as WebAssembly, which would add a runtime dependency and still not know what a variable
holds at run time; porting cc-safety-net's POSIX parser, which serves a design without a model and with many more
static rules.
