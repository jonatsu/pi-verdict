# 0008 - The user allow layer admits one simple command

---
status: accepted
date: 2026-10-04
---

## Background

The user `allow` layer tests **raw command text** (ADR-0006's ordering keeps it after `deny` and
`denyPaths`). The 2026-10-04 architecture audit (`research/2026-10-04-architecture-review.md`, F2)
found that a regex anchored on the first word therefore admits a whole **compound command**: with
`allow: ["^ls\\b"]`, the commands

```
ls
bash /tmp/evil.sh
```

and `ls & npm install evil-pkg` and `ls $(bash /tmp/evil.sh)` all match the anchor and are granted a
deterministic `allow` — no floor, no classifier, no human. The audit's V7 is the same shape for a
single command: `git log --format=x --output=<path>` matches a read-shaped `^git log` allow yet
writes a file, and `-o` is git's short form of the same flag.

The allow layer is the user's own declaration, but it was written as "these commands are fine",
not "the first word of these commands is fine". The gap is between the declaration's intent and the
spelling it matched.

## Decision

> **A user `allow` regex admits exactly one simple command. Anything else reaches the classifier.**

`allowAdmits(command)` gates the allow loop (`classifyByRules`); when it returns false the allow
regexes are skipped and the call falls through to the classifier, which may still allow it on the
evidence. The guard rejects a command that is not a single simple command:

- **An operator or newline** (`;`, `;;`, `&`, `&&`, `|`, `||`, `(`, `)`, a line break) — more than
  one command, or a pipeline/subshell the anchor did not intend to cover.
- **An unsound parse** — the `shellWords` scanner's `UNSOUND` sentinel (a command substitution inside
  double quotes, a backtick span, `eval`, `env -S`, a positional `sh -c` template, a here-document,
  process substitution, an unterminated quote, depth exhaustion), the same marker ADR-0007 uses.
- **A redirection other than to `/dev/null`** — `>`/`>>`/`<` (to `/dev/null` is inert and allowed).
- **A re-parser in command position** — `xargs`, `find … -exec`/`-execdir`.
- **A `git` invocation carrying a write flag** — `--output`/`-o`, `--exec`, `--ext-diff`,
  `--textconv`, `--git-dir`, `--work-tree`, bare or attached (`--output=…`, `-o<path>`).

No new lexer: the guard reuses `shellWords` (ADR-0007).

## Why this direction is safe

A rejected allow is **not** a deny. It defers the call to the classifier, which is the fallback
every uncovered command already has. The narrowing can only turn a silent deterministic `allow` into
a judged one, never the reverse, so the change is monotone in the same sense as ADR-0007: it removes
a path to permission, adds none.

## Consequences

- **BREAKING for a policy that relied on a first-word anchor to admit compound commands.** After
  this change `allow: ["^ls\\b"]` no longer admits `ls && <anything>`; if the compound form is
  genuinely wanted, it now needs its own `allow`, and even then a command carrying a shell operator
  will reach the classifier. Users who want a compound command to run unattended should express it
  as a `deny` exemption rather than an `allow`, or accept the classifier's judgment.
- The common case is unchanged: `ls -la`, `pwd`, `git status` under their exact allows stay
  zero-model-call rule allows.
- **Residual limitation, recorded not hidden:** redirect *targets* are not graded here — a
  redirecting command reaches the classifier, which sees the target in its action line. Deterministic
  S0/S1/S2 grading of a `>` target is deferred to the host-adapter round (audit V2).
- Pinned by the `simple-command allow guard` tests and the probe's `user-allow` family (which fail
  before this change: the four audit payloads were rule-allowed).
