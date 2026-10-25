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

## Amendment 2026-10-25: operand grading and git reach

The shape check above reads what a command *is*, not what its operands *touch*. Under
`allow: ["^cat\\b"]` the command `cat ~/.ssh/id_rsa` was one simple command, so it was a silent rule
allow, although a `read` of the same file is an S0 deny. Under the documented example
`allow: ["^git (status|log|diff)\\b"]`, `git diff /dev/null ~/.ssh/id_rsa` printed the key the same
way. The project goal is that a static rule may allow a call only when it can show the call is
harmless, so the allow step now also grades the operands (plan items 1, 1a and 2 of
`docs/plans/call-model-and-rule-hardening.md`). It lives in `allow-operands.ts`; `allowAdmits` stays
the shape check.

**(f) Operand grading.** Every operand is graded as a read through the path-sensitivity floor
(`classifyPath`), and the admission is refused unless each one grades `allow`; an S0 secret or an S1
system path refuses it. An operand is each word after the command word that does not start with `-`,
and also its value after an `=` (`dd if=~/x`: bash expands a tilde there); the value of a
`--name=value` option or of a leading assignment; the text of a short option from its first `/`
(`-f/home/u/.pypirc`); and every word after `--`. An option word that holds `$`, `~` or a glob
character refuses the admission, because the gate cannot tell where its letters end and its value
begins. A bare `.env` counts, which a path-token extractor would miss. Grading every word
over-extracts (`main` grades as `<cwd>/main`), which is the safe direction. More than 64 graded paths
(a glob's matches each count) refuse the admission, so the filesystem work per call stays bounded.

**Where relative operands resolve.** omp's `bash` runs in its `cwd` argument when one is given, so
every relative operand resolves from that directory, not the session cwd: `cat id_ed25519` with
`cwd: "~/.ssh"` reads the key. The gate resolves the argument as omp does (`callCwd`) and grades
every layer there, and a `cwd` it cannot resolve withholds the allow. This applies to every layer, not
only this step; `docs/layers.md` records it.

**The expansion rule.** The shell expands an operand before the command sees it, so the gate expands
it first where the result is exact: a leading `~` or `~/`, `$HOME` and `${HOME}` become the home
directory, quoted or not (the word view has lost the quotes, so a single-quoted `'$HOME'` is expanded
too, which only refuses more). An operand that still holds an expansion the gate cannot resolve
refuses the admission: any other `$`, `~user`, a brace expansion (a `{` with a `,` or `..` before its
`}`) and a glob. The gate does not expand other variables because it cannot know their values: omp
runs an agent's bash calls in one persistent shell, started from the user's shell snapshot and the
project's direnv `.envrc`, which the agent can write. Expanding from the gate's own environment would
turn an unknown value into a wrong one. One glob is exact enough to keep: a glob with no `/` that does
not start with `.` (`cat *.md`) matches only entries of the cwd, so the gate reads the cwd, matches
the pattern against every entry, hidden ones included and ignoring case, and grades every match. omp
replays the user's `shopt` settings into the agent's shell, so `dotglob`, `GLOBIGNORE` or `nocaseglob`
may be on, and the gate grades a superset of what any of them matches. So `cat *.pem` over a project
key, `cat k*` over a project symlink to `~/.ssh` and `cat *` beside a `.env` are refused. A glob that matches nothing (bash would pass the pattern itself), a cwd that cannot be read
and a bracket form the gate does not model (`[[:alpha:]]`) refuse the admission. In a `powershell`
command a backslash refuses the admission: the word view reads it as bash's escape, while PowerShell
keeps it as a path separator.

**The `HOME` guard.** In that persistent shell, `export HOME=~/.ssh` followed by `cat ~/id_rsa` reads
the key while the gate grades the real home. Once the call itself or any earlier command call on the
session branch may assign `HOME` (a plain or `+=` assignment, `${HOME:=…}`, `export`, `declare`,
`typeset`, `readonly`, `local`, `read`, `mapfile`, `readarray`, `unset`, `for HOME`, `printf -v HOME`),
every home-relative
operand refuses the admission. The scan is textual and over-matches on purpose: a false match costs
one classifier call. A branch the host cannot hand over counts as reassigned (fail closed). The scan
runs only when a home-relative operand needs it.

**(g) Git reads outside the work tree.** For `git diff` and `git grep`, `--no-index` (or an
abbreviation git's option parser accepts) refuses the admission, and so does any operand that is not an
option and resolves outside the cwd in its lexical or real form, because git implies `--no-index` for
such a path and then prints any file. Operands resolve from a `-C` directory as git resolves them.
"The project" is the session cwd, not the directory a `bash` call names in its `cwd` argument: a git
call that runs outside the project, through that argument or a `-C`, refuses the admission, since
outside any repository `git diff` implies `--no-index` (`cwd: "/proc"` with
`git diff self/environ self/cmdline` prints the environment).
Refusing a `git diff` of two revisions spelled like outside paths only costs a classifier call.

**(h) Git configuration injection.** Before the subcommand, `-c` (bare or attached), `--config-env` and
`--exec-path=<dir>` refuse the admission, since `core.fsmonitor`, `core.pager`, `diff.external`,
`core.sshCommand`, a `!` alias or a replaced exec path each run a program. A `-C <dir>` outside the cwd
refuses it too, so retargeting cannot dodge (g). git's global options are read by the same
`gitSubcommandIndex` the force-push rule uses, so a global option it does not model refuses the
admission instead of being skipped, which could hide the subcommand behind the option's value. The
documented `^git (status|log|diff)` regex never matched `git -c … status`; (h) matters for broader
allows such as `^git\b`.

**Why not a floor deny.** The S0 patterns as a bash deny would also hit legitimate commands that name
a key without printing it, such as `ssh -i ~/.ssh/id_x host` and `ssh-keygen -f`. A refused admission
is not a deny: the call reaches the classifier, which may still allow it. For the same reason the
grading runs with `builtinDenyFloor: false` too; the option turns built-in denies off, and a refusal
here denies nothing.

**Consequences.** BREAKING for a policy whose allows covered such commands: they now cost a classifier
call and fail closed headless with no model. Nothing new is denied, and `cat README.md`, `git status`,
`git log --oneline`, `git diff HEAD~1`, `ls -la` and a matching `ls *.md` stay zero-call rule allows.
Pinned by the `allow operand grading (ADR-0008 amendment)` and `bash cwd argument` tests and the
probe's `allow operand` cases in the `user-allow` family.

Two residuals remain. A recursive search such as `grep -r x ~` under a `^grep\b` allow is admitted:
the home directory itself is not S0, so the operand grades `allow` while the search walks into
`~/.ssh`. A short option with an attached relative value and no `/` (`git config -f.netrc --list`) is
not graded, because its value cannot be told from its letters.
