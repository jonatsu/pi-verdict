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
- **A re-parser in command position, or an option that runs a program** — `xargs`, `find … -exec`/
  `-execdir`/`-ok`/`-okdir`, `fd`/`fdfind -x`/`-X`/`--exec`/`--exec-batch`, `rg --pre`, `tar`,
  `bsdtar` or `gtar` with `--to-command`, `--use-compress-program`/`-I`, `--checkpoint-action`,
  `--info-script`/`-F`, `--new-volume-script`, `--rsh-command` or `--rmt-command`, `zip -TT`/
  `--unzip-command`, and `rsync -e`/`--rsh`/`--rsync-path`. An option that writes a file counts too,
  because the operand grading would read its target as a read: `find -delete`/`-fprint`/`-fprint0`/
  `-fprintf`/`-fls` and `sort -o`/`--output`/`--compress-program` (amended 2026-10-25: under
  `^find\b`, `find . -fprint ~/.bashrc` truncated that file as a silent rule allow).
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
`cwd: "~/.ssh"` reads the key. The gate resolves the argument as omp does (`resolveCommandCwd`) and grades
every layer there, and a `cwd` it cannot resolve withholds the allow. The classifier's action line,
the ask dialog, notifications and past transcript lines end with `| cwd: <dir>` when the call runs
outside the session cwd, so neither a model nor a human judges `cat config` without seeing that it
runs in `~/.kube`; a `cwd` inside a declared path is redacted like any other target (ADR-0002). This applies to every layer, not
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

**Recursive commands.** A recursive command walks below its directory operands, so an operand that is
no secret can still reach one: `grep -r x ~` reads `~/.ssh`. When the command word and its options say
the command recurses (`grep -r`/`-R`/`--recursive` and bundles such as `-rn`, any grep `-d` or
`--directories`, whose `recurse` value may sit in the next word, `rg`, `ag`, `ack`, `fd`, `find`, `du`,
`tree`, `tar`, `bsdtar`, `gtar`, `7z`/`7za`/`7zz`, `ls -R`, `zip -r`, `cp -r`/`-R`/`-a`, `rsync -r`/`-a`,
`scp -r`), an operand that
contains a credential directory refuses the admission, and so does a cwd that contains one, which a
command naming no directory searches. This is the test a scope tool's search takes
(`s0DirectoryBeneath`). A credential directory is any directory an S0 entry guards a file in, read
from the same table as the S0 grade: `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.docker`, `~/.gem`,
the credential homes under `~/.config` and under a relocated `$XDG_CONFIG_HOME`, `~/.omp/agent`,
`~/.pi/agent`, the agent directory, and omp's data directory (`~/.local/share/omp` or
`$XDG_DATA_HOME/omp`). An operand that is such a directory counts as well as one that contains it,
because the agent directory and `~/.docker` are not secret as a whole. `/proc` and the process and
thread directories below it (`/proc/self`, `/proc/<pid>`, `/proc/<pid>/task/<tid>`) count too, since
each holds an `environ` file. The predicate reads no option's argument, so it over-approximates (`grep -e r`
counts as recursive); a false match only costs a classifier call. `grep x ~/notes.txt` and
`grep -rn foo src` in a project stay rule allows.

One residual remains. A short option with an attached relative value and no `/`
(`git config -f.netrc --list`) is not graded, because its value cannot be told from its letters.

## Amendment 2026-11-02: the session's shell state

omp runs every bash call of a session in one persistent shell (omp 18.13.0: a module-level `shellSessions` map
in `exec/bash-executor.ts`, keyed by the session id that `tools/bash.ts` passes). An earlier call, approved by
the classifier, can therefore change what a later allowed command does. Under the deployed allow
`^git (status|log|diff|show|branch|remote -v)(\s|$)`, `export GIT_EXTERNAL_DIFF=/tmp/x.sh` makes a later
`git diff` run that script as a silent rule allow, and `PATH`, `LD_PRELOAD`, a shell function or an alias can
redirect any allowed command the same way. The `HOME` guard above covered one variable; it is now one case of a
general rule.

**Decision.** `SessionState` keeps a shell-state record per host session id (`shell-state.ts`). Every tool
call's `command` goes into its session's record before the call's verdict, whatever the verdict, including a
call the master switch or `subagentGate: "off"` lets through ungated. The first call of a session also reads in
the commands of every past entry once, through `getEntries` (off-branch entries included), else `getBranch`.
The record only grows: a rewind or a tree move hides an entry from the branch, not what it did to the shell, and
sibling calls of one assistant message reach the gate before the host appends any of them. A user allow then
leaves out what the record voids:

| Construct a command may run | What it voids |
| --- | --- |
| Setting `PATH`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `BASH_ENV`, `ENV`, `PS4` (expanded before each command under `set -x`) or `PROMPT_COMMAND`; a function definition (`name() {`, `function name`); `alias`; `enable`; `hash -p`; `shopt … expand_aliases`; `source`, `.`, `eval` or `trap` | Every user allow of a command |
| `HOME` | Home-relative operands, and `git` |
| `IFS` | Home-relative operands |
| `XDG_CONFIG_HOME` (a moved global gitconfig can set `core.fsmonitor`), any `GIT_*` variable, a `git config` that may write (not `--get`, `--get-all`, `--get-regexp`, `--list`/`-l`, `--show-origin`, `--show-scope`, `get` or `list`) | `git` |
| `RIPGREP_CONFIG_PATH` | `rg` |
| `TAR_OPTIONS` | `tar`, `gtar`, `bsdtar` |
| `ZIPOPT`, `ZIP` | `zip` |
| `RSYNC_RSH` | `rsync` |
| `LESSOPEN`, `LESSCLOSE` | `less` |
| `GREP_OPTIONS` | `grep`, `egrep`, `fgrep`, `rgrep` |

The record holds which of these 15 rows fired, as flags, not command text. Each command is read once through
the `shellWords` tokenizer (ADR-0007), which removes quoting and redirections, and split into simple commands
at operators and line breaks. Here-document bodies are removed first, since a body is one command's input and a
lone quote in it would mislead the tokenizer; a body ends at its delimiter line, and one whose delimiter line
never comes is kept and scanned.
A variable is set by an assignment word, by a name in the arguments of `export`, `declare`, `typeset`,
`readonly`, `local`, `read`, `mapfile`, `readarray` or `unset`, by `for X`, by `printf -v X`, and by a word
holding `${X:=…}` or `${X=…}`. The command name is the first word after the leading assignments and after the
wrappers `command`, `builtin`, `exec`, `env` and `nice`, so a quoted search pattern such as `rg 'fn main() {'`
names no construct. A leading assignment followed by a command word (`GIT_PAGER=cat git log`) changes that
command alone: it voids the call it is on and does not enter the record, while `PATH=x; ls` and
`export PATH=x` do. A voided command matches the basename of any word of the allowed command, so `env git diff`
counts. `CDPATH` voids nothing, since every operand the gate grades resolves from the call's own cwd. A command
over `BASH_MAX_MATCH_LEN`, or one the tokenizer stopped reading early (`$'…'`, an unterminated quote), takes a
substring scan instead: a row fires when any of its names occurs anywhere in the text. A command substitution
or a here-document does not trigger that scan: it cannot change the session's shell, and the allow step
already refuses an unsound command. The cost per call is the current command only, linear in its length.

**Fail direction.** While neither `getEntries` nor `getBranch` can be read, every user allow is voided,
home-relative or not, since the gate cannot tell which command an earlier call redefined. The test
`an unreadable session branch refuses every user allow, home-relative or not (fails closed)` pins it.

**Consequences.** The rows over-match on purpose: a false match sends later allowed commands of that session
to the classifier, which costs one model call each and denies nothing. A session that runs none of these
constructs keeps every allow on the fast path. Pinned by the `session shell-state guard (ADR-0008 amendment)`
tests. These spellings and paths are accepted residuals; the OS sandbox is the backstop (ADR-0009):

- `exec >file` redirects the shell's later output, which no row reads.
- direnv and JavaScript `eval` cells change the environment of a run without command text the gate sees.
- A nested or bare repository planted in a subdirectory and used as a call's `cwd` brings its own git config.
- `HOME` also moves the dotfiles of commands other than git, which matters only if a user allows such a command
  (`ssh`, `curl`).
- A user's own `!` commands share the shell, and they are the user's.
- A variable whose name the text does not spell out (`export "$V=…"`, a `declare -n` reference) or that is set
  through an array subscript (`PATH[0]=…`) is not recognized.
- `GCONV_PATH`, `LOCPATH`, `NLSPATH` and `DYLD_*` are not rows.
- A write to the global git config files under `~/.config/git/` (`config`, `attributes`) by a file tool is not
  an S2 path.
- An abbreviated long option shorter than five characters (`sort --o=~/.bashrc f`) still passes the
  side-effect option check, which matters only if a user allows `sort`.
- A `git config` written in an earlier session persists in the repository, beyond the session's record.
- A quote construction that misleads the tokenizer mid-command, so its unsound mark is not the last word
  (`echo "$(echo '"')"; export GIT_EXTERNAL_DIFF=/tmp/x; echo \'`), skips the substring scan, which runs only
  when the tokenizer stopped early so that ordinary commits with a command substitution void nothing.
- The substring scan does not watch `.` as the sourcing command, since a dot occurs in almost every command.
- A function definition after a prefix word such as `then`, `do` or `{` is not recognized.
- A `<<X` inside quotes, followed later by a line that is exactly `X`, hides the lines between from the scan.
