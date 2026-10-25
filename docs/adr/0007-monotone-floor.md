# 0007 - Monotone floor: a raw-text tripwire decides, a sound word view may only clear

---
status: accepted
date: 2026-10-04
---

## Background

The `git-push-force` floor rule was rewritten (fork, 2026-10-04) from a raw-string regex to a
shell-word view, so it could tell an argument from a command: `git push origin 'a&b' --force` is a
genuine force push (the old `[^;|&]*` class stopped at the quoted `&`), while
`git commit -m '… git push --force …'` is not, although the raw text contains the pattern. The 2026-10-04 architecture audit (`research/2026-10-04-architecture-review.md`, finding F4) found the result **non-monotone**: the word view models
the shell less faithfully than the regex it replaced, and every spot where its model is weaker than
the shell is a **bypass** — `$( … )` inside double quotes, `eval`, `env -S`, a `sh -c` template that
forwards `$1`, recursion past the depth cap, a backtick substitution, `bash -o pipefail -c`, a `+`
refspec. Each was a *new* miss the old regex caught (or a spelling neither caught), so a release
that swapped the mechanism could deny less than the one before it.

## Decision

> **A floor change may never turn a raw-text hit into a non-hit on an unsound parse.**

The `git-push-force` rule is now two layers:

1. **A raw-text tripwire decides every hit.** A coarse, over-approximating pattern anchored on a
   `push` word (fully flexible body, so `git --git-dir=X push …` and `-c/-C` gaps need no special
   handling) terminated by a bare `--force`, another `--force-*` form (only `--force-with-lease`
   is exempt), a bundled short `f` flag, or a `+` refspec. It also tests the spelling with unescaped
   backslash-newline continuations removed, so a split flag still matches. **If the tripwire does not
   hit, the rule returns false** — no word view runs.

2. **The tokenised word view may only clear a hit, never be the sole path to one.** It runs only
   after a tripwire hit. It returns true when it finds a `git push` with a force flag (confirm), and
   true whenever its parse is **unsound** — a sentinel marks a construct the scanner cannot resolve
   (`$(` inside double quotes, backticks, a here-document, a process substitution, `eval`, `env -S`
   forms, an unterminated quote, a `-c` template with a positional reference, an unmodelled shell
   option, an unmodelled `git` global option, an expansion or glob before git's subcommand,
   recursion past the depth cap). It returns false
   (clearing the tripwire hit) only when the parse is **sound** and contains no force push — the
   quoted-argument case, a non-`git` `push` (e.g. `docker push --force`), a `push` that is not
   git's subcommand (`git stash push -- +file`), and a `+word` that is a push option's value
   (`git push -o +x`).

Over-approximation is safe by construction: a false trip is cleared by a sound word view, so the
tripwire only has to never MISS. The floor's coverage can therefore only grow across releases.

## Consequences

- The word view keeps its precision role (pairing a `git` command with its force flag, recursing
  into `-c` strings) but its soundness role is now the load-bearing one; where it cannot resolve a
  construct faithfully it marks it unsound rather than producing a misleading parse.
- `--force-if-includes` is excluded in `isForceFlag` (a no-op without a lease); alone it falls to the
  classifier, alongside a lease. `--force` in the same command still denies.
- The deny reason for a tripwire hit stays `rule git-push-force: git push --force` — accurate,
  because the raw text really contains the pattern. No own-reason plumbing is needed.
- Detection is still token-level: a path or command hidden behind a construct the scanner marks
  unsound is denied (the deny direction), not silently allowed.

## Amendment (2026-10-25): the git and gh danger rules

`git-reset-hard`, `git-stash-clear`, `git-clean-force`, `git-checkout-dot`, `git-restore`, `gh-repo` and
`gh-release` were regexes over the raw command text. They denied text the shell never runs as that command,
such as `git commit -m "deny git stash clear"`, and no user `allow` rule can lift a floor deny. They also
missed a gap between the program and its subcommand, so `git -C dir reset --hard` and
`git -c k=v stash clear` reached the classifier.

These rules now take the same two layers as `git-push-force`, built from the shared word view in
`shell-words.ts`:

1. A gap-tolerant raw-text tripwire decides every hit, for example `\bgit\b[\s\S]*?\bstash\b[\s\S]*?\bclear\b`.
   It is also tested on the spelling with unescaped backslash-newlines removed.
2. The word view clears a hit only when its parse is sound and no command runs the subcommand with the
   rule's arguments. For git, the subcommand is read past git's global options; an unreadable option keeps
   the deny when a later word contains the subcommand's name. For gh, the group word (`repo`, `release`)
   must follow `gh`, and the action word follows it, read past `--repo` and its value; any other option
   keeps the deny when a later word contains an action name. A shell's `-c` script is read as a command.

The word view does not join words and re-run the regex, because joining loses the quoting that tells an
argument from a command.

`raw-device`, `remote-exec`, `env-exfil` and `fork-bomb` stay raw-text only. Their meaning spans a pipe, a
redirection or a function definition, which the word view splits or drops, so it cannot show that such a
hit is harmless. `rm-recursive`, `rm-root`, `sudo` and `chmod-777` also remain raw-text rules.

Two scope changes come with the shape. `git-checkout-dot` now denies any `.` argument, so
`git checkout HEAD -- .` is caught as well as `git checkout .`. The shared `-c` scan also reads a script
that follows a `+o` option (`bash +o posix -c '…'`), which the force-push word view used to skip.
