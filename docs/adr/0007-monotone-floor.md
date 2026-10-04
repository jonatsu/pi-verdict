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
   option, recursion past the depth cap). It returns false (clearing the tripwire hit) only when the
   parse is **sound** and contains no force push — the quoted-argument case and a non-`git` `push`
   (e.g. `docker push --force`).

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
