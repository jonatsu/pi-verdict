---
description: "Before writing or editing a code comment or doc comment in pi-verdict TypeScript."
globs: ["**/*.ts"]
paths:
  - "**/*.ts"
---

# Code comments

A comment carries reasoning the code cannot show: why the code exists, the constraint it honors, the direction it
fails, the host behavior it mirrors. When the code already says it, write no comment. When a better name would
say it, rename instead. Silence is a valid result.

## Shape

- Write one to three plain sentences, and prefer one line.
- Give an exported symbol a doc comment that states its contract: what it returns, and which way it fails.
- Name the fail direction on a security-relevant branch ("fails closed: an unreadable target asks"), and the
  protection it keeps ("no protected path reaches the classifier, ADR-0002").
- Give a regex one sentence on what it matches.

## References that resolve

Cite what a reader can open and what stays stable:

- an ADR (`ADR-0009`) or an issue (`#83`);
- a test that pins the behavior ("pinned by the test `denyPaths never rebuilds from an ancestor`");
- at most one host-source citation per mirrored function, written as "mirrors omp's `expandPath` (18.6.1)".

Provenance (which plan item, review finding, phase or round produced the code, and when) goes in the commit
message or the ADR. Plans get reorganized and renumbered, so an id like `item 6c`, `F13` or `Phase 4` in code
points at nothing a year later.

## State, not story

- Describe the code as it stands and why that holds. The debugging story belongs in the commit.
- Describe a value's role and let the code hold the number: "capped at `BASH_MAX_MATCH_LEN`", not the figure.
- State a predicate instead of an inventory: "every layer that reads `toolAccess` targets", not a list of the
  functions that do today.

## Sanctioned markers

- `// ====` section banners mark the file's sections; the module split follows them.
- `[pi-verdict local patch: …]` tags mark divergences from upstream `jesset/pi-verdict`.
- An annotation names its exit: `TODO(#NN): …`, `TODO(TODO.md: <item title>): …`, or `HACK: … remove when …`.
- Delete dead code outright; git keeps the history.

## Example

Before, 21 lines that bury one sentence under plan keys, a date, a rebuttal of a plan draft and a tour of host
internals:

```ts
/** Extracts the shell-executing lines of an omp `eval {language:"py"}` cell (item 4, F13):
 *  the bash floor applies to these, never to the whole code text. Self-contained per
 *  constraint 3 (own constants/parser, no host import) and verified 2026-10-05 against the
 *  oh-my-pi v18.6.1 source (`coding-agent/src/eval/py/runner.py`'s `transform_cell`, the
 *  `_LINE_MAGICS`/`_CELL_MAGICS` registries) — **not** the plan draft's `%sh`/`%%sh`: …
 *  … 16 more lines … */
```

After:

```ts
/** Returns the lines of a Python `eval` cell that run a shell command, so the bash floor can check them:
 *  a `!` line (also `name = !cmd`), every line after `%%bash`, and a direct shell call (`subprocess.*`,
 *  `os.system(`, `__omp_shell(`). A plain line scan, so a `!` inside a string also counts; that only adds
 *  scrutiny. Mirrors omp's py cell transform (18.6.1). JS cells get no extraction (ADR-0009). */
```
