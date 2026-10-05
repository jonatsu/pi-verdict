# probe — the shared gate-testing contract

One case table both sides run, executed offline against the real extension. It replaces prose
hand-backs: a case names a behaviour and the layer that must decide it, and the runner asserts
that layer for every case.

```
bun run probe                 # all cases
bun run probe --filter "hides"  # subset by label substring
```

## The three runs

Each case runs `adjudicate` up to three times, asserting **the layer that must decide the call**
(the `source`), not the verdict text:

| Run | Config | Model | Applies to |
|---|---|---|---|
| A | `case.config`, else `{}` | `hasUI: false`, no model | every case |
| B | same as A | `hasUI: true`, stub model returning `<verdict>allow</verdict>` | every case |
| C | consumer-policy fixture | `hasUI: false`, no model | `policy: "consumer"` cases only |

Run A exercises the headless path (gray-zone → fail-closed; asks degrade to deny). Run B
exercises the classifier (gray-zone → the stub's allow). Run C **re-asserts the same layer as
run A under the consumer policy**, so a case the floor covers stays covered: if the floor stopped
matching and the deployed `deny` regex took over, C reports the `user deny rule` reason and the
case fails.

## Layer vocabulary

`expected.layer` is the source that must decide the call:

- `rule` — the deterministic rule layer (built-in floor, user rules, or an in-cwd/file allow).
  Runs A and B assert `source: "rule"`.
- `allow` — a deterministic **rule-layer allow** (`allow/rule`), the layer the code returns for a
  non-S0/S1 read. This is distinct from a classifier allow.
- `classifier` — the gray zone. Run A (headless) asserts `fail-closed/deny`; run B asserts
  `classifier/allow`.
- `protected-path` — a `denyPaths`/`gateOmpDir` match. Run A asserts `protected-path/deny` (the ask
  degraded headless); run B asserts `protected-path/ask`.
- `rule-ask` — a rule-layer ask that is not a `denyPaths`/`gateOmpDir` match (e.g. the tool-access
  adapter's opaque ask: a known mutating call naming no target at all, ADR-0009). Run B asserts
  `rule/ask`; runs A and C assert `rule/deny` **with `degraded: true`** — a plain rule deny must
  never pass as a degraded rule-ask.

`expected.ruleId` and `expected.reasonIncludes` are substrings of the verdict reason. The floor
reason is `rule <id>: <reason>`, so `ruleId: "git-push-force"` matches the force-push floor rule.

## Open cases

A case carrying `known: "open"` states the **desired** (post-fix) expectation and must fail today.
The runner prints `~` for it, excludes it from the pass count, and **exits 1 if an open case
passes** (`open case now passes — remove the marker`). Fixing a defect means removing its marker,
not rewriting the case. Every case of an open item carries the marker and its `item` tag.

## Fixtures

The tree is built fresh per run under `os.tmpdir()` (`buildFixtures`), never committed: a symlink
in a git checkout breaks on Windows and pollutes the working tree. Symlink and `/etc` families are
`skipOn: "win32"`. Cleanup uses `rmSync` with `force` (unlinks symlinks without following them).

`kernelOpens` is a runner-side truth check: the raw spelling the gate sees must actually open the
same file the kernel target names. The oracle is `cat`, which passes the spelling to `open(2)`
untouched — Node's `fs` collapses `..` lexically before the syscall, which is exactly the
disagreement these cases test.

## The consumer-policy fixture

`probe/consumer-policy.json` is the committed synthetic fixture (exercised entries only). The real
policy stays consumer-side. Resolution order:

1. `PI_VERDICT_PROBE_POLICY` (env, absolute path)
2. `probe/consumer-policy.real.json` (gitignored; the documented default override)
3. `probe/consumer-policy.json` (synthetic)

`_meta` is stripped before loading. A `config` case and a `policy: "consumer"` case are mutually
exclusive.

## Provenance hand-back

`bun run provenance` prints the HEAD sha and one `sha256` line per committed extension blob. That
is the artifact the consumer's staged check compares (`git show <sha>:<path> | sha256sum`); the
hand-back is the output plus the SHA, no payload tables in prose.
