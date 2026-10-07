---
description: "Before writing or changing pi-verdict tests or probe cases."
globs: ["tests/**/*.ts", "probe/**/*.ts"]
paths:
  - "tests/**/*.ts"
  - "probe/**/*.ts"
---

# Tests and probe cases

Tests pin what the gate decides, so a test that fails when the behavior breaks and stays quiet otherwise is the
whole point. Test behavior through the real entry points: `toolCall` in `tests/`, `adjudicate` in `probe/`.

## Writing a test

- Build sessions with the helpers in `tests/pi-verdict.test.ts`: `session(cfg, opts)`, `toolCall`, `withTempDir`.
  Stub the model through `h.responses` and read what it was sent from `h.calls`.
- Title each test by the behavior it pins, in English, with `ADR-000N` or `#NN` where it helps:
  `describe("scope-tool glob paths (ADR-0009)")`, `test("a globbed write over a protected path asks")`.
- Prove a bug fix fails before and passes after: run the new test against a temporary copy of
  `git show HEAD:extensions/pi-verdict.ts`. The shared worktree's stash is off limits for this.
- Pin every security behavior (the floor, `denyPaths`, fail-closed, no protected-path leakage) with its own test.
- Assert on outcomes the test controls: call counts, verdicts, a deadline injected through the env. Wall-clock
  elapsed-time thresholds flake on a loaded machine.
- Isolate the agent directory through `PI_CODING_AGENT_DIR` pointing at a temp dir, and restore every environment
  variable and file a test touches.
- Build dangerous literals by concatenation, as in the source.

## Changing a test

Change an existing assertion only when the behavior it pins changes on purpose, and say why in the commit. A test
that blocks a fix is evidence about the fix first.

## Probe cases

- A case names the layer that must decide the call (`expected.layer`), not the verdict text; read
  `probe/README.md` for the layer vocabulary and the three runs.
- A case marked `known: "open"` states the fixed behavior and must fail today. Fixing the defect means removing
  the marker, not rewriting the case.
- Regenerate `docs/coverage.md` with `bun run coverage` in the same commit as any case change.
