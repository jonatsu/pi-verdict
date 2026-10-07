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

- Build sessions with the helpers in `tests/pi-verdict.test.ts`. `session(cfg, opts)` writes the config, builds the
  harness and installs the extension in the right order; prefer it to wiring `makeHarness` and `setConfig` by hand.
  `toolCall(h, name, input)` returns `{ block, reason }` or `undefined`. `userMsg`, `readAudit` and `withTempDir`
  cover transcripts, audit records and temp trees.
- Stub the model with `h.responses = [{ text: "<verdict>allow</verdict> reason" }]`: an `Error` entry is thrown,
  and the last entry repeats. Read what the model was sent from `h.calls`, and the UI stubs from `h.notifies`,
  `h.confirms` and `h.selectPicks`.
- Drive the real ask dialog with `driveDialogs` (the EXPLAIN-GATE tests) or `driveMouseDialog` (the mouse-click
  tests), which replay key scripts against `buildApproveDialog` through a fake `ui.custom`.
- Put a fixture that needs a real home path under `fs.mkdtempSync(path.join(os.homedir(), ".pv-t20-"))`; a tmp
  dir under `/var` collides with the S1 system-path floor.
- Keep tests offline: no network, no real model, no module mocks. A hand-built fake host is the extension's input.
- Give each feature one top-level `describe`, and title each test by the behavior it pins, in English, with `ADR-000N` or `#NN` where it helps:
  `describe("scope-tool glob paths (ADR-0009)")`, `test("a globbed write over a protected path asks")`.
- Prove a bug fix fails before and passes after: run the new test against a temporary copy of
  `git show HEAD:extensions/pi-verdict.ts`. The shared worktree's stash is off limits for this.
- Pin every security behavior (the floor, `denyPaths`, fail-closed, no protected-path leakage) with its own test.
- Assert on outcomes the test controls: call counts, verdicts, a deadline injected through the env. Wall-clock
  elapsed-time thresholds flake on a loaded machine.
- Isolate the agent directory through `PI_CODING_AGENT_DIR` pointing at a temp dir (`TMP_AGENT`), and restore every
  environment variable and file a test touches; the jev tests save and clear `OPENROUTER_API_KEY`,
  `TYPESAFE_API_KEY`, `PI_VERDICT_JEV_URL` and `PI_VERDICT_JEV_TRANSPORT`.
- Build dangerous literals by concatenation, as in the source.

## Changing a test

Change an existing assertion only when the behavior it pins changes on purpose, and say why in the commit. A test
that blocks a fix is evidence about the fix first. A source comment reading "pinned by the test …" means the
behavior and that test change together, in one commit, or not at all.

## Probe cases

- A case names the layer that must decide the call (`expected.layer`), not the verdict text; read
  `probe/README.md` for the layer vocabulary and the three runs.
- A case marked `known: "open"` states the fixed behavior and must fail today. Fixing the defect means removing
  the marker, not rewriting the case.
- Regenerate `docs/coverage.md` with `bun run coverage` in the same commit as any case change.
