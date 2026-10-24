# Subagent ask visibility on the root session (live repro, omp 18.12.6)

Date: 2026-10-24. Host: omp 18.12.6 (omp source tag v18.12.6 under `.scratch/research/oh-my-pi`). Extension: working tree at
HEAD `55812af` (the tree moved under the investigation from other commits; line numbers below are for that HEAD).
Method: interactive omp in tmux (200x50), throwaway agent dir + project under `/tmp`, `denyPaths: [<proj>/secret]`,
`audit: true`, `subagentAskTimeoutMs: 90000`, `--tools read,task`, copies of the user's `config.yml` (no
`extensionHandlers` key, so the host default of 30 000 ms applies). Pane polled every second.

## Verdict

- A (the dialog is not rendered while the subagent panel runs): REFUTED. The rich dialog appears in the root TUI about
  3 s after the subagent's call, under the `Subagents . 1 running` panel, and takes the keyboard.
- B (60 s is too short): PARTLY. The window that matters is not 60 s but omp's 30 s handler budget (below).
- C (queue): not the cause in the single-ask runs; queued dialogs do pile up after the failure (stale dialogs).
- D (found): omp's `extensionHandlers.toolCallTimeoutMs` (default 30 000 ms) kills the subagent's `tool_call` handler 30 s
  after the ask starts, because omp pauses that budget only for dialogs opened through the handler's own `ctx.ui`, and a
  subagent's `ctx.ui` is the no-op UI. pi-verdict opens the dialog on the captured root UI (`rootUi`), which the
  subagent handler's budget cannot see. The call is blocked with `Extension <path> timed out after 30000ms`, but the
  root dialog stays open (nothing aborts it), so the user answers a dialog whose call is already dead.

## Evidence

Per variant (times local, UTC+3; audit `ts` is UTC). `toolCallTimeoutMs` = omp `extensionHandlers.toolCallTimeoutMs`.

| Run | toolCallTimeoutMs | Answer | Result |
|---|---|---|---|
| v1 | 30 000 (default) | never | Dialog visible 22:28:22. Subagent read fails with `Extension .../index.ts timed out after 30000ms`, three attempts (bare path, absolute, selector). Audit: 4 subagent ask records at 19:28:18.8, 19:28:50.4, 19:29:21.9, 19:29:54.8 (UTC), all `resolution: timeout`; the notice `Auto Mode blocked (subagent ask, no human)` appears at 22:29:52, i.e. ask 1 + 90 s (pi-verdict's own deadline firing on a stale dialog). |
| v3 | 30 000 (default) | Yes at +45 s | Ask 19:40:42.695Z. omp log `Extension handler timed out` at 22:41:12.694 (+30.0 s). User pressed Yes at 22:41:27 (+45 s). Audit: `userAnswer: allowed`, `resolution: human`, `answeredAt 19:41:27.721Z` yet the subagent's read returned the timeout error and the subagent reported "the gate may simply have stalled". A retry's dialog (read secret/x.txt:1) was still open at 22:42:07 after the subagent had finished, until its 90 s deadline at 22:42:44. |
| v4 | 200 000 | Yes at +45 s | Same input. Read returned `TOPSECRET-CONTENT-123`, audit `human/allowed`, no `timed out` in the omp log. |
| v5 | 30 000 (default) | Yes at +10 s | Read returned the content; audit `human/allowed` (answeredAt 19:46:12.7Z). Answers inside 30 s work. |
| v6 | 30 000 (default) | two subagents, Yes at +20 s and +23 s | Only one ask record appeared (`ReadSecretA`, human/allowed); both reads returned content. The second subagent was not asked. Not explained; inconclusive on queue behavior. |

Pane lines (v1, 22:28:22):

```
 Subagents · 1 running
  └─ • ... ReadFirstLine ⟨sonic⟩: Read secret/x.txt and report its first line
 🛡️ [subagent ReadFirstLine (sonic)] Auto Mode: protected path
 read: secret/x.txt
 Allow this access?
 → Yes / No / No, with explanation…
```

The user's own logs fit the same mechanism: their `~/.omp/agent/config.yml` has no `extensionHandlers` key, the omp logs
hold `Extension handler timed out` for the installed copy on 2026-10-20 and 2026-10-24, and a `human` answer at 59.4 s is
28+ s after the call was already blocked.

## Root cause

1. omp `emitToolCall` runs each handler through `raceHandlerWithTimeout` with `timeoutMs =
   extensionHandlers.toolCallTimeoutMs` (default 30 000):
   `packages/coding-agent/src/extensibility/extensions/runner.ts:1945-1995` and `:300-372`. On expiry it returns
   `{ block: true, reason: "Extension <path> timed out after Nms" }`.
2. The budget pauses only inside `createHandlerUIContext` (`runner.ts:195-262`: `runDialog` and the `custom` wrapper call
   `timeoutBudget.pause()/resume()`), and that wrapper is applied to the handler's own `ctx.ui`. A subagent's `ctx.ui`
   has no UI (`ctx.hasUI` is false), so the paused-budget path never covers the root dialog.
3. pi-verdict chooses `ui = !sub || ctx.hasUI ? ctx.ui : rootUi` (`extensions/pi-verdict/index.ts:915`) and shows the
   dialog with `confirmAsk(rootUi, ...)` (`ui/dialog.ts:450`, `pickAsk` uses `ui.custom`). `rootUi` is the root's
   `ctx.ui` captured at `session_start` (`index.ts:423`), where the budget is not wired.
4. The dialog's cancellation is `AbortSignal.any([deadline, ctx.signal])` (`index.ts:1030-1031`). omp 18.12.6's
   `ExtensionContext` has no `signal` property (interface at `.../extensions/types.ts:671`; context built at
   `runner.ts:1486-1540`; pi's type does have `signal`, `node_modules/@earendil-works/pi-coding-agent/dist/core/extensions/types.d.ts:236`).
   So `ctx.signal` is `undefined` on omp, only pi-verdict's own deadline (default 60 000 ms) can close the dialog, and
   it fires long after omp already blocked the call. The `subagent-cancelled` path (`index.ts:1036-1039`, documented as
   "Cancelling a subagent run closes its pending root dialog") cannot trigger on omp 18.12.6 for the same reason; not
   tested live.
5. The documented requirement, `toolCallTimeoutMs >= subagentAskTimeoutMs + 60000` (`docs/configuration.md`,
   `USER_CONFIG_TEMPLATE` hint in `config.ts:187`), is not met on the user's install, and nothing detects it.

Consequences seen by the user: the subagent is blocked about 30 s after the ask with a message that names an extension
timeout rather than a pending ask; the dialog can only be answered into a dead call; retries by the subagent stack more
stale dialogs behind it (serialized by `serializeDialog`, `subagent.ts:29`); the audit then reads `human` or `timeout`.

## Fix proposal (not implemented)

1. Immediate, no code: set `extensionHandlers.toolCallTimeoutMs: 120000` (>= `subagentAskTimeoutMs + 60000`) in the omp
   `config.yml` that the agent-setup repository deploys. Verified by run v4 (45 s answer works, no timeout).
2. Code, minimal: bound the dialog by the host's budget so it never outlives the call. In `index.ts:1029-1031` replace
   the deadline with `min(subagentAskTimeoutMs, hostHandlerBudgetMs - elapsedSinceHandlerStart - margin)`, with
   `hostHandlerBudgetMs` a new user-only config key defaulting to 30 000 (mirrors omp's default; documented next to
   `subagentAskTimeoutMs`), and show the remaining seconds in the dialog text. A dialog that closes itself with a root
   notice ("subagent ask expired: raise extensionHandlers.toolCallTimeoutMs") replaces the stale-dialog trap. Optional
   follow-up in the same change: warn once at the first subagent ask when `subagentAskTimeoutMs + 60000 >
   hostHandlerBudgetMs`.
3. Upstream (oh-my-pi): subagent `tool_call` handlers need either a `ctx.signal` or a delegating `ctx.ui` that routes to the
   root UI and pauses the handler budget; a dialog opened by a handler should be aborted by the handler's own signal.

Test plan: (a) unit test with an injected fake `rootUi` whose `custom` never settles and a short host budget: the deadline
must abort the dialog, `confirmAsk` must return `"aborted"` before the budget, and the audit resolution must be
`timeout`; (b) live: the same tmux harness with the default `config.yml`, answering at +45 s: after the fix no stale dialog
remains after the block and the root shows the expiry notice; with `toolCallTimeoutMs: 200000` the +45 s answer still
works (v4 baseline).
