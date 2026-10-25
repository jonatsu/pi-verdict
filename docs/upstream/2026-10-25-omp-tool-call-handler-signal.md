# Draft: omp `tool_call` handlers need the handler signal

Status: draft, not posted. Target: a comment on [can1357/oh-my-pi#15365](https://github.com/can1357/oh-my-pi/issues/15365)
("Expose invocation-scoped context purpose and cancellation to extensions", open). Read against omp v18.12.6 and
upstream `main` at `0b5c27ab24` (2026-10-22); the cited code is the same in both.

## Why a comment, not a new issue

Issue #15365 already asks for the handler's cancellation signal, and its triage leaves the shape open: a `signal` on
`ContextEvent` alone, or a generic per-handler `ctx.signal` on every event (open question 2, with #14935 adding a
per-event signal to `before_subagent_spawn`). pi-verdict's case is a `tool_call` handler, so it is evidence for the
generic `ctx.signal`. A separate issue would split the same decision across two threads.

Evidence for the case: `research/2026-10-24-subagent-ask-timeout.md` (live repro, omp 18.12.6).

## Comment text

> A data point for open question 2, from a `tool_call` handler rather than `context`: it argues for the generic
> per-handler `ctx.signal`.
>
> [pi-verdict](https://github.com/jonatsu/pi-verdict) is a permission gate. When a subagent's tool call needs a human
> decision, its `tool_call` handler opens the dialog on the root session's UI, because the subagent's own `ctx.ui` has
> no UI (`hasUI` is false). `emitToolCall` bounds the handler with `extensionHandlers.toolCallTimeoutMs` (default
> 30 s), and `createHandlerUIContext` pauses that budget only for dialogs opened through the handler's own `ctx.ui`
> (`runner.ts:195-262`). So 30 s after the ask, the runner blocks the call with `Extension <path> timed out after
> 30000ms`, and `handlerSignal` aborts. The dialog on the root UI cannot see that signal, because `createHandlerContext`
> (`runner.ts:274-286`) threads it only into `ctx.ui`. The dialog stays open, and the user answers a call that is
> already blocked. Retries by the subagent stack more such dialogs behind it.
>
> pi's `ExtensionContext` already has `signal: AbortSignal | undefined`, and pi-verdict passes `ctx.signal` to the
> dialog. On omp, `ctx.signal` is `undefined`, so that path never fires. As a workaround, pi-verdict reads
> `extensionHandlers.toolCallTimeoutMs` itself and closes the dialog a few seconds before the budget ends. That
> mirrors the runner's private timer and has no way to see the other abort source, the invoking operation's `signal`
> (for example a cancelled subagent run).
>
> Smallest change that fixes it: expose the same `handlerSignal` on the scoped context in `createHandlerContext`, for
> example `Object.defineProperty(scoped, "signal", { value: handlerSignal, enumerable: true, configurable: true })`.
> That gives "aborts when the invoking operation ends or the handler timeout fires" on every event, matches pi's
> field name, and needs no per-event field.
>
> A related, separate question: a handler that legitimately waits on another session's UI has no way to pause its own
> budget. A `ctx.ui` for a subagent handler that routes dialogs to the root UI, through the same `runDialog` pause,
> would remove the need for the root-UI capture entirely. I'm not asking for that here; `ctx.signal` alone fixes the
> stale dialog.

## After posting

Record the comment's URL in `TODO.md` item 2 and close that item. When omp ships the field, pi-verdict can drop
`readHostHandlerBudget` in favour of `ctx.signal` (`docs/host-contract.md`).
