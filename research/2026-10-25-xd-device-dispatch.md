# Which omp `xd://` devices dispatch a gated tool call

Read date: 2026-10-25. Read-only research behind the rule allow for `xd://` device reads and writes, recorded in the [ADR-0009](../docs/adr/0009-tool-access-adapter.md) amendment of the same date. This is a dated record of omp 18.12.6.

## Sources and pins

- omp installed: `omp/18.12.6`. The source clone `.scratch/research/oh-my-pi` declares `18.12.6` in `packages/coding-agent/package.json`, the tag `v18.12.6` recorded in [2026-10-24-host-code-loading-paths.md](2026-10-24-host-code-loading-paths.md). Versions match.
- Citation prefixes. `CA` = `.scratch/research/oh-my-pi/packages/coding-agent/src`. `TUI` = `.scratch/research/oh-my-pi/packages/tui/src`.
- Nothing was executed against the host. "Inferred" marks a statement derived from reading code paths.

## Summary

Every `read xd://...` returns text the host generates about tools: the device listing, one tool's documentation and parameter schema, a one-line usage string, or a named documentation topic. No device read returns stored data; memory, recall and archive content is reached by running the tool, which is a write.

A `write xd://<name>` either dispatches the session tool `<name>` or, for four built-in names, runs host code directly. A dispatched tool runs through its own `ExtensionToolWrapper`, which emits a separate `tool_call` event that the gate adjudicates on its own. The four built-in devices (`resolve`, `reject`, `propose`, `report_issue`) emit no nested event, so the outer `write` is the only call the gate sees.

The host never opens a filesystem path for an `xd://` URL. The scheme is device-backed, so the router has no file to locate, and a write goes to the handler.

## Device classification

| URL shape | `read` returns | `write` does | Nested `tool_call` on write |
| --- | --- | --- | --- |
| `xd://` (the root) | Listing of mounted devices with one-line summaries | Throws "Cannot write to xd:// itself" | No (error) |
| `xd://<tool>`, any session tool | Documentation and JSON schema of the tool | Runs the tool with the JSON content as its arguments; `?`, `help` or empty content returns the documentation instead | Yes |
| `xd://<tool>/<topic>` | One named documentation topic of the tool | Throws "Invalid xd:// URL" | No (error) |
| `xd://resolve`, `xd://reject` | One-line usage string | Applies or discards a staged preview by calling its stored `apply` or `reject` function | No |
| `xd://propose` | One-line usage string | Submits the plan-mode proposal to its handler | No |
| `xd://report_issue` | One-line usage string | Records a tool complaint in the local issue store when autoqa is on | No |

## Evidence

### The scheme is device-backed and never a file

- `XdProtocolHandler.spec` declares `backing: "device"`, `immutable: true` and `write: { via: "handler", scope: "device" }` (`CA/internal-urls/xd-protocol.ts:57-64`).
- The router locates a file only for `spec.backing === "file"` (`CA/internal-urls/router.ts:296`); everything else is a resource served by the handler. `router.write` calls `handler.write` (`CA/internal-urls/router.ts:494-501`).
- The `write` tool sends a handler-backed target to `router.write` and returns its result, never reaching the filesystem pipeline (`CA/tools/write.ts:807-809`, `CA/tools/write.ts:865-893`).
- A device name is the text after `xd://`, compared case-sensitively against the tool map. The prefix test is case-insensitive, and a name holding `/`, `?` or `#` is rejected (`TUI/tools/xd-url.ts:13-20`). A topic URL is exactly `xd://<name>/<topic>` (`TUI/tools/xd-url.ts:26-29`).

### What a read returns

- `resolve` serves a topic URL from `#topic` and every other URL from `#usage`, as `text/plain` (`CA/internal-urls/xd-protocol.ts:66-76`).
- `#usage` returns the report-issue usage, the resolution-device usage, the listing for the root, or `xdevDocs` for a named tool (`CA/internal-urls/xd-protocol.ts:118-124`).
- `xdevListing` renders one line per mounted device from its summary (`CA/tools/xdev.ts:309-317`). `xdevDocs` renders the tool's name, label, description and schema (`CA/tools/xdev.ts:113-130`, `CA/tools/xdev.ts:320-322`).
- The resolution and report-issue usages are fixed one-line strings (`CA/tools/resolve.ts:53-62`, `CA/tools/report-tool-issue.ts:51-53`).
- `#topic` returns an entry of the tool's `docTopics()` map (`CA/internal-urls/xd-protocol.ts:127-135`), documented as on-demand documentation topics. The only built-in tool with topics is `eval` (`CA/tools/eval.ts:322-327`).

### What a write does

- `XdProtocolHandler.write` takes `report_issue` first, then the resolution devices, then dispatches every other name through `dispatchXdevTool` (`CA/internal-urls/xd-protocol.ts:78-115`).
- The resolution device names are `resolve`, `reject` and `propose` (`TUI/tools/resolve.ts:21-27`, `TUI/tools/resolve.ts:199-201`); the report device is `report_issue` (`TUI/tools/report-tool-issue.ts:17`).
- `dispatchResolutionDevice` calls the plan-proposal handler for `propose`, and otherwise the pending preview invoker (`CA/tools/resolve.ts:278-323`). The invoker calls the `apply` or `reject` function the staging tool registered (`CA/tools/resolve.ts:147-184`). `ast_edit` and custom tools register them (`CA/tools/ast-edit.ts:440`, `CA/sdk.ts:2729`). No tool wrapper runs, so no `tool_call` is emitted (inferred from the call chain).
- `dispatchReportIssueDevice` records the report and returns "Noted, thanks!" (`CA/tools/report-tool-issue.ts:660-677`).
- `dispatchXdevTool` resolves the name in the session tool map, returns the documentation for help content, validates the JSON arguments, and calls `executable.execute` on the resolved tool (`CA/tools/xdev.ts:433-484`, `CA/tools/xdev.ts:446`, `CA/tools/xdev.ts:475-484`). `resolveXdevTool` accepts mounted names and active top-level tools (`CA/tools/xdev.ts:256-259`).

### Why the dispatched tool emits its own `tool_call`

- The xd state reads the session's canonical tool map (`CA/tools/index.ts:862-865`, `CA/tools/index.ts:910`), and the session refuses an xd state over any other map (`CA/session/session-tools.ts:495-497`).
- The SDK replaces every entry of that map with an `ExtensionToolWrapper` (`CA/sdk.ts:3625-3630`); later additions are wrapped as they are set (for example `CA/sdk.ts:3666`, `CA/sdk.ts:3708`, `CA/sdk.ts:3789`).
- `ExtensionToolWrapper.execute` emits `tool_call` unless the loop already emitted one for the same tool call id and tool name (`CA/extensibility/extensions/wrapper.ts:233-312`, the comment at `:241-246` names nested xd device dispatches). The loop marks only the outer tool, keyed `id:name` (`CA/session/agent-session.ts:5335`, `CA/extensibility/extensions/runner.ts:617-628`), so the inner tool's event fires. A `block` result throws before the tool runs (`CA/extensibility/extensions/wrapper.ts:309-312`).
- The `ToolCallEventResult` documentation states the same for nested `write xd://` device calls (`CA/extensibility/shared-events.ts:344-349`).
- The `xdevApproved` flag that the outer write passes down (`CA/internal-urls/xd-protocol.ts:104-107`) skips only omp's own approval prompt, after the `tool_call` event (`CA/extensibility/extensions/wrapper.ts:360`).
- The user's audit log shows the pattern: every `write xd://mcp__lazy_skills_server_load_skill` is followed within about 0.4 seconds by a separately adjudicated `mcp__lazy_skills_server_load_skill` call.

## Consequences for the gate

- A `read` of any `xd://` URL can be a rule allow: its result is documentation the host generates.
- A `write` to `xd://<name>` can be a rule allow when `<name>` is not one of the four built-in devices, because the tool it runs is adjudicated as its own call. The root, a topic URL and a malformed name fail in the host and stay with the classifier.
- The name the handler sees is the WHATWG-parsed href (`CA/internal-urls/parse.ts:59`, `CA/internal-urls/xd-protocol.ts:79`), not the raw text. Parsing drops empty credentials and an empty port and strips tab, LF, CR and edge C0 controls, so `xd://:@resolve` or `xd://res\tolve` reaches `resolve`. Only a name made of letters, digits, `_` and `-` survives parsing unchanged, so only such a name can be a rule allow (added after review, 2026-10-25).
- `resolve`, `reject`, `propose` and `report_issue` stay with the classifier. Applying a staged preview runs code that the staging tool chose earlier, and the gate sees no other call for it.
- The deny-side layers still read the URL text. They match it only as a path under the session directory, because the host never resolves it to a file.

## Residuals

- The nested event depends on omp wrapping every tool in the canonical map. A host change that dispatched an unwrapped tool would make the outer allow unguarded; re-check `CA/sdk.ts` and `CA/tools/xdev.ts` on each host upgrade.
- On pi, which registers no `xd` scheme, the URL text is an ordinary relative path (`xd:/<name>` under the session directory). The device allow therefore applies only when the host is omp; on pi the text takes the floor's path grades, S0 included.
