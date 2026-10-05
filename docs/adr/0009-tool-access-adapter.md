# 0009 - One model of what a tool call touches: the tool-access adapter

---
status: accepted
date: 2026-10-05
---

## Background

Every file-tool consumer — user rules, `denyPaths`, the built-in floor, self-protection — read a
single `input.path` field. omp's own multi-header `edit` breaks that assumption:
`normalizeToolEventInput` (`extensibility/tool-event-input.ts`, verified against the installed omp
18.6.1 source) derives `path`/`paths` from the patch text's hashline headers, but only for **zero
or one** header — a patch touching two or more files gets `{input, paths}` with **no `path`**.
`classifyPath(String(input.path ?? ""), cwd, true, floorOn)` then reads the empty string, resolves
it to the session cwd, and the in-project write allowance fires: `allow/rule`, zero model calls,
for a patch that may also write `~/.bashrc`, `.git/hooks/`, or any `denyPaths` entry. The same gap
applies to the apply-patch edit mode (`*** Update File:`/`*** Move to:` lines inside one `input`
string, never derived into `path`/`paths` by omp at all — `extractHashlinePaths` only recognizes
hashline headers), to `patch`-mode `edits[].rename`, to `ast_edit`'s `paths: string[]`, and to any
host or future tool whose shape the gate has never modeled.

## Decision

> **One pure, host-agnostic function — `toolAccess(toolName, input): ToolAccess` — models every
> target a tool call reads or writes. Every file-tool consumer reads from it instead of
> `input.path` alone.**

```ts
interface ToolAccess {
	direction: "observing" | "mutating" | "unknown";
	kind: "command" | "file" | "code" | null;
	reads: string[];
	writes: string[];
	command: string | null;
	opaque: boolean;
	scope: boolean;
}
```

- **`direction`** is name-keyed, not payload-keyed: `observing` for `read`, `grep`, `find`, `ls`,
  `glob`, `ast_grep`; `mutating` for `write`, `edit`, `ast_edit`; `unknown` for everything else
  (bash/powershell included — their grading stays on the separate command channel, unchanged).
  `unknown` is never opaque and never mutating-by-shape: whatever targets its payload yields still
  go through the deny-side layers below; otherwise it stays gray, exactly as before this ADR.
- **`kind`** is shape-keyed: a known observing/mutating tool is always `"file"`; an unknown tool
  infers `"code"` from a `code` field or `"command"` from a `command` field (e.g. `debug`'s DAP
  request) — `command` carries that field's text either way. A shape-inferred `"command"` never
  enters `classifyBash`: every consumer of `kind`/`command` stays scoped to the known command tool
  names (`bash`, `powershell`).
- **Shape-keyed extraction**, applied regardless of `direction`: a singular `path`/`_path` field; a
  plural `paths: string[]` field; a hashline-wrapped `path` value (`[path#TAG]`) unwrapped first; an
  observing tool's path additionally split on `;`, `,` and whitespace, keeping both the whole string
  and every part (omp's `read` opens each part of such a list separately while the gate graded only
  the whole string as one path). When a string field `input`/`_input` is present, it is **always**
  parsed as patch text, whatever `path`/`paths` also say — recognizing hashline file headers
  (`[PATH]`/`[PATH#TAG]`, legacy `¶PATH`; a trailing `#`+4-hex tag and one layer of matching quotes
  are stripped), `MV DEST` op lines, and the apply-patch lines `*** Add File:`, `*** Update File:`,
  `*** Delete File:` and `*** Move to:` (the move destination is a write and the source stays a
  target — the move deletes it there). `patch`-mode `edits[].rename` values are targets too.
- **Opaque rule**, narrowed by a 2026-10-05 re-review of the first draft: `opaque` fires only for a
  **known mutating name** (`write`, `edit`, `ast_edit`) whose extraction yields no target at all —
  deterministic ask (headless → deny). When patch text is present, opaqueness is **grammar-driven**:
  only what the hashline/apply-patch grammar itself recognizes counts, so a host-derived or
  model-supplied `path`/`paths` value is added to the target set for grading but never by itself
  makes the call non-opaque — a payload in an unrecognized grammar ("sloppy") stays opaque even if
  `paths` names something. The original draft made any `unknown`-direction tool opaque whenever its
  payload carried a `content`/`input` field; that caught omp's own `retain {content}` tool (no
  `path`, listed in no starter config) and any third-party content-bearing tool. The opaque ask
  exists to catch a file write whose target can't be found — an unknown tool that names no file is
  not that case, so the narrower rule drops both the false positive and the MCP/`task` name-prefix
  carve-out the first draft needed to avoid it.
- **`scope`** (`grep`, `find`, `ls`, `glob`, `ast_grep`, `ast_edit`): the tool's `path`/`paths`
  accept a directory or glob and the search covers a subtree. It drives the **bidirectional**
  `denyPaths`/`gateOmpDir` compare (a declared base sitting *inside* the searched subtree hits, not
  only a target sitting inside a declared base) and the pathless default: an omitted path on an
  **observing** call (scope or not — `read` included) resolves to the cwd; on a **mutating** scope
  tool (`ast_edit`) it does not — the call is opaque instead. A pathless `read`/scope call keeps the
  grading it always had; a pathless `write`/`edit`/`ast_edit` deliberately changes **silent in-cwd
  allow → deterministic ask**.
- **Consumer migration.** `userRuleTargets` (feeds user `deny` *and* `allow`) stays scoped to known
  observing/mutating tools: an unlisted tool's shape-inferred fields never reach user rules, so a
  `deny`/`allow` regex can never key on an MCP tool's payload by coincidence. `denyPathCandidates`
  (feeds the `denyPaths`/`gateOmpDir` ask only) returns every target regardless of direction — an
  unknown tool's extracted targets now reach this ask, where today nothing grades them at all.
  `classifyWrites`/`classifyReads` grade every target through the existing S0–S3 tiers (deny on the
  first tier hit; the in-cwd write allowance fires only when every target sits in-cwd); a
  single-target call behaves bit-for-bit as before, since both functions are thin wrappers around
  the unchanged `classifyPath`. Self-protection (layer 0) additionally tests every adapter
  `reads`/`writes` target and, for `kind: "code"`, runs the command-direction substring signatures
  over the code text — an apply-patch `*** Update File: <agentDir>/config/pi-verdict.json` or an
  `eval` cell shelling out to touch the gate's own files no longer bypasses layer 0.
- **Exemption ordering**, stated once: the `tools` exact-name allowlist is checked **after** every
  deny-side layer (the floor, user `deny`, the `.omp` gate, `denyPaths`, user `allow`) and **before**
  the opaque ask and the classifier fall-through. A listed tool carrying a protected-path target now
  faces the ask instead of a silent allow.

## Field evidence (design-time only — constraint: nothing at runtime depends on it)

Verified 2026-10-05 against the installed omp 18.6.1 source
(`@oh-my-pi/pi-coding-agent/src/extensibility/tool-event-input.ts`,
`@oh-my-pi/pi-coding-agent/src/edit/hashline-compact.md`,
`@oh-my-pi/pi-coding-agent/dist/types/edit/schemas.d.ts`,
`@oh-my-pi/pi-coding-agent/dist/types/edit/plan-mode-guard.d.ts`) and the omp 18.5.1 line citations
the original plan recorded; the two versions agree on every cited fact:

- `edit` ships **five** modes (`EDIT_MODES`): `replace` (`{path, old_string, new_string,
  replace_all?}`), `patch` (`{path, edits: [{op?, diff?, rename?}]}`), `apply_patch` (`{input}`),
  `hashline` (`{input}`), `sloppy` (`{input}`) — `sloppy` is a named mode, not merely "whatever the
  gate failed to parse".
- `normalizeToolEventInput` only touches `edit`, and only when `path` is **already absent**: zero
  recognized hashline headers in `input`/`_input` → the object is returned unchanged (no `path`, no
  `paths` — this is also why omp itself never derives a target for `apply_patch`/`sloppy` text, and
  why the adapter's own grammar has to); exactly one header → `{..., path, paths}`; two or more →
  `{..., paths}` with **no `path`** — the defect this ADR closes. `_path` is promoted to `path` only
  when neither `input` nor `_input` is a string at all (the `replace`/`patch` fallback path).
  `normalizeHashlineHeaderPath` strips a trailing `#`+4-hex tag (`/#[0-9a-fA-F]{4}$/`) then one layer
  of matching `"`/`'` quotes. `extractHashlinePaths` strips a leading BOM once for the whole input,
  trims a trailing `\r` per line, and requires the bracket form to start the raw line exactly (no
  leading trim) while the legacy `¶` form tolerates leading whitespace.
- Apply-patch line literals, from `edit/index.ts`'s own tool example: `*** Begin Patch` / `*** Add
  File: <path>` / `*** Update File: <path>` / `*** Move to: <path>` (inside an `Update File` block)
  / `*** Delete File: <path>` / `*** End Patch`.
- `hashline-compact.md`: `MV DEST` "moves/renames after prior section edits"; `REM` deletes the file
  (no target — nothing to add).
- `write = {path, content?}` (content optional), `read = {path}` — neither has a derived field.
  `write` may carry a hashline-wrapped `path` (`plan-mode-guard.ts`'s `unwrapHashlineHeaderPath`:
  strictly `[path]` or `[path#XXXX]`, a 4-hex tag — the same shape `extractHashlinePaths` parses).
- `eval = {language: 'py' | 'js', code, title?, timeout?, reset?}`; `ast_edit = {ops: [{pat, out}],
  paths: string[]}`; omp `glob = {path?, hidden?, gitignore?, limit?}` — the pattern *is* `path`.
- pi 0.84.3's `edit` is single-file `{path, edits: [{oldText, newText}]}` — the multi-file
  silent-allow risk is observed on omp today, but the adapter's contract closes it on every host,
  including hosts that do not exist yet.

## Alternatives considered

- **Per-tool special-casing instead of one adapter.** Rejected: the defect recurs for every new
  path-bearing field a host adds (`ast_edit`, `glob`, a future tool); one shape-keyed function is the
  single place grammar drift gets caught, by the probe cases, not by N copies of the same logic.
- **Trust the host's own derived `path`/`paths` fields.** Rejected: omp's own derivation is
  incomplete (the defect this ADR exists to close) and the gate must not depend on a specific host's
  behavior (universal-plugin constraint 2) — the adapter parses the raw patch text itself.
- **Opaque-by-shape for any `unknown`-direction tool with a `content`/`input` field.** Rejected (see
  "Opaque rule" above): caught tools with no file-write semantics at all.

## Consequences

- **BREAKING**: a listed `tools`-exempt tool carrying a protected-path target now faces the
  deterministic ask instead of a silent allow (exemption ordering).
- **BREAKING**: an unknown tool's extracted targets now reach the `denyPaths`/`gateOmpDir` ask, where
  today nothing grades them.
- **BREAKING**: a pathless `write`/`edit`/`ast_edit` call changes from a silent in-cwd allow to a
  deterministic opaque ask.
- Multi-target writes/reads are graded as a set: the ask dialog's `detail` and the classifier
  transcript's action line both name every target once there is more than one, instead of showing
  only the first or falling back to raw JSON.
- `userRuleTargets` keeps its known-tool-only scope (pinned by a regression test): an MCP tool's
  payload can never accidentally satisfy a user `allow` regex.
- Pinned by the `tool-access` probe family (multi-header `edit`, apply-patch multi-file, a `paths`
  spoof against unparseable patch text, patch-mode `rename`, the observing list-split, `ast_edit`
  scope precedence) and the `tool-access adapter` test suite.
