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
  carve-out the first draft needed to avoid it. *Amendment:* an opaque call skips the user `allow`
  loop and the `tools` exemption as well, because its model-supplied `path`/`paths` do not name the
  target the call really writes; a user allow regex that matched them used to admit the call.
- **`scope`** (`grep`, `find`, `ls`, `glob`, `ast_grep`, `ast_edit`): the tool's `path`/`paths`
  accept a directory or glob and the search covers a subtree. It drives the **bidirectional**
  `denyPaths`/`gateOmpDir` compare (a declared base sitting *inside* the searched subtree hits, not
  only a target sitting inside a declared base) and the pathless default: an omitted path on an
  **observing** call (scope or not — `read` included) resolves to the cwd; on a **mutating** scope
  tool (`ast_edit`) it does not — the call is opaque instead. A pathless `read`/scope call keeps the
  grading it always had; a pathless `write`/`edit`/`ast_edit` deliberately changes **silent in-cwd
  allow → deterministic ask**.
- **Glob paths** (amendment): a `grep`, `find`, `glob`, `ast_grep` or `ast_edit` target is graded
  twice, as spelled and by its literal prefix, the part before the first path segment containing
  `*`, `?`, `[` or `{` (a leading glob segment grades as the cwd). The worst grade wins in the floor
  (S0 and `.git` patterns), in `gateOmpDir` and in `denyPaths`, so `**/*.pem` still hits the S0
  extension rule through its spelling and `~/.ssh/*.pub` hits it through its prefix. The prefix gets
  no subtree rule of its own except in `denyPaths`, whose scope compare is already bidirectional.
  Because neither grade can say what the glob matches, a call with such a
  target never receives a rule allow: the floor's allow becomes gray, and the user `allow` loop and
  the `tools` exemption are skipped. Before the amendment, a wildcard spelling such as
  `~/.config/g?/hosts.yml` matched neither the S0 regexes nor a `denyPaths` base and was allowed
  with no model call.
- **Search over a credential directory's parent** (amendment): a scope tool whose target strictly
  contains a home-anchored S0 directory (`~/.config` over `~/.config/gh`, or `~` itself) is graded
  gray, not allow, because the search walks into it. A plain `read` of a directory is unchanged.
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

## Phase 3 amendment: kind `code` grading rules (item 4)

`kind: "code"` (an `eval` cell) was declared by this ADR's type but left entirely ungraded: it
reached `classifyByRules`' final `else` (gray, `tool not covered by built-in rules`), skipping the
built-in floor, and `userRuleTargets` already returned `[]` for it (R2-2, unknown direction) —
which also meant the starter template's `allow: ["^ls\b"]` matched nothing, but only by the same
accident that excluded it from `deny`, `denyPaths` and `gateOmpDir` too. A Python cell can shell
out (`!cmd`, `%%bash`), so a code call is not inert the way an unrecognised MCP tool's opaque
payload is.

**Decision:** `kind: "code"` gets its own grading, asymmetric by design — never through the user
`allow` loop or the `tools` exact-name exemption, always through everything that can stop it
before the classifier:

- User `deny` tests the whole code text (`denyTargets = [...targets, access.command]`), alongside
  the unaffected `targets`-based check (`targets` stays `[]` for an unknown-direction tool, so this
  is purely additive).
- `denyPathCandidates` and `hitOmpDir` extract from the code text the same way they extract from a
  bash command: `bashPathTokens` for path mentions, `OMP_DIR_IN_COMMAND` for a bare `.omp` word
  with no path separator around it (`dest = ".omp"`).
- User `allow` is **never** reached: `targets` stays `[]`, so a code call always falls through to
  the classifier unless something above denies or asks first — the starter `^ls\b` cannot admit a
  Python cell that happens to assign a variable named `ls` (F4).
- The `tools` exact-name exemption now excludes `kind: "code"` explicitly
  (`access.kind !== "code"`): its documented scope was always "the tool has no shape worth
  grading," which a `code` field contradicts. **BREAKING**: a user who listed `eval` in `tools`
  loses that exemption — every call now reaches the classifier (or an earlier deny/ask) instead of
  bypassing it.
- `BASH_DANGER_RULES`, the tripwire (ADR-0007) and `allowAdmits` (ADR-0008) never run over the
  whole code text — a Python cell is not a shell command line, and most of its text is ordinary
  code those patterns were never meant to read.
- **The bash floor does apply, narrowly**: `pyEvalShellLines` extracts a Python eval cell's
  shell-executing lines — a `!cmd`/`name = !cmd` line, and a `%%bash` cell magic's body (every line
  from the next one to the end of the cell) — and only those lines reach `classifyBash` (F13).
  Verified 2026-10-05 against the **upstream `oh-my-pi` repository at tag `v18.6.1`** (cloned to
  `.scratch/research/oh-my-pi`, matching the installed `@oh-my-pi/pi-coding-agent@18.6.1` exactly):
  `coding-agent/src/eval/py/runner.py`'s `transform_cell` docstring and its `_LINE_MAGICS`/
  `_CELL_MAGICS` registries. This **corrects** the original plan draft's `!`/`%sh`/`%%bash`/`%%sh`
  citation — `_LINE_MAGICS` has no `"sh"` entry (the line magics are `pip`, `cd`, `pwd`, `ls`,
  `env`, `set_env`, `time`, `timeit`, `who`, `whos`, `reset`, `load`, `run`; none of them shells
  out) and `_CELL_MAGICS` registers only `"bash"` as shell-executing — `capture`/`timeit`/
  `writefile` pass their body to `_exec_source` → `ast.parse` directly, with no re-transform, so
  none of them can nest a `!`-line or a `%%bash` block. `pyEvalShellLines` is a plain line scan,
  not Python's own string/comment-aware tokenizer (`_magic_line_indices`): a `!`/`%%bash` spelling
  inside a string literal or comment is a false positive here, the accepted safe direction (ADR-0001
  caveat; ADR-0007 precedent — a raw-text tripwire decides every hit, never a sandbox proof).
  Backslash line-continuation folding is not reproduced; a continued `!`-line is read as separate
  lines instead, which only widens what counts as a candidate. The extraction also covers a third
  form — a **direct shell-API line** (`__omp_shell(`,
  `subprocess.Popen/run/call/check_call/check_output(`, `os.system(`), pushed whole: omp injects
  `__omp_shell` into the cell namespace (`runner.py:1777`), so a model can shell out without a
  `!` line, and the danger rules are regexes over text so the whole line is enough.
  **Recorded residual:** js cells get no equivalent extraction — `language: "js"` code
  reaches no built-in floor at all; their code text still feeds user `deny`, `denyPaths`
  tokenization and the `.omp` word check, and the classifier remains the backstop.

Pinned by the `eval semantics` test describe (user deny on code text, the F4 starter-allow
non-admission, the F13 `!`/`%%bash` floor hits with a js-language negative control, denyPaths/
`.omp` extraction from code text, and the `tools`-exemption loss), by the direct shell-API floor
hit (`os.system(` — pinned alongside the action-cap and layer-0 group) and by `session_start`'s
coverage-report tests.

## Phase 3 amendment: session_start coverage report and side-effecting tools warning (item 4)

Two schema-driven, one-time `session_start` diagnostics, neither of which affects adjudication:

- **Tool coverage report** (Claude-review F15: the adapter is payload-keyed and `session_start` has
  no payload to run it on, so this inspects each active tool's declared schema instead, via
  `getActiveTools()`/`getAllTools()` — present on both hosts per the plan's citations, guarded at
  runtime by a `typeof` capability check since this ADR's own universal-plugin constraint 2
  forbids depending on a specific host/version). Tools already covered — a known observing/
  mutating/command name, or a name in the user's `tools` allowlist — are skipped; everything else
  is checked for `COVERAGE_SIGNAL_FIELDS` (`path`, `paths`, `input`, `_input`, `code`, `command`,
  `content` — kept in lockstep with the adapter's own field names, Claude-review R2-14) in its
  declared schema. A schema with none of them stays gray/classifier-only forever (`noFields`); one
  with a matching field name under an unexpected JSON-Schema `type` is a field the adapter's
  string/string-array readers silently treat as absent today (`untyped`). Delivered as a single
  `"info"` notification, **gated behind `--auto-mode-debug`/`PI_AUTO_MODE_DEBUG`** — the plan's
  "debug-channel note, not noise" is read literally as the file's one existing low-level diagnostic
  channel, not as an unconditional once-per-session notice: an unchanging tool roster would
  otherwise repeat the same report every session for a user who never acts on it.
- **Side-effecting tools warning**: `tools` naming a persistent-memory tool (`learn`, `memory_edit`,
  `retain` — the explicit set the starter template's own comment already excludes them for) fires
  one unconditional `"warning"` notification — these calls bypass the classifier entirely, and the
  consumer's choice to list them stays theirs; the gate only stops being silent about it.

Pinned by the `session_start coverage report and side-effecting tools warning` test describe,
including the debug-off and capability-absent silent branches.

## Host path spelling amendment: raw and expanded forms

The adapter yields the paths a call names as the model wrote them, but omp rewrites a path argument
before it opens the file. A spelling that omp resolves to a credential or system file therefore
graded as a harmless in-project path and was a rule allow with no model call and no human: `read`
of `@~/.config/age/keys.txt`, `read` of a `file://` URL naming an XDG credential file, `write` of
`@/etc/cron.d/x`.

**Decision:** one pure function, `hostPathForms`, derives every spelling of a target that the gate
must grade, and every layer that reads a file or scope target reads those forms (`gradedReads` and
`gradedWrites` on `ToolAccess`). `expandHostPath` mirrors omp's `expandPath` (18.6.1): a stray
leading `:` before a path shape, the `@` shorthand only before `/`, `~`, `~/`, a Windows absolute
path or a registered internal scheme (so `@my-file.txt` stays literal), unicode spaces turned into
spaces, a `file://` URL turned into its path with percent escapes decoded, a Windows extended-length
prefix removed, and the tilde expanded (`~name` is `$HOME/name`). Verified against the omp 18.6.1
source (`tools/path-utils.ts`).

The grading rule is the same everywhere: a target is graded in its raw form and in each expanded
form, and the worst grade wins. That covers the built-in floor (S0-S5), `denyPaths`, `gateOmpDir`,
self-protection and the transcript redactor. A user `deny` regex matches when any form matches; a
user `allow` regex admits the call only when every form is admitted, so an allow for the project
cannot carry a spelling that expands outside it. Under WSL (`WSL_DISTRO_NAME` or `WSL_INTEROP` set, as the host checks) a Windows drive path also
contributes its mount form, because the host opens `C:\x` as `/mnt/c/x` (`normalizeWindowsDriveAliasPath`,
18.6.1). The forms exist for grading only: dialog details,
transcript action lines and the action cap still show and count the targets as the model wrote them.
A target longer than the action budget gets no derived forms, because it is asked about before any
allow.

*Selector suffixes.* The host's `read` and `grep` split a trailing selector (`:N-M`, `:-N`, `:raw`,
`:conflicts`, `:img`, or one range plus `:raw`) from the path and open the rest, so both tools'
targets also contribute the peeled form, for the raw and the expanded spelling alike (`.env:raw` is
`.env`). The peel mirrors omp's `splitPathAndSel` (18.6.1). It is not applied to `ast_grep`, `glob`,
`find`, `ls` or the mutating tools, which the host does not peel; a tool the gate does not model gets
the peeled form too, because an extra form only widens what is graded.

*Delimited entries.* The host splits every `read`, `grep`, `glob`, `ast_grep` and `ast_edit` path
entry at top-level `;`, `,` and whitespace (`expandDelimitedPathEntries`, 18.6.1; a brace group and a
backslash-escaped character are not separators), so each such tool's targets contribute the parts of
every entry, in `path` and in each `paths` element, mutating `ast_edit` included. The host tries `;`,
then `,`, then whitespace, then all three, and keeps a split only when its parts resolve; the gate
cannot see the filesystem the host sees, so it grades the parts of every split. This replaces the
observing tools' earlier split of the single `path` field, which left `paths` entries and `ast_edit`
whole. `write` and `edit` open one file and are not split. A part is graded like any other form: the
worst grade wins, and a user `allow` regex has to admit it.

*Missing relative `read` targets.* When a relative path does not exist, omp's `read` looks for a unique
workspace file whose path ends with the same text and reads that (`findUniqueWorkspaceSuffix`, 18.6.1),
so the spelling of a missing path says nothing about the file opened. A `read` with such a target, or
a list with one such part, grades gray. Only the path the host would choose counts (`hostReadPath`:
image question cut, then the selector cut unless the whole text names an existing file, then
expansion), and a list is examined part by part only when the whole entry is missing, so
`src/a.ts:1-5,40-60` and `docs/My Notes.md` keep their allow when the file exists. The gray grade withholds the floor's allow, and neither a user `allow` rule nor a `tools` entry admits the call, so the classifier decides (headless: fail-closed deny). A target
that exists, an absolute path and a directory are unchanged, and so is a session whose project
directory does not exist, because there is nothing to relocate to. This is a **BREAKING** narrowing of
the rule allow for reads: a typo in a relative path now costs a classifier call.

*Registered schemes only.* The search tools' backslash-to-slash conversion is skipped for a URL of a
scheme that omp's InternalUrlRouter registers (`skill`, `rule`, `memory`, `agent`, `history`,
`artifact`, `local`, `proc`, `cfg`, `ssh`, `security`, `vault`, `issue`, `pr`, `mcp`, `omp`, `xd`,
`attachment`, `conflict`; 18.6.1) and applied to everything else. Any other `scheme://` text is an
ordinary relative path to the host (`a:` is a directory name), so `a://..\..\.config\age\keys.txt`
reaches a credential file two directories up. The same list decides which `@` shorthand targets
`expandHostPath` accepts. Hosts that register more schemes through an extension (omp's RPC host URIs)
are not listed; their URLs are graded converted, the safe direction.

*Glob listings.* The glob amendment above withholds the floor's allow from every glob target because
neither grade can say what the glob matches. For `glob` alone that is too strict: it returns file
names and never contents, so what a wrong guess exposes is a name. A `glob` call keeps the floor's
allow when its literal prefix and every other graded form resolve inside the project directory (in
both lexical and real spelling) and none hits an S0 or S3 rule. A declared `denyPaths` base at or
under the prefix and a `.omp` directory under `gateOmpDir` are asked about by their own layers
before the allow is read, so the allow never overrides them. A pattern that can leave the project
(`../**`, `~/**`, `/etc/**`) or a `scheme://` URL stays gray. `grep`, `ast_grep` and `ast_edit` read or rewrite contents
and keep the glob rule unchanged, and a user `allow` rule or `tools` entry still skips every glob
target, `glob` included.
