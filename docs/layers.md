# The layer map

The contract the probe asserts: which layer decides a tool call, in what order, and what the
probe's `expected.layer` means for each. It complements [security-principles.md](./security-principles.md),
which states *why* the layers exist; this document states the order and the observable output.

## Layers, in order

A tool call is adjudicated by the first layer that decides it. `adjudicate` returns a `Verdict`
whose `source` names the deciding layer.

| Order | Layer | Decides | `Verdict.source` |
|---|---|---|---|
| 0 | Self-protection | a hard deny that no configuration exempts, not even `builtinDenyFloor:false` (ADR-0005). It covers writes to the gate's config, the trust store and the installed copy (a single-file copy: the extension file and its sibling `jev-adapter.ts`; the module directory `extensions/pi-verdict/`: the directory by prefix, the sibling `jev-adapter.ts`, and a decoy entry file `pi-verdict.ts` or `pi-verdict.js` beside it, since omp keeps the first extension of a name and discovers top-level files first; a decoy under another directory is the code-loading ask's concern; an omp plugin or a pi `npm` or `git` package install: the whole package directory); writes to the plugin workspace manifest and lock (`package.json`, `omp-plugins.lock.json`) and to a project `plugin-overrides.json`; reads and writes of `verdicts/`, where a read or search of a directory above it inside the gate's own trees also counts; and reads of the trust store. A file-tool read of the config itself passes. A shell command, or eval code text, that names any of these files or `verdicts/` is denied in either direction | `rule` |
| 1 | Built-in deny floor | bash danger rules (regex `pattern` or `check`) and path-sensitivity grades S0–S5, graded over every tool-access adapter target, in each form the host can resolve it to (the worst grade wins); for a `language:"py"` eval cell, the extracted shell-out lines only | `rule` |
| 2 | User `deny` rules | any user deny regex matching any form of a known tool's adapter target, an internal URL target also as written (for a code call, the whole code text) | `rule` |
| 3 | Forced `.omp` gate | `gateOmpDir` asks on a `.omp` access (any tool's adapter target, including an unlisted tool's) | `protected-path` |
| 4 | `denyPaths` | a declared protected path match (any tool's adapter target, including an unlisted tool's); also a call that the strict form of the transcript redactor matches, such as a `${HOME}` spelling the tokeniser misses, checked right after the `denyPaths` hit and before user `allow` (ADR-0002 amendment) | `protected-path` |
| 4a | Code-loading ask | a write where omp or pi loads code in a later session (ADR-0011): an agent directory's code directories and launcher and config files, the omp plugin roots (profile ones included), a project's `.omp` and `.pi` trees, `mcp.json` or an LSP or DAP config name (`{,.}{lsp,dap}.{json,yaml,yml}`) directly in the call's working directory, and the LSP and DAP names in the home directory. A directory that holds such locations (an agent directory itself, a `.omp` or `.pi` directory, `~/.omp`) counts too. A file tool's write targets count, also in the form rebuilt from their nearest existing ancestor, and a read does not; a shell command or eval cell asks on any path token in the set or a bare working-directory launcher name, with `$PWD` and `$PI_CODING_AGENT_DIR` expanded; `ast_edit` also asks when such a location exists inside the subtree it edits. The reason names the location class and the path, so it runs after both `denyPaths` asks, which withhold a declared path. Off with `builtinDenyFloor:false`; a user `allow` rule or `tools` entry cannot skip it | `rule` |
| 5 | Over-cap action ask | an action whose counted text (the tool name plus the command, the code, or every adapter target) exceeds `BASH_MAX_MATCH_LEN`, asked **before** user `allow` so no rule can allow an unread tail | `rule` |
| 6 | User `allow` rules / `tools` exemption | a user allow regex matching every known-tool target in every form the host can resolve it to (a bash command must also be one simple command whose every operand, after `~` and `$HOME` expansion, grades as a floor-allowed read even with `builtinDenyFloor:false`, with no other unresolvable expansion, no home-relative operand once `HOME` may have been reassigned, and for `git` no injected configuration, no `-C` outside the cwd and no `diff`/`grep` reaching outside it; a refused command reaches the classifier, ADR-0008 and its amendment), or an exact `tools` name match. Neither admits a `kind:"code"` call, an opaque call, a target holding a glob metacharacter (a `glob` listing included), a target in a registered internal URL scheme (`ssh://`, `vault://`; an omp `xd://` device URL only outside `read` and `write`), or a `read` of a relative path that does not exist; both are also suspended while `policyDegraded` holds (ADR-0010) | `rule` |
| 7 | Opaque ask | a known mutating call (write/edit/ast_edit, ADR-0009) whose payload names no extractable target: no target at all, or patch text that does not parse (a `path`/`paths` beside it does not rescue the call) | `rule` |
| 8 | Classifier | the gray zone, adjudicated by the model (fail-closed) | `classifier` / `fail-closed` |
| 9 | Policy degradation | while `policyDegraded` holds (the user's own policy failed to load or loaded in part, ADR-0010), a layer-8 allow is withheld: the first layer and the cascade fallback become an **ask**; the subagent second model is **denied outright** (no human is left to ask) | `degraded-policy` (on the ask paths) |

Deny beats allow at every step. There is no built-in allowlist: a command the floor does not deny
and no user rule covers reaches the classifier.

Every layer resolves a relative path from the directory the call runs in. That is the session cwd,
except for omp's `bash`, which runs in its `cwd` argument; the gate resolves it as omp's
`resolveToCwd` does (`callCwd`). A `cwd` argument also counts as a path the command touches, so a
declared path that contains it asks. A `cwd` the gate cannot resolve (an internal URL, a value that
is not a string, or any `cwd` on pi or for `powershell`, whose schemas take none) leaves the
session cwd in place and withholds every user `allow` rule and `tools` exemption. The classifier's
action line names the directory when it is not the session cwd.

A file call that no layer above decides takes the floor's own grade: allow for a read the floor does not
deny and for a write inside the project, gray otherwise. Four target shapes turn that allow gray, so the
classifier sees the call: a target holding a glob metacharacter (an in-project `glob` listing keeps the
allow), a target in a registered internal URL scheme, a `read` of a relative path that does not exist (the
host may open another file), and a scope-tool search whose directory contains a credential directory.

On omp, an `xd://` device URL is not graded as a file. A `read` of one returns documentation the host
generates, and a `write xd://<tool>` runs the tool as its own gated `tool_call`, so the floor grades both as
allow and the internal-URL shape does not withhold it. The floor grades these gray instead: a write to
`xd://resolve`, `xd://reject`, `xd://propose` or `xd://report_issue` (host code with no nested call), to the
root `xd://` or to a topic URL, and a write to a name with any character outside letters, digits, `_` and
`-`, since omp's URL parsing can rewrite such a name (`xd://:@resolve` reaches `resolve`). A device URL given to any tool other than
`read` and `write` is held back like every internal URL. On pi, which has no `xd` scheme, the text is a
relative path and takes the path grades, S0 included, except that an allow turns gray, so a host
misdetected as pi never allows a device write silently ([research/2026-10-25-xd-device-dispatch.md](../research/2026-10-25-xd-device-dispatch.md)).

## Three consequences the probe encodes

1. **Layer identity, not verdict text, is the contract.** A case asserts the `source` that must
   decide it. `rule`-layer denies carry no classifier call at all; a `classifier` case in run A
   (headless) is `fail-closed`, in run B is `classifier`. The probe asserts both.

2. **Headless asks degrade to deny.** An ask that reaches presentation with no interactive UI
   (`pi -p`, json, rpc) becomes `deny` with `degraded: true`. This is why a `denyPaths` case is
   `protected-path/deny` in run A and `protected-path/ask` in run B — same layer, different
   observable verdict, both asserted.

3. **A `rule` allow is deterministic and distinct from a classifier allow.** `expected.layer:
   "allow"` means the rule layer returned `allow/rule` with no model call — the layer the code
   returns for a read or an in-project write the floor admits, a user allow match, or a `tools`
   match. It is not "the classifier happened to allow it."
