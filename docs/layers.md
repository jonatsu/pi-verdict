# The layer map

The contract the probe asserts: which layer decides a tool call, in what order, and what the
probe's `expected.layer` means for each. It complements [security-principles.md](./security-principles.md),
which states *why* the layers exist; this document states the order and the observable output.

## Layers, in order

A tool call is adjudicated by the first layer that decides it. `adjudicate` returns a `Verdict`
whose `source` names the deciding layer.

| Order | Layer | Decides | `Verdict.source` |
|---|---|---|---|
| 0 | Self-protection | a hard deny that no configuration exempts, not even `builtinDenyFloor:false` (ADR-0005). It covers writes to the gate's config, the trust store and the installed copy (a single-file copy: the extension file and its sibling `jev-adapter.ts`; the module directory `extensions/pi-verdict/`: the directory by prefix, the sibling `jev-adapter.ts`, and a decoy entry file `pi-verdict.ts` or `pi-verdict.js` beside it, since the host keeps the first extension of a name and discovers top-level files first; an omp plugin or a pi `npm` or `git` package install: the whole package directory); writes to the plugin workspace manifest and lock (`package.json`, `omp-plugins.lock.json`) and to a project `plugin-overrides.json`; reads and writes of `verdicts/`, where a read or search of a directory above it inside the gate's own trees also counts; and reads of the trust store. A file-tool read of the config itself passes. A shell command, or eval code text, that names any of these files or `verdicts/` is denied in either direction | `rule` |
| 1 | Built-in deny floor | bash danger rules (regex `pattern` or `check`) and path-sensitivity grades S0–S5, graded over every tool-access adapter target, in each form the host can resolve it to (the worst grade wins); for a `language:"py"` eval cell, the extracted shell-out lines only | `rule` |
| 2 | User `deny` rules | any user deny regex matching any form of a known tool's adapter target (for a code call, the whole code text) | `rule` |
| 3 | Forced `.omp` gate | `gateOmpDir` asks on a `.omp` access (any tool's adapter target, including an unlisted tool's) | `protected-path` |
| 4 | `denyPaths` | a declared protected path match (any tool's adapter target, including an unlisted tool's); also a call that the strict form of the transcript redactor matches, such as a `${HOME}` spelling the tokeniser misses, checked right after the `denyPaths` hit and before user `allow` (ADR-0002 amendment) | `protected-path` |
| 5 | Over-cap action ask | an action whose counted text (the tool name plus the command, the code, or every adapter target) exceeds `BASH_MAX_MATCH_LEN`, asked **before** user `allow` so no rule can allow an unread tail | `rule` |
| 6 | User `allow` rules / `tools` exemption | a user allow regex matching every known-tool target in every form the host can resolve it to (a bash command must also be one simple command, ADR-0008), or an exact `tools` name match. Neither admits a `kind:"code"` call, an opaque call, a target holding a glob metacharacter (a `glob` listing included), a target in a registered internal URL scheme (`ssh://`, `vault://`), or a `read` of a relative path that does not exist; both are also suspended while `policyDegraded` holds (ADR-0010) | `rule` |
| 7 | Opaque ask | a known mutating call (write/edit/ast_edit, ADR-0009) whose payload names no extractable target: no target at all, or patch text that does not parse (a `path`/`paths` beside it does not rescue the call) | `rule` |
| 8 | Classifier | the gray zone, adjudicated by the model (fail-closed) | `classifier` / `fail-closed` |
| 9 | Policy degradation | while `policyDegraded` holds (the user's own policy failed to load or loaded in part, ADR-0010), a layer-8 allow is withheld: the first layer and the cascade fallback become an **ask**; the subagent second model is **denied outright** (no human is left to ask) | `degraded-policy` (on the ask paths) |

Deny beats allow at every step. There is no built-in allowlist: a command the floor does not deny
and no user rule covers reaches the classifier.

A file call that no layer above decides takes the floor's own grade: allow for a read the floor does not
deny and for a write inside the project, gray otherwise. Four target shapes turn that allow gray, so the
classifier sees the call: a target holding a glob metacharacter (an in-project `glob` listing keeps the
allow), a target in a registered internal URL scheme, a `read` of a relative path that does not exist (the
host may open another file), and a scope-tool search whose directory contains a credential directory.

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
