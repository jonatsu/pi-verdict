# The layer map

The contract the probe asserts: which layer decides a tool call, in what order, and what the
probe's `expected.layer` means for each. It complements [security-principles.md](./security-principles.md),
which states *why* the layers exist; this document states the order and the observable output.

## Layers, in order

A tool call is adjudicated by the first layer that decides it. `adjudicate` returns a `Verdict`
whose `source` names the deciding layer.

| Order | Layer | Decides | `Verdict.source` |
|---|---|---|---|
| 0 | Self-protection | writes to the gate's own config/trust/audit and the installed copy | `rule` |
| 1 | Built-in deny floor | bash danger rules (regex `pattern` or `check`) and path-sensitivity grades S0–S5, graded over every tool-access adapter target | `rule` |
| 2 | User `deny` rules | any user deny regex matching a known tool's adapter target | `rule` |
| 3 | Forced `.omp` gate | `gateOmpDir` asks on a `.omp` access (any tool's adapter target, including an unlisted tool's) | `protected-path` |
| 4 | `denyPaths` | a declared protected path match (any tool's adapter target, including an unlisted tool's) | `protected-path` |
| 5 | User `allow` rules / `tools` exemption | a user allow regex matching every known-tool target, or an exact `tools` name match | `rule` |
| 6 | Opaque ask | a known mutating call (write/edit/ast_edit, ADR-0009) whose payload names no target at all | `rule` |
| 7 | Classifier | the gray zone, adjudicated by the model (fail-closed) | `classifier` / `fail-closed` |

Deny beats allow at every step. There is no built-in allowlist: a command the floor does not deny
and no user rule covers reaches the classifier.

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
   returns for a non-S0/S1 read or a user allow match. It is not "the classifier happened to
   allow it."
