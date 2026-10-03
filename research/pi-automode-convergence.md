# pi-automode convergence comparison: pi-verdict@0.2.0 vs @czottmann/pi-automode current state

Collection date 2026-08-27; comparison source is czottmann/pi-automode `main@718aa4f` (v1.13.0 + 2 commits that day, latest commit 2026-08-26 13:46 UTC: #30 classifier streaming timeout enforcement). The pi-verdict side is based on 0.2.0 baseline facts, without re-investigation.

## 1. TL;DR

1. **There is no longer any essential difference in decision approach**: the core architecture of “deterministic dangerous floor → user rules → deterministic allow fast path → classifier fallback → fail-closed on all paths” has been the established pattern for czottmann since v1.0.0 on 2026-06-14; pi-verdict 0.2.0 independently converged to the same form after removing the allowlist.
2. **The remaining differences are not in architecture but in three layers**: the semantic position of ask (three-state classifier vs rule layer + two-state classifier), rule engine engineering depth (unbash AST vs regex), and diagnostics/tamper-proofing support—all three are “copyable”; what is truly “uncopyable” is only the zero-dependency single-file form and the evidence-driven methodology.
3. **Judgment on continued existence of the independent project**: the remaining value is mainly the methodology narrative + two experimental features not adopted upstream (three-state ask, shadow cache telemetry); positioning should shrink from “architectural differentiation” to “experimental playground + evidence base,” while evaluating contribution of features upstream in parallel.

## 2. Convergence point checklist (architectural convergence)

| # | Convergence point | czottmann (path) | pi-verdict (path) |
|---|---|---|---|
| 1 | deny-first overall pipeline form | v1.0.0 (06-14) present from first release | 0.2.0 (August) reached after removing allowlist |
| 2 | Deterministic dangerous floor precedes model | v1.0.0: TLS weakening/profile/authorized_keys/cron/self-edit | 0.2.0: bash dangerous regex 14 items + path sensitivity S0-S5 |
| 3 | No built-in deterministic allowlist | `permissions.allow` defaults to `[]`; built-in allow serves only as soft-deny exceptions in the classifier prompt (only covers soft-deny, never covers hard-deny) | 0.2.0 removes it entirely (audit conclusion: soundness requires shell AST) |
| 4 | floor overrides all allow paths | hard-deny check occurs before all three allow tiers and cannot be bypassed by allow rules | floor occurs before user allow |
| 5 | Classifier evidence = user text + tool call input, excluding tool results and assistant prose | token-budgeted selection (4000 each, keep first and last user messages, mark omissions) | Fixed window (most recent 5 user messages + 10 tool calls, pending action at the end) |
| 6 | Bounded output + strict parsing contract | one-token `0/1` conservative gate → strict JSON `{decision,tier,reason}`, malformed means block | `<verdict>allow|ask|deny</verdict>` prefix contract, malformed means deny |
| 7 | Retries and timeouts | detailed retries once (512/1200 two tiers); 20s per request, streaming covered starting today | 512→1024 two-tier retry; 25s |
| 8 | Classifier default = session model, can be specially configured | `classifierModel` else `ctx.model`; `/automode model` persists | default introspects session model; `--auto-mode-model` |
| 9 | Read-only tool routing configurable | `classifyReadOnlyTools` (default false = read-only fast path) | no special case, always gray→classifier (equivalent to the other side enabling this switch) |
| 10 | All paths fail-closed | docs explicitly state default posture; missing model/auth failure/parse failure/timeout/action over context all block | same (timeout/parse failure→deny) |

## 3. Residual differences table

Grading: **essential** (structural, hard to copy) / **copyable** (constitutes the current substantive behavioral difference, but the other side can copy it) / **surface** (parameter-level).

| # | Dimension | pi-verdict@0.2.0 | czottmann current | Grading |
|---|---|---|---|---|
| 1 | ask semantic position | three-state classifier: model can initiate ask, runtime human confirmation; non-interactive downgrades to deny | two-state classifier allow/block; ask only at rule layer (UI confirm), after acceptance forced through classifier and all allow tiers disabled; “explicit user authorization” is modeled as an `explicit_intent` allow tier in detailed review | copyable (bidirectional: adding an ask enum on their side / adding an ask rule layer on ours are both small changes), but currently it is the **sharpest philosophical disagreement**: runtime human intervention initiated by model vs human intervention triggered only by rules pre-declared by the user |
| 2 | Rule matching syntax | regex; bash = full command string, file tools = absolute path | glob + unbash AST: bash multiple commands need full structural coverage, redirections need explicit coverage, `bash -c`/`eval` literal script penetrating analysis, symlink/case/Unicode normalization, recursive grep/find domain checks; malformed deny/ask rules fail-closed | copyable (requires introducing an AST dependency or building one); currently a substantive gap in engineering depth |
| 3 | Rule tamper-proofing | none | hard-deny editing its own security control files (`.pi` settings, extensions directory, own configuration), including symlink and case-variant bypass detection (#24/#25) | copyable |
| 4 | floor optionality | `builtinDenyFloor:false` can be turned off entirely (user-sovereignty orientation) | floor cannot be turned off, only disabled entirely; optionality all lies in the allow direction | **essential (philosophical)**: the other side will most likely reject this design; this is one of our few “uncopyable” points |
| 5 | thinking handling | `thinkingEnabled:false` explicitly disables | default follows server default; configurable low..max (`clampThinkingLevel`); docs acknowledge high levels can burn through 512/1200 tokens causing fail-closed | copyable (bidirectional); current substantive behavioral difference, we have blackhole research backing |
| 6 | Cache | shadow cache observe-only telemetry (LRU128 hit rate/divergence count), no effective cache | **no decision cache**; `cacheRetention:"short"` + stable session hash ID is vendor prompt cache affinity (cost optimization). What the brief calls “classifier cache” is verified from source as this, not a verdict cache | neither side has a verdict cache; our side uniquely has “pre-effective data accumulation” method, copyable |
| 7 | Diagnostics and observability | `--auto-mode-debug`, `/automode on\|off` | `automode_inspect` read-only agent tool (registration source verification to prevent impersonation) + accompanying diagnostic skill; JSONL observation logs (ccusage-compatible, `classifierIo` raw I/O); 12 denial history entries; status line `AM● a: d: ca: cd:` | copyable |
| 8 | Engineering form | ~700-line single file / 0 dependencies / 36 stub tests / bilingual README | multi-file ~6700 lines / 1 dependency (unbash) / 10 test files / ADR×2 / 6 docs / npm Trusted Publishing + provenance | **essential** (minimalism is a value, not a function) |
| 9 | Maintenance activity | npm just released 0.2.0 | first release 06-14, 14 versions in 2.5 months, 3 external contributors, 97 stars, still commits on collection day | surface (current gap, changeable) |
| 10 | Methodology narrative | five evidence-driven research documents archived; allowlist removal backed by security audit conclusion | “CC auto mode for pi” behavior replication + ADR records | **essential (uncopyable)**, but not a functional difference |

## 4. Implications for positioning

- **README comparison table must be rewritten**: the comparison table in `pi-permission-landscape.md` is based on a pre-0.2.0 snapshot (“allowlist 78 + dangerous regex 13”). After removing the allowlist, any implication that “our floor/allowlist is thicker” no longer holds and has reversed—the other side's floor is thicker and cannot be disabled, and its rule engine is deeper. The differentiation narrative shrinks to four points: three-state ask (landscape has confirmed it is unique across the category), `builtinDenyFloor` can be disabled, zero-dependency single file, shadow cache + evidence base.
- **collaboration assessment (for czottmann, using the candidate analysis approach from landscape)**:
  - **A. Contribute features upstream**: three-state ask (their JSON contract adding an `ask` enum + non-interactive downgrade to block is enough), shadow cache telemetry, research evidence for `thinkingEnabled:false`. Low cost; acceptance depends on the other side's philosophy—the ask rule layer + mandatory review may be a deliberate design (the model does not initiate questions; humans intervene only where the user pre-declares).
  - **B. Stay independent, positioning as “experimental playground + evidence base”**: pi-verdict as a feature testbed, mature features contributed upstream; the minimalist form keeps continued existence low-cost.
  - **C. Merge/archive**: the other side has already won on engineering maturity and community; merging means abandoning the methodology assets; only as an exit option.
  - Judgment: **B as primary, A in parallel, C only as exit**. The conclusion that “the independent project's value mainly remains methodology narrative + two experimental features” holds; no need to defend shortcomings.

## 5. Endnotes

- Collection date: 2026-08-27; comparison source state: `main@718aa4f` (v1.13.0 + 2 commits, including #30 streaming timeout).
- Sources: gh api repository metadata and releases; `README.md`; `docs/automode-classifier-flow.md` (15-step verdict flow); `docs/configuration.md`; `CHANGELOG.md`; `extensions/auto-mode/{classifier,constants,extension,hard-deny,package}.ts` (classifier.ts 754 lines, extension.ts 946 lines verified section by section); `package.json` (only 1 runtime dependency unbash@4.0.10).
- One correction to the brief: czottmann has no “classifier (decision) cache”; its caching mechanism is vendor prompt cache affinity (source `cacheRetention:"short"` + `classifierCacheSessionId`).
- Incidental empirical evidence: during this collection, the local pi-verdict floor successfully intercepted a `rm -rf` command targeting RamDisk; deny floor works normally.
