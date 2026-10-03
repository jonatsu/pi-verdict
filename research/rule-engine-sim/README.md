# Rule-Engine Benefit Measurement: tree-sitter AST Port vs. Allowlist Breadth (.issue #6 Decision Basis)

We cross-replayed Bash tool calls (746 across 1,027 tool calls) from all real sessions in the past ~3 days against “this repository’s rule layer × pi-permission@1.3.3’s tree-sitter AST (same-version wasm + the same 11-node allowlist).” **Conclusion: the measured benefit of porting was zero, with a negative effect (gray zone +16%); no real security holes were found. The actual targets are allowlist breadth and classifier cost structure.**

## Method

- Data source: all project sessions from the past ~3 days in `~/.pi/agent/sessions`; Bash tool calls in assistant messages (pure-function replay; no live extension needed)
- This repository’s rule layer: extracted verbatim from `extensions/pi-verdict.ts` (types stripped with `Bun.Transpiler`, then eval); behavior matches production
- AST check: web-tree-sitter@0.26.11 + tree-sitter-bash@0.25.1, reproducing ALLOWED_KINDS (11 node types) + ALLOWED_PUNCT (6 punctuation marks) from pi-permission `src/ast/analyzer.ts`, with fail-closed semantics
- Its allowlist: extracted from its `src/rules/builtins.ts` (50 unconditional + 9 conditional — **narrower than this repository’s 78+9**)
- Reproduce: `cd ~/tmp/ast-lab && npm i web-tree-sitter@0.26.11 tree-sitter-bash@0.25.1 && bun measure.ts` (path is in the script header)

## Results (2026-08-26 Replay)

| Metric | Value |
|---|---|
| This layer’s absorption rate (746 Bash calls) | allow 140(18.8%)/ deny 19(2.6%)/ **gray 590(78.8%)** |
| Gray-zone calls the port could absorb (AST clean ∧ its allowlist matches) | **0 calls** |
| AST clean but not covered by the allowlist | 148 calls (upper bound; actual matches are zero) |
| Side effect: benign allows demoted to “AST unclean → send to classifier” | 94 calls → gray-zone rate 78.8% → ~91.8% |
| Redirections to sensitive paths (real security holes) | **0** |

All 94 “allow ∧ AST unclean” cases were reviewed by category and were benign: 67 `2>/dev/null` cases, 25 variable-prefix assignments (`P=… && cat $P/…`), and 2 heredocs writing project files; only 2 were `command_substitution`, both benign (`ls -la $(which pi)`).

## Attribution: Why the Port Has No Benefit

pi-permission’s architecture is “AST selects structurally clean commands × narrow allowlist (50)” — the AST makes auto-allow more selective; it does not increase absorption. Most of this repository’s gray-zone traffic comes from **allowlist breadth** (leading-command targets: `head 459/echo 328/grep 291/cd 262/git 170/gh 109/python3 86/sed 67/if·for 96/bun 42`) and **compound statements** (`if`/`for`/heredoc are mis-split by naive segmentation; the AST would only “send them to the classifier correctly,” the same outcome as today). Neither area benefits from the port.

## Actual Targets (Indicated by Data, Not Yet Decided)

1. **Allowlist breadth**: conditionally allow a read-only subset of `gh` (≈109 calls), make `sed` quote-aware (`sed -n '125,170p'` currently fails because of quote mismatch), and fix false splits of `if`/`for`/heredoc segments — roughly estimated to absorb 100–200 calls and reduce the gray-zone rate to ~65%
2. **Classifier cost structure**: the gray zone is structural (78.8%); one configuration setting pointing `--auto-mode-model` to a lightweight model amortizes all costs (self-reflection large models take 3–15s/call + ~8K tokens vs. lightweight Flash-class models)
3. The measurement rejected “remove the rule layer and focus on the classifier”: load ×1.7 (590→1027), losing 19 zero-cost denies and the only live brake when the classifier is down

## Signal to Reopen the Discussion

Reopen discussion of adding the AST if real traffic shows a **sensitive-path redirection bypass** (e.g. `echo x > /etc/passwd`: the rule layer allows it, the danger regex does not match, and path sensitivity does not cover Bash redirections) — the theoretical hole exists, but it did not appear in 3 days of traffic.
