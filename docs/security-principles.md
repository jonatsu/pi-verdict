# Security Design Principles

This document states the security design principles behind pi-verdict and how they map to what is actually shipped. It complements the [pipeline](../README.md#pipeline) section in the README and the [ADRs](./adr/). Where a principle describes a direction rather than shipped behavior, it says so explicitly — this document deliberately makes no claims the implementation does not back.

pi-verdict is a **fail-closed, layered permission gate** for coding agents. It is not a sandbox and does not attempt to formally prove that arbitrary agent-generated programs are safe.

## Principles

### 1. Fail closed by default

When the system cannot establish that an action is safe, it must not silently allow it. Classifier exceptions, malformed verdicts, timeouts, unavailable models, and non-interactive `ask` verdicts all degrade to `deny` — never to automatic approval.

```text
uncertainty → friction     (never: uncertainty → permission)
```

### 2. Self-protection and deterministic floors come before AI

The snapshot-free self-protection layer runs first. It hard-denies agent writes to the gate's own files (the policy file, the trust store, and the installed extension copy under a recognized root) and agent reads of the trust store and of `<agentDir>/verdicts/`; reads of the policy file pass. [docs/layers.md](./layers.md) holds the exact list. No user `allow` rule, `builtinDenyFloor: false`, or `autoDeny: false` lifts these denies.

Development checkouts are not protected, and the layer does not keep a baseline or restore files. Bash-side matching uses substrings and can be obfuscated.

The built-in deny floor (bash danger regexes + path sensitivity grades) runs next, before the classifier. The classifier may interpret ambiguity; it cannot override a hard deny, and user allow rules cannot override one either.

### 3. The classifier judges semantics, not syntax

Coding agents routinely generate long pipelines, heredocs, embedded interpreters, and command substitutions. Regex floors and allowlists cannot realistically classify such payloads, so: **deterministic rules establish the floor; the classifier handles the remaining semantic ambiguity.** A long read-only pipeline may be complex but low-impact; a short heredoc may be syntactically simple but arbitrarily destructive. Decisions focus on what an action *does*, not how it is spelled.

Known limitation, stated honestly: bash-side path extraction is token-level — command substitution and base64-embedded paths produce no floor hit and fall to the classifier's vigilance ([ADR-0002](./adr/0002-deny-paths-deterministic-ask.md)).

### 4. Adjudicate by impact, not by complexity

A long command is not automatically dangerous, and a short one is not automatically safe — so the deciding axis is *impact*, never length or syntactic complexity: long read-only actions can auto-allow; short destructive ones deny or ask. This is what keeps protection meaningful without producing approval fatigue. The one length rule is a safety limit, not a judgment: an action longer than the rule layer can read in full (`BASH_MAX_MATCH_LEN`, 8192 characters) is asked about before any user `allow` rule can admit it, because no rule can vouch for a tail it never read.

### 5. Verdicts are informed judgments, not proofs

A classifier `allow` means "consistent with policy and user intent as far as the model can tell" — it does **not** mean "proven incapable of causing harm." That distinction is fundamental to the security model and to why the deterministic floor exists at all.

### 6. Minimize the classifier's trusted input

The classifier receives only what it needs to judge: a condensed transcript (user messages + tool calls, **no tool results**), with the action under review pinned as the last line — hardened against forged-line injection (#22). When denyPaths are configured, the classifier gets an *existence hint* only — it never sees the path plaintext ([ADR-0002](./adr/0002-deny-paths-deterministic-ask.md)). This limits indirect prompt-injection surface without starving semantic adjudication.

### 7. Protected resources are matched by canonical identity

Path matching compares lexical and realpath forms (#20), with case folding on case-insensitive filesystems and macOS firmlink prefixes (#21). Relative, `~`, and `$HOME` spellings are expanded, `${HOME}` is caught by the strict transcript-redactor match, and every file-tool target is graded in each form the host can resolve it to (omp's own path rewrites, read selectors, shell-escaped spaces, WSL drive aliases; [ADR-0009](./adr/0009-tool-access-adapter.md)). Other environment variables are not expanded. The path-sensitivity floor reconstructs non-existent targets from the nearest realpath ancestor; `denyPaths` and user-rule path targets match base tier plus the kernel-true spelling for `..`-spellings, with no ancestor rebuild, so such targets may fall to the classifier's existence hint. A path that merely *looks* workspace-local is not trusted as workspace-local.

### 8. User policy may weaken only the built-in floor by explicit opt-in

User rules are the user's own security declarations (deny beats allow; denyPaths are the stronger declaration channel). The built-in protections, the deny floor and the code-loading ask ([ADR-0011](./adr/0011-code-loading-ask.md)), can be turned off only with an explicit `builtinDenyFloor: false` in the user's config. Self-protection is separate and remains enforced.

### 9. Platform differences are documented, not silently weaker

Security semantics must not silently degrade just because an action is expressed differently. Where full parity is not shipped, the gap is documented instead: on Windows the built-in floor covers bash-shaped patterns only — PowerShell-native dangerous commands rely on the classifier, which fails closed (see [Status & limitations](../README.md#status--limitations)).

### 10. Optimize for safe automation, not maximum automation

The objective is to maximize useful automation while minimizing unsafe automatic execution. Both extremes lose: "everything → ask" breeds approval fatigue and blind approvals; "everything ambiguous → allow" breeds silent unsafe execution. The three-state verdict exists for exactly this reason — auto-approve clearly low-impact actions, escalate the ambiguous ones, deny what violates hard policy.

### 11. A permission gate, not a sandbox

pi-verdict makes tool authorization safer and more explainable; it provides no OS-level isolation. For strong guarantees, stack it with what it deliberately is not: OS sandboxing, container isolation, filesystem/network restrictions, least-privilege execution. The strongest model is a *policy gate + semantic adjudication + technical isolation* — never any single mechanism.

## Directions (not yet shipped)

**Capability-aware authorization.** Decisions today key off tool names, paths, and command strings, with the classifier covering uncovered tools (MCP and custom tools reach the classifier unless you name them in `tools`; their `path`, `paths` and patch fields still feed the `denyPaths` and `.omp` asks, and a `tools` entry never skips those asks). Expressing policy in terms of capabilities (`filesystem.write`, `network`, `credential-access`, `destructive`, …) instead of command spellings is a direction we find right, and it is not implemented today. When it ships, this section moves into the principles above.

## Summary

The self-protection layer runs before configurable rules. The full layer order, with the verdict source each layer reports, is in [docs/layers.md](./layers.md); in outline:

```text
                     Tool Call
                         │
                         ▼
              ┌────────────────────────┐
              │ Self-protection layer  │   (config-exempt hard denies)
              └───────────┬────────────┘
                  deny ◄───┼──► continue
                           │
                           ▼
         ┌───────────────────────────────────┐
         │ Deterministic rule layer          │   (built-in floor, your deny rules, protected-path
         │                                   │    and over-cap asks, your allow rules and tools — no LLM)
         └─────────────────┬─────────────────┘
          deny / ask ◄─────┼─────► allow   (a floor grade or one of your rules)
                           │
                         gray
                           ▼
              ┌────────────────────┐
              │  LLM classifier    │   (semantic judgment, fail-closed)
              └─────────┬──────────┘
                        ▼
              allow / ask / deny     (ask → human; non-interactive → deny)
```

Optionally stacked *outside* the gate: OS sandboxing / container / filesystem & network restrictions — pi-verdict complements isolation, it does not replace it.

> **Core principle: deterministic controls for what must never be allowed, LLMs for what syntax alone cannot decide, technical isolation to limit the consequences of inevitable mistakes.**
