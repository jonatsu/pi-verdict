# OS-level sandboxing beneath the gate — draft

**Status: draft, future work, not scheduled.** Written 2026-10-05 from a design brainstorm. This is an incomplete
starting point for a later spec or technical design, not an executable plan. Each statement below is labelled as a
user decision, a fact (with its source), a recommendation, or a provisional idea.

## Original idea

pi-verdict decides whether a call may run, but once a call is allowed nothing limits what it does. The floor matches
the text of a shell command, and shell can spell the same action in endless ways: through variables, `eval`, a
decoded payload piped into `sh`, or a script written first and run later. The deterministic floor is therefore a
tripwire, not a boundary, and the classifier is a model that can be wrong. An OS-level sandbox would enforce limits
on what an allowed command can touch, whatever its spelling.

## Purpose and intended outcome

- **Purpose (recommendation).** Raise the security ceiling. A mistake by the floor or the classifier should become a
  failed system call, not a leaked secret or a damaged file outside the project.
- **Desired outcome (provisional).** An allowed bash command cannot read the gate's protected paths (the S0 tier and
  the user's `denyPaths`) or write outside the project and temporary directories, on the hosts and platforms the
  user runs.
- **Observable success signal (provisional).** With the gate's verdict forced to `allow`, `cat ~/.ssh/id_rsa` and a
  write to `~/.bashrc` from bash fail with a permission error, while an ordinary build and test run in the project
  succeeds.

## Constraints and context

- **User decision (2026-10-05).** This is future work. pi-verdict was chosen over similar plugins because it supports
  omp natively, while most plugins support only Pi. Several omp-capable sandbox options already exist. The idea is
  worth keeping for a later implementation.
- **Fact.** Both hosts let a `tool_call` handler change the input a tool runs with:
  - omp 18.5.1 accepts a replacement `input` in the handler's result. When several handlers set one, the last one
    wins (`extensibility/shared-events.ts:325-335`).
  - pi 0.84.3 has the handler mutate `event.input` in place (`dist/core/extensions/types.d.ts:803-812`).

  A gate could therefore wrap an allowed bash command in a sandbox launcher without replacing the bash tool.
- **Fact.** pi-verdict ships with zero runtime dependencies (`AGENTS.md`). A sandbox library would be the first.
- **Fact.** File tools such as `read`, `write` and `edit` run inside the host process. Wrapping a bash command does not
  confine them, so the gate's path layers stay the only control for file tools.

## Prior art (researched 2026-10-05)

No omp-native sandbox *plugin* was found. The omp options wrap the whole host process instead:

- `mikeatlas/omp-sbx`, a Docker microVM;
- `cellarium-ai/omp-sandbox`, Docker;
- bubblewrap launcher gists;
- `yeet-src/agent-jail`, which uses Landlock, confines the filesystem only, and calls itself experimental.

Pi has several per-command sandbox extensions. Whether any of them works on omp is unconfirmed:

- the upstream pi example extension, which replaces the `bash` tool and uses Anthropic's sandbox runtime;
- `carderne/pi-sandbox`;
- `@sysid/pi-sandbox`, which adds a `tool_call` path guard for file tools;
- `@yandy0725/pi-sandbox`, which uses bubblewrap, Landlock, seatbelt and a Windows restricted token.

Anthropic's `@anthropic-ai/sandbox-runtime` (v0.0.78, "Beta Research Preview", Apache-2.0) uses a different
mechanism on each platform:

- Linux: bubblewrap plus a seccomp filter;
- macOS: `sandbox-exec` profiles;
- Windows: a dedicated user plus WFP filters.

It filters the network through a proxy and needs `bwrap`, `socat` and `rg` on Linux. Its library call
`SandboxManager.wrapWithSandbox(command)` returns the wrapped command string.

Neither pi nor omp ships a built-in bash sandbox as far as the search found; treat that as unconfirmed.

Sources:

- https://github.com/earendil-works/pi/blob/main/packages/coding-agent/examples/extensions/sandbox/index.ts
- https://github.com/carderne/pi-sandbox
- https://www.npmjs.com/package/@sysid/pi-sandbox
- https://raw.githubusercontent.com/yandy/pi-packages/main/pi-sandbox/README.md
- https://github.com/mikeatlas/omp-sbx
- https://github.com/cellarium-ai/omp-sandbox/
- https://github.com/yeet-src/agent-jail
- https://registry.npmjs.org/@anthropic-ai/sandbox-runtime/latest
- https://github.com/can1357/oh-my-pi/blob/main/packages/coding-agent/CHANGELOG.md

## Branches considered

All four remain open. A and B-or-C are alternatives. D composes with B or C.

- **A. Compose with an existing process-level sandbox; document it.**
  - What changes: the README recommends running omp under an existing wrapper such as `agent-jail`, a bubblewrap
    launcher or a container, beside pi-verdict.
  - Gain: no code, and it confines the file tools as well as bash.
  - Cost: two policies that drift apart, and the gate's own config and audit paths must stay writable inside the
    wrapper.
- **B. Wrap each allowed bash command with Anthropic's sandbox runtime.**
  - What changes: after an `allow`, the gate rewrites the command through `wrapWithSandbox`.
  - Gain: per-command confinement inside one plugin, network filtering, and three platforms maintained upstream.
  - Cost: the first runtime dependency, a beta library, extra system binaries, Apache-2.0 notices, and the omp rule
    that the last handler to set `input` wins.
- **C. Wrap each allowed bash command with our own minimal launcher.**
  - What changes: the gate invokes `bwrap`, or Landlock where available, directly with a small fixed profile.
  - Gain: no dependency, and a profile we fully control.
  - Cost: we maintain the platform matrix. macOS and Windows would start unsupported.
- **D. Derive the sandbox profile from the gate's policy.**
  - What changes: the S0 tier, the user's `denyPaths` and the gate's self-protection set become unreadable or
    unwritable paths in the profile. The project and temporary directories become writable.
  - Gain: one policy drives both the decision and the enforcement, which no surveyed plugin offers. This is the
    reason to build rather than compose.
  - Cost: dual-form path matching must translate exactly into the sandbox's path rules.

**Recommendation (provisional).** Use A as the near-term answer, documented now at no cost. Later, build D on top of
C on Linux first, and revisit B if network filtering or macOS becomes a requirement. The smallest evidence that could
change this recommendation is a spike: on omp, replace an allowed bash command with a `bwrap` invocation under WSL2,
and confirm that it runs and that output and exit codes pass through unchanged.

## Scope

- **In scope (provisional).** Confinement of bash commands the gate has allowed, on omp first and on pi where the same
  hook works.
- **Excluded.** File tools, which stay with the gate's path layers. Network policy in the first version. Replacing the
  gate's verdicts with sandbox decisions; the sandbox is a second barrier, not a new decider.

## Parked

- Telling the classifier when a sandbox is active, so that it may be less strict. Parked because it lowers the first
  barrier on the strength of the second one, and that trade needs its own analysis.
- Confining `eval` (omp's JavaScript and Python execution tool), which runs in-process like the file tools.

## Open questions for the spec or technical design

1. Does omp's bash tool run a replaced `input` exactly as given, and how should the gate coexist with another plugin
   that also rewrites `input`?
2. Do bubblewrap user namespaces work under WSL2 on the user's machine, or is Landlock the only option there?
3. What must stay writable inside the sandbox so that common toolchains work: package caches, `~/.cache`, git
   credential helpers, and the agent directory?
4. Should a sandbox failure, such as a missing `bwrap`, block the call (fail closed) or run it unconfined with a
   warning?
5. Does this need a spec (user-visible behaviour: which commands now fail and how the user is told), or can it go
   straight to a technical design? To be decided with the user when the draft is picked up.
