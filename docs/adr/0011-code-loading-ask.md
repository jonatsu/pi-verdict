# 0011 - Code-loading ask: writes where the host loads code ask the user

---
status: accepted
date: 2026-10-24
---

## Context

omp and pi load code from fixed places at session start: extension, hook, tool and command
directories, plugin and package install roots, and configuration files that name a module, a
shell or a process to start (`mcp.json` servers, `models.yml` key commands, the `extensions`
and `shellPath` settings). A file an agent writes there runs in every later session, in-process
or as a child process, before the gate sees any call it makes.

Before this decision, such a write reached the classifier like any other gray call. On omp
18.12.6 a `write` of `~/.omp/agent/extensions/evil.ts`, a decoy `extensions/pi-verdict.ts`, a
`plugins/node_modules/x/index.ts`, an edit of `config.yml`, and an `ast_edit` over the extensions
directory all went gray. A classifier allow there grants persistent code execution, which is
more than the single action the classifier was asked about. omp also loads project-level code
with no trust prompt at all: `isProjectTrusted` is constantly true in its extension runner, so
a write into `<project>/.omp/extensions/` runs the next time anyone starts omp in that
directory. pi gates its project directory behind a trust store, but a trusted project, or one
under a trusted parent, loads a new extension silently.

The inventory of loaders this decision rests on was read from omp 18.12.6 (tag `v18.12.6`) and
pi 0.84.3 (`dist/`) on 2026-10-24.

## Decision

1. **A built-in ask, like `denyPaths`.** A call that writes into a host code-loading location is
   a terminal ask. With no UI it degrades to deny; a subagent's ask that no human answers is
   denied (`resolveAskWithoutHuman` denies every non-classifier ask). No model is consulted, and
   a user `allow` regex or `tools` entry cannot skip it.

2. **Pipeline position.** After the user `deny` rules and the forced `.omp` gate, before
   `denyPaths`. The floor and self-protection still deny first: a write into the gate's own
   install directory stays a hard deny.

   ```mermaid
   flowchart LR
     SP[0 self-protection] --> F[1 floor] --> UD[2 user deny] --> OG[3 forced .omp gate]
     OG --> CL[3a code-loading ask] --> DP[4 denyPaths] --> REST[5.. over-cap, allow, classifier]
   ```

3. **Writes only.** A file tool's write targets count, and so does every target of a tool the
   adapter cannot classify (ADR-0009). A read does not ask. A shell command or an `eval` cell
   asks when one of its path tokens falls in the set, as with `denyPaths`, because a token's
   direction is unknown; a command that only lists or reads such a path therefore asks too. A
   scope tool that writes (`ast_edit`) is matched in both directions, so an edit over an
   ancestor of an extensions directory asks.

4. **The set.** The user chose it on 2026-10-24.

   | Scope | omp | pi |
   | --- | --- | --- |
   | Agent directory (`<agentDir>`, every spelling the gate resolves, and `.omp/agent`, `.omp/profiles/<name>/agent`, `.pi/agent` anywhere) | `extensions/`, `hooks/`, `tools/`, `commands/`, `mcp.json`, `.mcp.json`, `models.yml`, `config.yml`, `settings.json`, `lsp.*`, `.lsp.*`, `dap.*` | `extensions/`, `npm/`, `git/`, `bin/`, `settings.json`, `models.json`, `trust.json` |
   | Plugin root | `~/.omp/plugins/` (and `$XDG_DATA_HOME/omp/plugins/`) | none |
   | Any project | `.omp/{extensions,hooks,tools,commands,plugins}/`, `.omp/{mcp.json,.mcp.json,config.yml,settings.json}`, `.omp/{lsp,dap}.*` | `.pi/{extensions,npm,git}/`, `.pi/settings.json` |
   | The call's working directory | `mcp.json`, `.mcp.json`, `lsp.*`, `.lsp.*`, `dap.*` | none |

   The directory entries and the `.omp/` and `.pi/` files match as path segments wherever they
   sit, because a subagent or a worktree session runs in another directory than the root
   session. The generic names in the last row (`mcp.json`, `lsp.json`) match only directly in the
   working directory, since the host reads them nowhere else and the names are common.

5. **General config files ask on any write.** `config.yml` and `settings.json` hold launch keys
   (`extensions`, `shellPath`, `python.interpreter`, `packages`, `npmCommand`) among unrelated
   settings. Predicting the file's content after an edit, a patch or a shell write is brittle and
   would fail open, so every write asks. The user may narrow this later if the asks prove noisy;
   the code keeps these files in their own list so that change grades only that list.

6. **Off with the floor.** The ask belongs to the built-in protections, so `builtinDenyFloor:false`
   turns it off with them. Self-protection is unaffected.

7. **Reason text.** The ask's reason names the location class and the path. These paths are not
   user secrets, so ADR-0002's withholding does not apply, and the Explain option stays offered.

## Accepted residuals

- **Foreign project trees.** omp also loads code and MCP servers from `<project>/.codex`,
  `.gemini`, `.cursor`, `.vscode/mcp.json`, `.windsurf`, `opencode.json` and `.claude` (the last is
  inert while `claude` is in `disabledProviders`). They stay with the classifier.
- **Configuration that names code elsewhere.** A listed extension path, an MCP `command` or an LSP
  server binary can live anywhere; the ask covers the file that names it, not the target. A
  project-local binary that a default LSP server resolves (`node_modules/.bin`, `.venv/bin`) is not
  covered.
- **Shell rc files and dotenv files.** `~/.bashrc` and the like run in omp's shell snapshot; they
  are the user's own files outside the host trees. Dotenv files can redirect the agent directory,
  and the floor already treats `.env` files as S0.
- **Indirect shell writes.** `cd ~/.omp/agent && echo … > extensions/x.ts` names no path token in
  the set, the same residual `denyPaths` accepts. OS-level sandboxing is the backstop.
- **pi's legacy global npm root** (`npm root -g`) sits outside the agent directory and is not
  covered.
- **Host drift.** The set is a point-in-time reading of omp 18.12.6 and pi 0.84.3; a host upgrade
  can add a loader. The omp drift audit re-checks it.

## Consequences

- An agent that legitimately installs an extension or edits host config now needs a human, and a
  headless run cannot do it at all.
- Edits of `config.yml` and `settings.json` ask even for harmless keys (decision 5).
- The probe gains one case per row of the set, and `docs/layers.md` gains layer 3a.
