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

The inventory of loaders this decision rests on ([research/2026-10-24-host-code-loading-paths.md](../../research/2026-10-24-host-code-loading-paths.md)) was read from omp 18.12.6 (tag `v18.12.6`) and
pi 0.84.3 (`dist/`) on 2026-10-24.

## Decision

1. **A built-in ask, like `denyPaths`.** A call that writes into a host code-loading location is
   a terminal ask. With no UI it degrades to deny; a subagent's ask that no human answers is
   denied (`resolveAskWithoutHuman` denies every non-classifier ask). No model is consulted, and
   a user `allow` regex or `tools` entry cannot skip it.

2. **Pipeline position.** After the forced `.omp` gate, `denyPaths` and the redactor's
   protected-path ask, before the over-cap ask and user `allow`. The floor and self-protection
   still deny first: a write into the gate's own install directory stays a hard deny. Both
   protected-path asks come first because this ask's reason carries the path (decision 7): a
   path the user declared in `denyPaths` keeps its withheld reason (ADR-0002).

   ```mermaid
   flowchart LR
     SP[0 self-protection] --> F[1 floor] --> UD[2 user deny] --> OG[3 forced .omp gate]
     OG --> DP[4 denyPaths] --> CL[4a code-loading ask] --> REST[5.. over-cap, allow, classifier]
   ```

3. **Writes only.** A file tool's write targets count, and so does every target of a tool the
   adapter cannot classify (ADR-0009). A read does not ask. A shell command or an `eval` cell
   asks when one of its path tokens falls in the set, as with `denyPaths`, because a token's
   direction is unknown; a command that only lists or reads such a path therefore asks too. A
   bare working-directory launcher name in a command or cell (`> mcp.json`) counts as a token,
   and a command's `$PWD` and `$PI_CODING_AGENT_DIR` are expanded first. A target that names a
   directory holding locations of the set asks as well, because a command aimed at it (`tar -C`,
   `cp -r`, `mv`, `ln -s`) writes into them: an agent directory itself, a `.omp` or `.pi`
   directory, an omp profile directory, `~/.omp` and `$XDG_DATA_HOME/omp`. Each target is also
   graded in the form rebuilt from its nearest existing ancestor, so a new file under a symlink
   to an agent directory is matched where it lands; `denyPaths` keeps its own no-rebuild rule. A
   scope tool that writes (`ast_edit`) is matched in both directions, so an edit over an
   ancestor of an extensions directory asks.

4. **The set.** The user chose it on 2026-10-24.

   | Scope | omp | pi |
   | --- | --- | --- |
   | Agent directory (`<agentDir>`, every spelling the gate resolves, and `.omp/agent`, `.omp/profiles/<name>/agent`, `.pi/agent` anywhere) | `extensions/`, `hooks/`, `tools/`, `commands/`, `mcp.json`, `.mcp.json`, `models.yml`, `config.yml`, `settings.json`, the LSP and DAP names | `extensions/`, `npm/`, `git/`, `bin/`, `settings.json`, `models.json`, `trust.json` |
   | Plugin root | `~/.omp/plugins/`, `~/.omp/profiles/<name>/plugins/`, and the same two under `$XDG_DATA_HOME/omp/` | none |
   | Any project | `.omp/{extensions,hooks,tools,commands,plugins}/`, `.omp/{mcp.json,.mcp.json,config.yml,settings.json}`, the LSP and DAP names in `.omp/` | `.pi/{extensions,npm,git}/`, `.pi/settings.json` |
   | The call's working directory | `mcp.json`, `.mcp.json`, the LSP and DAP names | none |
   | The home directory | the LSP and DAP names | none |

   The LSP and DAP names are exactly the files omp reads, `{,.}{lsp,dap}.{json,yaml,yml}`
   (`lsp.json`, `.lsp.yaml`, `dap.yml` and so on). omp reads them in the home directory from any
   working directory. The directory entries and the `.omp/` and `.pi/` files match as path
   segments wherever they sit, because a subagent or a worktree session runs in another directory
   than the root session. The generic names in the working-directory row (`mcp.json`, `lsp.json`)
   match only directly in the working directory, since the host reads them nowhere else and the
   names are common.

5. **General config files ask on any write.** `config.yml` and `settings.json` hold launch keys
   (`extensions`, `shellPath`, `python.interpreter`, `packages`, `npmCommand`) among unrelated
   settings. Predicting the file's content after an edit, a patch or a shell write is brittle and
   would fail open, so every write asks. The user may narrow this later if the asks prove noisy;
   the code keeps these files in their own list so that change grades only that list.

6. **Off with the floor.** The ask belongs to the built-in protections, so `builtinDenyFloor:false`
   turns it off with them. Self-protection is unaffected.

7. **Reason text.** The ask's reason names the location class and the path. These paths are not
   user secrets, so ADR-0002's withholding does not apply, and the Explain option stays offered.
   A path that is also a `denyPaths` declaration is decided by the protected-path ask before
   this one (decision 2), so its plaintext stays withheld.

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
- **Indirect shell writes.** `cd "$OMP_DIR" && echo … > extensions/x.ts`, where a variable the
  gate does not expand holds the directory, names no path token in the set, the same residual
  `denyPaths` accepts. So is a working directory whose path holds whitespace, where an expanded
  `"$PWD/mcp.json"` splits into two tokens. OS-level sandboxing is the backstop.
- **A broad `ast_edit` scope.** A scope tool that writes is matched against the existing locations
  under the agent directories, the plugin roots and the scope's own `.omp/` and `.pi/`, not against
  every directory beneath it, so an `ast_edit` over `~/src` that reaches a project's
  `.omp/extensions/` does not ask.
- **pi's legacy global npm root** (`npm root -g`) sits outside the agent directory and is not
  covered.
- **Host drift.** The set is a point-in-time reading of omp 18.12.6 and pi 0.84.3; a host upgrade
  can add a loader. The omp drift audit re-checks it.
- **Native and lazy loaders.** omp's grammar files and native addon under `~/.omp/natives/` (a compiled
  omp loads its `.node` addon from there; the npm install does not) and the cwd-first `sys.path` of the
  Python eval kernel, where a project file can shadow a module, are not in the set.

### Open questions

These were not traced in the source reading and may widen the set:

- whether a project settings layer can re-enable a provider the user listed in `disabledProviders`
  (settings arrays replace on merge), which decides whether the foreign trees above stay inert;
- whether omp's `shellMinimizer.settingsPath`, `launch.*` or the auth broker configuration name a
  command;
- whether a subagent in another working directory re-runs project discovery for hooks and tools.

## Consequences

- An agent that legitimately installs an extension or edits host config now needs a human, and a
  headless run cannot do it at all.
- Edits of `config.yml` and `settings.json` ask even for harmless keys (decision 5).
- A command that names an agent directory or a `.omp` directory in a path token, such as
  `cd ~/.omp/agent` or `ls ./.omp`, asks (decision 3); a bare `cd .omp` is not a path token and does
  not.
- The probe gains one case per row of the set, and `docs/layers.md` gains layer 4a.
