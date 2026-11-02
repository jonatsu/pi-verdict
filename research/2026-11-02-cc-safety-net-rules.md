# cc-safety-net built-in rules and switches, compared with pi-verdict

Read on 2026-11-02 from cc-safety-net 2.7.1, commit `755a548` (https://github.com/kenryu42/cc-safety-net, MIT), and from the user's
agent-setup repository at the same date. Citations are `path:line` in cc-safety-net at that commit unless they name another repository.
This note is the research input to `TODO.md` item 9 (configurable command rules and per-rule overrides of the floor);
`research/2026-11-02-cc-safety-net.md` covers the tool's architecture. "Inferred" marks a statement not traced in full.

## 1. Outcome model

cc-safety-net decides `allow` or `deny` (`src/core/decision.ts:11-19`). It has no model and no gray zone. It asks only when standard mode
cannot verify a command (`raw-text.dangerous-command` or an unverifiable shell source) and the host can prompt a person, which today is
Claude Code alone (`src/gate/pipeline.ts:341-358`, `src/hosts/hook/common.ts:221-229`). Every deny carries an `intent` that picks the advice
the agent gets: `hard_stop`, `use_alternative`, `scope_down`, `manual_only` or `stop_and_explain` (`src/core/denial.ts:20-31`).

The gate runs, first hit wins: malformed input and size limits, its own `policy.json` guard, the `policy apply` guard, the `.git` metadata
guard, secret protection, then command analysis (`src/gate/pipeline.ts:148-312`). Parse limits deny rather than analyze partly
(`SECURITY.md:27-32`).

## 2. Built-in rules

`src/core/rules/destructive.ts` lists 74 rule ids; all deny. Ten are catastrophic and no switch turns them off
(`src/core/policy/effective-rules.ts:13-67`): recursive deletes of root, home or `.git` through `rm`, PowerShell, `cmd` and `find`.
Each other rule is either always on or gated by a capability (section 3).

| Family | Rules (ids shortened) | Source |
| --- | --- | --- |
| git | `push-force` (also `+refspec`), `push-delete` (also `:ref`), `push-mirror`, `reset-hard`, `reset-merge`, `clean-force` (not with `-n`), `rm-force` (not `--cached`), `checkout-force`, `checkout-double-dash`, `checkout-ref-path`, `checkout-pathspec-from-file`, `checkout-ambiguous`, `switch-discard-changes`, `switch-force`, `restore-worktree`, `restore-unstaged` (`--staged` alone passes), `branch-force-delete`, `rebase-abort`, `merge-abort`, `tag-delete`, `reflog-delete`, `stash-drop`, `stash-clear`, `worktree-remove-force`, `ssh-env` (`GIT_SSH_COMMAND`, `core.sshCommand` on a network subcommand), `alias-config` (unresolvable `-c alias.`) | `src/gate/analyzer/git/rules.ts`, `git/index.ts` |
| Recursive delete | `rm`/`rmdir` targets classified in order: root or home, `.git` metadata, temp or `allow_paths` (allowed), dynamic target, cwd is home, the cwd itself, inside cwd (paranoid only), outside cwd. The trigger is the recursive flag, not `-f` | `src/gate/analyzer/recursive-delete-targets.ts:248-360`, `rm.ts:64` |
| find, rsync, xargs, parallel, awk | `find.delete` unless every start point is scoped, `find.exec-rm-recursive-force`, `rsync.delete` outside cwd, and dynamic `xargs`, `parallel` and `awk system()` forms | `find.ts`, `rsync.ts`, `xargs.ts`, `parallel.ts`, `awk.ts` |
| Devices | `dd.device-write`, `mkfs.device`, `disk.erase` (`diskutil`, `wipefs`, `sgdisk`, `parted`), `shred.target`, `redirect.block-device` | `device.ts:16-140` |
| PowerShell, cmd | the delete rules above for `Remove-Item` and its aliases, `rmdir /s`, `del /s`, and an unreadable nested PowerShell delete | `powershell/remove-item.ts`, `cmd.ts` |
| Interpreters, shell | `interpreter.dangerous-command` (dangerous code in `python`/`node`/`ruby`/`perl` `-c`/`-e`), `interpreter.one-liner-paranoid` (any inline code), `shell.dynamic-structure`, `shell.dynamic-executable`, unverifiable shell sources (`curl … \| sh`, unresolved `eval`/`source`/`bash -c`), and `raw-text.dangerous-command` for text it cannot parse | `segment.ts`, `derived-input.ts`, `dangerous-text.ts:21-43` |
| Network | `network.cloud-metadata` (requests to metadata hosts such as 169.254.169.254), `network.upload-remote` (`curl -d/-F/-T`, `wget --post-*` to a non-loopback URL) | `network.ts` |
| Other | `unshare.user-namespace` | `namespace.ts` |
| Guards (not switchable) | its own `policy.json`, `policy apply` run by the agent, deletes or moves of `.git` and its hooks | `src/gate/guards/` |
| Secrets | about 138 ids: basenames (`.env`, `.npmrc`, `.netrc`, `id_rsa`, `credentials` …), `.env.*` variants (examples and templates exempt), SSH key variants, 21 extensions (`pem`, `p12`, `pfx`, `jks`, `asc`, `ovpn`, `kdbx` …), `.key`/`.keystore` patterns, home paths (`~/.ssh`, `~/.aws`, `~/.gcp`, `~/.config/gcloud`, `~/.kube/config`, `~/.docker/config.json`, `~/.config/gh/hosts.yml`), and the credential files of 13 coding CLIs (their config files are default off) | `src/core/rules/secret.ts` |

No package-manager rule is built in; packs for Terraform and the cloud CLIs ship as separate rulebooks (`README.md`). `sudo`, `env`,
`command`, `time`, `timeout`, `nohup` and similar wrappers are looked through, not denied (`transparent-wrappers.ts:13-22`).

## 3. Switches

- **Safety level** (`policy.json` `safety.level`, or env `CC_SAFETY_NET_LEVEL`, which can only raise it): `standard` (default), `strict`
  or `paranoid`, presets of three capabilities (`src/core/policy/safety-level.ts:11-15`):
  - `fail_closed` (strict and paranoid) denies partial parses, dynamic delete targets, dynamic executables and every unverifiable shell
    source, drops standard mode's secret relaxations and removes the ask path;
  - `paranoid_rm` blocks recursive deletes inside the cwd except in temp dirs;
  - `paranoid_interpreters` blocks every inline interpreter one-liner.
  `safety.overrides` sets each capability either way, and `CC_SAFETY_NET_STRICT`, `_PARANOID`, `_PARANOID_RM` and
  `_PARANOID_INTERPRETERS` can only switch one on (`src/core/policy/env.ts:82-152`).
- **Per-rule overrides**: `destructive_command_protection.overrides` and `secret_protection.overrides` map a rule id to `"on"` or `"off"`;
  catastrophic ids ignore them (`src/core/policy/store.ts:450-476,663-672`). `destructive_command_protection.enabled: false` turns off
  every non-catastrophic built-in rule.
- **Paths**: `destructive_command_protection.allow_paths` treats a path like a temp dir for deletes; `secret_protection.allow_paths`
  exempts a path, with one glob form `<folder>/**/<exact-name>`, from every secret rule except the coding-CLI ones;
  `secret_protection.deny_paths` adds protected paths. None may cover the home directory or above (`allow-paths.ts:7-66`).
- **Workflow**: `workflow.worktree_mode` (or `CC_SAFETY_NET_WORKTREE`) allows local git discards in a linked worktree; a disposable repo in
  a trusted temp dir is always relaxed except for pushes (`git/worktree-relaxation.ts`, `git/temp-root-relaxation.ts`).
- **Layering**: a project `policy.json` merges over the user's and may weaken it; `CC_SAFETY_NET_PROJECT_TIGHTEN_ONLY=1` drops the
  weakenings (`src/core/policy/merge.ts`, `store.ts:94-103`). An invalid policy is salvaged with protective defaults and marked degraded.

## 4. Custom rules

User rules live in rulebooks: `<home>/.cc-safety-net/rules/<name>/rulebook.json` (or under `$CC_SAFETY_NET_HOME`), listed by name in
`rules/rule.json`, with the same layout per project (`src/core/policy/paths.ts:44-71`). They are read at every call, user scope first,
and the first matching rule wins (`src/cli/rule/doc.ts:7-15`). A rule only adds a block: the outcome is always deny, with id
`custom.<rulebook>/<rule>` and default intent `manual_only` (`src/core/rules/custom.ts:41-47`). Built-in overrides do not touch them.

- Version 1 rule: `name`, `command` (basename, lower-cased, `.exe` dropped), optional `subcommand`, `block_args` (any literal token
  equal to one, short-option bundles expanded, so `-Ap` matches `-A`), `reason`, optional `intent`. The subcommand is read past git's and
  docker's global options and their values (`custom.ts:95-174`, `custom-subcommand.ts`).
- Version 2 rule: `match.command_path` (leading non-option words in order), `match.any_args`, `match.exclude_args`; no regex, glob or
  substring (`custom.ts:49-89`). An unknown value-taking option before the path makes the rule miss, which the docs call a deliberate
  fail-open.
- A rulebook declares `allowed_commands` and may carry `tests` fixtures (`{command, expect, rule}`), checked by `rule verify`.
- `rule.json` `overrides` turn one custom rule off or replace its reason; `transparent_wrappers` and `command_tools` extend analysis.
- A broken rulebook drops that rulebook only; a broken `rule.json` drops its scope; nothing is denied for bad config (`SECURITY.md:22`).
  Rulebooks are not tamper-protected (`SECURITY.md:23`).

## 5. The user's setup (agent-setup)

- cc-safety-net runs at the standard level with `CC_SAFETY_NET_PARANOID_INTERPRETERS=1` (global mise config). Its policy turns
  `secret.ext.asc` off (`cc-safety-net/policy.json`), and `scripts/safety-net.sh pki` turns `secret.ext.pem` and
  `secret.ext-pattern.key` off for a while, because agents in one project handle `.pem` test keys.
- Two rulebooks, about 50 rules with fixtures:
  - `local-overrides`: git staging and bypasses (`add -A/-u/./:/`, `commit -a`, `--no-verify` on commit and push, `push --delete`,
    `checkout .`), docker and podman prunes and volume removal, `find -delete/-exec/-ok`, `fd -x/-X`, `npm publish`,
    `npm unpublish --force`, global installs for npm, pnpm, yarn and bun, supply-chain cooldown bypasses, `gh repo delete`,
    `gh release delete`, `gh pr merge`, `rg -r`, and systemctl verbs that stay blocked even with `--user`;
  - `systemctl-system`: lifecycle verbs on system units (version 2 rules with `exclude_args: ["--user"]`).
- The deployed pi-verdict policy (`agents/omp/pi-verdict.json`) re-expresses most of these as about 55 hand-written `deny` regexes over
  raw text. They match quoted text, can miss reordered global options, and the `systemctl` regex also denies `systemctl --user restart`,
  because a regex cannot express the `--user` exception.

## 6. Differences from pi-verdict's built-in rules

| Topic | cc-safety-net | pi-verdict |
| --- | --- | --- |
| Outcomes | deny only; ask only for an unverifiable command on Claude Code | allow, ask or deny; a call no rule decides goes to the classifier |
| Rule count | 74 command rules plus about 138 secret rules | 16 bash floor rules, path tiers S0-S3, code-loading ask, self-protection |
| git | 26 rules, including `push --delete/--mirror`, `branch -D`, `tag -d`, `stash drop`, `reset --merge`, `rm -f`, `switch --discard-changes`, `worktree remove --force`, `GIT_SSH_COMMAND` | 6 rules: force push, `reset --hard`, `stash clear`, `clean -f`, `checkout .`, `restore`; the rest reach the classifier |
| Recursive delete | graded by target: root, home and `.git` always denied, temp dirs and `allow_paths` allowed, outside cwd denied, inside cwd allowed unless paranoid | every `rm -r` denied (`rm-recursive`), no temp exemption |
| sudo, chmod, fork bomb | `sudo` is looked through, not denied; no chmod or fork-bomb rule | `sudo`, `chmod 777`/setuid and a fork bomb are denied |
| GitHub | none built in (user rulebook) | `gh repo` and `gh release` changes denied |
| Network | cloud metadata hosts, `curl`/`wget` uploads | `curl \| sh` and environment or history piped to a network tool |
| Interpreters | dangerous inline code denied; every one-liner in paranoid mode | no interpreter rule; the classifier judges them, and Python `eval` cells get the bash floor on their shell lines |
| Secrets | basename, extension and prefix signatures anywhere on disk, plus home paths and CLI credentials | S0 denies reads and writes of credential homes (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, gcloud, the agent's own databases …) and of a few signatures anywhere on disk (`.env*`, `.envrc`, `*credential*`, `id_rsa*`, `*.pem`, `*_history`, `.netrc`, `.npmrc`, `.pypirc`, `.vault-token`, `/proc/*/environ`), with no `.pub`, example or per-path exemption; the user's `denyPaths` add asks. It lacks most of cc-safety-net's extensions (`.key`, `.p12`, `.pfx`, `.jks`, `.kdbx`, `.ovpn` …) |
| Git metadata | deletes and moves of `.git` and its hooks | writes to `.git/hooks`, `.git/config`, `.git/modules`, `.gitmodules` (S3) |
| Tightening | three levels and per-capability switches | `builtinDenyFloor` (all or nothing), `autoDeny: false` (denies become asks), `gateOmpDir`, classifier settings |
| Per-rule switches | `"on"`/`"off"` per built-in id, catastrophic exempt | none |
| Path exemptions | `allow_paths` for deletes and secrets | none; `denyPaths` only adds protection |
| User command rules | declarative rulebooks, deny only | raw-text regexes: `deny` denies, `allow` allows after operand grading (ADR-0008) |
| Project config | may weaken the user's unless `PROJECT_TIGHTEN_ONLY` | may only narrow (ADR-0006) |
| Broken config | drops the broken source, never denies | empty rules, floor on, every model allow withheld (ADR-0010) |

## 7. What this means for item 9

- The rulebook rule shape is a proven base: adopting its fields (`command`, `subcommand`, `block_args`, `match.command_path`,
  `any_args`, `exclude_args`, `reason`) lets agent-setup move its rulebooks across nearly unchanged, and `exclude_args` is what the
  `systemctl --user` case needs. pi-verdict adds `action: "ask"` (user decision of 2026-11-02).
- The `tests` fixtures give each rulebook its own checks; pi-verdict could run them at load or through a CLI, as `rule verify` does.
- Per-rule overrides of the floor need a non-overridable set like cc-safety-net's catastrophic ids; for pi-verdict that is at least
  self-protection and `rm-root`.
- The `.pem` case needs a path-scoped exemption like `secret_protection.allow_paths`: pi-verdict's S0 tier already denies every read
  and write of a `*.pem` file anywhere, and only `builtinDenyFloor: false` lifts it today.
- Candidates for new built-in floor rules, each to be weighed under the 80/20 rule against the classifier, which already sees these calls:
  `git push --delete/--mirror`, `git branch -D`, `git tag -d`, `git stash drop`, cloud metadata requests and `curl` uploads.
