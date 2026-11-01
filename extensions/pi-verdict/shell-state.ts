// ============================================================================
// Session shell state: which user allows an earlier command may have voided (ADR-0008)
//
// omp runs every bash call of an agent session in one persistent shell, so a variable, function or alias
// one call sets changes what a later call runs: `export GIT_EXTERNAL_DIFF=…` turns an allowed `git diff`
// into a program run, and `PATH` or a function can redirect any command. The rule layer cannot see that
// shell, so it scans the commands of the session branch for the constructs that do this.
// ============================================================================

/** What a construct makes the rule layer unable to vouch for. */
type Voids =
	/** Every command: the construct can redirect any command word. */
	| { readonly kind: "every-allow" }
	/** Every operand spelled through the home directory or split by the shell. */
	| { readonly kind: "home-operands" }
	/** The named commands, matched by the basename of any word, so `env git diff` counts. */
	| { readonly kind: "commands"; readonly names: readonly string[] };

/** Where a word sits in command position: the start of a line, after an operator or a keyword that takes
 *  a command, or after a prefix builtin that runs one. */
const COMMAND_POSITION = String.raw`(?:^|[;&|(){}\n\x60!]|\b(?:then|do|else|elif|if|while|until|time|exec|command|builtin)\s)\s*`;
/** The end of a builtin's name: whitespace, an operator or the end of the text. */
const WORD_END = String.raw`(?=[\s;&|)]|$)`;

/** Returns a regex for the ways a shell command may assign a variable whose name matches `name` (a regex
 *  source): `X=` and `X+=`, the `${X:=…}` and `${X=…}` default expansions, a builtin that declares, reads
 *  into or unsets a name on its line, a `for X` loop and `printf -v X`. Not a read such as `$X=`. */
function assigns(name: string): RegExp {
	const n = `(?:${name})`;
	return new RegExp(
		[
			String.raw`(?<![\w$])${n}\s*\+?=`,
			String.raw`\$\{${n}:?=`,
			String.raw`\b(?:export|declare|typeset|readonly|local|read|mapfile|readarray|unset)\b[^\n;&|]*(?<![\w\${])${n}\b`,
			String.raw`\bfor\s+${n}\b`,
			String.raw`-v\s*${n}\b`,
		].join("|"),
	);
}

/** Returns a regex for a builtin in command position, so a pattern in a quoted search string does not count. */
function builtin(source: string): RegExp {
	return new RegExp(COMMAND_POSITION + source);
}

const EVERY_ALLOW: readonly Voids[] = [{ kind: "every-allow" }];
const commands = (...names: string[]): readonly Voids[] => [{ kind: "commands", names }];

/**
 * Each construct a command may run and what it voids. The scan is textual and over-matches on purpose: a
 * false match costs one classifier call per later allowed command. `CDPATH` voids nothing, since every
 * operand the gate grades is resolved from the call's own cwd.
 */
const SHELL_STATE_ROWS: readonly { readonly construct: RegExp; readonly voids: readonly Voids[] }[] = [
	{ construct: assigns("PATH|LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT|BASH_ENV|ENV"), voids: EVERY_ALLOW },
	// A function definition, `name() {` or `function name`, which shadows any command of that name.
	{ construct: /[\w.:@+-]+\s*\(\s*\)\s*(?:[{(]|\[\[|\b(?:if|for|while|until|case|select)\b)/, voids: EVERY_ALLOW },
	{ construct: builtin(String.raw`function\s+[^\s(){};&|]+`), voids: EVERY_ALLOW },
	{ construct: builtin(`(?:alias|enable|source|\\.|eval|trap)${WORD_END}`), voids: EVERY_ALLOW },
	{ construct: builtin(String.raw`hash\s[^\n;&|]*-[a-z]*p`), voids: EVERY_ALLOW },
	{ construct: builtin(String.raw`shopt\s[^\n;&|]*\bexpand_aliases\b`), voids: EVERY_ALLOW },
	{ construct: assigns("HOME"), voids: [{ kind: "home-operands" }, ...commands("git")] },
	{ construct: assigns("IFS"), voids: [{ kind: "home-operands" }] },
	// A moved global gitconfig can set `core.fsmonitor`; `GIT_*` covers `GIT_EXTERNAL_DIFF`, `GIT_DIR` and the rest.
	{ construct: assigns(String.raw`XDG_CONFIG_HOME|GIT_\w*`), voids: commands("git") },
	{ construct: assigns("RIPGREP_CONFIG_PATH"), voids: commands("rg") },
	{ construct: assigns("TAR_OPTIONS"), voids: commands("tar", "gtar", "bsdtar") },
	{ construct: assigns("ZIPOPT|ZIP"), voids: commands("zip") },
	{ construct: assigns("RSYNC_RSH"), voids: commands("rsync") },
	{ construct: assigns("LESSOPEN|LESSCLOSE"), voids: commands("less") },
	{ construct: assigns("GREP_OPTIONS"), voids: commands("grep", "egrep", "fgrep", "rgrep") },
];

/** What the session's shell state voids for the user allows of this call. */
export interface ShellState {
	/** No user allow may admit a command. */
	readonly everyAllow: boolean;
	/** No user allow may admit a home-relative operand. */
	readonly homeOperands: boolean;
	/** No user allow may admit a command with a word of one of these basenames. */
	readonly commands: ReadonlySet<string>;
}

/** The state that voids every allow, for a branch the gate cannot read. */
const FAIL_CLOSED: ShellState = { everyAllow: true, homeOperands: true, commands: new Set() };

/** Returns what the constructs in a command text void. */
export function shellStateOf(text: string): ShellState {
	let everyAllow = false;
	let homeOperands = false;
	const voided = new Set<string>();
	for (const row of SHELL_STATE_ROWS) {
		if (!row.construct.test(text)) continue;
		for (const v of row.voids) {
			switch (v.kind) {
				case "every-allow":
					everyAllow = true;
					break;
				case "home-operands":
					homeOperands = true;
					break;
				case "commands":
					for (const name of v.names) voided.add(name);
					break;
				default: {
					const unreachable: never = v;
					throw new Error(`unknown shell-state void ${String(unreachable)}`);
				}
			}
		}
	}
	return { everyAllow, homeOperands, commands: voided };
}

/** The part of the host session the scan reads: the branch of past entries. */
export interface BranchSource {
	getBranch(): readonly unknown[];
}

/** Returns a reader for `RuleContext.shellState` that scans this call's command and the session branch on
 *  its first call only, so a call no user allow matches never reads the branch. */
export function lazyShellState(host: BranchSource, input: Readonly<Record<string, unknown>>): () => ShellState {
	let state: ShellState | undefined;
	return () => {
		state ??= sessionShellState(host, input);
		return state;
	};
}

/**
 * Returns what this call's command and the command of every earlier tool call on the session branch void.
 * Fails closed: a branch the host cannot hand over voids every allow.
 */
function sessionShellState(host: BranchSource, input: Readonly<Record<string, unknown>>): ShellState {
	let branch: readonly unknown[];
	try {
		if (typeof host.getBranch !== "function") return FAIL_CLOSED;
		branch = host.getBranch();
	} catch {
		return FAIL_CLOSED;
	}
	const texts = branch.flatMap(toolCallCommands);
	if (typeof input.command === "string") texts.push(input.command);
	// Joined by newlines, which every row reads as a command boundary, so each row tests the text once.
	return shellStateOf(texts.join("\n"));
}

/** Returns the string `command` argument of every tool call in one assistant message entry. */
function toolCallCommands(entry: unknown): string[] {
	const message = field(entry, "type") === "message" ? field(entry, "message") : undefined;
	const content = field(message, "role") === "assistant" ? field(message, "content") : undefined;
	if (!Array.isArray(content)) return [];
	return content.flatMap((block: unknown) => {
		const command = field(block, "type") === "toolCall" ? field(field(block, "arguments"), "command") : undefined;
		return typeof command === "string" ? [command] : [];
	});
}

/** Returns a property of an object value, or undefined for anything else. */
function field(value: unknown, key: string): unknown {
	// Safe: any non-null object can be indexed by a string key, and the value stays unknown.
	return typeof value === "object" && value !== null ? (value as Record<string, unknown>)[key] : undefined;
}
