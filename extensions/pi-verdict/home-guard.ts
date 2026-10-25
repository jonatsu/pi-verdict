// ============================================================================
// HOME guard: whether `~` still names the home directory the gate knows
//
// omp runs every bash call of an agent session in one persistent shell, so an assignment of `HOME` in
// one call moves `~` and `$HOME` for every later call. The allow-operand grading expands both to the
// gate's own home, which is only right while no command may have reassigned it.
// ============================================================================

/** The ways a shell command may assign `HOME`, each matched as text. */
const HOME_ASSIGNMENTS = {
	/** `HOME=…` or `HOME+=…`, not a read such as `$HOME=` or a longer name. */
	plain: String.raw`(?<![\w$])HOME\s*\+?=`,
	/** The `${HOME:=…}` and `${HOME=…}` default expansions, which assign when `HOME` is unset. */
	defaulted: String.raw`\$\{HOME:?=`,
	/** A builtin that declares, reads into or unsets a variable named on its line. */
	builtin: String.raw`\b(?:export|declare|typeset|readonly|local|read|mapfile|readarray|unset)\b[^\n;&|]*(?<![\w\${])HOME\b`,
	/** A loop variable. */
	loop: String.raw`\bfor\s+HOME\b`,
	/** `printf -v HOME`. */
	printfTarget: String.raw`-v\s*HOME\b`,
} as const;

/** Matches text that may assign `HOME`; over-matching only refuses home-relative admissions. */
const HOME_ASSIGNMENT = new RegExp(Object.values(HOME_ASSIGNMENTS).join("|"));

/** Returns whether a command text may assign `HOME`. */
export function assignsHome(command: string): boolean {
	return HOME_ASSIGNMENT.test(command);
}

/** The part of the host session a HOME scan reads: the branch of past entries. */
export interface BranchSource {
	getBranch(): readonly unknown[];
}

/**
 * Returns whether this call's command, or the command of any earlier tool call on the session branch, may
 * assign `HOME`. Fails closed: a branch the host cannot hand over counts as reassigned.
 */
export function homeReassignedInSession(host: BranchSource, input: Readonly<Record<string, unknown>>): boolean {
	if (typeof input.command === "string" && assignsHome(input.command)) return true;
	let branch: readonly unknown[];
	try {
		if (typeof host.getBranch !== "function") return true;
		branch = host.getBranch();
	} catch {
		return true;
	}
	return branch.some((entry) => toolCallCommands(entry).some(assignsHome));
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

/** Returns `fn`'s value, computed on the first call only, so the branch is scanned at most once per call. */
export function once<T>(fn: () => T): () => T {
	let computed: { value: T } | null = null;
	return () => {
		computed ??= { value: fn() };
		return computed.value;
	};
}
