import type { UiContext } from "./subagent.ts";

// ============================================================================
// The root session's UI, shared by every session in the process
// ============================================================================

// Both values are module-level on purpose: the host builds one extension instance per session, subagent sessions
// included, and module variables are what those instances share. A subagent has no UI of its own, so its asks
// reach the user through the root session's UI, one dialog at a time.

let rootUi: UiContext | null = null;
let dialogTail: Promise<void> = Promise.resolve();

/** The UI of the top-level interactive session in this process; null while that session is headless or gone. */
export function currentRootUi(): UiContext | null {
	return rootUi;
}

/** Publishes a root session's UI, or clears it for a headless root; a replaced root (`/new`, `/resume`) overwrites
 *  it. Returns the published value, which the session hands back to `releaseRootUi`. */
export function publishRootUi(ui: UiContext | null): UiContext | null {
	rootUi = ui;
	return ui;
}

/** Clears the root UI at session shutdown, only when it still holds the one this session published. */
export function releaseRootUi(published: UiContext | null): void {
	if (published !== null && rootUi === published) rootUi = null;
}

/** Runs dialogs one after another, so asks from several sessions never open over each other on the root UI. */
export function serializeDialog<T>(fn: () => Promise<T>): Promise<T> {
	const run = dialogTail.then(fn, fn);
	dialogTail = run.then(
		() => undefined,
		() => undefined,
	);
	return run;
}
