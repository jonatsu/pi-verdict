// Probe fixtures: a real filesystem tree, built fresh per run under the OS temp dir.
//
// The tree exists so that path-layer cases exercise the kernel's own resolution (symlinks,
// `..`, dangling links, loops) rather than the gate's lexical guess. Committed fixture trees
// are deliberately avoided: a symlink in a git checkout breaks on Windows and pollutes the
// repo working tree. Cleanup uses rmSync with force, which unlinks symlinks without
// following them — a link to `/` must never be traversed during teardown.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/** The fixture tree handed to `buildCases`. Every member is an absolute path. */
export interface FixtureTree {
	/** mkdtemp root; all other members live under it. */
	root: string;
	/** Per-case cwd (must exist). */
	work: string;
	/** `<root>/escape/link` → `/` (kernel-escape link; prefix `..` escapes it). */
	escapeLink: string;
	/** `<root>/subLink` → `<root>/protected/sub` (an existing directory). */
	subLink: string;
	/** `<root>/link\name` → `/` (a filename containing a backslash, legal on POSIX). */
	backslashLink: string;
	/** `<root>/dangling` → `<agentDir>/config/pi-verdict-trust.json` (protected and missing). */
	dangling: string;
	/** `<root>/loop` → `loop` (self-referential symlink). */
	loop: string;
	/** `<root>/xdg` root of an XDG_CONFIG_HOME tree. */
	xdg: string;
	/** Whether the symlink members were created (POSIX only). */
	hasSymlinks: boolean;
}

/** POSIX only: the symlink members and `.config` fixture tree are not created on win32. */
const POSIX = process.platform !== "win32";

function mkdirp(p: string): void {
	fs.mkdirSync(p, { recursive: true });
}

function writeFile(p: string, content: string): void {
	mkdirp(path.dirname(p));
	fs.writeFileSync(p, content);
}

/**
 * Build the fixture tree under a fresh `mkdtemp` root. The caller owns the returned root and
 * must call `cleanupFixtures(root)`; the temp dir is never a relative path (a crash must not
 * leave symlinks inside the repo checkout).
 */
export function buildFixtures(agentDir: string): FixtureTree {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), ".pv-probe-"));
	// A relative or surprising root would defeat the "escape" fixtures and, worse, could
	// leave symlinks-to-`/` inside the checkout; refuse anything not under the OS temp dir.
	const tmp = path.resolve(os.tmpdir());
	if (!path.resolve(root).startsWith(tmp + path.sep)) {
		throw new Error(`probe fixtures: mkdtemp root ${root} is not under ${tmp}`);
	}

	const work = path.join(root, "work");
	mkdirp(work);

	// Ordinary project files: a relative path that exists must keep the verdict it always had.
	writeFile(path.join(work, "README.md"), "readme\n");
	writeFile(path.join(work, "src", "a.ts"), "export {};\n");
	writeFile(path.join(work, "@my-file.txt"), "literal\n");

	// Plain files/dirs the path-tier cases name.
	writeFile(path.join(root, "repo", ".config", "age", "data"), "repo-config-age\n");
	writeFile(path.join(root, "foo.config", "age", "data"), "foo-config-age\n");
	mkdirp(path.join(root, "repo", ".git", "hooks"));
	writeFile(path.join(root, "protected", "secret"), "protected-secret\n");
	mkdirp(path.join(root, "protected", "sub"));
	writeFile(path.join(root, "gnupghome", "pubring.kbx"), "gnupghome-keyring\n");
	mkdirp(path.join(root, "escape"));

	// XDG_CONFIG_HOME tree: the homes the item-9 cases name.
	writeFile(path.join(root, "xdg", "age", "key.txt"), "xdg-age-key\n");
	writeFile(path.join(root, "xdg", "gnupg", "pubring.kbx"), "xdg-gnupg-keyring\n");
	writeFile(path.join(root, "xdg", "sops", "age", "keys.txt"), "xdg-sops-keys\n");
	writeFile(path.join(root, "xdg", "glab-cli", "config.yml"), "xdg-glab-config\n");
	writeFile(path.join(root, "xdg", "gh", "config.yml"), "xdg-gh-config\n");

	const escapeLink = path.join(root, "escape", "link");
	const subLink = path.join(root, "subLink");
	const backslashLink = path.join(root, `${"link"}\\name`);
	const dangling = path.join(root, "dangling");
	const loop = path.join(root, "loop");

	let hasSymlinks = false;
	if (POSIX) {
		fs.symlinkSync("/", escapeLink);
		fs.symlinkSync(path.join(root, "protected", "sub"), subLink);
		fs.symlinkSync("/", backslashLink);
		fs.symlinkSync(path.join(agentDir, "config", "pi-verdict-trust.json"), dangling);
		fs.symlinkSync("loop", loop);
		hasSymlinks = true;
	}

	return {
		root,
		work,
		escapeLink,
		subLink,
		backslashLink,
		dangling,
		loop,
		xdg: path.join(root, "xdg"),
		hasSymlinks,
	};
}

/**
 * Remove the fixture tree. `force` covers an already-removed root; `recursive` is required for
 * the directories. rmSync unlinks symlinks without following them, so the links to `/` and the
 * self-loop are removed safely.
 */
export function cleanupFixtures(root: string): void {
	fs.rmSync(root, { recursive: true, force: true });
}
