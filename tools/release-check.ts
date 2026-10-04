// Release gate (local, pre-tag; deliberately not in CI): the version, the annotated tag, and the
// tag's commit must agree. ci.yml pushes are untagged (fetch-depth 1) and would fail here;
// publish.yml already double-checks tag == version.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

/**
 * `git <args>` as a trimmed string, or null when git fails (missing tag, not a repo). A null lets
 * the caller report a specific failure instead of a stack trace.
 */
function gitOrNull(args: string[]): string | null {
	try {
		return execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
	} catch {
		return null;
	}
}

function main(): void {
	const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
	const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8")) as { version: string };
	const version = pkg.version;
	const tag = `v${version}`;
	function fail(msg: string): never {
		console.error(`release-check: ${msg}`);
		process.exit(1);
	}

	if (gitOrNull(["tag", "-l", tag]) !== tag) fail(`tag ${tag} does not exist`);

	const tagType = gitOrNull(["cat-file", "-t", tag]);
	if (tagType !== "tag") fail(`tag ${tag} is not annotated (type ${tagType ?? "unknown"})`);

	const taggedPkg = gitOrNull(["show", `${tag}:package.json`]);
	if (taggedPkg === null) fail(`cannot read package.json at ${tag}`);
	const taggedVersion = (JSON.parse(taggedPkg) as { version: string }).version;
	if (taggedVersion !== version) fail(`tag ${tag} carries version ${taggedVersion}, but package.json says ${version}`);

	const tagCommit = gitOrNull(["rev-parse", `${tag}^{commit}`]);
	if (tagCommit === null) {
		console.error(`release-check: cannot resolve ${tag}^{commit}`);
		process.exit(1);
	}
	const head = gitOrNull(["rev-parse", "HEAD"]);
	console.log(`release-check: ok — ${tag} (annotated, commit ${tagCommit.slice(0, 12)}) matches package.json ${version}`);
	if (head !== tagCommit) {
		console.error(`release-check: note: HEAD ${head?.slice(0, 12) ?? "?"} is not the tag commit (bump commit not HEAD)`);
	}
}

main();
