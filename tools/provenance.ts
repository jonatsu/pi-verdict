// Provenance: sha256 of the committed extension blobs at HEAD.
//
// The hand-back is this output plus the HEAD sha. It matches the consumer's staged check exactly:
//   git show <sha>:<path> | sha256sum
// Nothing here is CI-gated; it is a local pin artifact, so a dirty working tree only warns
// (stderr) and the exit code stays 0.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";

function main(): void {
	const git = (args: string[]): Buffer => execFileSync("git", args, { maxBuffer: 64 * 1024 * 1024 });
	const head = git(["rev-parse", "HEAD"]).toString("utf8").trim();
	console.log(`HEAD ${head}`);
	// Every committed blob under extensions/, so a new module joins the pin without an edit here.
	const files = git(["ls-tree", "-r", "--name-only", "HEAD", "--", "extensions/"])
		.toString("utf8")
		.split("\n")
		.filter((file) => file !== "");
	if (files.length === 0) {
		console.error("provenance: no files under extensions/ at HEAD");
		process.exitCode = 1;
		return;
	}
	let dirty = false;
	for (const file of files) {
		let blob: Buffer;
		try {
			blob = git(["cat-file", "blob", `HEAD:${file}`]);
		} catch {
			console.error(`provenance: ${file} not found at HEAD`);
			process.exitCode = 1;
			return;
		}
		console.log(`${createHash("sha256").update(blob).digest("hex")}  ${file}`);
		// Warn (do not fail) when the working tree differs from the committed blob.
		try {
			const work = fs.readFileSync(file);
			if (!work.equals(blob)) {
				dirty = true;
				console.error(`provenance: warning: ${file} differs from the HEAD blob (dirty tree or CRLF)`);
			}
		} catch {
			dirty = true;
			console.error(`provenance: warning: ${file} missing in the working tree`);
		}
	}
	if (dirty) console.error(`provenance: working tree differs from HEAD; the hashes above are the committed blobs`);
}

main();
