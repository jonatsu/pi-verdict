import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { HOME_VARIABLE, MAX_GRADED_OPERANDS } from "./allow-operands.ts";
import { s0NameHits, s0ReadHits } from "./floor.ts";
import type { FloorHit } from "./shell.ts";
import { ASSIGNMENT, PREFIX_WORDS, type SoundPrefix, soundPrefix, wordBasename } from "./shell-words.ts";

// ============================================================================
// Floor: a shell command that reads a secret file (ADR-0014)
// ============================================================================

/** How a reading command uses its positional words. */
type ReadKind =
	| "files" // every positional is a file it reads
	| "pattern" // the first positional is a pattern, script or filter unless an option supplied one
	| "copy" // every positional but the destination is a source
	| "load" // the first positional is loaded into the shell
	| "tar" // in create, append or update mode, the files after the options are sources
	| "zip" // every positional after the archive is a source
	| "7z" // in `a` or `u` mode, every positional after the archive is a source
	| "options"; // only the file-reading option values count

/** One reading command's arguments: the options that take a value, and which of those values are files it
 *  reads. A value-taking option the table lacks is read as a flag, which can only add a deny. */
interface ReaderSpec {
	readonly kind: ReadKind;
	/** Short option letters that take a value, attached or as the next word. */
	readonly short?: string;
	/** Long options that take a value, as `--name=value` or the next word. */
	readonly long?: readonly string[];
	/** The short and long options among them whose value is a file the command reads. */
	readonly fileShort?: string;
	readonly fileLong?: readonly string[];
	/** The options that supply the pattern, so the first positional is a file again. */
	readonly patternShort?: string;
	readonly patternLong?: readonly string[];
	/** Long options that take two values; with `fileSecond`, the second one is a file the command reads. */
	readonly twoValues?: readonly string[];
	readonly fileSecond?: readonly string[];
	/** Options that name the destination, so every positional is a source. */
	readonly targetShort?: string;
	readonly targetLong?: readonly string[];
	/** Short options whose value is a list running to the next option word (zip's `-x`, `-i`). */
	readonly listShort?: string;
	/** Options end at the first positional, which is the command the program runs (xargs). */
	readonly optionsFirst?: boolean;
}

const FILES: ReaderSpec = { kind: "files" };
const HEAD_TAIL: ReaderSpec = {
	kind: "files",
	short: "nc",
	long: ["--lines", "--bytes", "--pid", "--sleep-interval", "--max-unchanged-stats"],
};
const BASE_ENCODE: ReaderSpec = { kind: "files", short: "w", long: ["--wrap"] };
const GREP: ReaderSpec = {
	kind: "pattern",
	short: "ABCDdefm",
	long: [
		"--after-context",
		"--before-context",
		"--context",
		"--devices",
		"--directories",
		"--regexp",
		"--file",
		"--max-count",
		"--label",
		"--group-separator",
		"--include",
		"--exclude",
		"--exclude-dir",
		"--exclude-from",
		"--binary-files",
	],
	fileShort: "f",
	fileLong: ["--file"],
	patternShort: "ef",
	patternLong: ["--regexp", "--file"],
};
const AWK: ReaderSpec = {
	kind: "pattern",
	short: "fFve",
	long: ["--file", "--field-separator", "--assign", "--source", "--include", "--load", "--exec"],
	fileShort: "f",
	fileLong: ["--file", "--exec"],
	patternShort: "fe",
	patternLong: ["--file", "--source", "--exec"],
};
const COPY: ReaderSpec = {
	kind: "copy",
	short: "tS",
	long: ["--target-directory", "--suffix"],
	targetShort: "t",
	targetLong: ["--target-directory"],
};

/** bat, installed as `batcat` on Debian and Ubuntu. */
const BAT: ReaderSpec = {
	kind: "files",
	short: "lHrm",
	long: [
		"--language",
		"--highlight-line",
		"--line-range",
		"--map-syntax",
		"--theme",
		"--style",
		"--tabs",
		"--terminal-width",
		"--wrap",
		"--file-name",
		"--diff-context",
		"--paging",
		"--pager",
		"--color",
		"--decorations",
		"--italic-text",
	],
};

/** The commands that print, transform, copy, load or archive the files they name. */
const READERS: Readonly<Record<string, ReaderSpec>> = {
	cat: FILES,
	tac: { kind: "files", short: "s", long: ["--separator"] },
	nl: { kind: "files", short: "bdfhilnsvw" },
	head: HEAD_TAIL,
	tail: HEAD_TAIL,
	less: { kind: "files", short: "bhjkoOpPtTxyz#" },
	more: { kind: "files", short: "n" },
	bat: BAT,
	batcat: BAT,
	od: {
		kind: "files",
		short: "AjNStw",
		long: ["--address-radix", "--skip-bytes", "--read-bytes", "--strings", "--format", "--width", "--endian"],
	},
	xxd: { kind: "files", short: "cglosn" },
	hexdump: { kind: "files", short: "efns" },
	strings: { kind: "files", short: "ntTe", long: ["--bytes", "--radix", "--encoding", "--target"] },
	base64: BASE_ENCODE,
	base32: BASE_ENCODE,
	cut: { kind: "files", short: "bcdf", long: ["--bytes", "--characters", "--delimiter", "--fields", "--output-delimiter"] },
	sort: {
		kind: "files",
		short: "kotST",
		long: [
			"--key",
			"--output",
			"--field-separator",
			"--temporary-directory",
			"--buffer-size",
			"--parallel",
			"--batch-size",
			"--compress-program",
			"--random-source",
			"--files0-from",
			"--sort",
		],
	},
	uniq: { kind: "files", short: "fsw", long: ["--skip-fields", "--skip-chars", "--check-chars"] },
	diff: {
		kind: "files",
		short: "CUFILSWXx",
		long: [
			"--label",
			"--exclude",
			"--exclude-from",
			"--ignore-matching-lines",
			"--show-function-line",
			"--starting-file",
			"--width",
			"--tabsize",
			"--horizon-lines",
			"--line-format",
			"--from-file",
			"--to-file",
			"--palette",
		],
		fileLong: ["--from-file", "--to-file"],
	},
	cmp: { kind: "files", short: "in", long: ["--ignore-initial", "--bytes"] },
	comm: { kind: "files", long: ["--output-delimiter"] },
	paste: { kind: "files", short: "d", long: ["--delimiters"] },
	fold: { kind: "files", short: "w", long: ["--width"] },
	column: { kind: "files", short: "csoNRHlWEO" },
	grep: GREP,
	egrep: GREP,
	fgrep: GREP,
	rg: {
		...GREP,
		short: "ABCEMTdefgjmrt",
		long: [
			...(GREP.long ?? []),
			"--encoding",
			"--max-columns",
			"--type-not",
			"--glob",
			"--iglob",
			"--threads",
			"--replace",
			"--type",
			"--max-depth",
			"--pre",
			"--pre-glob",
			"--type-add",
			"--sort",
			"--sortr",
			"--color",
			"--colors",
			"--path-separator",
			"--max-filesize",
			"--context-separator",
			"--field-match-separator",
			"--ignore-file",
		],
	},
	ag: {
		kind: "pattern",
		short: "ABCGgmp",
		long: [
			"--ignore",
			"--ignore-dir",
			"--depth",
			"--pager",
			"--file-search-regex",
			"--max-count",
			"--after",
			"--before",
			"--context",
			"--path-to-ignore",
		],
	},
	sed: {
		kind: "pattern",
		short: "efl",
		long: ["--expression", "--file", "--line-length"],
		fileShort: "f",
		fileLong: ["--file"],
		patternShort: "ef",
		patternLong: ["--expression", "--file"],
	},
	awk: AWK,
	gawk: AWK,
	jq: {
		kind: "pattern",
		short: "fL",
		long: ["--from-file", "--indent"],
		fileShort: "f",
		fileLong: ["--from-file"],
		patternShort: "f",
		patternLong: ["--from-file"],
		twoValues: ["--arg", "--argjson", "--slurpfile", "--rawfile"],
		fileSecond: ["--slurpfile", "--rawfile"],
	},
	yq: {
		kind: "pattern",
		short: "Iop",
		long: ["--indent", "--output-format", "--input-format", "--expression", "--from-file"],
		fileLong: ["--from-file"],
		patternLong: ["--expression", "--from-file"],
	},
	cp: COPY,
	mv: COPY,
	scp: { kind: "copy", short: "cDFiJlLoPSX" },
	rsync: {
		kind: "copy",
		short: "eBfMT",
		long: [
			"--rsh",
			"--filter",
			"--exclude",
			"--include",
			"--exclude-from",
			"--include-from",
			"--files-from",
			"--temp-dir",
			"--rsync-path",
			"--password-file",
			"--chmod",
			"--chown",
			"--log-file",
			"--compare-dest",
			"--copy-dest",
			"--link-dest",
			"--partial-dir",
			"--backup-dir",
			"--suffix",
			"--block-size",
			"--max-size",
			"--min-size",
			"--bwlimit",
			"--timeout",
			"--port",
			"--remote-option",
			"--info",
			"--debug",
		],
	},
	tar: {
		kind: "tar",
		short: "fCTXbHVgKNIL",
		long: [
			"--file",
			"--directory",
			"--files-from",
			"--exclude-from",
			"--exclude",
			"--blocking-factor",
			"--format",
			"--label",
			"--listed-incremental",
			"--starting-file",
			"--newer",
			"--newer-mtime",
			"--use-compress-program",
			"--transform",
			"--xform",
			"--owner",
			"--group",
			"--mode",
			"--mtime",
			"--tape-length",
			"--to-command",
			"--exclude-tag",
			"--strip-components",
			"--suffix",
			"--sort",
			"--warning",
		],
	},
	zip: {
		kind: "zip",
		short: "bnOtZP",
		long: [
			"--temp-path",
			"--suffixes",
			"--output-file",
			"--from-date",
			"--before-date",
			"--compression-method",
			"--password",
			"--exclude",
			"--include",
		],
		listShort: "xi",
	},
	"7z": { kind: "7z" },
	"7za": { kind: "7z" },
	"7zz": { kind: "7z" },
	rev: FILES,
	fmt: { kind: "files", short: "pw", long: ["--prefix", "--width"] },
	pr: {
		kind: "files",
		short: "hlNoswW",
		long: ["--header", "--length", "--first-line-number", "--indent", "--separator", "--width", "--page-width"],
	},
	shuf: { kind: "files", short: "ino", long: ["--input-range", "--head-count", "--output", "--random-source"] },
	expand: { kind: "files", short: "t", long: ["--tabs"] },
	unexpand: { kind: "files", short: "t", long: ["--tabs"] },
	join: { kind: "files", short: "eot12j" },
	install: { ...COPY, short: "gmoSt", long: ["--group", "--mode", "--owner", "--suffix", "--target-directory"] },
	sqlite3: { kind: "options" },
	sqlite: { kind: "options" },
	openssl: { kind: "options" },
	source: { kind: "load" },
	".": { kind: "load" },
	dd: { kind: "options" },
	curl: { kind: "options" },
	wget: { kind: "options" },
	gh: { kind: "options" },
};

const XARGS_LONG = [
	"--arg-file",
	"--delimiter",
	"--eof",
	"--replace",
	"--max-lines",
	"--max-args",
	"--max-procs",
	"--max-chars",
	"--process-slot-var",
];

/** xargs's own options, read up to the command it runs; its `-a` value is a file it reads. */
const XARGS: ReaderSpec = {
	kind: "options",
	short: "adEILnPs",
	long: XARGS_LONG,
	fileShort: "a",
	fileLong: ["--arg-file"],
	optionsFirst: true,
};

/** A wrapper's options that take a value, and how many positional words it reads before the command it runs. */
interface WrapperSpec {
	readonly short: string;
	readonly long?: readonly string[];
	/** Positional words before the command: timeout's duration, ssh's host. */
	readonly leading: number;
	/** `env` also takes variable assignments before the command. */
	readonly assignments?: boolean;
}

/** Commands that run the command after their own options, so a reading command behind them still reads. */
const WRAPPERS: Readonly<Record<string, WrapperSpec>> = {
	sudo: {
		short: "ugCDhpRrtTU",
		long: ["--user", "--group", "--close-from", "--chdir", "--host", "--prompt", "--role", "--type", "--command-timeout", "--other-user"],
		leading: 0,
	},
	doas: { short: "uC", leading: 0 },
	env: { short: "uCaS", long: ["--unset", "--chdir", "--argv0"], leading: 0, assignments: true },
	timeout: { short: "sk", long: ["--signal", "--kill-after"], leading: 1 },
	nice: { short: "n", long: ["--adjustment"], leading: 0 },
	ionice: { short: "cnpPu", long: ["--class", "--classdata", "--pid", "--pgid", "--uid"], leading: 0 },
	nohup: { short: "", leading: 0 },
	time: { short: "fo", long: ["--format", "--output"], leading: 0 },
	command: { short: "", leading: 0 },
	stdbuf: { short: "ioe", long: ["--input", "--output", "--error"], leading: 0 },
	exec: { short: "a", leading: 0 },
	builtin: { short: "", leading: 0 },
	setsid: { short: "", leading: 0 },
	busybox: { short: "", leading: 0 },
	flock: { short: "wE", long: ["--timeout", "--conflict-exit-code"], leading: 1 },
	xargs: { short: XARGS.short ?? "", long: XARGS_LONG, leading: 0 },
	ssh: { short: "BbcDEeFIiJLlmOoPpQRSWw", leading: 1 },
};

/** yq's subcommands, which come before its expression. */
const YQ_SUBCOMMANDS: ReadonlySet<string> = new Set(["e", "eval", "ea", "eval-all"]);

/** tar's modes that read the files they name. */
const TAR_READ_MODES = /[cru]/;
const TAR_LONG_READ_MODES = ["--create", "--append", "--update"];

/** curl options whose `@file` value it sends, and the options that send a file whatever its spelling. */
const CURL_AT_FILE = new Set(["-d", "--data", "--data-binary", "--data-ascii", "--json", "-H", "--header"]);
const CURL_FORM = new Set(["-F", "--form"]);
const CURL_UPLOAD = new Set(["-T", "--upload-file"]);
/** curl's short options that take a value; the first of them in a bundle takes the rest of it. */
const CURL_SHORT_WITH_VALUE = "AbcCdDeEFHKmoPQrtTuUwxXyYz";
const WGET_UPLOAD = new Set(["--post-file", "--body-file"]);

/** sqlite shell options that take the next word, which is no file. */
const SQLITE_VALUES = new Set([
	"-cmd",
	"-separator",
	"-newline",
	"-nullvalue",
	"-escape",
	"-maxsize",
	"-mmap",
	"-pagecache",
	"-lookaside",
	"-heap",
	"-vfs",
]);
/** openssl options whose value is a file it reads. */
const OPENSSL_FILES = new Set(["-in", "-inkey", "-key", "-kfile", "-CAkey", "-signkey"]);

const SHELL_RECURSION_DEPTH = 3;

/** Glob entries examined per call; past it, globs are left to the classifier, so a large directory cannot stall
 *  the gate. */
const GLOB_NAME_LIMIT = 4096;

/** Directories beyond the command cwd a relative operand is also graded from when the working directory is
 *  unknown. */
const MAX_CD_TARGETS = 8;

/** Where a shell command's relative operands resolve, and what the session's shell may have changed. */
export interface ReadContext {
	/** The directory the call names for the command. */
	readonly commandCwd: string;
	/** The directory the command runs in after a leading `cd X &&`, or null when it is unknown. */
	readonly workingDirectory: string | null;
	/** An earlier command of the session may have reassigned `HOME`. */
	readonly homeReassigned: boolean;
}

/** The operands one reading command reads, parsed from the words after it. */
interface ParsedArgs {
	readonly positionals: string[];
	readonly files: string[];
	readonly patternGiven: boolean;
	readonly targetGiven: boolean;
}

/** Parses the words after a reading command by its spec: options and their values, then positionals. */
function parseArgs(args: readonly string[], spec: ReaderSpec): ParsedArgs {
	const parsed: ParsedArgs = { positionals: [], files: [], patternGiven: false, targetGiven: false };
	const flags = { pattern: false, target: false };
	let optionsEnded = false;
	for (let k = 0; k < args.length; k++) {
		const word = args[k];
		if (optionsEnded || word === "-" || !word.startsWith("-")) {
			parsed.positionals.push(word);
			if (spec.optionsFirst) break;
			continue;
		}
		if (word === "--") {
			optionsEnded = true;
			continue;
		}
		k = word.startsWith("--") ? longOption(args, k, spec, parsed, flags) : shortOption(args, k, spec, parsed, flags);
	}
	return { ...parsed, patternGiven: flags.pattern, targetGiven: flags.target };
}

/** Reads one long option at `args[k]` and returns the index of its last word. */
function longOption(
	args: readonly string[],
	k: number,
	spec: ReaderSpec,
	parsed: ParsedArgs,
	flags: { pattern: boolean; target: boolean },
): number {
	const word = args[k];
	const eq = word.indexOf("=");
	const name = eq === -1 ? word : word.slice(0, eq);
	let at = k;
	if (spec.twoValues?.includes(name)) {
		const second = args[at + 2];
		if (second !== undefined && spec.fileSecond?.includes(name)) parsed.files.push(second);
		return at + 2;
	}
	const takes = spec.long?.includes(name) || spec.fileLong?.includes(name) || spec.patternLong?.includes(name);
	if (!takes) return at;
	const value = eq === -1 ? args[++at] : word.slice(eq + 1);
	if (value === undefined) return at;
	if (spec.fileLong?.includes(name)) parsed.files.push(value);
	if (spec.patternLong?.includes(name)) flags.pattern = true;
	if (spec.targetLong?.includes(name)) flags.target = true;
	return at;
}

/** Reads one short option bundle at `args[k]` and returns the index of its last word. */
function shortOption(
	args: readonly string[],
	k: number,
	spec: ReaderSpec,
	parsed: ParsedArgs,
	flags: { pattern: boolean; target: boolean },
): number {
	const word = args[k];
	let at = k;
	for (let c = 1; c < word.length; c++) {
		const letter = word[c];
		if (spec.listShort?.includes(letter)) {
			while (args[at + 1] !== undefined && !args[at + 1].startsWith("-")) at++;
			return at;
		}
		const takes = spec.short?.includes(letter) || spec.fileShort?.includes(letter) || spec.patternShort?.includes(letter);
		if (!takes) continue;
		const rest = word.slice(c + 1);
		const value = rest !== "" ? rest : args[++at];
		if (value === undefined) return at;
		if (spec.fileShort?.includes(letter)) parsed.files.push(value);
		if (spec.patternShort?.includes(letter)) flags.pattern = true;
		if (spec.targetShort?.includes(letter)) flags.target = true;
		return at;
	}
	return at;
}

/** The words a reading command at `seg[at]` reads as files. */
function readWords(seg: readonly string[], at: number): string[] {
	const name = wordBasename(seg[at]);
	const spec = READERS[name];
	const args = seg.slice(at + 1);
	if (name === "dd") return args.filter((w) => w.startsWith("if=")).map((w) => w.slice(3));
	if (name === "curl") return curlFiles(args);
	if (name === "sqlite3" || name === "sqlite") return sqliteFiles(args);
	if (name === "openssl") return valuesOf(args, OPENSSL_FILES);
	if (name === "wget") return valuesOf(args, WGET_UPLOAD);
	if (name === "gh")
		return args[0] === "gist" && args[1] === "create"
			? parseArgs(args.slice(2), { kind: "files", short: "df", long: ["--desc", "--filename"] }).positionals.filter((w) => w !== "-")
			: [];
	const parsed = parseArgs(args, spec);
	const { positionals, files } = parsed;
	switch (spec.kind) {
		case "files":
			return [...positionals, ...files];
		case "pattern": {
			const rest = name === "yq" && YQ_SUBCOMMANDS.has(positionals[0] ?? "") ? positionals.slice(1) : positionals;
			return [...(parsed.patternGiven ? rest : rest.slice(1)), ...files];
		}
		case "copy":
			return parsed.targetGiven ? positionals : positionals.slice(0, -1);
		case "load":
			return positionals.slice(0, 1);
		case "zip":
			return positionals.slice(1);
		case "7z":
			return ["a", "u"].includes(positionals[0] ?? "") ? positionals.slice(2) : [];
		case "options":
			return files;
		case "tar":
			return tarSources(args, spec);
		default: {
			const unknown: never = spec.kind;
			return unknown;
		}
	}
}

/** The sources a tar in create, append or update mode reads; none in any other mode. An old-style first
 *  word (`czf`) is a bundle whose value letters take the next words in order. */
function tarSources(args: readonly string[], spec: ReaderSpec): string[] {
	let rest = args;
	let reads = false;
	if (args[0] !== undefined && !args[0].startsWith("-")) {
		const bundle = args[0];
		reads = TAR_READ_MODES.test(bundle);
		const values = [...bundle].filter((letter) => spec.short?.includes(letter)).length;
		rest = args.slice(1 + values);
	}
	const parsed = parseArgs(rest, spec);
	reads ||= rest.some((w) => (/^-[A-Za-z]+$/.test(w) && TAR_READ_MODES.test(w.slice(1))) || TAR_LONG_READ_MODES.includes(w));
	return reads ? parsed.positionals : [];
}

/** The database an sqlite shell opens, its first positional, and an `-init` file it reads. Its options take a
 *  single dash; those in `SQLITE_VALUES` take the next word. */
function sqliteFiles(args: readonly string[]): string[] {
	const files: string[] = [];
	for (let k = 0; k < args.length; k++) {
		const word = args[k].replace(/^--(?=[a-z])/, "-"); // sqlite accepts each option with one dash or two
		if (word === "-init" && args[k + 1] !== undefined) files.push(args[++k]);
		else if (SQLITE_VALUES.has(word)) k++;
		else if (!args[k].startsWith("-")) {
			files.push(args[k]);
			break;
		}
	}
	return files;
}

/** The values of the named options among `args`, as the next word or after `=`. */
function valuesOf(args: readonly string[], names: ReadonlySet<string>): string[] {
	const values: string[] = [];
	for (let k = 0; k < args.length; k++) {
		const word = args[k];
		const eq = word.indexOf("=");
		if (word.startsWith("--") && eq !== -1 && names.has(word.slice(0, eq))) values.push(word.slice(eq + 1));
		else if (names.has(word) && args[k + 1] !== undefined) values.push(args[++k]);
	}
	return values;
}

/** The files curl sends: an `@file` data or header value, a form field's `@file` or `<file`, a
 *  `--data-urlencode` `@file` or `name@file`, an upload, and a `file://` URL, whose local file it prints. `--data-raw`
 *  sends its text as written. */
function curlFiles(args: readonly string[]): string[] {
	const files: string[] = [];
	const option = (name: string, value: string): void => {
		if (CURL_AT_FILE.has(name) && value.startsWith("@")) files.push(value.slice(1));
		else if (CURL_UPLOAD.has(name)) files.push(value);
		else if (CURL_FORM.has(name)) {
			const field = /^[^=]*=[@<]([^;]*)/.exec(value);
			if (field) files.push(field[1]);
		} else if (name === "--data-urlencode") {
			const at = value.indexOf("@");
			if (at !== -1 && !value.slice(0, at).includes("=")) files.push(value.slice(at + 1));
		}
	};
	for (let k = 0; k < args.length; k++) {
		const word = args[k];
		const eq = word.indexOf("=");
		if (word.startsWith("--") && eq !== -1) option(word.slice(0, eq), word.slice(eq + 1));
		else if (word.startsWith("--") || word.length === 2) {
			if (
				args[k + 1] !== undefined &&
				(CURL_AT_FILE.has(word) || CURL_FORM.has(word) || CURL_UPLOAD.has(word) || word === "--data-urlencode")
			)
				option(word, args[++k]);
		} else if (/^-[A-Za-z]/.test(word)) {
			// A bundle (`-sSd @f`): the first short option that takes a value takes the rest, or the next word.
			const at = [...word.slice(1)].findIndex((c) => CURL_SHORT_WITH_VALUE.includes(c)) + 1;
			if (at === 0) continue;
			const value = at + 1 < word.length ? word.slice(at + 1) : args[++k];
			if (value !== undefined) option(`-${word[at]}`, value);
		} else if (word.toLowerCase().startsWith("file://")) files.push(decodeFileUrl(word));
	}
	return files.filter((f) => f !== "-" && f !== "");
}

/** The index of the word after a wrapper's options, assignments and leading positionals: the command it runs. */
function afterWrapper(words: readonly string[], at: number, spec: WrapperSpec): number {
	let leading = spec.leading;
	let optionsEnded = false;
	for (let k = at + 1; k < words.length; k++) {
		const word = words[k];
		if (!optionsEnded && word === "--") optionsEnded = true;
		else if (!optionsEnded && word.startsWith("-") && word.length > 1) {
			const eq = word.indexOf("=");
			const takesNext = word.startsWith("--")
				? eq === -1 && (spec.long?.includes(word) ?? false)
				: [...word.slice(1)].findIndex((c) => spec.short.includes(c)) === word.length - 2;
			if (takesNext) k++;
		} else if (spec.assignments && ASSIGNMENT.test(word)) continue;
		else if (leading > 0) leading--;
		else return k;
	}
	return words.length;
}

/**
 * Returns the words one simple command reads as files: the operands of its command word when that is a reading
 * command, found past assignments, reserved words (`then`, `do`, `{`) and wrappers with their options
 * (`timeout 30 cat`, `ssh -p 22 host cat`), plus the `-a` file of an `xargs` among those wrappers. A word in an
 * argument position is never taken for the command, so `timeout 30 find . -name .env` reads nothing.
 */
function readingWords(words: readonly string[]): string[] {
	const read: string[] = [];
	let k = 0;
	while (k < words.length && (ASSIGNMENT.test(words[k]) || PREFIX_WORDS.has(words[k]))) k++;
	while (k < words.length) {
		const name = wordBasename(words[k]);
		const wrapper = Object.hasOwn(WRAPPERS, name) ? WRAPPERS[name] : undefined;
		if (wrapper === undefined) {
			if (Object.hasOwn(READERS, name)) read.push(...readWords(words, k));
			break;
		}
		if (name === "xargs") read.push(...parseArgs(words.slice(k + 1), XARGS).files);
		k = afterWrapper(words, k, wrapper);
	}
	return read;
}

/** The literal parts of one operand word, after the shell's expansion of a leading `~` and `$HOME`. */
interface Spelling {
	readonly text: string;
	readonly homeRelative: boolean;
}

function spelled(word: string): Spelling {
	const home = os.homedir();
	const viaTilde = word === "~" || word.startsWith("~/");
	// The shell's own process is `self` from where it reads, so `/proc/$$/environ` is its environment.
	const replaced = word.replace(HOME_VARIABLE, () => home);
	const text = (viaTilde ? home + replaced.slice(1) : replaced).replace(/^\/proc\/(?:\$\$|\$BASHPID|\$\{BASHPID\})\//, "/proc/self/");
	return { text, homeRelative: viaTilde || replaced !== word };
}

/** Grades the operands of one command's reading words and redirections against S0, sharing one budget of
 *  full gradings per call; past it, an operand is graded by its spelling. */
class OperandGrader {
	private formsLeft = MAX_GRADED_OPERANDS;
	private namesLeft = GLOB_NAME_LIMIT;
	private readonly graded = new Set<string>();
	private readonly listings = new Map<string, readonly string[] | null>();
	readonly hits: FloorHit[] = [];

	/** `bases` are the directories a relative operand may resolve from: the known working directory, or when it
	 *  is unknown the command cwd and each literal `cd` target of the command. */
	constructor(
		private readonly where: ReadContext,
		private readonly bases: readonly string[],
	) {}

	/** Grades one operand word as a file the command reads. */
	grade(word: string): void {
		if (word === "" || word === "-") return;
		const { text, homeRelative } = spelled(word);
		const expansion = text.search(/[$*?[{]|^~/);
		if (expansion === -1) {
			if (homeRelative && this.where.homeReassigned) this.byName(text);
			else if (path.isAbsolute(text)) this.fully(text, ["/"]);
			else {
				if (this.where.workingDirectory === null) this.byName(text);
				this.fully(text, this.bases);
			}
			return;
		}
		const lastSlash = text.lastIndexOf("/");
		const literalDir = !/[$*?[{~]/.test(text.slice(0, lastSlash + 1)) && !/[${~]/.test(text.slice(lastSlash + 1));
		if (literalDir && !(homeRelative && this.where.homeReassigned)) {
			this.globbed(text.slice(0, lastSlash + 1), text.slice(lastSlash + 1));
			return;
		}
		// An expansion in the directory part: the literal tail after it still names the file.
		const last = Math.max(...["$", "*", "?", "[", "{", "}", "~"].map((c) => text.lastIndexOf(c)));
		const tail = text.indexOf("/", last);
		if (tail !== -1) this.byName(text.slice(tail));
	}

	/** Grades a path as written, from each of `bases`, in every canonical form while the budget lasts, each pair
	 *  once; past the budget, by its spelling. One operand spends one unit however many bases it is graded from.
	 *  The text keeps its `..`, so the kernel walk resolves a symlink before it. */
	private fully(text: string, bases: readonly string[]): void {
		const fresh = bases.filter((base) => !this.graded.has(`${base}\0${text}`));
		if (fresh.length === 0) return;
		for (const base of fresh) this.graded.add(`${base}\0${text}`);
		const spend = this.formsLeft > 0;
		if (spend) this.formsLeft--;
		for (const base of fresh) {
			if (!spend) {
				this.byName(path.resolve(base, text));
				continue;
			}
			const { rules, forms } = s0ReadHits(text, base);
			for (const rule of rules) this.hits.push({ rule, reason: `rule ${rule}: shell command reads a secret file`, forms });
		}
	}

	/** A hit by spelling alone carries no forms, so only an unscoped override lifts it. */
	private byName(text: string): void {
		for (const rule of s0NameHits(text)) this.hits.push({ rule, reason: `rule ${rule}: shell command reads a secret file`, forms: [] });
	}

	/** Expands a glob in the last segment of a literal directory as bash does by default: case-sensitive, a
	 *  leading dot matched only by a pattern that starts with one, and nothing when nothing matches. Past
	 *  `GLOB_NAME_LIMIT` names examined in one call, globs are left to the classifier. */
	private globbed(dir: string, pattern: string): void {
		const tokens = globTokens(pattern);
		if (tokens === null) return;
		const hidden = pattern.startsWith(".");
		for (const base of path.isAbsolute(dir) ? ["/"] : this.bases) {
			if (this.namesLeft <= 0) return;
			// Joined as text, so the directory read follows a symlink before a `..` as the shell does.
			const names = this.listing(path.isAbsolute(dir) ? dir : `${base}/${dir}`);
			if (names === null) continue;
			for (const name of names) {
				if (this.namesLeft-- <= 0) return;
				if ((hidden || !name.startsWith(".")) && globMatches(tokens, name)) this.fully(dir + name, [base]);
			}
		}
	}

	private listing(dir: string): readonly string[] | null {
		const cached = this.listings.get(dir);
		if (cached !== undefined) return cached;
		let names: readonly string[] | null;
		try {
			names = fs.readdirSync(dir);
		} catch {
			names = null;
		}
		this.listings.set(dir, names);
		return names;
	}
}

/** One element of a one-segment glob: a run of `*`, or a test for a single character. */
type GlobToken = { readonly kind: "star" } | { readonly kind: "char"; readonly test: (c: string) => boolean };

/** Parses a one-segment glob, or returns null for a form this does not model: an unclosed bracket, a
 *  character class (`[[:alpha:]]`), a backslash or a reversed range. A `]` right after `[` or `[!` is a member. */
function globTokens(pattern: string): GlobToken[] | null {
	const tokens: GlobToken[] = [];
	for (let k = 0; k < pattern.length; k++) {
		const c = pattern[k];
		if (c === "\\") return null;
		if (c === "*") {
			if (tokens.at(-1)?.kind !== "star") tokens.push({ kind: "star" });
		} else if (c === "?") tokens.push({ kind: "char", test: () => true });
		else if (c === "[") {
			let j = k + 1;
			const negate = pattern[j] === "!" || pattern[j] === "^";
			if (negate) j++;
			const members: [string, string][] = [];
			for (let first = true; j < pattern.length && (first || pattern[j] !== "]"); first = false) {
				if (pattern[j] === "[" || pattern[j] === "\\") return null;
				const ranged = pattern[j + 1] === "-" && pattern[j + 2] !== undefined && pattern[j + 2] !== "]";
				const range: [string, string] = ranged ? [pattern[j], pattern[j + 2]] : [pattern[j], pattern[j]];
				if (range[0] > range[1]) return null;
				members.push(range);
				j += ranged ? 3 : 1;
			}
			if (j >= pattern.length) return null;
			tokens.push({ kind: "char", test: (ch) => negate !== members.some(([lo, hi]) => ch >= lo && ch <= hi) });
			k = j;
		} else tokens.push({ kind: "char", test: (ch) => ch === c });
	}
	return tokens;
}

/** Whether a name matches glob tokens. Greedy, backtracking only to the last star, so the cost is bounded by
 *  the name's length times the pattern's, never exponential. */
function globMatches(tokens: readonly GlobToken[], name: string): boolean {
	let t = 0;
	let s = 0;
	let star = -1;
	let resume = 0;
	while (s < name.length) {
		const token = tokens[t];
		if (token?.kind === "char" && token.test(name[s])) {
			t++;
			s++;
		} else if (token?.kind === "star") {
			star = t++;
			resume = s;
		} else if (star !== -1) {
			t = star + 1;
			s = ++resume;
		} else return false;
	}
	while (tokens[t]?.kind === "star") t++;
	return t === tokens.length;
}

/**
 * Returns a hit for each S0 entry a file the command reads hits (ADR-0014): an operand of a reading command
 * (`cat`, `grep -f`, `cp` sources, `source`, `curl -d @…`), also behind a wrapper or inside an `sh -c`
 * script, and the target of an input redirection. Only the simple commands before the first unsound word
 * are read. Adds denies only: an operand the gate cannot expand is left to the classifier.
 */
export function secretReads(command: string, where: ReadContext): readonly FloorHit[] {
	const prefix = soundPrefix(command);
	const bases = where.workingDirectory !== null ? [where.workingDirectory] : directoryBases(prefix, where);
	const grader = new OperandGrader(where, bases);
	gradePrefix(prefix, grader, 0);
	return grader.hits;
}

/** The directories a relative operand may resolve from when the working directory is unknown: the command cwd,
 *  then the literal `cd` and `pushd` targets of the command and its `sh -c` scripts, at most `MAX_CD_TARGETS`.
 *  Absolute and home targets come first, so relative decoys cannot crowd them out; a relative target is resolved
 *  from the target before it (`cd ~/.config && cd gh` reaches `~/.config/gh`) and from the command cwd. */
function directoryBases(prefix: SoundPrefix, where: ReadContext): string[] {
	const absolute: string[] = [];
	const chained: string[] = [];
	const fromCwd: string[] = [];
	let latest = where.commandCwd;
	for (const text of cdTargets(prefix, where, 0)) {
		latest = path.resolve(latest, text);
		if (path.isAbsolute(text)) absolute.push(latest);
		else {
			chained.push(latest);
			fromCwd.push(path.resolve(where.commandCwd, text));
		}
	}
	const bases = [where.commandCwd];
	for (const dir of [...absolute, ...chained, ...fromCwd]) {
		if (bases.length > MAX_CD_TARGETS) break;
		if (!bases.includes(dir)) bases.push(dir);
	}
	return bases;
}

/** `cd` and `pushd` options that come before the directory: `-P`, `-L`, `-e`, `-@`, pushd's `-n`, and `--`. */
const CD_OPTION = /^-(?:[PLe@n]+|-)$/;

/** The literal `cd` and `pushd` targets in order, home expanded; a target with an expansion is skipped. */
function cdTargets(prefix: SoundPrefix, where: ReadContext, depth: number): string[] {
	const targets: string[] = [];
	for (const words of prefix.commands) {
		let at = words.findIndex((word) => !ASSIGNMENT.test(word) && !PREFIX_WORDS.has(word));
		if (at === -1 || !["cd", "pushd"].includes(words[at])) continue;
		do at++;
		while (at < words.length && CD_OPTION.test(words[at]));
		const target = words[at];
		if (target === undefined || target.startsWith("-") || target.startsWith("+")) continue;
		const { text, homeRelative } = spelled(target);
		if (!/[$*?[{~]/.test(text) && !(homeRelative && where.homeReassigned)) targets.push(text);
	}
	if (depth < SHELL_RECURSION_DEPTH) for (const script of prefix.scripts) targets.push(...cdTargets(soundPrefix(script), where, depth + 1));
	return targets;
}

function gradePrefix(prefix: SoundPrefix, grader: OperandGrader, depth: number): void {
	for (const words of prefix.commands) for (const word of readingWords(words)) grader.grade(word);
	for (const input of prefix.inputs) grader.grade(input);
	if (depth >= SHELL_RECURSION_DEPTH) return;
	for (const script of prefix.scripts) gradePrefix(soundPrefix(script), grader, depth + 1);
}

/** The path a `file://` URL names, or the URL text when it does not decode; curl prints the local file. */
function decodeFileUrl(url: string): string {
	const rest = url.slice("file://".length).replace(/^localhost(?=\/)/i, "");
	try {
		return decodeURIComponent(rest);
	} catch {
		return rest;
	}
}
