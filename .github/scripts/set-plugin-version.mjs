// Set the Claude Code plugin manifest's `version` to the version being released.
//
// Invoked from `.github/scripts/version-bump.sh` after a successful
// `pnpm publish`, and committed alongside the CHANGELOG promotion.
//
//   NEW_VERSION — the semver string being released, e.g. "1.2.3"
//
// Why this is committed while package.json's version is not: Claude Code reads
// `plugin/.claude-plugin/plugin.json` straight out of the git checkout when it
// installs the plugin from this repo's marketplace, so the value users see is
// whatever is committed. A working-tree-only bump (the package.json/pyproject
// pattern) would leave the plugin advertising a frozen placeholder forever —
// which is how it ended up reporting 0.1.0 while npm was at 2.14.1.
//
// Fails loudly (non-zero exit, `::error::` on stderr) on a missing manifest, a
// manifest without a string `version`, or a bad NEW_VERSION. The caller decides
// what to do with that: post-publish it logs the failure and continues to the
// tag push rather than stranding an already-published release.
//
// Self-contained on purpose (node builtins only): the release workflow may run
// a trusted copy of this file, which only works if it imports nothing in-repo.

import { readFileSync, renameSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";

const MANIFEST_PATH = "plugin/.claude-plugin/plugin.json";
const SEMVER = /^[0-9]+\.[0-9]+\.[0-9]+$/;

/**
 * @param {string} message
 * @returns {never}
 */
function fail(message) {
  process.stderr.write(`::error::plugin manifest version: ${message}\n`);
  process.exit(1);
}

/**
 * Write `contents` to `path` atomically: write a sibling temp file, then rename
 * it over the target. A crash mid-write leaves the original file intact.
 * @param {string} path
 * @param {string} contents
 */
function atomicWrite(path, contents) {
  const tmp = join(dirname(path), `.${basename(path)}.${process.pid}.tmp`);
  writeFileSync(tmp, contents);
  renameSync(tmp, path);
}

const newVersion = process.env.NEW_VERSION;
if (!newVersion || !SEMVER.test(newVersion))
  fail(
    `NEW_VERSION must be a strict X.Y.Z semver string (got: '${newVersion ?? ""}')`,
  );

let raw;
try {
  raw = readFileSync(MANIFEST_PATH, "utf8");
} catch (err) {
  fail(
    `could not read ${MANIFEST_PATH}: ${err instanceof Error ? err.message : String(err)}`,
  );
}

let manifest;
try {
  manifest = JSON.parse(raw);
} catch (err) {
  fail(
    `${MANIFEST_PATH} is not valid JSON: ${err instanceof Error ? err.message : String(err)}`,
  );
}

// Require the field to already exist: a manifest that lost its `version` key is
// a structural change this script must not paper over by inventing one.
if (typeof manifest.version !== "string")
  fail(`${MANIFEST_PATH} has no string "version" field to update`);

// Rewrite the value in place rather than re-serializing the parsed object:
// `JSON.stringify` reflows arrays and drops the file's Prettier formatting, and
// the release commit lands on the default branch where format:check runs.
const updated = raw.replace(
  /("version"\s*:\s*)"(?:[^"\\]|\\.)*"/,
  (_match, key) => `${key}${JSON.stringify(newVersion)}`,
);
if (updated === raw && manifest.version !== newVersion)
  fail(`could not locate the "version" value in ${MANIFEST_PATH}`);

let reparsed;
try {
  reparsed = JSON.parse(updated);
} catch (err) {
  fail(
    `rewriting the version produced invalid JSON: ${err instanceof Error ? err.message : String(err)}`,
  );
}
// The regex targets the first `"version":` in the file; if the manifest ever
// grows a nested one that comes first, this catches the wrong-field rewrite
// instead of silently shipping it.
if (reparsed.version !== newVersion)
  fail(
    `rewrite did not set the top-level "version" to ${newVersion} in ${MANIFEST_PATH}`,
  );
delete reparsed.version;
const originalWithoutVersion = { ...manifest };
delete originalWithoutVersion.version;
if (JSON.stringify(reparsed) !== JSON.stringify(originalWithoutVersion))
  fail(`rewriting the version changed other fields in ${MANIFEST_PATH}`);

atomicWrite(MANIFEST_PATH, updated);
process.stdout.write(`Set ${MANIFEST_PATH} version to ${newVersion}.\n`);
