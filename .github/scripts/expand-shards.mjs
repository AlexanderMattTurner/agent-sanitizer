#!/usr/bin/env node
/**
 * Expand the declarative mutation-shard config into a concrete shard matrix.
 *
 * `.github/mutation-shards.json` declares only what a human must decide: which
 * big files are worth chunking into `splitEvery`-line slices, and how many
 * whole-file shards to spread everything else over. WHICH files get mutated is
 * `scripts/shipped-sources.mjs`'s answer, so a newly published module or a new
 * `.hooks/lib` one joins the matrix the moment it is committed — no config to
 * remember, and no hand-listed second copy of the mutated set to drift from it.
 *
 * Slice ranges are computed from each file's CURRENT length, so a growing file
 * gets more shards on its own and no shard drifts past the file's end.
 *
 * Both the workflow (to build the job matrix) and aggregate-mutation.mjs (to
 * demand one report per shard) call this on the same checkout, so the shard set
 * and its count are guaranteed identical — the gate can never score a subset.
 *
 * Usage: node expand-shards.mjs   → prints the shard array as JSON to stdout.
 */
import { readFileSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { mutatedSources } from "../../scripts/shipped-sources.mjs";

// The open-ended sentinel the last slice of a split file uses so lines beyond
// the computed boundary (e.g. appended between checkout and Stryker's read) are
// still mutated. Mirrors Stryker's `file:start-end` --mutate syntax.
export const EOF_SENTINEL = 99999;

/** @param {string} repoRoot @param {string} file @returns {number} */
const lineCount = (repoRoot, file) =>
  readFileSync(join(repoRoot, file), "utf8").split("\n").length;

/**
 * Spread `files` over `binCount` shards, longest file first into the smallest
 * shard so far.
 *
 * Balanced by LINE COUNT, not file count: a shard's runtime tracks the mutants
 * in it, so an even split by count puts the whole long tail on one runner.
 * Ties break on path, keeping the matrix a pure function of the tree — the
 * workflow and the aggregator expand it separately and must agree exactly.
 *
 * @param {{file: string, lines: number}[]} files
 * @param {number} binCount
 * @returns {string[][]} one sorted path list per shard
 */
function balance(files, binCount) {
  const bins = Array.from({ length: binCount }, () => ({
    lines: 0,
    files: /** @type {string[]} */ ([]),
  }));
  const byLinesDesc = [...files].sort(
    (a, b) => b.lines - a.lines || a.file.localeCompare(b.file),
  );
  for (const { file, lines } of byLinesDesc) {
    const target = bins.reduce((a, b) => (b.lines < a.lines ? b : a));
    target.lines += lines;
    target.files.push(file);
  }
  return bins.map((bin) => bin.files.sort());
}

/**
 * @param {string} repoRoot absolute path to the repository root
 * @returns {{ id: string, mutate: string }[]} concrete shards for the matrix
 */
export function expandShards(repoRoot) {
  const config = JSON.parse(
    readFileSync(join(repoRoot, ".github", "mutation-shards.json"), "utf8"),
  );
  const { splitEvery, groupCount } = config;
  if (!Number.isInteger(splitEvery) || splitEvery <= 0) {
    throw new Error(
      `mutation-shards.json splitEvery must be a positive integer, got ${JSON.stringify(splitEvery)}`,
    );
  }
  if (!Number.isInteger(groupCount) || groupCount <= 0) {
    throw new Error(
      `mutation-shards.json groupCount must be a positive integer, got ${JSON.stringify(groupCount)}`,
    );
  }

  const mutated = mutatedSources(repoRoot);
  const splitFiles = (config.split ?? []).map((entry) => entry.file);
  // A `split` entry outside the mutated set is a stale path: its shard mutates
  // a file no scope scores, while the file it was renamed from silently falls
  // into the groups below and is mutated twice.
  const stale = splitFiles.filter((file) => !mutated.includes(file));
  if (stale.length > 0) {
    throw new Error(
      `mutation-shards.json splits ${stale.join(", ")}, which the mutated set ` +
        `does not contain. Point the split entry at the file's current path.`,
    );
  }

  const shards = [];
  for (const { id, file } of config.split ?? []) {
    const chunks = Math.max(
      1,
      Math.ceil(lineCount(repoRoot, file) / splitEvery),
    );
    for (let i = 0; i < chunks; i++) {
      const start = i * splitEvery + 1;
      // The last chunk ends open so the tail is always covered even if the file
      // grew past the last boundary since this expansion was computed.
      const end = i === chunks - 1 ? EOF_SENTINEL : (i + 1) * splitEvery;
      shards.push({ id: `${id}-${i + 1}`, mutate: `${file}:${start}-${end}` });
    }
  }

  const grouped = mutated.filter((file) => !splitFiles.includes(file));
  // An empty shard is still a matrix job the aggregator demands a report from,
  // and it scores nothing while looking like coverage.
  if (grouped.length < groupCount) {
    throw new Error(
      `mutation-shards.json groupCount is ${groupCount} but only ` +
        `${grouped.length} mutated file(s) remain after the split entries, so ` +
        `at least one shard would mutate nothing. Lower groupCount.`,
    );
  }
  const bins = balance(
    grouped.map((file) => ({ file, lines: lineCount(repoRoot, file) })),
    groupCount,
  );
  bins.forEach((files, i) =>
    shards.push({ id: `group-${i + 1}`, mutate: files.join(",") }),
  );
  return shards;
}

// Print the matrix only when run directly (not when imported by the aggregator).
if (
  process.argv[1] &&
  realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
  process.stdout.write(JSON.stringify(expandShards(repoRoot)));
}
