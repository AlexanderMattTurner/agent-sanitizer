#!/usr/bin/env node
// Drop GENERATED files' sections from a unified diff, so the automated reviewer
// reads the hand-written change instead of a rebuilt artifact.
//
// PROBLEM CLASS — a review budget spent on bytes nobody wrote. This repo commits
// its build outputs (plugin/dist/hooks/plugin-hooks.bundle.mjs and friends), so a
// 25-line source edit arrives as a ~30k-line diff. That is over
// prepare-pr-review-input.sh's MAX_DIFF_LINES, so the review is skipped
// entirely and the source edit gets no automated read at all — the opposite of
// what the size guard is for. The artifacts need no review anyway: CI rebuilds
// each one and fails on any difference, so the diff cannot disagree with its
// sources.
//
// Ownership comes from `resolve-generated.mjs --owned`, the same oracle the
// auto-resolver partitions on, passed in on argv. A path is never classified
// here.
//
// Reads the diff on stdin, writes the filtered diff on stdout, and reports what
// it dropped on stderr. Fails OPEN: a section whose header this cannot parse
// unambiguously is KEPT, because the cost of keeping a generated file is some
// wasted review budget and the cost of dropping a hand-written one is an unread
// change.
//
// Usage: node .github/scripts/strip-generated-diff.mjs <owned-list-file> <diff
// where <owned-list-file> holds one owned path per line.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

// A section header git wrote for a path with no whitespace, which every owned
// path in this repo is. A quoted or space-bearing path does not match, and its
// section is kept — see the fail-open note above.
const HEADER = /^diff --git a\/(\S+) b\/(\S+)$/u;

/** True when `path` is generated: an exact `owns` entry, or under an
 * `ownsPrefix` (which the oracle prints with its trailing slash). */
function isOwned(path, owned) {
  return owned.some((entry) =>
    entry.endsWith("/") ? path.startsWith(entry) : path === entry,
  );
}

/** Split a unified diff into sections, each starting at a `diff --git` line.
 * A leading chunk before the first header (git emits none, but a caller may
 * prepend text) becomes its own always-kept section. */
function splitSections(diff) {
  const lines = diff.split("\n");
  /** @type {string[][]} */
  const sections = [];
  for (const line of lines) {
    if (HEADER.test(line) || sections.length === 0) sections.push([]);
    sections[sections.length - 1].push(line);
  }
  return sections.map((s) => s.join("\n"));
}

/** The filtered diff and the paths dropped from it.
 * @param {string} diff a unified diff
 * @param {string[]} owned paths and path prefixes that are generated
 * @returns {{ kept: string, dropped: {path: string, lines: number}[] }} */
export function stripGenerated(diff, owned) {
  /** @type {{path: string, lines: number}[]} */
  const dropped = [];
  const kept = [];
  for (const section of splitSections(diff)) {
    const header = HEADER.exec(section.split("\n", 1)[0]);
    // Both sides must be generated, so a rename that moves a hand-written file
    // onto a generated path (or the reverse) stays in the review.
    if (header && isOwned(header[1], owned) && isOwned(header[2], owned)) {
      dropped.push({ path: header[2], lines: section.split("\n").length });
      continue;
    }
    kept.push(section);
  }
  return { kept: kept.join("\n"), dropped };
}

/** The note prepended to a filtered diff, so the reviewer knows the artifacts
 * changed and why it is not being shown them. Empty when nothing was dropped —
 * an unfiltered diff must pass through byte for byte. */
export function omissionNote(dropped) {
  if (dropped.length === 0) return "";
  const rows = dropped.map(
    (d) => `#   ${d.path} (${d.lines} diff lines, omitted)`,
  );
  return [
    `# NOTE: ${dropped.length} generated file(s) are omitted from the diff below.`,
    "# They are build outputs listed in config/auto-resolve-regen-rules.json.",
    "# CI rebuilds each one and fails on any difference, so they cannot disagree",
    "# with the sources shown here. Review the sources.",
    ...rows,
    "",
    "",
  ].join("\n");
}

function main(ownedListFile) {
  const owned = readFileSync(ownedListFile, "utf8").split("\n").filter(Boolean);
  const diff = readFileSync(0, "utf8");
  const { kept, dropped } = stripGenerated(diff, owned);
  process.stdout.write(
    dropped.length === 0 ? diff : omissionNote(dropped) + kept,
  );
  for (const d of dropped)
    process.stderr.write(
      `strip-generated-diff: omitted ${d.path} (${d.lines} lines)\n`,
    );
}

// Only when RUN, not when the test suite imports the pure functions above.
if (
  process.argv[1] &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1])
)
  main(process.argv[2]);
