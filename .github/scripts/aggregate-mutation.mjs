#!/usr/bin/env node
/**
 * Aggregate the JSON reports emitted by the sharded mutation jobs into one
 * global mutation score and apply the break threshold.
 *
 * Each shard runs Stryker over a disjoint slice of the codebase (line ranges of
 * the big files, whole files for the rest) with `thresholds.break` nulled, so no
 * single shard knows the project-wide score. This script deduplicates the
 * per-mutant verdicts across every shard's `mutation.json`, computes the same
 * mutation score Stryker would, and fails the build if it falls under the break
 * threshold read from `stryker.conf.json` (single source of truth — the shards
 * derive their config from the same file, so the gate can never drift from it).
 *
 * Usage: node aggregate-mutation.mjs <reports-dir>
 * Exits non-zero when the score is under threshold or when no reports are found
 * (a vacuous pass would silently disable the gate).
 */
import {
  appendFileSync,
  readdirSync,
  readFileSync,
  realpathSync,
} from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { expandShards } from "./expand-shards.mjs";

// Detected mutants are caught by the suite; undetected slip through. Mutants
// that never produced a real verdict (compile/runtime errors, ignored, pending)
// are excluded from the score, exactly as Stryker does.
const DETECTED = new Set(["Killed", "Timeout"]);
const UNDETECTED = new Set(["Survived", "NoCoverage"]);

// When the SAME mutant surfaces in more than one shard report (see the dedup
// note on tallyMutants), the copies can disagree. Resolve to the strongest
// verdict: detected beats undetected, and Survived (covered, uncaught) beats
// NoCoverage (never reached). This mirrors the unsharded verdict, because the
// shard whose --mutate range OWNS the mutant runs it against the full suite and
// produces the real result, while a neighbour shard that only clips the mutant's
// span reports a spurious NoCoverage/Survived. Higher index = stronger; a status
// outside this list (indexOf -1) is weaker than every real verdict.
const STATUS_STRENGTH = [
  "Ignored",
  "Pending",
  "CompileError",
  "RuntimeError",
  "NoCoverage",
  "Survived",
  "Timeout",
  "Killed",
];
const strength = (status) => STATUS_STRENGTH.indexOf(status);

/**
 * Deduplicate mutants across shard reports by identity and tally the score.
 *
 * The big files are sharded by LINE RANGE, and a mutant whose span straddles a
 * tile boundary is instrumented by BOTH adjacent shards; incremental shards can
 * likewise carry a mutant forward from an earlier tiling. Either way the SAME
 * mutant appears in more than one report. Summing raw double-counts it — and
 * because a duplicate copy frequently lands as NoCoverage/Survived (the
 * neighbour shard only clips the mutant's edge), the raw sum deflates the score
 * well below the true, unsharded value (e.g. 82.5% raw vs 84.2% deduped).
 * Collapsing to one verdict per unique mutant makes the gate score exactly what
 * an unsharded `stryker run` would.
 *
 * @param {Array<{files: Record<string, {mutants: Array<object>}>}>} reports
 *   parsed `mutation.json` objects, one per shard
 * @returns {{counts: Record<string, number>, total: number, detected: number,
 *   undetected: number, score: number}}
 */
export function tallyMutants(reports) {
  const verdicts = new Map();
  for (const report of reports) {
    for (const path of Object.keys(report.files)) {
      for (const mutant of report.files[path].mutants) {
        const loc = mutant.location;
        const id = [
          path,
          loc.start.line,
          loc.start.column,
          loc.end.line,
          loc.end.column,
          mutant.mutatorName,
          mutant.replacement,
        ].join(":");
        const prev = verdicts.get(id);
        if (prev === undefined || strength(mutant.status) > strength(prev)) {
          verdicts.set(id, mutant.status);
        }
      }
    }
  }

  // Prototype-less: `status` comes out of a Stryker JSON report, so a report
  // naming a mutant status `__proto__` would otherwise route the write through
  // Object.prototype instead of becoming an own property.
  const counts = Object.create(null);
  for (const status of verdicts.values()) {
    counts[status] = (counts[status] || 0) + 1;
  }
  const detected = [...DETECTED].reduce((n, s) => n + (counts[s] || 0), 0);
  const undetected = [...UNDETECTED].reduce((n, s) => n + (counts[s] || 0), 0);
  const scored = detected + undetected;
  const score = scored === 0 ? 0 : (detected / scored) * 100;
  // Spread back to an ordinary object at the boundary: the accumulation needed
  // the null prototype, the RESULT is compared and JSON-stringified by callers.
  // Spreading copies own properties with CreateDataProperty, so a `__proto__`
  // status stays an own key here instead of reaching Object.prototype.
  return {
    counts: { ...counts },
    total: verdicts.size,
    detected,
    undetected,
    score,
  };
}

function main(reportsDir) {
  const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
  const strykerConf = JSON.parse(
    readFileSync(join(repoRoot, "stryker.conf.json"), "utf8"),
  );
  const breakThreshold = strykerConf.thresholds?.break;
  if (typeof breakThreshold !== "number") {
    throw new Error(
      `stryker.conf.json thresholds.break must be a number, got ${JSON.stringify(breakThreshold)}`,
    );
  }

  const reportFiles = readdirSync(reportsDir, { recursive: true })
    .map((entry) => join(reportsDir, entry.toString()))
    .filter((p) => p.endsWith("mutation.json"));

  // Every shard uploads exactly one report. Demand one per shard so a silently
  // missing artifact fails the gate loudly instead of scoring a subset as if it
  // were the whole project. The count comes from the SAME expander the workflow
  // used to build the matrix, so the two can never drift.
  const shardCount = expandShards(repoRoot).length;
  if (reportFiles.length !== shardCount) {
    throw new Error(
      `Expected ${shardCount} shard report(s) (one per shard) but found ${reportFiles.length} under ${reportsDir}; refusing to gate on a partial result.`,
    );
  }

  const reports = reportFiles.map((f) => JSON.parse(readFileSync(f, "utf8")));
  const { counts, total, score } = tallyMutants(reports);

  const lines = [
    `Aggregated ${reportFiles.length} shard report(s): ${total} mutants total.`,
    `Status breakdown: ${JSON.stringify(counts)}`,
    `Mutation score: ${score.toFixed(2)}% (break threshold ${breakThreshold}%).`,
  ];
  process.stdout.write(`${lines.join("\n")}\n`);
  if (process.env.GITHUB_STEP_SUMMARY) {
    appendFileSync(
      process.env.GITHUB_STEP_SUMMARY,
      `### Mutation testing\n\n${lines.map((l) => `- ${l}`).join("\n")}\n`,
    );
  }

  if (score < breakThreshold) {
    process.stderr.write(
      `Final mutation score ${score.toFixed(2)} under breaking threshold ${breakThreshold}.\n`,
    );
    process.exit(1);
  }
}

// Run only when invoked directly (not when imported by a test).
if (
  process.argv[1] &&
  realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  const reportsDir = process.argv[2];
  if (!reportsDir) {
    throw new Error("usage: aggregate-mutation.mjs <reports-dir>");
  }
  main(reportsDir);
}
