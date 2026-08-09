#!/usr/bin/env node
/**
 * Aggregate the JSON reports emitted by the sharded mutation jobs into one
 * global mutation score and apply the break threshold.
 *
 * Each shard runs Stryker over a disjoint slice of the codebase (line ranges of
 * the big files, whole files for the rest) with `thresholds.break` nulled, so no
 * single shard knows the project-wide score. This script deduplicates the
 * per-mutant verdicts across every shard's `mutation.json` and computes the same
 * mutation score Stryker would — once per gated SCOPE.
 *
 * There are three scopes because the mutated set is three populations with very
 * different histories: `src/` has been mutated (and hardened) for months and
 * keeps `stryker.conf.json`'s `thresholds.break`, while the Claude-hook layer
 * and the CLI were outside the gate entirely until they were added to the shard
 * matrix and carry their own ratchet (`hookScopeBreak` in
 * `.github/mutation-shards.json`). Scoring them as one blended number would let
 * the newly-added files quietly pull the library's long-standing floor down.
 * Each scope's threshold is applied independently; any one failing fails the
 * build.
 *
 * The third scope is `.hooks/lib/`: repo tooling that ships to nobody, so the
 * manifest-derived shipped set cannot see it, but that has a node suite
 * (`test/guard-pairs.test.mjs`) exercising it and real consequences when it
 * silently stops resolving — the pre-commit guard-pair map is derived there, and
 * a resolver arm that quietly breaks means guards stop running with no red.
 *
 * `hookScopeBreak` is a RATCHET set below the first measurement (a local
 * unsharded run over `claude-hooks/lib/*.mjs` + `bin/sanitize-cli.mjs` scored
 * 41.68%), deliberately with room under it because the rest of the hook layer
 * had never been mutated when it was chosen. Raise it as the real number lands
 * in the job summary; never lower it, and never lower `thresholds.break`
 * because the hook scope is behind.
 *
 * `toolingScopeBreak` is the same kind of ratchet with NO measurement behind it
 * yet — it starts at 1, which is not a quality bar but a liveness one: the
 * empty-scope check below still fails the build if no shard mutates the scope.
 * The first CI run prints the real score in the job summary; raise it to just
 * under that number then.
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
 * Report file keys as repo-relative POSIX paths.
 *
 * Stryker keys `files` relative to `projectRoot`, but the field is optional and
 * a runner is free to emit absolute keys. Normalizing here means both the dedup
 * identity and the scope split below key off the same shape no matter which the
 * shard produced — an absolute key would otherwise dedup against nothing and
 * land in the wrong scope.
 *
 * @param {{projectRoot?: string}} report
 * @param {string} path
 */
const relativize = (report, path) => {
  const root = (report.projectRoot ?? "")
    .replace(/\\/g, "/")
    .replace(/\/$/, "");
  const posixPath = path.replace(/\\/g, "/");
  return root && posixPath.startsWith(`${root}/`)
    ? posixPath.slice(root.length + 1)
    : posixPath;
};

/**
 * Path prefixes that separate the three gated scopes (see the file header).
 *
 * Every scope NAMES what it claims — none of them is "everything else". A
 * catch-all would partition every possible string by construction, so a
 * directory that later joins the mutated set would silently inherit whichever
 * ratchet the negation covered, scored against a floor it was never measured
 * against. Named prefixes make such a path claimed by nobody, which
 * `test/aggregate-mutation.test.mjs` fails on at test time.
 */
const SRC_PREFIX = "src/";
const TOOLING_PREFIX = ".hooks/lib/";
const HOOK_PREFIXES = ["claude-hooks/", "bin/"];

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
 * @param {(file: string) => boolean} [inScope]  keep only mutants whose file
 *   passes this predicate (repo-relative path); defaults to every file
 * @returns {{counts: Record<string, number>, total: number, detected: number,
 *   undetected: number, score: number}}
 */
export function tallyMutants(reports, inScope = () => true) {
  const verdicts = new Map();
  for (const report of reports) {
    for (const rawPath of Object.keys(report.files)) {
      const path = relativize(report, rawPath);
      if (!inScope(path)) continue;
      for (const mutant of report.files[rawPath].mutants) {
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

/**
 * The gated scopes, in report order.
 *
 * Exported so the partition itself is testable: the three predicates must
 * assign every mutated path to exactly one scope. A path claimed twice is
 * double-gated (and the stricter floor applied to files it was never meant
 * for); a path claimed by none is silently ungated, which is the failure the
 * whole per-scope split exists to prevent.
 *
 * @param {{breakThreshold: number, hookScopeBreak: number, toolingScopeBreak: number}} thresholds
 * @returns {{name: string, inScope: (f: string) => boolean, threshold: number}[]}
 */
export const gatedScopes = ({
  breakThreshold,
  hookScopeBreak,
  toolingScopeBreak,
}) => [
  {
    name: "src (library)",
    inScope: (/** @type {string} */ f) => f.startsWith(SRC_PREFIX),
    threshold: breakThreshold,
  },
  {
    name: "claude-hooks + bin",
    inScope: (/** @type {string} */ f) =>
      HOOK_PREFIXES.some((prefix) => f.startsWith(prefix)),
    threshold: hookScopeBreak,
  },
  {
    name: ".hooks/lib (repo tooling)",
    inScope: (/** @type {string} */ f) => f.startsWith(TOOLING_PREFIX),
    threshold: toolingScopeBreak,
  },
];

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
  const shardConf = JSON.parse(
    readFileSync(join(repoRoot, ".github", "mutation-shards.json"), "utf8"),
  );
  const hookScopeBreak = shardConf.hookScopeBreak;
  if (typeof hookScopeBreak !== "number" || hookScopeBreak <= 0) {
    throw new Error(
      `.github/mutation-shards.json hookScopeBreak must be a positive number, got ${JSON.stringify(hookScopeBreak)}`,
    );
  }
  const toolingScopeBreak = shardConf.toolingScopeBreak;
  if (typeof toolingScopeBreak !== "number" || toolingScopeBreak <= 0) {
    throw new Error(
      `.github/mutation-shards.json toolingScopeBreak must be a positive number, got ${JSON.stringify(toolingScopeBreak)}`,
    );
  }

  const scopes = gatedScopes({
    breakThreshold,
    hookScopeBreak,
    toolingScopeBreak,
  });

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

  const lines = [`Aggregated ${reportFiles.length} shard report(s).`];
  const failures = [];
  for (const scope of scopes) {
    const { counts, total, detected, undetected, score } = tallyMutants(
      reports,
      scope.inScope,
    );
    // A scope that scored nothing is a broken matrix, not a pass: it means no
    // shard mutated those files, so the floor would be applied to an empty set
    // and wave the whole scope through.
    if (detected + undetected === 0) {
      throw new Error(
        `Scope "${scope.name}" produced no scored mutants across ${reportFiles.length} report(s); refusing to gate vacuously.`,
      );
    }
    lines.push(
      `${scope.name}: ${total} mutants, ${JSON.stringify(counts)}`,
      `${scope.name}: mutation score ${score.toFixed(2)}% (break threshold ${scope.threshold}%).`,
    );
    if (score < scope.threshold) {
      failures.push(
        `${scope.name}: mutation score ${score.toFixed(2)} under breaking threshold ${scope.threshold}.`,
      );
    }
  }

  process.stdout.write(`${lines.join("\n")}\n`);
  if (process.env.GITHUB_STEP_SUMMARY) {
    appendFileSync(
      process.env.GITHUB_STEP_SUMMARY,
      `### Mutation testing\n\n${lines.map((l) => `- ${l}`).join("\n")}\n`,
    );
  }

  if (failures.length > 0) {
    process.stderr.write(`${failures.join("\n")}\n`);
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
