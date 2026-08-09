#!/usr/bin/env node
/**
 * Run the test suite under c8 and apply a coverage floor to EVERY shipped file.
 *
 * The old `.c8rc.json` hardcoded `include: ["src/**\/*.mjs"]`, so the 100% floor
 * was computed over a file set that excluded the entire Claude-hook layer and
 * the published CLI — more than half the `exports` map. A new early return in
 * `claude-hooks/lib/hook-io.mjs`, or a whole new untested `claude-hooks/lib`
 * module, therefore kept the run green at "100%". The include list is derived
 * from `scripts/shipped-sources.mjs` instead, so there is no list to keep in
 * sync: a newly published module is measured the moment it is published.
 *
 * Two scopes, two floors (see SCOPES): `src/` stays at 100% and the hook layer
 * carries its own explicit, lower ratchet. c8 applies one threshold set per
 * invocation, so the suite runs once with checking off and the floors are
 * applied afterwards by one `c8 report` pass per scope over the same raw
 * coverage — one test run, two gates.
 *
 * Usage: node scripts/coverage.mjs [extra node --test args]
 */
import { spawnSync } from "node:child_process";
import { readFileSync, realpathSync, rmSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { findRepoRoot, hookScope, srcScope } from "./shipped-sources.mjs";

/**
 * The roots `--all` walks, derived from the include list itself.
 *
 * c8 only discovers a file with ZERO executed lines if it lives under a `--src`
 * root. A hardcoded root list would reintroduce this script's own bug one
 * directory deeper: a shipped file in a new top-level directory would be passed
 * as `--include`, land in a scope, and be present in the shard matrix (so
 * `test/shipped-gates.test.mjs` stays green) — yet never be walked, so it would
 * be ABSENT from the report rather than scored 0% against the floor, and c8
 * skips the threshold check entirely for an empty report (verified: exit 0).
 *
 * @param {string[]} includes @returns {string[]}
 */
export const srcRoots = (includes) => [
  ...new Set(includes.map((file) => file.split("/")[0])),
];

const EXCLUDES = ["test/**", "**/*.test.mjs", "**/*.fuzz.test.mjs"];

/**
 * The coverage floors, per scope. Together the scopes must partition the
 * shipped set — `test/shipped-gates.test.mjs` asserts exactly that, so a scope
 * added here without a matching split leaves no file unmeasured.
 *
 * `src/` is the library proper and is held at 100% — never lower it.
 *
 * The hook layer's floor is a RATCHET, not a target: it sits a little under the
 * measured value and should only ever move up. The headroom is deliberate.
 * Several of these hooks are also driven the way Claude Code drives them — as
 * subprocesses executing the committed `plugin/dist` BUNDLE — and those lines
 * are attributed to the bundle, not back to the source here, so the measured
 * ratio moves when a file merely grows. A floor pinned to the exact measurement
 * would go red for that alone, which is how floors get lowered. Raise it
 * whenever the real number climbs.
 *
 * @type {{ name: string, files: (repoRoot: string) => string[],
 *   thresholds: Record<string, number> }[]}
 */
export const SCOPES = [
  {
    name: "src (library)",
    files: srcScope,
    thresholds: { lines: 100, branches: 100, functions: 100, statements: 100 },
  },
  {
    name: "claude-hooks + bin (ratchet)",
    files: hookScope,
    // Measured 96.34 / 91.19 / 90.15 / 96.34 — each floor sits ~3 points under.
    thresholds: { lines: 93, branches: 88, functions: 87, statements: 93 },
  },
];

/**
 * How far a measurement may run ahead of its floor before the build says so.
 *
 * CONTRIBUTING.md says the ratchet "should only ever move up", and nothing
 * enforced that half: c8 fails when the measurement drops BELOW the floor and is
 * silent however far above it climbs. The hook floor had drifted to 72%
 * functions against a measured 90% — room for 47 shipped functions to become
 * entirely untested with CI still green. A ratchet that only ever catches
 * regressions relative to a stale number is not a ratchet.
 *
 * 6 points, not the ~1 an exactly-pinned floor would allow, because the headroom
 * noted above is real: the hooks that Claude Code drives as subprocesses run the
 * committed `plugin/dist` BUNDLE, and those lines are attributed to the bundle
 * rather than back to the source here, so the ratio moves when a file merely
 * grows. 6 absorbs that drift while still being far smaller than the 18-point
 * gap that accumulated unnoticed — and the failure it raises is "raise the
 * floor, in both files", which is a two-line edit, not a debugging session.
 */
export const RATCHET_SLACK = 6;

/** c8 flags shared by the collecting run and every report pass.
 * @param {string[]} includes */
const commonArgs = (includes) => [
  "--all",
  ...srcRoots(includes).map((dir) => `--src=${dir}`),
  ...includes.map((file) => `--include=${file}`),
  ...EXCLUDES.map((pattern) => `--exclude=${pattern}`),
];

function main() {
  const repoRoot = findRepoRoot();
  // Resolved rather than taken from PATH so the script behaves identically run
  // directly and run through the pnpm script.
  const c8Bin = join(repoRoot, "node_modules", ".bin", "c8");

  /** @param {string[]} args @param {string} what */
  const run = (args, what) => {
    const result = spawnSync(c8Bin, args, { cwd: repoRoot, stdio: "inherit" });
    if (result.error) throw result.error;
    if (result.status !== 0) {
      process.stderr.write(
        `coverage: ${what} failed (exit ${result.status})\n`,
      );
      process.exit(result.status ?? 1);
    }
  };

  const allShipped = SCOPES.flatMap((scope) => scope.files(repoRoot));

  // One collecting run over every shipped file. Thresholds are off here so a
  // failure at this step is a TEST failure and reads as one.
  run(
    [
      ...commonArgs(allShipped),
      "--reporter=text",
      "--reporter=lcov",
      "--check-coverage=false",
      "node",
      "--test",
      ...process.argv.slice(2),
    ],
    "test suite",
  );

  for (const scope of SCOPES) {
    const files = scope.files(repoRoot);
    // A scope that resolved to nothing would pass vacuously and silently retire
    // its own floor — the exact fail-open this script exists to close.
    if (files.length === 0)
      throw new Error(
        `coverage: scope "${scope.name}" matched no shipped files`,
      );
    process.stdout.write(`\nCoverage floor — ${scope.name}\n`);
    // json-summary rides along with the text table so the same numbers c8 just
    // gated on are the ones the ratchet check below reads — a second report pass
    // would be a second measurement to disagree with. It lands in the default
    // report dir on purpose: `--report-dir` also relocates where `c8 report`
    // LOOKS for the raw V8 output (`<report-dir>/tmp`), so pointing it at a
    // scratch directory makes the pass report zero coverage.
    const summaryPath = join(repoRoot, "coverage", "coverage-summary.json");
    // Removed first so a reporter that failed to write cannot be read as the
    // previous scope's numbers.
    rmSync(summaryPath, { force: true });
    run(
      [
        "report",
        ...commonArgs(files),
        "--reporter=text",
        "--reporter=json-summary",
        "--check-coverage",
        ...Object.entries(scope.thresholds).map(([k, v]) => `--${k}=${v}`),
      ],
      `coverage floor for ${scope.name}`,
    );
    assertRatcheted(scope, readSummary(summaryPath));
  }
}

/** @param {string} path @returns {Record<string, number>} metric -> percentage */
function readSummary(path) {
  const { total } = JSON.parse(readFileSync(path, "utf8"));
  return Object.fromEntries(
    Object.entries(total).map(([metric, { pct }]) => [metric, pct]),
  );
}

/**
 * The other half of the ratchet: fail when a floor has fallen too far BEHIND
 * what the suite actually covers, naming both files that have to move.
 *
 * @param {{ name: string, thresholds: Record<string, number> }} scope
 * @param {Record<string, number>} measured
 */
export function assertRatcheted(scope, measured) {
  // A floor naming a metric the report does not carry is gating on nothing;
  // skipping it quietly would retire that floor without anyone editing it.
  for (const metric of Object.keys(scope.thresholds))
    if (typeof measured[metric] !== "number")
      throw new Error(
        `coverage: scope "${scope.name}" has a ${metric} floor, but the coverage summary reports no ${metric}`,
      );
  const stale = Object.entries(scope.thresholds)
    .filter(([metric, floor]) => measured[metric] - floor > RATCHET_SLACK)
    .map(
      ([metric, floor]) =>
        `  ${metric}: measured ${measured[metric]}%, floor ${floor}% ` +
        `(${(measured[metric] - floor).toFixed(2)} points of slack, max ${RATCHET_SLACK})`,
    );
  if (stale.length === 0) return;
  throw new Error(
    `coverage: the "${scope.name}" floor has stopped ratcheting —\n` +
      `${stale.join("\n")}\n` +
      "Raise these floors to just under the measured values in BOTH " +
      "scripts/coverage.mjs (SCOPES) and test/shipped-gates.test.mjs (HOOK_FLOORS/SRC_FLOORS).",
  );
}

// Importable without side effects: the contract test reads SCOPES and must not
// run the suite to do it.
if (
  process.argv[1] &&
  realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  main();
}
