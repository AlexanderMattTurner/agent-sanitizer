/**
 * The one way a test may turn a clock reading into a verdict: an ABSOLUTE
 * budget, generous enough that only a change in the code's complexity class can
 * break it.
 *
 * A cost gate here exists to catch a path going super-linear — a regex retried
 * at every start offset, a string rebuilt once per finding, a re-walk of a
 * walked tree — on attacker-shaped input. Each gate runs its entry point ONCE
 * on an input sized so the linear implementation costs tenths of a second, and
 * fails when that one run exceeds a ceiling at least ten times what the linear
 * code was measured at. A quadratic at that size overshoots the ceiling by
 * another order of magnitude, so no runner is slow or busy enough to blur the
 * two.
 *
 * What this gives up, on purpose: a constant-factor regression (twice as slow,
 * five times as slow) passes. The fitted growth exponents and calibration
 * ratios this replaced could see some of those, and flaked on loaded runners
 * because they had to: a gate that resolves a 1.5x change is reading the
 * machine as much as the code. Super-linear REGEX behaviour does not need a
 * clock at all — `eslint.config.mjs` and `test/regex-recheck.test.mjs` decide it
 * from the pattern.
 *
 * Every reading is CPU time (`process.cpuUsage`), not wall clock: `node --test`
 * runs suites in parallel, and time spent descheduled behind another suite is
 * not time the code spent. `test/real-clock-thresholds.test.mjs` fails any
 * other test that compares a clock reading against a threshold.
 */
import assert from "node:assert/strict";

/**
 * Why a budget cannot be read under Stryker: a mutation run rewrites every
 * source expression behind a per-mutant branch and runs workers in parallel, so
 * the code under test slows several-fold for reasons that are not the code.
 * `STRYKER_NAMESPACE` is set on every test process the tap runner spawns (see
 * `@stryker-mutator/tap-runner`'s `runFile`); nothing else in this repo sets it.
 */
export const MUTATION_RUN = process.env.STRYKER_NAMESPACE
  ? "Stryker instruments the code under test, so an absolute budget measures the instrumentation"
  : null;

/** `unit` repeated to exactly `n` UTF-16 units. */
export const grow = (unit, n) =>
  unit.repeat(Math.ceil(n / unit.length)).slice(0, n);

/**
 * `built`, with a string replaced by a flat copy of itself. A string built by
 * concatenation is a V8 rope that the first scan flattens, which would charge a
 * whole-text copy to the timed call; the hooks never pay it (their text comes
 * off `JSON.parse` flat).
 * @template T
 * @param {T} built
 * @returns {T}
 */
const flat = (built) =>
  typeof built === "string" ? structuredClone(built) : built;

/**
 * Throws unless ONE warm run of `run` costs at most `ceilingMs` of CPU.
 *
 * `input(attempt)` builds the call's argument: attempt 0 for the warm-up, 1 for
 * the timed run, both built before the clock starts. They must differ (by a
 * unit, so the shape is unchanged): the HTML layer and the carve remember the
 * last text they analysed, and a timed run handed the warm-up's own input
 * would measure a memo hit rather than the work.
 *
 * The reading is reported through `t.diagnostic` on the green path too, so a
 * runner this file has never been measured on reports its own numbers. Skips
 * itself under a mutation run ({@link MUTATION_RUN}).
 * @template T
 * @param {import("node:test").TestContext} t
 * @param {string} label  what was timed, for the diagnostic and the failure
 * @param {number} ceilingMs
 * @param {(attempt: number) => T} input
 * @param {(built: T) => unknown | Promise<unknown>} run
 * @returns {Promise<void>}
 */
export async function assertUnderBudget(t, label, ceilingMs, input, run) {
  if (MUTATION_RUN) {
    t.skip(MUTATION_RUN);
    return;
  }
  const warm = flat(input(0));
  const timed = flat(input(1));
  await run(warm);
  const mark = process.cpuUsage();
  await run(timed);
  const spent = process.cpuUsage(mark);
  const cpuMs = (spent.user + spent.system) / 1000;
  t.diagnostic(`${label}: ${cpuMs.toFixed(1)}ms CPU (ceiling ${ceilingMs}ms)`);
  assert.ok(
    cpuMs <= ceilingMs,
    `${label} took ${cpuMs.toFixed(1)}ms of CPU, over its ${ceilingMs}ms ceiling — a ceiling ten times what the linear code costs, so this is a change of complexity class, not a slow runner`,
  );
}
