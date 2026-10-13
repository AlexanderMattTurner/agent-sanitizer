/**
 * CPU-time measurement for the gates that read cost rather than correctness.
 *
 * Two kinds of gate read it. A BUDGET (`test/hook-latency.test.mjs`) is a cost
 * against a calibration pass, a ratio because machine speed and the coverage
 * instrumentation scale both sides. A GROWTH gate — every complexity gate in
 * the repo — is a fitted EXPONENT: how cost grows across input sizes, never a
 * ratio of two samples against a constant tuned for one test. A single sample
 * on each side lands on either side of any constant on a loaded runner: one
 * collector pause read a linear Python shape at ~580x, and a slow runner read
 * a quadratic control at 12.99x against a limit of 15.
 *
 * {@link growth} is the one estimator. It samples three or more geometrically
 * spaced sizes, interleaved, keeping each size's fastest per-call CPU reading,
 * and fits the slope of ln(cost) on ln(size). Every gate classifies that slope
 * against ONE shared pair of thresholds, read from
 * `tests/data/growth-exponents.json` so the Python twin (`tests/_growth.py`)
 * means the same thing by "linear":
 *
 * - {@link LINEAR_MAX_EXPONENT} (1.35): a gate passes below it. Every gate
 *   that ships read 0.74-1.14 here on a 4-core machine at load average 18-28
 *   (the JS growth gates 0.74-1.14, the Python ones 0.79-1.07, a few constant-
 *   cost entry points near 0), and `n log n` over an 8x span reads ~1.1. The
 *   weakest real defect either suite has caught read 1.59 (a per-finding
 *   rebuild, 27.1x for 8x) and 1.57 (`_redact_line`, 2.97x for 2x).
 * - {@link SUPERLINEAR_MIN_EXPONENT} (1.7): a positive control passes above
 *   it. The controls read 1.85-2.49 at the same load (quadratic specimen
 *   1.98-2.05, the collision memo reverted 1.85, the copy-quadratic 2.47-2.49).
 *   The band between the two is deliberately dead: a control drifting into it
 *   fails, rather than a gate and its control sharing one cut-off that noise
 *   can straddle.
 *
 * Every timed block is charged in CPU time rather than wall clock: time
 * descheduled behind another test worker is not time the code spent. This
 * module and `tests/_growth.py` are the only test code allowed to turn a clock
 * reading into a verdict — `test/real-clock-thresholds.test.mjs` fails any
 * other test that does, including one reading it through an accessor imported
 * from here (`measure`, `growth`, `clockResolutionMs`). So a verdict on a
 * reading — a budget in units, an absolute ceiling, the clock's granularity,
 * the calibration floor, "this costs more than that" — is an `assert*` below
 * that takes the reading and throws; the test never compares it itself.
 *
 * Every reading is also taken on a young generation of ONE size
 * ({@link PINNED_HEAP_FLAGS}), so a cost is a fact about the code rather than
 * about how big the heap's history happened to leave the nursery.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { it } from "node:test";

/**
 * Why a cost gate cannot be read under Stryker.
 *
 * A mutation run rewrites every source file so each expression sits behind a
 * per-mutant branch, and it runs four workers at once — the code under test
 * slows several-fold while a test file's own calibration, which Stryker does not
 * instrument, does not. The cheapest budget goes red first, and Stryker aborts
 * every shard whose initial dry run is red. A gate reading this says so and
 * stands down rather than reporting a regression it cannot see.
 *
 * `STRYKER_NAMESPACE` is set on every test process the tap runner spawns (see
 * `@stryker-mutator/tap-runner`'s `runFile`), in both the dry run and the mutant
 * runs; nothing else in this repo sets it.
 */
export const MUTATION_RUN = process.env.STRYKER_NAMESPACE
  ? "Stryker instruments the code under test but not this file's timing, so the ratios measure the instrumentation"
  : null;

/**
 * The V8 flags every process that reads a cost gate runs with: the young
 * generation pinned at the 16 MB semi-space V8 grows it to by default.
 *
 * Unpinned, V8 sizes the nursery from the process's history: it starts at 1 MB,
 * doubles after scavenges that keep a lot alive, and drops back to 1 MB after a
 * GC that is reducing memory. A call holding a working set proportional to its
 * input pays a scavenge, which copies that working set, each time it allocates
 * the nursery's capacity: roughly n / capacity scavenges of n each, so the
 * smaller the nursery the more a fit over n reads the collector rather than the
 * code. `sanitizeText` on a soft hyphen every other character is the case that
 * showed it: it spends 68% of its CPU scavenging on a 1 MB semi-space against
 * 11% on a 16 MB one. With the semi-space at 2-4 MB its fit reads 1.23-1.37 and
 * its 256 KB call 10-13 ms; grown, the readings are 1.01-1.10 and ~5.5 ms. A CI
 * run read 1.37 with 0.645/1.972/5.622/10.868 ms per call, while every other
 * shape there read ~1.
 *
 * `v8.setFlagsFromString` does not reach a heap that is already configured, so
 * the flags go on the command line. `node --test` forwards them to the process
 * it runs each suite in. A memory-reducing GC then leaves the nursery at 16 MB,
 * where without the flags it drops to 1 MB.
 */
const PINNED_HEAP_FLAGS = [
  "--min-semi-space-size=16",
  "--max-semi-space-size=16",
];

/** Throws unless this process runs with {@link PINNED_HEAP_FLAGS}. */
function assertHeapPinned() {
  const missing = PINNED_HEAP_FLAGS.filter(
    (flag) => !process.execArgv.includes(flag),
  );
  assert.ok(
    missing.length === 0,
    `a cost gate needs the young generation pinned, and this process lacks ${missing.join(" ")}: run \`node --test ${PINNED_HEAP_FLAGS.join(" ")} <file>\` (see PINNED_HEAP_FLAGS in test/helpers/cpu-timing.mjs)`,
  );
}

/** `unit` repeated to exactly `n` UTF-16 units. */
export const grow = (unit, n) =>
  unit.repeat(Math.ceil(n / unit.length)).slice(0, n);

/**
 * The FASTEST of {@link SAMPLES} timed runs after a warm-up call.
 *
 * Collector pauses, and the descheduling the CPU clock still sees, only ever ADD
 * time, so the minimum is the closest any of the samples got to the cost of the
 * code itself. A median still carries whatever noise landed on the middle
 * sample, which on a shared runner is most of them. The estimator loses nothing
 * the gates are for: a path that got an order of magnitude slower is an order of
 * magnitude slower in its fastest run too. Eight rather than four because four
 * tries are not enough on a loaded runner for the collector to miss one: at four
 * the dearest cells read up to 1.7x their own median, at eight up to 1.1x, which
 * is what lets the budgets stay tight enough to catch a doubling.
 */
const SAMPLES = 8;

/**
 * A timed block, in ms: the CPU time the process spent, and the wall clock it
 * occupied.
 * @typedef {{cpu: number, wall: number}} Timing
 */

/** The CPU time a block charged the process, in ms. `process.cpuUsage` counts
 * every thread, so a collector pass or a background compile the block provoked
 * is charged to it — which is the intent, since the hook pays for those too.
 * @param {ReturnType<typeof process.cpuUsage>} mark
 * @returns {number} */
const cpuSince = (mark) => {
  const spent = process.cpuUsage(mark);
  return (spent.user + spent.system) / 1000;
};

/**
 * A block's cost, in both clocks. `cpu` is what a ratio reads: a ratio cancels a
 * slower machine because both sides run at that speed, but not a busy one,
 * because the two sides are timed over blocks of very different length — a 1 ms
 * calibration pass reliably catches a quiet slot for its fastest sample and a
 * 250 ms parse5 run never does, so the divisor stays flat while the numerator
 * inflates.
 *
 * Each call gets its own document from `input(attempt)`. Handing every call the
 * same string measures a memo hit rather than the work: the HTML layer
 * remembers its last parse, so the warm-up builds the tree the timed runs then
 * reuse — 81 ms for a 256 KB fragment against the 160 ms a hook pays for a
 * document it is seeing for the first time, which is the only case there is.
 * The inputs differ in length by one code point, so the shape is unchanged.
 * @template T
 * @param {(attempt: number) => T} input
 * @param {(built: T) => unknown | Promise<unknown>} fn
 * @returns {Promise<Timing>}
 */
export async function measure(input, fn) {
  assertHeapPinned();
  await fn(input(0));
  const best = { cpu: Infinity, wall: Infinity };
  for (let i = 1; i <= SAMPLES; i++) {
    const text = input(i);
    const mark = process.cpuUsage();
    const started = performance.now();
    await fn(text);
    // Each estimator takes its own minimum: the quietest sample by wall clock
    // need not be the cheapest by CPU, and taking the pair from one sample would
    // charge the CPU figure for whatever made that sample the quietest.
    best.wall = Math.min(best.wall, performance.now() - started);
    best.cpu = Math.min(best.cpu, cpuSince(mark));
  }
  return best;
}

/**
 * The one pair of thresholds every growth gate in the repo classifies against,
 * read from the same file the Python harness (`tests/_growth.py`) reads. The
 * module header above gives the measurements behind the values.
 */
const EXPONENTS = JSON.parse(
  readFileSync(
    new URL("../../tests/data/growth-exponents.json", import.meta.url),
    "utf8",
  ),
);
/** A gate passes when its fitted exponent is BELOW this. */
export const LINEAR_MAX_EXPONENT = EXPONENTS.linear_max_exponent;
/** A positive control passes when its fitted exponent is ABOVE this. */
export const SUPERLINEAR_MIN_EXPONENT = EXPONENTS.superlinear_min_exponent;

/** A timed block has to last at least this long to be a measurement rather than
 * timer noise, however cheap the call it is made of. */
const MIN_BLOCK_MS = 5;
/** ...and is matched to the largest size's call only up to this long. Past it a
 * block is one call: a block this long no longer finds a quiet slot that a
 * longer one would miss, and matching a 300 ms parse would multiply what every
 * gate costs by the number of sizes. */
const MAX_BLOCK_MS = 50;
/** How many distinct inputs each size cycles through. */
const BLOCK_RING = 8;
/** Interleaved rounds: every size is sampled this many times, and the fastest
 * per-call reading of each size is the one the fit reads. Fewer than the eight
 * {@link measure} takes because a fit is less fragile than a budget: an end
 * size read even 1.7x high (the worst four samples gave a budget) moves a
 * four-size exponent by 0.23, inside the margin on either threshold — and every
 * round costs one block per size. */
const ROUNDS = 5;

/**
 * `count` sizes from `lo` to `hi` inclusive, evenly spaced on a log scale — so
 * every step is the same RATIO, which is what a log-log fit weighs evenly.
 * @param {number} lo
 * @param {number} hi
 * @param {number} [count]
 * @returns {number[]}
 */
export function geometricSizes(lo, hi, count = 4) {
  assert.ok(count >= 3 && hi > lo, "a growth fit needs three or more sizes");
  const step = (hi / lo) ** (1 / (count - 1));
  return Array.from({ length: count }, (_, i) => Math.round(lo * step ** i));
}

/**
 * The least-squares slope of ln(cost) against ln(size): the `k` in cost ~ n^k.
 * @param {number[]} sizes
 * @param {number[]} costs
 * @returns {number}
 */
export function fitExponent(sizes, costs) {
  assert.ok(
    costs.every((c) => c > 0),
    "a cost of zero has no logarithm; the CPU clock reported no time",
  );
  const xs = sizes.map(Math.log);
  const ys = costs.map(Math.log);
  const mean = (/** @type {number[]} */ v) =>
    v.reduce((a, b) => a + b, 0) / v.length;
  const mx = mean(xs);
  const my = mean(ys);
  let num = 0;
  let den = 0;
  for (let i = 0; i < xs.length; i++) {
    num += (xs[i] - mx) * (ys[i] - my);
    den += (xs[i] - mx) ** 2;
  }
  return num / den;
}

/**
 * A fitted growth curve: the exponent, and the per-call CPU ms each size read.
 * @typedef {{exponent: number, sizes: number[], costs: number[]}} Growth
 */

/**
 * `built`, with a string replaced by a flat copy of itself. A string built by
 * concatenation is a V8 rope that the first regex or scan flattens, charging a
 * whole-text copy to whichever timed call reads it first; the hook never pays it
 * (its text comes off `JSON.parse` flat), and it lands unevenly across sizes,
 * inflating the top of the curve (`sanitizeText` over a soft hyphen every other
 * character read 1.00-1.19 on ropes, 0.98-1.02 flattened). A structured clone
 * is a flat copy that keeps its representation (Latin-1 stays one byte a unit).
 * @template T
 * @param {T} built
 * @returns {T}
 */
const flat = (built) =>
  typeof built === "string" ? structuredClone(built) : built;

/**
 * The order {@link growth} visits `count` sizes in on its even rounds (every
 * other size from the smallest, then the ones between: 0, 2, 1, 3 for four),
 * reversed on its odd rounds. Plain ascending order runs sizes 1, 0, 0, 1 and
 * 2, 3, 3, 2 back to back at round boundaries, so one fast stretch of the runner
 * can cover just the smaller or the larger half of the curve and move a
 * four-size fit by 0.4 (CI read `sanitizeText/cjk-prose` at 1.36 that way). In
 * this order no contiguous stretch holds one half without the other.
 * @param {number} count
 * @returns {number[]}
 */
function visitOrder(count) {
  const indices = Array.from({ length: count }, (_, i) => i);
  return [
    ...indices.filter((i) => i % 2 === 0),
    ...indices.filter((i) => i % 2 === 1),
  ];
}

/**
 * How `fn`'s per-call CPU cost grows across `sizes`, as a fitted exponent.
 *
 * Three things make the number survive a loaded runner, each closing a way a
 * single ratio of two samples did not:
 *
 * - EVERY size is sampled {@link ROUNDS} times, INTERLEAVED ({@link visitOrder},
 *   then reversed, round after round), and each keeps its fastest per-call
 *   reading. A burst of load lands on every size alike rather than on
 *   whichever size happened to be timing, and a collector pause has to hit the
 *   same size in every round to survive the minimum.
 * - Every timed block lasts about as long as one call at the LARGEST size (at
 *   least {@link MIN_BLOCK_MS}, at most {@link MAX_BLOCK_MS}), with smaller
 *   sizes batched to match. Fastest-of-N is fair only between blocks of
 *   similar length: a 1 ms block reliably finds a quiet slot and a 250 ms one
 *   never does, which biases a ratio of the two upward.
 * - The verdict is a least-squares fit over three or more sizes, so one
 *   misread size moves it by a fraction of its own error rather than all of it.
 *
 * Each call gets its own input from `input(size, attempt)`; `attempt` counts
 * up from 0, and inputs at one size should differ only by a unit, so a memo
 * that remembers its last argument cannot answer for the work (see
 * {@link measure}).
 * @template T
 * @param {(size: number, attempt: number) => T} input
 * @param {(built: T) => unknown | Promise<unknown>} fn
 * @param {number[]} sizes
 * @returns {Promise<Growth>}
 */
export async function growth(input, fn, sizes) {
  assertHeapPinned();
  const build = (/** @type {number} */ size, /** @type {number} */ attempt) =>
    flat(input(size, attempt));
  // The first call per size warms the code. When even that is past the block
  // cap it sizes the block (one call); otherwise one more call, now warm, does.
  // Its noise only moves how many calls a block holds.
  const single = [];
  for (const size of sizes) {
    const warm = build(size, 0);
    let mark = process.cpuUsage();
    await fn(warm);
    let spent = cpuSince(mark);
    if (spent < MAX_BLOCK_MS) {
      const sizing = build(size, 1);
      mark = process.cpuUsage();
      await fn(sizing);
      spent = cpuSince(mark);
    }
    single.push(spent);
  }
  const blockMs = Math.min(MAX_BLOCK_MS, Math.max(MIN_BLOCK_MS, ...single));
  const repeats = single.map((ms) =>
    Math.max(1, Math.ceil(blockMs / Math.max(ms, 1e-3))),
  );
  const rings = sizes.map((size) =>
    Array.from({ length: BLOCK_RING }, (_, i) => build(size, 2 + i)),
  );
  const next = sizes.map(() => 0);
  const costs = sizes.map(() => Infinity);
  const order = visitOrder(sizes.length);
  for (let round = 0; round < ROUNDS; round++)
    for (const i of round % 2 ? [...order].reverse() : order) {
      const mark = process.cpuUsage();
      for (let k = 0; k < repeats[i]; k++)
        await fn(rings[i][next[i]++ % BLOCK_RING]);
      costs[i] = Math.min(costs[i], cpuSince(mark) / repeats[i]);
    }
  return { exponent: fitExponent(sizes, costs), sizes, costs };
}

/**
 * One line naming a curve, for a diagnostic or a failure message.
 * @param {Growth} curve
 * @returns {string}
 */
export const describeGrowth = ({ exponent, sizes, costs }) =>
  `exponent ${exponent.toFixed(2)} over n=${sizes.join("/")} (${costs.map((c) => c.toFixed(3)).join("/")}ms CPU per call)`;

/**
 * The gate: `curve` must classify as at most linear.
 * @param {string} name
 * @param {Growth} curve
 */
export function assertLinear(name, curve) {
  assert.ok(
    curve.exponent < LINEAR_MAX_EXPONENT,
    `${name} grew super-linearly: ${describeGrowth(curve)}; linear is below ${LINEAR_MAX_EXPONENT}`,
  );
}

/**
 * The positive control: `curve` must classify as super-linear, or the harness
 * cannot see the defect class the gates beside it exist for.
 * @param {string} name
 * @param {Growth} curve
 */
export function assertSuperlinear(name, curve) {
  assert.ok(
    curve.exponent > SUPERLINEAR_MIN_EXPONENT,
    `${name} is a deliberate super-linear control but read ${describeGrowth(curve)}; it must exceed ${SUPERLINEAR_MIN_EXPONENT}, so every linear verdict beside it is suspect`,
  );
}

/** How long a probe block busy-waits, and how many it runs. */
const PROBE_MS = 0.2;
const PROBE_BLOCKS = 40;

/**
 * The finest CPU-time reading this clock resolves, in ms.
 *
 * `process.cpuUsage` reports microseconds, but a kernel that accumulates rusage
 * at tick granularity only ever reports whole ticks — 1 ms, or 4 ms — and a
 * calibration pass costs about one millisecond, so on such a kernel the unit is
 * quantized to within its own size and no ratio means anything. Busy-wait blocks
 * well under a tick and keep the smallest non-zero reading: it comes back near
 * {@link PROBE_MS} on a microsecond clock and at a whole tick otherwise.
 * @returns {number}
 */
export function clockResolutionMs() {
  let finest = Infinity;
  for (let i = 0; i < PROBE_BLOCKS; i++) {
    const mark = process.cpuUsage();
    const until = performance.now() + PROBE_MS;
    let spin = 0;
    while (performance.now() < until) spin += Math.sqrt(spin + 1);
    const spent = cpuSince(mark);
    if (spent > 0 && spent < finest) finest = spent;
  }
  return finest;
}

/** The coarsest clock a cost gate can be read on. A reading no finer than this
 * cannot resolve a calibration pass, and {@link growth} would size its blocks
 * from a reading of zero. */
const RESOLUTION_CEILING_MS = 0.5;

/**
 * Throws unless this kernel's CPU clock is fine enough to read a cost gate on.
 * @param {string} what  what would be quantized, for the message
 */
export function assertClockResolves(what) {
  const resolution = clockResolutionMs();
  assert.ok(
    resolution <= RESOLUTION_CEILING_MS,
    `process.cpuUsage resolves no finer than ${resolution.toFixed(3)}ms on this kernel, so ${what} quantized to within their own size`,
  );
}

/** A calibration pass at or under this is quantized to within a percent of
 * itself, so a ratio dividing by it means nothing. */
const MIN_UNIT_MS = 0.1;

/**
 * Throws unless a calibration unit (CPU ms per pass) is a measurement and not
 * timer noise.
 * @param {number} unit
 */
export function assertCalibrated(unit) {
  assert.ok(
    unit > MIN_UNIT_MS,
    `calibration ran in ${unit.toFixed(3)}ms of CPU — too fast to divide by`,
  );
}

/**
 * Throws unless a cost, in calibration units, is within `budget`.
 * @param {string} label  what was timed
 * @param {number} units
 * @param {number} budget
 * @param {number} cpuMs  the same cost in CPU ms, for the message
 */
export function assertWithinBudget(label, units, budget, cpuMs) {
  assert.ok(
    units <= budget,
    `${label} ran in ${units.toFixed(1)} units (${cpuMs.toFixed(1)}ms CPU), budget ${budget}`,
  );
}

/**
 * Throws unless a cost fits an absolute ceiling. Read it off {@link measure}'s
 * `cpu` — the fastest of {@link SAMPLES} runs in CPU time — and never its
 * `wall`, which a loaded runner inflates without the code having changed.
 * @param {string} label  what was timed
 * @param {number} cpuMs
 * @param {number} ceilingMs
 */
export function assertWithinCeiling(label, cpuMs, ceilingMs) {
  assert.ok(
    cpuMs <= ceilingMs,
    `${label} took ${cpuMs.toFixed(1)}ms of CPU at best, ceiling ${ceilingMs}ms`,
  );
}

/**
 * Throws unless `cost` exceeds `baseline` — the positive control that a shape
 * driving a dearer path really does cost more.
 * @param {string} label
 * @param {number} cost  CPU ms
 * @param {number} baseline  CPU ms
 * @param {string} why  what it means when this fails
 */
export function assertDearerThan(label, cost, baseline, why) {
  assert.ok(
    cost > baseline,
    `${label} (${cost.toFixed(1)}ms CPU) no longer costs more than the baseline (${baseline.toFixed(1)}ms CPU) — ${why}`,
  );
}

/**
 * An `it` whose verdict rests on a timing, and so has none under a mutation run.
 * @param {string} name
 * @param {(t: import("node:test").TestContext) => void | Promise<void>} fn
 * @returns {void}
 */
export const timed = (name, fn) =>
  it(name, async (t) => {
    if (MUTATION_RUN) {
      t.skip(MUTATION_RUN);
      return;
    }
    await fn(t);
  });
