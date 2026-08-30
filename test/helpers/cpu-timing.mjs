/**
 * CPU-time measurement for the gates that read cost rather than correctness.
 *
 * Every such gate is a RATIO — a cost against a calibration, or a cost at one
 * input size against the same cost at another — because machine speed and the
 * coverage instrumentation scale both sides, so a ratio survives a slow or
 * instrumented runner in a way milliseconds do not. A ratio does not cancel a
 * BUSY machine, though, so a timed block is charged in CPU time rather than wall
 * clock: time descheduled behind another test worker is not time the code spent,
 * and the CPU clock does not charge it.
 *
 * Shared by `test/hook-latency.test.mjs` (budgets against a calibration pass)
 * and `test/algorithmic-complexity.test.mjs` (growth against input length).
 */
import assert from "node:assert/strict";
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

/** A timed block has to last at least this long to be a measurement rather than
 * timer noise, however cheap the call it is made of. */
const MIN_BLOCK_MS = 5;
/** How many distinct documents a timed block cycles through. */
const BLOCK_RING = 8;

/**
 * The per-call CPU cost of `fn`, timed over as many calls as it takes to fill a
 * block of `blockMs`.
 *
 * One 32 KB pass costs a fraction of a millisecond on a fast machine, and that
 * is the number a scaling gate divides by. Timing a batch and dividing keeps
 * the small end meaningful at any machine speed.
 *
 * `blockMs` is what makes the two sides of a scaling ratio comparable: the
 * caller passes the cost of the side it will be divided into, since
 * fastest-of-N is fair only between blocks of similar length (see
 * {@link measure}). Under {@link MIN_BLOCK_MS} the floor wins and the bias runs
 * the other way.
 * @template T
 * @param {(attempt: number) => T} input
 * @param {(built: T) => unknown | Promise<unknown>} fn
 * @param {number} blockMs
 * @returns {Promise<number>}
 */
export async function measurePerCall(input, fn, blockMs) {
  const single = (await measure(input, fn)).cpu;
  // A zero would divide into a repeat count no loop finishes. The resolution
  // probe callers run first is what normally catches a clock too coarse to
  // measure these calls; this refuses to hang if one gets past it.
  assert.ok(single > 0, "the CPU clock reported no time for a timed call");
  const repeats = Math.ceil(Math.max(MIN_BLOCK_MS, blockMs) / single);
  if (repeats <= 1) return single;
  // The block cycles a ring of distinct documents for the same reason `measure`
  // varies its input, and a ring rather than one document per call because
  // `repeats` runs to the hundreds on a fast machine and each document is a
  // whole input. Consecutive calls always differ, which is what a one-entry
  // parse memo needs to miss.
  const ring = [];
  for (let i = 0; i < Math.min(repeats, BLOCK_RING); i++)
    ring.push(input(SAMPLES + 1 + i));
  const block = await measure(
    () => /** @type {T} */ (/** @type {unknown} */ (undefined)),
    async () => {
      for (let i = 0; i < repeats; i++) await fn(ring[i % ring.length]);
    },
  );
  return block.cpu / repeats;
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
 * cannot resolve a calibration pass, and {@link measurePerCall} would divide a
 * matched block by a zero. */
export const RESOLUTION_CEILING_MS = 0.5;

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
