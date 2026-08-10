/**
 * Latency gates for the three BLOCKING hook paths.
 *
 * `scanText` runs in the SessionStart hook, `classifyPrompt` in the
 * UserPromptSubmit hook, and `sanitizeText` over every tool result. All three
 * are dead wait the user pays before anything happens, and a regression in one
 * is invisible from the inside — it reads as "the agent is slow" — while the
 * correctness suites stay perfectly green. That is how a per-code-point RegExp
 * scan sat in the carve analysis charging ~250 ms per megabyte, and how a
 * document got tokenized twice over by two layers that each wanted its own tree.
 *
 * Every budget is a RATIO against a calibration measured in this same process:
 * one code-point-by-code-point pass over a fixed 256 KB text, which is the
 * cheapest full read of a document anything here can do. Machine speed, CPU
 * contention and the coverage instrumentation scale both sides, so the ratios
 * survive a loaded CI runner in a way wall-clock milliseconds do not — the
 * calibration is written in this file, rather than reaching for a native
 * builtin, precisely so it pays the same instrumentation tax as the code it
 * normalizes.
 */
import { describe, it, before } from "node:test";
import assert from "node:assert/strict";

// The nine document shapes and the three blocking entry points are the
// benchmark's, imported rather than restated: its milliseconds are only evidence
// for the budgets below while both read the same table, and a copy kept in step
// by convention is not a single source. `scripts/bench-hooks.mjs` sweeps only
// when it is the process entry point, so importing it costs nothing.
import { ENTRIES, SHAPES } from "../scripts/bench-hooks.mjs";

const { claudeAdapter } = await import("agent-control-plane-core/claude");
const { judgeSanitizeUserPrompt } =
  await import("../claude-hooks/sanitize-user-prompt.mjs");

/**
 * Why the ratios cannot be read under Stryker.
 *
 * A mutation run rewrites every source file so each expression sits behind a
 * per-mutant branch, and it runs four workers at once — the code under test
 * slows several-fold while this file's calibration, which Stryker does not
 * instrument, does not. The clean budgets are the tightest here, so they go red
 * first, and Stryker aborts every shard whose initial dry run is red. The gate
 * says so and stands down rather than reporting a regression it cannot see.
 *
 * `STRYKER_NAMESPACE` is set on every test process the tap runner spawns (see
 * `@stryker-mutator/tap-runner`'s `runFile`), in both the dry run and the mutant
 * runs; nothing else in this repo sets it.
 */
const MUTATION_RUN = process.env.STRYKER_NAMESPACE
  ? "Stryker instruments the code under test but not this file's calibration, so the ratios measure the instrumentation"
  : null;

const KB = 1024;
const SMALL = 32 * KB;
const LARGE = 256 * KB;
// Shapes carrying no invisible code point at all — the overwhelming majority of
// real pastes, and the ones the counters answer without the code-point array.
// `html-prose` is clean by that measure but not by cost: it is the one shape
// that reaches the remark/rehype graph, so it carries its own budget.
const CLEAN = ["ascii-prose", "cjk-prose", "emoji-prose"];

/**
 * Ceiling per (entry, shape) at LARGE, in calibration units — 1.6x the dearest
 * reading across the ways this file is run: standalone, and twice under the
 * parallel `node scripts/coverage.mjs` suite, whose contention moves a cell by
 * up to 1.8x between samples. That is the headroom a shared runner needs while
 * still catching the order-of-magnitude regressions this file exists for. A
 * budget that is not re-derived after a win is a ceiling nothing defends, so
 * these move DOWN with every improvement.
 */
const BUDGET = {
  scanText: {
    "ascii-prose": 4,
    "cjk-prose": 6,
    "emoji-prose": 5,
    "html-prose": 5,
    "joiner-dense": 25,
    "vs-dense": 15,
    "emoji-zwj": 17,
    "payload-run": 65,
    "payload-scattered": 23,
  },
  classifyPrompt: {
    "ascii-prose": 5,
    "cjk-prose": 7,
    "emoji-prose": 6,
    "html-prose": 5,
    "joiner-dense": 48,
    "vs-dense": 37,
    "emoji-zwj": 33,
    "payload-run": 94,
    "payload-scattered": 32,
  },
  sanitizeText: {
    "ascii-prose": 2,
    "cjk-prose": 5,
    "emoji-prose": 6,
    "html-prose": 69,
    "joiner-dense": 76,
    "vs-dense": 40,
    "emoji-zwj": 42,
    "payload-run": 52,
    "payload-scattered": 7,
  },
};

// A hard wall-clock backstop on top of the ratios: a machine so slow that a
// blocking hook takes this long over 256 KB is one the ratios would still call
// healthy, and the user would still be waiting. The dearest cell measured is
// 97 ms uninstrumented and 443 ms under the coverage run, so this sits BELOW
// 1.6x the instrumented worst case, and well below the SLOW_HOOK_THRESHOLD_MS
// notice the hook layer posts at.
const WALL_CLOCK_CEILING_MS = 600;

// LARGE is 8x SMALL, so linear scaling costs 8x. Anything past this is
// super-linear in the document length — the shape of blow-up that turns a
// tolerable paste into a hang — and it is measured on one machine in one
// process, so it needs no headroom for machine speed, only for timer noise.
const SCALING_LIMIT = 24;
// Below this a SMALL measurement is timer noise, and its scaling ratio says
// nothing. Shapes that cheap are pinned by their LARGE budget instead.
const SCALABLE_FLOOR_MS = 2;

const CALIBRATION_TEXT = SHAPES["ascii-prose"](LARGE);

/** One pass over the text, a code point at a time — the unit every budget is
 * quoted in. Deliberately trivial: it must not get faster or slower for any
 * reason except the machine it runs on. */
function calibrationPass(text) {
  let seen = 0;
  for (const ch of text) seen += ch.length;
  return seen;
}

/**
 * Median of three timed runs after a warm-up call, in ms. Three is enough
 * because the gates below are ratios with room to spare, and a wider sample
 * would cost more wall clock than the regression it protects against.
 * @param {() => unknown | Promise<unknown>} fn
 */
async function measure(fn) {
  await fn();
  const runs = [];
  for (let i = 0; i < 3; i++) {
    const started = performance.now();
    await fn();
    runs.push(performance.now() - started);
  }
  return runs.sort((a, b) => a - b)[1];
}

const calibrate = () => measure(() => calibrationPass(CALIBRATION_TEXT));

/**
 * `fn`'s cost in calibration units, calibrating on BOTH sides of the
 * measurement and taking the larger unit. The test runner runs files in
 * parallel, so the load on the machine drifts during a run; a single calibration
 * taken up front can be read against a shape measured under quite different
 * contention. Bracketing the measurement keeps the two comparable, and taking
 * the larger unit resolves a drift in the direction that does not manufacture a
 * failure.
 * @param {() => unknown | Promise<unknown>} fn
 */
async function unitsFor(fn) {
  const opening = await calibrate();
  const cost = await measure(fn);
  return { cost, units: cost / Math.max(opening, await calibrate()) };
}

/** @type {{unit: number, large: Record<string, number>, small: Record<string, number>, units: Record<string, number>}} */
const timing = { unit: 0, large: {}, small: {}, units: {} };

/** The key a measurement is filed under. */
const key = (entry, shape) => `${entry} · ${shape}`;

before(async () => {
  if (MUTATION_RUN) return;
  timing.unit = await calibrate();
  for (const [entry, run] of Object.entries(ENTRIES))
    for (const [shape, generate] of Object.entries(SHAPES)) {
      const large = generate(LARGE);
      const small = generate(SMALL);
      const measured = await unitsFor(() => run(large));
      timing.large[key(entry, shape)] = measured.cost;
      timing.units[key(entry, shape)] = measured.units;
      timing.small[key(entry, shape)] = await measure(() => run(small));
    }
});

/** An `it` whose verdict rests on the timings, and so has none under Stryker.
 * @param {string} name @param {(t: import("node:test").TestContext) => void} fn */
const timed = (name, fn) =>
  it(name, (t) => {
    if (MUTATION_RUN) {
      t.skip(MUTATION_RUN);
      return;
    }
    fn(t);
  });

/** Every (entry, shape) pair, as the tests iterate them. */
const PAIRS = Object.keys(ENTRIES).flatMap((entry) =>
  Object.keys(SHAPES).map((shape) => [entry, shape]),
);

describe("blocking-hook latency", () => {
  it("the budget table covers exactly the imported shapes and entries", () => {
    // The shapes come from the benchmark; the ceilings are quoted here. A shape
    // added there with no ceiling here would otherwise be compared against
    // `undefined`, which reds — but names the timing, not the missing budget.
    assert.deepEqual(
      PAIRS.map(([entry, shape]) => key(entry, shape)).sort(),
      Object.entries(BUDGET)
        .flatMap(([entry, shapes]) =>
          Object.keys(shapes).map((shape) => key(entry, shape)),
        )
        .sort(),
    );
  });

  timed("the calibration is a measurement, not timer noise", () => {
    // Every ratio below divides by this. A machine that materializes 256 KB in
    // under a third of a millisecond is not one these gates can speak about, so
    // say so loudly rather than passing on a division by noise.
    assert.ok(
      timing.unit > 0.3,
      `calibration ran in ${timing.unit.toFixed(3)}ms — too fast to divide by`,
    );
  });

  for (const [entry, shape] of PAIRS)
    timed(
      `${entry}: a 256 KB ${shape} document stays inside its budget`,
      () => {
        const at = key(entry, shape);
        assert.ok(
          timing.units[at] <= BUDGET[entry][shape],
          `${at} took ${timing.units[at].toFixed(1)} units (${timing.large[at].toFixed(1)}ms), budget ${BUDGET[entry][shape]}`,
        );
      },
    );

  timed("no blocking hook spends longer than the wall-clock ceiling", () => {
    for (const [entry, shape] of PAIRS) {
      const at = key(entry, shape);
      assert.ok(
        timing.large[at] <= WALL_CLOCK_CEILING_MS,
        `${at} took ${timing.large[at].toFixed(1)}ms over 256 KB, ceiling ${WALL_CLOCK_CEILING_MS}ms`,
      );
    }
  });

  for (const [entry, shape] of PAIRS)
    timed(`${entry}: ${shape} cost grows with length, not faster`, (t) => {
      const at = key(entry, shape);
      if (timing.small[at] < SCALABLE_FLOOR_MS) {
        t.skip(
          `${timing.small[at].toFixed(2)}ms at 32 KB is below the ${SCALABLE_FLOOR_MS}ms noise floor`,
        );
        return;
      }
      const growth = timing.large[at] / timing.small[at];
      assert.ok(
        growth <= SCALING_LIMIT,
        `${at} cost ${growth.toFixed(1)}x for 8x the document, limit ${SCALING_LIMIT}x`,
      );
    });

  timed(
    "enough pairs clear the noise floor for the scaling gate to mean something",
    () => {
      // Without this the scaling gate could silently degrade to zero pairs on a
      // fast machine and still report green.
      const scalable = PAIRS.filter(
        ([entry, shape]) =>
          timing.small[key(entry, shape)] >= SCALABLE_FLOOR_MS,
      );
      assert.ok(
        scalable.length >= 6,
        `only ${scalable.length} pairs were timeable at 32 KB`,
      );
    },
  );

  timed(
    "the shapes really do split into cheap and carve-path documents",
    () => {
      // A positive control on the budget table: if every shape were answered by
      // the bulk regex passes, the carve-path budgets would be gating nothing and
      // could be tightened to the baseline. This fails when a shape stops
      // driving the arm it was written for.
      //
      // The comparand is ascii-prose alone, not the dearest CLEAN shape. Clean
      // means "carries no invisible code point", which is not the same as cheap:
      // emoji-prose is dear because emoji are multi-code-point clusters, and
      // charging a carve shape against THAT reads a segmentation cost as a carve
      // cost. ascii-prose is the one shape with neither, so it is the floor a
      // document that reached the per-code-point analysis must clear.
      for (const entry of Object.keys(ENTRIES)) {
        const baseline = timing.large[key(entry, "ascii-prose")];
        for (const shape of Object.keys(SHAPES)) {
          if (CLEAN.includes(shape) || shape === "html-prose") continue;
          const at = key(entry, shape);
          assert.ok(
            timing.large[at] > baseline,
            `${at} (${timing.large[at].toFixed(1)}ms) no longer costs more than plain ascii for ${entry} (${baseline.toFixed(1)}ms) — it is not exercising the carve analysis`,
          );
        }
      }
    },
  );

  it("the hook entry carries the same budget as the classifier it wraps", async (t) => {
    if (MUTATION_RUN) {
      t.skip(MUTATION_RUN);
      return;
    }
    // The gate the user actually waits on is the hook, not the library
    // function. Judging adds only constant work, so a clean paste through
    // judgeSanitizeUserPrompt must stay inside the same clean budget — this is
    // what fails if the cost ever moves into the hook's own wrapper.
    const prompt = SHAPES["ascii-prose"](LARGE);
    const event = claudeAdapter.parse({
      hook_event_name: "UserPromptSubmit",
      prompt,
    });
    const { cost, units } = await unitsFor(() =>
      judgeSanitizeUserPrompt(event),
    );
    const budget = BUDGET.classifyPrompt["ascii-prose"];
    assert.ok(
      units <= budget,
      `the hook judged a clean 256 KB prompt in ${units.toFixed(1)} units (${cost.toFixed(1)}ms), budget ${budget}`,
    );
  });
});
