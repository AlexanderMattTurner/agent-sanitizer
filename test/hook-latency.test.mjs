/**
 * Latency gates for the hook paths a user waits on.
 *
 * `classifyPrompt` runs inside the prompt-submit hook and BLOCKS submission;
 * `sanitizeText` runs inside the tool-output hook and blocks the result reaching
 * the model. Whatever either spends is dead wait. A regression there is
 * invisible from the inside — it reads as "the agent is slow" — and the
 * correctness suites are indifferent to it, which is how a per-code-point RegExp
 * scan sat in the carve analysis charging ~250 ms per megabyte.
 *
 * Every budget is a RATIO against a calibration measured in this same process:
 * one code-point-by-code-point pass over a fixed 256 KB input, which is the
 * cheapest full read of a text anything here can do. Machine speed, CPU
 * contention and the coverage instrumentation scale both sides, so the ratios
 * survive a loaded CI runner in a way wall-clock milliseconds do not — the
 * calibration is written in this file, rather than reaching for a native
 * builtin, precisely so it pays the same instrumentation tax as the code it
 * normalizes.
 */
import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { classifyPrompt } from "../src/prompt.mjs";
import { sanitizeText } from "../src/output.mjs";

const { claudeAdapter } = await import("agent-control-plane-core/claude");
const { judgeSanitizeUserPrompt } =
  await import("../claude-hooks/sanitize-user-prompt.mjs");

/**
 * Why the ratios cannot be read under Stryker.
 *
 * A mutation run rewrites every source file so each expression sits behind a
 * per-mutant branch, and it runs four workers at once — the code under test
 * slows several-fold while this file's calibration, which Stryker does not
 * instrument, does not. The cheap-input budget is the tightest here, so it goes
 * red first, and Stryker aborts every shard whose initial dry run is red. The
 * gate says so and stands down rather than reporting a regression it cannot see.
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
const cp = (n) => String.fromCodePoint(n);
const grow = (unit, n) => unit.repeat(Math.ceil(n / unit.length)).slice(0, n);

/**
 * Median of three timed runs after a warm-up call, in ms. Three is enough
 * because the gates below are ratios with room to spare, and a wider sample
 * would cost more wall clock than the regression it protects against.
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

// Text shapes with materially different cost profiles. The clean ones answer
// from bulk regex passes; the rest each drive a different arm of the carve
// analysis or the HTML layer, which is per-code-point (or per-node) work no bulk
// pass can do. A homogeneous "x".repeat(n) exercises only the first group, which
// is exactly how a carve-path regression would slip through.
const SHAPES = {
  "ascii-prose": (n) =>
    grow("The quick brown fox jumps over the lazy dog. ", n),
  "cjk-prose": (n) => grow("速い茶色の狐が怠惰な犬を飛び越える。", n),
  "emoji-prose": (n) => grow("🙂 ok 🚀 go 🎉 ", n),
  "joiner-dense": (n) => grow("می" + cp(0x200c) + "خواهم ", n),
  "vs-dense": (n) => grow("漢" + cp(0xe0100), n),
  "payload-run": (n) => grow(cp(0x200b), n),
  "payload-scattered": (n) => grow("a" + cp(0x00ad), n),
  "emoji-zwj": (n) => grow("\u{1F3F3}️‍\u{1F308}", n),
  "html-prose": (n) =>
    grow('<p class="x">hello <a href="https://e.com/a?q=1">link</a></p>\n', n),
};

// Ceilings in calibration units — roughly 2.5x what each entry costs on each
// shape today, measured both standalone and under the parallel coverage run,
// which is the headroom a shared runner needs while still catching the
// order-of-magnitude regressions this file exists for. CHEAP_BUDGET is an order
// tighter, and each entry's `cheap` list names the shapes that entry has no
// per-code-point work to do on: past ten passes' worth of work, such an input is
// being analyzed for something it does not contain. The lists differ per entry
// because the entries read different things — a soft hyphen every other
// character is real work for the prompt classifier's scatter count and almost
// none for the strip the output path runs.
const CHEAP_BUDGET = 10;

/**
 * The blocking entry points, each with the shapes it must answer cheaply.
 * @type {Record<string, { run: (text: string, shape: string) => unknown,
 *   cheap: string[], budget: Record<string, number> }>}
 */
const ENTRIES = {
  classifyPrompt: {
    run: (text) => classifyPrompt(text),
    // Markup is not a prompt-gate concern: the classifier reads invisibles and
    // ANSI, and HTML-shaped text carries neither.
    cheap: ["ascii-prose", "cjk-prose", "emoji-prose", "html-prose"],
    budget: {
      "ascii-prose": CHEAP_BUDGET,
      "cjk-prose": CHEAP_BUDGET,
      "emoji-prose": CHEAP_BUDGET,
      "html-prose": CHEAP_BUDGET,
      "joiner-dense": 180,
      "vs-dense": 90,
      "payload-run": 110,
      "payload-scattered": 36,
      "emoji-zwj": 80,
    },
  },
  sanitizeText: {
    // Layers 2 and 3 run on the HTML-shaped input only, matching the output
    // hook's own policy (WEB_INGRESS_TOOLS, or MCP output that trips
    // HTML_TAG_PRESENT); every other shape takes the Layer-1 path the majority
    // of tool results take.
    run: (text, shape) =>
      sanitizeText(
        text,
        shape === "html-prose" ? { html: true, exfilScan: true } : {},
      ),
    // A scattered soft hyphen carries no joiner and no variation selector, so
    // the carve analysis finds nothing to preserve and the strip is a bulk pass.
    cheap: ["ascii-prose", "cjk-prose", "emoji-prose", "payload-scattered"],
    budget: {
      "ascii-prose": CHEAP_BUDGET,
      "cjk-prose": CHEAP_BUDGET,
      "emoji-prose": CHEAP_BUDGET,
      "payload-scattered": CHEAP_BUDGET,
      "html-prose": 205,
      "joiner-dense": 240,
      "vs-dense": 105,
      "payload-run": 55,
      "emoji-zwj": 95,
    },
  },
};

// LARGE is 8x SMALL, so linear scaling costs 8x. Anything past this is
// super-linear in the input length — the shape of blow-up that turns a tolerable
// paste into a hang — and it is measured on one machine in one process, so it
// needs no headroom for machine speed, only for timer noise.
const SCALING_LIMIT = 24;
// Below this a SMALL measurement is timer noise, and its scaling ratio says
// nothing. Cases that cheap are pinned by their LARGE budget instead.
const SCALABLE_FLOOR_MS = 2;

/**
 * The one path whose cost is known to grow faster than its input, pinned where
 * the blow-up actually shows.
 *
 * Layer 2/3 on HTML is super-linear — measured 7.2x for 4x the input at these
 * sizes, most of it inside parse5's `detachNode`, which is O(siblings) per
 * detached node. The 8x step above cannot see it, because the path is still
 * roughly linear below 256 KB, so it gets its own step and its own ceiling: a
 * ratchet holding the exponent where it is, not a budget saying this is fine.
 * The companion case below fails if the growth ever comes back down to linear,
 * which is the signal to delete this exception rather than leave a ceiling
 * nothing is under.
 */
const SUPERLINEAR = {
  entry: "sanitizeText",
  shape: "html-prose",
  from: 128 * KB,
  to: 512 * KB,
  linear: 4,
  limit: 12,
};

const CALIBRATION_TEXT = SHAPES["ascii-prose"](LARGE);

/** One pass over the input, a code point at a time — the unit every budget is
 * quoted in. Deliberately trivial: it must not get faster or slower for any
 * reason except the machine it runs on. */
function calibrationPass(text) {
  let seen = 0;
  for (const ch of text) seen += ch.length;
  return seen;
}

const calibrate = () => measure(() => calibrationPass(CALIBRATION_TEXT));

/**
 * `fn`'s cost in calibration units, calibrating on BOTH sides of the
 * measurement and taking the larger unit. The test runner runs files in
 * parallel, so the load on the machine drifts during a run; a single calibration
 * taken up front can be read against a case measured under quite different
 * contention. Bracketing the measurement keeps the two comparable, and taking
 * the larger unit resolves a drift in the direction that does not manufacture a
 * failure.
 */
async function unitsFor(fn) {
  const opening = await calibrate();
  const cost = await measure(fn);
  return { cost, units: cost / Math.max(opening, await calibrate()) };
}

/** Every entry x shape pair the gates below speak about. */
const CASES = Object.keys(ENTRIES).flatMap((entry) =>
  Object.keys(SHAPES).map((shape) => ({
    entry,
    shape,
    name: `${entry}/${shape}`,
  })),
);

/** @type {{unit: number, large: Record<string, number>, small: Record<string, number>,
 *   units: Record<string, number>, superlinear: Record<string, number>}} */
const timing = {
  unit: 0,
  large: {},
  small: {},
  units: {},
  superlinear: { from: 0, to: 0 },
};

before(async () => {
  if (MUTATION_RUN) return;
  timing.unit = await calibrate();
  for (const { entry, shape, name } of CASES) {
    const { run } = ENTRIES[entry];
    const large = SHAPES[shape](LARGE);
    const small = SHAPES[shape](SMALL);
    const measured = await unitsFor(() => run(large, shape));
    timing.large[name] = measured.cost;
    timing.units[name] = measured.units;
    timing.small[name] = await measure(() => run(small, shape));
  }
  const { run } = ENTRIES[SUPERLINEAR.entry];
  for (const end of ["from", "to"]) {
    const text = SHAPES[SUPERLINEAR.shape](SUPERLINEAR[end]);
    timing.superlinear[end] = await measure(() => run(text, SUPERLINEAR.shape));
  }
});

/** An `it` whose verdict rests on the timings, and so has none under Stryker.
 * @param {string} name
 * @param {(t: import("node:test").TestContext) => void | Promise<void>} fn */
const timed = (name, fn) =>
  it(name, async (t) => {
    if (MUTATION_RUN) {
      t.skip(MUTATION_RUN);
      return;
    }
    await fn(t);
  });

describe("hook-path latency", () => {
  timed("the calibration is a measurement, not timer noise", () => {
    // Every ratio below divides by this. A machine that materializes 256 KB in
    // under a third of a millisecond is not one these gates can speak about, so
    // say so loudly rather than passing on a division by noise.
    assert.ok(
      timing.unit > 0.3,
      `calibration ran in ${timing.unit.toFixed(3)}ms — too fast to divide by`,
    );
  });

  for (const { entry, shape, name } of CASES)
    timed(`${name}: 256 KB stays inside its budget`, () => {
      const budget = ENTRIES[entry].budget[shape];
      assert.ok(
        timing.units[name] <= budget,
        `${name} ran in ${timing.units[name].toFixed(1)} units (${timing.large[name].toFixed(1)}ms), budget ${budget}`,
      );
    });

  for (const { name } of CASES)
    timed(`${name}: cost grows with input length, not faster`, (t) => {
      if (timing.small[name] < SCALABLE_FLOOR_MS) {
        t.skip(
          `${timing.small[name].toFixed(2)}ms at 32 KB is below the ${SCALABLE_FLOOR_MS}ms noise floor`,
        );
        return;
      }
      const growth = timing.large[name] / timing.small[name];
      assert.ok(
        growth <= SCALING_LIMIT,
        `${name} cost ${growth.toFixed(1)}x for 8x the input, limit ${SCALING_LIMIT}x`,
      );
    });

  timed(
    "enough cases clear the noise floor for the scaling gate to mean something",
    () => {
      // Without this the scaling gate could silently degrade to zero cases on a
      // fast machine and still report green.
      const scalable = CASES.filter(
        ({ name }) => timing.small[name] >= SCALABLE_FLOOR_MS,
      );
      assert.ok(
        scalable.length >= 8,
        `only ${scalable.length} cases were timeable at 32 KB: ${scalable.map((c) => c.name).join(", ")}`,
      );
    },
  );

  for (const entry of Object.keys(ENTRIES))
    timed(`${entry}: the shapes really do split into cheap and heavy`, () => {
      // A positive control on the budget table: if every shape were answered by
      // the bulk regex passes, the heavy budgets would be gating nothing and
      // could be tightened to CHEAP_BUDGET. This fails when a shape stops
      // driving the arm it was written for.
      const { cheap } = ENTRIES[entry];
      const dearest = Math.max(
        ...cheap.map((shape) => timing.large[`${entry}/${shape}`]),
      );
      for (const shape of Object.keys(SHAPES).filter((s) => !cheap.includes(s)))
        assert.ok(
          timing.large[`${entry}/${shape}`] > dearest,
          `${entry}/${shape} (${timing.large[`${entry}/${shape}`].toFixed(1)}ms) no longer costs more than the dearest cheap shape (${dearest.toFixed(1)}ms) — it is not exercising the path it was written for`,
        );
    });

  timed(
    "the hook entry carries the same budget as the classifier it wraps",
    async () => {
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
      assert.ok(
        units <= CHEAP_BUDGET,
        `the hook judged a clean 256 KB prompt in ${units.toFixed(1)} units (${cost.toFixed(1)}ms), budget ${CHEAP_BUDGET}`,
      );
    },
  );

  const superlinearName = `${SUPERLINEAR.entry}/${SUPERLINEAR.shape}`;
  const superlinearGrowth = () =>
    timing.superlinear.to / timing.superlinear.from;
  const sizeStep = SUPERLINEAR.to / SUPERLINEAR.from;

  timed(
    `${superlinearName}: the known super-linearity does not get worse`,
    () => {
      assert.ok(
        superlinearGrowth() <= SUPERLINEAR.limit,
        `${superlinearName} cost ${superlinearGrowth().toFixed(1)}x for ${sizeStep}x the input (${timing.superlinear.from.toFixed(1)}ms → ${timing.superlinear.to.toFixed(1)}ms), limit ${SUPERLINEAR.limit}x`,
      );
    },
  );

  timed(`${superlinearName}: the exception is still earning its place`, () => {
    // The other half of the ratchet. A ceiling of 12x on a path that grew
    // linearly would gate nothing at all, so this fails the moment the HTML
    // layer stops being super-linear — and the fix is to delete SUPERLINEAR and
    // let the ordinary scaling gate own it.
    assert.ok(
      superlinearGrowth() > SUPERLINEAR.linear,
      `${superlinearName} grew ${superlinearGrowth().toFixed(1)}x for ${sizeStep}x the input — that is linear, so delete SUPERLINEAR and let the ${SCALING_LIMIT}x gate cover it`,
    );
  });
});
