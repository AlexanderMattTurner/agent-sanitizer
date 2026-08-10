/**
 * Latency gates for the UserPromptSubmit path.
 *
 * classifyPrompt runs inside the prompt-submit hook and BLOCKS submission, so
 * its cost is dead wait the user pays before the prompt is sent. A regression
 * there is invisible from the inside — it reads as "the agent is slow" — and
 * the correctness suites are indifferent to it, which is how a per-code-point
 * RegExp scan sat in the carve analysis charging ~250 ms per megabyte.
 *
 * Every budget is a RATIO against a calibration measured in this same process:
 * one code-point-by-code-point pass over a fixed 256 KB prompt, which is the
 * cheapest full read of a prompt anything here can do. Machine speed, CPU
 * contention and the coverage instrumentation scale both sides, so the ratios
 * survive a loaded CI runner in a way wall-clock milliseconds do not — the
 * calibration is written in this file, rather than reaching for a native
 * builtin, precisely so it pays the same instrumentation tax as the code it
 * normalizes.
 */
import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { classifyPrompt } from "../src/prompt.mjs";

const { claudeAdapter } = await import("agent-control-plane-core/claude");
const { judgeSanitizeUserPrompt } =
  await import("../claude-hooks/sanitize-user-prompt.mjs");

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
function measure(fn) {
  fn();
  const runs = [];
  for (let i = 0; i < 3; i++) {
    const started = performance.now();
    fn();
    runs.push(performance.now() - started);
  }
  return runs.sort((a, b) => a - b)[1];
}

// Prompt shapes with materially different cost profiles. The clean ones answer
// from bulk regex passes; the rest each drive a different arm of the carve
// analysis, which is per-code-point work no bulk pass can do. A homogeneous
// "x".repeat(n) exercises only the first group, which is exactly how a
// carve-path regression would slip through.
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
};

// Shapes carrying no invisible code point at all — the overwhelming majority of
// real pastes, and the ones the counters answer without the code-point array.
const CLEAN = ["ascii-prose", "cjk-prose", "emoji-prose"];

// Ceiling per shape at LARGE, in calibration units — roughly 2.5x what the shape
// costs today, measured both standalone and under the parallel coverage run,
// which is the headroom a shared runner needs while still catching the
// order-of-magnitude regressions this file exists for. CLEAN_BUDGET is an order
// tighter because a prompt with no invisible code point in it must never reach
// the per-code-point analysis at all: past ten passes' worth of work, a clean
// paste is being analyzed for something it does not contain.
const CLEAN_BUDGET = 10;
const BUDGET = {
  "ascii-prose": CLEAN_BUDGET,
  "cjk-prose": CLEAN_BUDGET,
  "emoji-prose": CLEAN_BUDGET,
  "joiner-dense": 180,
  "vs-dense": 90,
  "payload-run": 110,
  "payload-scattered": 36,
  "emoji-zwj": 80,
};

// LARGE is 8x SMALL, so linear scaling costs 8x. Anything past this is
// super-linear in the prompt length — the shape of blow-up that turns a
// tolerable paste into a hang — and it is measured on one machine in one
// process, so it needs no headroom for machine speed, only for timer noise.
const SCALING_LIMIT = 24;
// Below this a SMALL measurement is timer noise, and its scaling ratio says
// nothing. Shapes that cheap are pinned by their LARGE budget instead.
const SCALABLE_FLOOR_MS = 2;

const CALIBRATION_TEXT = SHAPES["ascii-prose"](LARGE);

/** One pass over the prompt, a code point at a time — the unit every budget is
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
 * taken up front can be read against a shape measured under quite different
 * contention. Bracketing the measurement keeps the two comparable, and taking
 * the larger unit resolves a drift in the direction that does not manufacture a
 * failure.
 */
function unitsFor(fn) {
  const before_ = calibrate();
  const cost = measure(fn);
  const unit = Math.max(before_, calibrate());
  return { cost, unit, units: cost / unit };
}

/** @type {{unit: number, large: Record<string, number>, small: Record<string, number>, units: Record<string, number>}} */
const timing = { unit: 0, large: {}, small: {}, units: {} };

before(() => {
  timing.unit = calibrate();
  for (const [name, generate] of Object.entries(SHAPES)) {
    const large = generate(LARGE);
    const small = generate(SMALL);
    const measured = unitsFor(() => classifyPrompt(large));
    timing.large[name] = measured.cost;
    timing.units[name] = measured.units;
    timing.small[name] = measure(() => classifyPrompt(small));
  }
});

describe("prompt-submit latency", () => {
  it("the calibration is a measurement, not timer noise", () => {
    // Every ratio below divides by this. A machine that materializes 256 KB in
    // under a third of a millisecond is not one these gates can speak about, so
    // say so loudly rather than passing on a division by noise.
    assert.ok(
      timing.unit > 0.3,
      `calibration ran in ${timing.unit.toFixed(3)}ms — too fast to divide by`,
    );
  });

  for (const name of Object.keys(SHAPES))
    it(`${name}: a 256 KB prompt stays inside its budget`, () => {
      assert.ok(
        timing.units[name] <= BUDGET[name],
        `${name} classified in ${timing.units[name].toFixed(1)} units (${timing.large[name].toFixed(1)}ms), budget ${BUDGET[name]}`,
      );
    });

  for (const name of Object.keys(SHAPES))
    it(`${name}: cost grows with prompt length, not faster`, (t) => {
      if (timing.small[name] < SCALABLE_FLOOR_MS) {
        t.skip(
          `${timing.small[name].toFixed(2)}ms at 32 KB is below the ${SCALABLE_FLOOR_MS}ms noise floor`,
        );
        return;
      }
      const growth = timing.large[name] / timing.small[name];
      assert.ok(
        growth <= SCALING_LIMIT,
        `${name} cost ${growth.toFixed(1)}x for 8x the prompt, limit ${SCALING_LIMIT}x`,
      );
    });

  it("enough shapes clear the noise floor for the scaling gate to mean something", () => {
    // Without this the scaling gate could silently degrade to zero shapes on a
    // fast machine and still report green.
    const scalable = Object.keys(SHAPES).filter(
      (name) => timing.small[name] >= SCALABLE_FLOOR_MS,
    );
    assert.ok(
      scalable.length >= 4,
      `only ${scalable.length} shapes were timeable at 32 KB: ${scalable.join(", ")}`,
    );
  });

  it("the shapes really do split into cheap and carve-path prompts", () => {
    // A positive control on the budget table: if every shape were answered by
    // the bulk regex passes, the carve-path budgets would be gating nothing and
    // could be tightened to CLEAN_BUDGET. This fails when a shape stops driving
    // the arm it was written for.
    const cleanest = Math.max(...CLEAN.map((n) => timing.large[n]));
    const carved = Object.keys(SHAPES).filter((n) => !CLEAN.includes(n));
    for (const name of carved)
      assert.ok(
        timing.large[name] > cleanest,
        `${name} (${timing.large[name].toFixed(1)}ms) no longer costs more than the cleanest prompt (${cleanest.toFixed(1)}ms) — it is not exercising the carve analysis`,
      );
  });

  it("the hook entry carries the same budget as the classifier it wraps", () => {
    // The gate the user actually waits on is the hook, not the library
    // function. Judging adds only constant work, so a clean paste through
    // judgeSanitizeUserPrompt must stay inside the same clean budget — this is
    // what fails if the cost ever moves into the hook's own wrapper.
    const prompt = SHAPES["ascii-prose"](LARGE);
    const event = claudeAdapter.parse({
      hook_event_name: "UserPromptSubmit",
      prompt,
    });
    const { cost, units } = unitsFor(() => judgeSanitizeUserPrompt(event));
    assert.ok(
      units <= CLEAN_BUDGET,
      `the hook judged a clean 256 KB prompt in ${units.toFixed(1)} units (${cost.toFixed(1)}ms), budget ${CLEAN_BUDGET}`,
    );
  });
});
