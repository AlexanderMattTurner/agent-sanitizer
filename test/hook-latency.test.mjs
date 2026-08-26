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
 * {@link calibrationPass} over a fixed 256 KB input, the cheapest full read of a
 * text anything here can do. Machine speed and the coverage instrumentation
 * scale both sides, so the ratios survive a slow or instrumented runner in a way
 * milliseconds do not — the calibration lives in this file, rather than reaching
 * for a native builtin, so it pays the same instrumentation tax as the code it
 * normalizes. A ratio does not cancel a BUSY machine, though, so every timed
 * block is charged in CPU time rather than wall clock (see {@link measure}).
 * {@link REALISTIC_MS} is the lone exception.
 */
import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { classifyPrompt } from "../src/prompt.mjs";
import { sanitizeText } from "../src/output.mjs";
import { scanText } from "../src/instructions.mjs";
import {
  foldConfusables,
  selectFoldableFindings,
} from "../src/confusables.mjs";

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
 * is what lets the budgets below stay tight enough to catch a doubling.
 */
const SAMPLES = 8;

/**
 * A timed block, in ms: the CPU time the process spent, and the wall clock it
 * occupied.
 * @typedef {{cpu: number, wall: number}} Timing
 */

/** The CPU time a block charged the process, in ms. `process.cpuUsage` counts
 * every thread, so a collector pass or a background compile the block provoked
 * is charged to it — which is the intent, since the hook pays for those too. */
const cpuSince = (mark) => {
  const spent = process.cpuUsage(mark);
  return (spent.user + spent.system) / 1000;
};

/**
 * A block's cost, in both clocks. `cpu` is what every ratio below reads: a ratio
 * cancels a slower machine because both sides run at that speed, but not a busy
 * one, because the two sides are timed over blocks of very different length — a
 * 1 ms calibration pass reliably catches a quiet slot for its fastest sample and
 * a 250 ms parse5 run never does, so the divisor stays flat while the numerator
 * inflates. Time descheduled behind another test worker is not time this code
 * spent, and the CPU clock does not charge it.
 *
 * Each call gets its own document from `input(attempt)`. Handing every call the
 * same string measures a memo hit rather than the work: the HTML layer
 * remembers its last parse, so the warm-up builds the tree the timed runs then
 * reuse — 81 ms for a 256 KB fragment against the 160 ms a hook pays for a
 * document it is seeing for the first time, which is the only case there is.
 * The inputs differ in length by one code point, so the shape is unchanged.
 * @param {(attempt: number) => string} input
 * @param {(text: string) => unknown | Promise<unknown>} fn
 * @returns {Promise<Timing>}
 */
async function measure(input, fn) {
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
 * is the number the scaling gate divides by. Timing a batch and dividing keeps
 * the small end meaningful at any machine speed.
 *
 * `blockMs` is what makes the two sides of a scaling ratio comparable: the
 * caller passes the cost of the side it will be divided into, since
 * fastest-of-N is fair only between blocks of similar length (see
 * {@link measure}). Under {@link MIN_BLOCK_MS} the floor wins and the bias runs
 * the other way — those cells sit an order of magnitude clear of
 * {@link SCALING_LIMIT}.
 * @param {(attempt: number) => string} input
 * @param {(text: string) => unknown | Promise<unknown>} fn
 * @param {number} blockMs
 * @returns {Promise<number>}
 */
async function measurePerCall(input, fn, blockMs) {
  const single = (await measure(input, fn)).cpu;
  // A zero would divide into a repeat count no loop finishes. The resolution
  // probe in `before` is what normally catches a clock too coarse to measure
  // these calls; this refuses to hang if one gets past it.
  assert.ok(single > 0, "the CPU clock reported no time for a timed call");
  const repeats = Math.ceil(Math.max(MIN_BLOCK_MS, blockMs) / single);
  if (repeats <= 1) return single;
  // The block cycles a ring of distinct documents for the same reason `measure`
  // varies its input, and a ring rather than one document per call because
  // `repeats` runs to the hundreds on a fast machine and each document is
  // SMALL bytes. Consecutive calls always differ, which is what a one-entry
  // parse memo needs to miss.
  const ring = [];
  for (let i = 0; i < Math.min(repeats, BLOCK_RING); i++)
    ring.push(input(SAMPLES + 1 + i));
  const block = await measure(
    () => "",
    async () => {
      for (let i = 0; i < repeats; i++) await fn(ring[i % ring.length]);
    },
  );
  return block.cpu / repeats;
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
  "emoji-zwj": (n) => grow("\u{1F3F3}\u{FE0F}\u{200D}\u{1F308}", n),
  "html-prose": (n) =>
    grow('<p class="x">hello <a href="https://e.com/a?q=1">link</a></p>\n', n),
  "run-dense": (n) =>
    grow("ordinary instruction text " + cp(0x200b).repeat(12) + "\n", n),
};

/**
 * The ceiling, in calibration units, for a shape an entry has no per-code-point
 * work to do on: past a dozen passes' worth of work, such an input is being
 * analyzed for something it does not contain. Each entry's `cheap` list names
 * its own such shapes, because the entries read different things — a soft hyphen
 * every other character is real work for the prompt classifier's scatter count
 * and almost none for the strip the output path runs.
 *
 * This and every `budget` entry below is 1.3x the DEAREST reading across four
 * environments: standalone, under the parallel coverage run, standalone against
 * four workers of competing CPU and allocation load, and the GitHub runner. The
 * instrumented run reads LOWER on every heavy cell, since c8 charges this file's
 * calibration harder than the code under test, so the ceilings come from the
 * uninstrumented ones. Within one machine no case reads more than 1.12x its own
 * median, so 1.3x covers run-to-run variation and nothing more.
 *
 * Between machines the same ratio moves further: `sanitizeText/payload-scattered`
 * costs 9.9ms of CPU on the runner against 6.5ms here for the same ~0.89ms unit,
 * so the ceiling has to be the dearest microarchitecture's, not the developer's.
 * Every ceiling still sits under twice its case's median on the environment that
 * set it, which is the standard: a doubling is red, and anything looser is a
 * ceiling nothing is under. The per-case diagnostic each gate emits is what makes
 * a runner's numbers readable, so this table can be re-derived from CI.
 */
const CHEAP_BUDGET = 15;

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
      "joiner-dense": 31,
      "vs-dense": 34,
      "payload-run": 84,
      "payload-scattered": 29,
      "emoji-zwj": 31,
      "run-dense": 48,
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
      // The dearest cell in the table, and the one the ratio is doing the
      // least for: it is parse5 building a 256 KB fragment, so it moves with
      // the parser rather than with anything here.
      "html-prose": 250,
      "joiner-dense": 43,
      "vs-dense": 38,
      "payload-run": 59,
      "emoji-zwj": 38,
      "run-dense": 32,
    },
  },
  scanText: {
    // The SessionStart scan reads every instruction file before the session can
    // start, so its cost is startup the user watches — the one hook path where
    // a regression has already cost 30 seconds once.
    run: (text) => scanText(text),
    cheap: ["ascii-prose", "cjk-prose", "emoji-prose", "html-prose"],
    budget: {
      "joiner-dense": 22,
      "vs-dense": 17,
      // One 256 KB run decodes as a single payload, so this case is dominated by
      // one large allocation and swings with the collector — the widest budget
      // here buys tolerance for that rather than for a slower machine.
      "payload-run": 64,
      "payload-scattered": 17,
      "emoji-zwj": 19,
      "run-dense": 34,
    },
  },
};

// LARGE is 8x SMALL, so linear scaling costs 8x. Anything past this is
// super-linear in the input length — the shape of blow-up that turns a tolerable
// paste into a hang — and it is measured on one machine in one process, so it
// needs no headroom for machine speed, only for timer noise.
const SCALING_LIMIT = 24;

/**
 * The confusable fold, which the PreToolUse hook runs over a tool call's path and
 * command fields.
 *
 * It gets its own case rather than a row in the matrix because its cost is
 * driven by the number of FINDINGS, not by the text alone — and the findings are
 * attacker-influenced, since the command being vetted is whatever the model was
 * told to run. One Cyrillic small a (U+0430, which folds to "a") every fifteen
 * characters is the dense end of that.
 */
const FOLD_GLYPH = "\u0430";
const foldText = (n) => grow(FOLD_GLYPH + "bcdefghijklmn ", n);
const FOLD_BUDGET = 16;

/**
 * The one gate that promises a NUMBER rather than a ratio.
 *
 * Every budget above is machine-relative on purpose, and a table of ratios can
 * stay green while each hook takes a second, so the thing a user actually
 * notices \u2014 the wait before a session starts, the wait before a prompt goes \u2014
 * needs a ceiling in milliseconds — and, alone here, in WALL-CLOCK milliseconds,
 * since a user waits through descheduling too and the CPU clock the ratios use
 * would understate the very thing this gate promises. The input is ordinary text
 * at 256 KB, larger than most pastes; the adversarial shapes keep their ratio
 * budgets, because a ceiling wide enough for 256 KB of nothing but zero-width
 * space on a slow runner would not be a guarantee about anything.
 *
 * c8 multiplies wall clock by roughly seven here, which is a fact about the
 * instrumentation and not about the hook, so this half stands down under
 * coverage \u2014 and `pnpm test` runs the whole suite under coverage. The
 * uninstrumented step in `.github/workflows/node-tests.yaml` ("Run the hook
 * latency gates uninstrumented") is what makes CI read it; without that step
 * this gate would be local-only.
 */
const REALISTIC_MS = 40;
const REALISTIC_SIZE = 256 * KB;
const REALISTIC_TEXT = grow(
  "The quick brown fox jumps over the lazy dog. " +
    "\u901f\u3044\u8336\u8272\u306e\u72d0\u304c\u6020\u60f0\u306a\u72ac\u3092\u98db\u3073\u8d8a\u3048\u308b\u3002" +
    "\ud83d\ude42 ok \ud83d\ude80 go \ud83c\udf89 ",
  REALISTIC_SIZE,
);

/** Every offset of {@link FOLD_GLYPH}, as the scanner would report them. */
function foldFindings(text) {
  const findings = [];
  for (let i = 0; i < text.length; i++)
    if (text[i] === FOLD_GLYPH)
      findings.push({ index: i, char: FOLD_GLYPH, latinEquivalent: "a" });
  return findings;
}

const CALIBRATION_TEXT = SHAPES["ascii-prose"](LARGE);

/**
 * One pass over the input, a code point at a time — the unit every budget is
 * quoted in. Deliberately trivial: it must not get faster or slower for any
 * reason except the machine it runs on.
 *
 * Indexing rather than iterating is what keeps that promise. `for (const ch of
 * text)` reads the same code points but materializes a string for each one, so
 * its cost tracks the young generation's size — which the rest of the process
 * sets, not the machine. This loop allocates nothing.
 */
function calibrationPass(text) {
  let seen = 0;
  for (let i = 0; i < text.length;) {
    const point = text.codePointAt(i);
    seen += point;
    i += point > 0xffff ? 2 : 1;
  }
  return seen;
}

/** The unit, in CPU ms per pass. */
const calibrate = async () =>
  (await measure(() => CALIBRATION_TEXT, calibrationPass)).cpu;

/** How long a probe block busy-waits, and how many it runs. */
const PROBE_MS = 0.2;
const PROBE_BLOCKS = 40;

/**
 * The finest CPU-time reading this clock resolves, in ms.
 *
 * `process.cpuUsage` reports microseconds, but a kernel that accumulates rusage
 * at tick granularity only ever reports whole ticks — 1 ms, or 4 ms — and the
 * calibration pass costs about one millisecond, so on such a kernel the unit is
 * quantized to within its own size and no ratio here means anything. Busy-wait
 * blocks well under a tick and keep the smallest non-zero reading: it comes back
 * near {@link PROBE_MS} on a microsecond clock and at a whole tick otherwise.
 */
function clockResolutionMs() {
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

/**
 * `fn`'s CPU cost in calibration units, calibrating on BOTH sides of the
 * measurement and taking the larger unit. The test runner runs files in
 * parallel, so the machine's clock speed and cache pressure drift during a run;
 * a single calibration taken up front can be read against a case measured in
 * quite different conditions. Bracketing the measurement keeps the two
 * comparable, and taking the larger unit resolves a drift in the direction that
 * does not manufacture a failure.
 * @returns {Promise<{cost: Timing, units: number}>}
 */
async function unitsFor(input, fn) {
  const opening = await calibrate();
  const cost = await measure(input, fn);
  return { cost, units: cost.cpu / Math.max(opening, await calibrate()) };
}

/** Every entry x shape pair the gates below speak about. */
const CASES = Object.keys(ENTRIES).flatMap((entry) =>
  Object.keys(SHAPES).map((shape) => ({
    entry,
    shape,
    name: `${entry}/${shape}`,
  })),
);

/**
 * Every figure here is CPU ms except `realistic`, which is the wall clock the
 * millisecond ceiling is about.
 * @type {{unit: number, large: Record<string, number>, small: Record<string, number>,
 *   units: Record<string, number>,
 *   realistic: Record<string, number>,
 *   fold: Record<string, number>, foldUnits: number, foldChanged: boolean}} */
const timing = {
  unit: 0,
  large: {},
  small: {},
  units: {},
  realistic: {},
  fold: { small: 0, large: 0 },
  foldUnits: 0,
  foldChanged: false,
};

/** The coarsest clock these gates can be read on. A reading no finer than this
 * cannot resolve the calibration pass, and `measurePerCall` would divide a
 * matched block by a zero. Checked here rather than in a test body: every
 * measurement below is downstream of it. */
const RESOLUTION_CEILING_MS = 0.5;

before(async () => {
  if (MUTATION_RUN) return;
  const resolution = clockResolutionMs();
  assert.ok(
    resolution <= RESOLUTION_CEILING_MS,
    `process.cpuUsage resolves no finer than ${resolution.toFixed(3)}ms on this kernel, so the calibration pass is quantized to within its own size`,
  );
  timing.unit = await calibrate();
  for (const { entry, shape, name } of CASES) {
    const { run } = ENTRIES[entry];
    const measured = await unitsFor(
      (attempt) => SHAPES[shape](LARGE - attempt),
      (text) => run(text, shape),
    );
    timing.large[name] = measured.cost.cpu;
    timing.units[name] = measured.units;
    timing.small[name] = await measurePerCall(
      (attempt) => SHAPES[shape](SMALL - attempt),
      (text) => run(text, shape),
      measured.cost.cpu,
    );
  }
  for (const [entry, { run }] of Object.entries(ENTRIES))
    // Not "html-prose", so `sanitizeText` takes the Layer-1 path the majority of
    // tool results take rather than the markup path only web ingress reaches.
    timing.realistic[entry] = (
      await measure(
        (attempt) => REALISTIC_TEXT.slice(0, REALISTIC_TEXT.length - attempt),
        (text) => run(text, "realistic-prose"),
      )
    ).wall;
  for (const [size, key] of [
    [SMALL, "small"],
    [LARGE, "large"],
  ]) {
    const text = foldText(size);
    // Built once: enumerating the offsets is the scanner's job, not the fold's,
    // and timing it here would charge this gate for the test's own loop.
    const findings = foldFindings(text);
    const fold = () =>
      foldConfusables(text, selectFoldableFindings(text, findings));
    // The fold takes no parse and holds no memo, so every run may share one
    // input; the offsets `findings` carries are only valid for this one.
    const measured = await unitsFor(() => text, fold);
    timing.fold[key] = measured.cost.cpu;
    if (key === "large") {
      timing.foldUnits = measured.units;
      timing.foldChanged = fold() !== text;
    }
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
    // Every ratio below divides by this. `process.cpuUsage` accounts in whole
    // microseconds, so a pass under a tenth of a millisecond is quantized to
    // within a percent of itself and the ratios stop meaning anything — say so
    // loudly rather than passing on a division by noise.
    assert.ok(
      timing.unit > 0.1,
      `calibration ran in ${timing.unit.toFixed(3)}ms of CPU — too fast to divide by`,
    );
  });

  for (const { entry, shape, name } of CASES)
    timed(`${name}: 256 KB stays inside its budget`, (t) => {
      const { cheap, budget: heavy } = ENTRIES[entry];
      // `cheap` is the only declaration of which shapes an entry answers
      // cheaply; a shape in neither list yields undefined and fails loud.
      const budget = cheap.includes(shape) ? CHEAP_BUDGET : heavy[shape];
      // Emitted on the green path too: the table above is derived from the
      // dearest reading across machines, and a passing run is the only place a
      // machine this file has never been measured on reports its numbers.
      t.diagnostic(
        `${name}: ${timing.units[name].toFixed(1)}/${budget} units (${timing.large[name].toFixed(1)}ms CPU, unit ${timing.unit.toFixed(3)}ms)`,
      );
      assert.ok(
        timing.units[name] <= budget,
        `${name} ran in ${timing.units[name].toFixed(1)} units (${timing.large[name].toFixed(1)}ms CPU), budget ${budget}`,
      );
    });

  for (const { name } of CASES)
    timed(`${name}: cost grows with input length, not faster`, () => {
      const growth = timing.large[name] / timing.small[name];
      assert.ok(
        growth <= SCALING_LIMIT,
        `${name} cost ${growth.toFixed(1)}x for ${LARGE / SMALL}x the input, limit ${SCALING_LIMIT}x`,
      );
    });

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
          `${entry}/${shape} (${timing.large[`${entry}/${shape}`].toFixed(1)}ms CPU) no longer costs more than the dearest cheap shape (${dearest.toFixed(1)}ms CPU) — it is not exercising the path it was written for`,
        );
    });

  for (const entry of Object.keys(ENTRIES))
    timed(
      `${entry}: 256 KB of ordinary text is answered in under ${REALISTIC_MS}ms`,
      (t) => {
        if (process.env.NODE_V8_COVERAGE) {
          t.skip(
            "c8 multiplies wall clock several-fold; the uninstrumented CI step reads this gate",
          );
          return;
        }
        // Vacuity guard: a ceiling in milliseconds is trivially met by a shorter
        // input, and REALISTIC_TEXT is built by slicing a repeated unit, so its
        // length is worth asserting rather than assuming.
        assert.equal(REALISTIC_TEXT.length, REALISTIC_SIZE);
        assert.ok(
          timing.realistic[entry] <= REALISTIC_MS,
          `${entry} took ${timing.realistic[entry].toFixed(1)}ms on 256 KB of ordinary text, ceiling ${REALISTIC_MS}ms`,
        );
      },
    );

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
      const { cost, units } = await unitsFor(
        () => prompt,
        () => judgeSanitizeUserPrompt(event),
      );
      assert.ok(
        units <= CHEAP_BUDGET,
        `the hook judged a clean 256 KB prompt in ${units.toFixed(1)} units (${cost.cpu.toFixed(1)}ms CPU), budget ${CHEAP_BUDGET}`,
      );
    },
  );

  timed(
    "foldConfusables: a glyph-stuffed field stays inside its budget",
    () => {
      // The positive control comes first: a fold that matched nothing would time
      // an empty loop and pass this budget however slow the real fold got.
      assert.ok(
        timing.foldChanged,
        "the fold changed nothing — the gate is timing a no-op, not the fold",
      );
      assert.ok(
        timing.foldUnits <= FOLD_BUDGET,
        `folding 256 KB of look-alikes took ${timing.foldUnits.toFixed(1)} units (${timing.fold.large.toFixed(1)}ms CPU), budget ${FOLD_BUDGET}`,
      );
    },
  );

  timed("foldConfusables: cost grows with the field length, not faster", () => {
    const growth = timing.fold.large / timing.fold.small;
    assert.ok(
      growth <= SCALING_LIMIT,
      `the fold cost ${growth.toFixed(1)}x for ${LARGE / SMALL}x the field, limit ${SCALING_LIMIT}x`,
    );
  });
});
