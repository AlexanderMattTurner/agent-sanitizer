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
 * The FASTEST of four timed runs after a warm-up call, in ms.
 *
 * Contention and collector pauses only ever ADD time, so the minimum is the
 * closest any of the samples got to the cost of the code itself, and it is what
 * keeps these gates readable on a two-core shared runner that is also running
 * the rest of the suite. A median still carries whatever noise landed on the
 * middle sample, which on such a runner is most of them. The estimator loses
 * nothing the gates are for: a path that got an order of magnitude slower is an
 * order of magnitude slower in its fastest run too.
 */
const SAMPLES = 4;
async function measure(fn) {
  await fn();
  let best = Infinity;
  for (let i = 0; i < SAMPLES; i++) {
    const started = performance.now();
    await fn();
    best = Math.min(best, performance.now() - started);
  }
  return best;
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

// Ceilings in calibration units for the shapes an entry does real work on. Each
// is sized off the DEARER of two measurements — standalone, and under the
// parallel coverage run, where the ratios move because c8 instruments the code
// under test harder than it instruments this file's calibration — with 1.6x on
// top. The two environments disagree by up to ~40% on the same case, so 1.6x is
// what covers that disagreement and nothing more: enough that a green run means
// the path is where it was left, tight enough that a doubling is red. Anything
// with more slack than that is a ceiling nothing is under. CHEAP_BUDGET is
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
      "joiner-dense": 115,
      "vs-dense": 90,
      "payload-run": 110,
      "payload-scattered": 25,
      "emoji-zwj": 78,
      "run-dense": 44,
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
      // The dearest cell in the table, and the one the ratio is doing the least
      // for: it is parse5 building a 256 KB fragment, so it moves with the
      // parser rather than with anything here. SUPERLINEAR below is what
      // actually holds this path.
      "html-prose": 290,
      "joiner-dense": 270,
      "vs-dense": 113,
      "payload-run": 56,
      "emoji-zwj": 101,
      "run-dense": 30,
    },
  },
  scanText: {
    // The SessionStart scan reads every instruction file before the session can
    // start, so its cost is startup the user watches — the one hook path where
    // a regression has already cost 30 seconds once.
    run: (text) => scanText(text),
    cheap: ["ascii-prose", "cjk-prose", "emoji-prose", "html-prose"],
    budget: {
      "joiner-dense": 37,
      "vs-dense": 18,
      // One 256 KB run decodes as a single payload, so this case is dominated by
      // one large allocation and swings with the collector — the widest budget
      // here buys tolerance for that rather than for a slower machine.
      "payload-run": 67,
      "payload-scattered": 23,
      "emoji-zwj": 22,
      "run-dense": 24,
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
  limit: 12,
};

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
const FOLD_BUDGET = 23;

/**
 * The one gate that promises a NUMBER rather than a ratio.
 *
 * Every budget above is machine-relative on purpose, and a table of ratios can
 * stay green while each hook takes a second, so the thing a user actually
 * notices \u2014 the wait before a session starts, the wait before a prompt goes \u2014
 * needs a ceiling in milliseconds. The input is ordinary text at 256 KB, which
 * is several times any real instruction set and larger than most pastes; the
 * adversarial shapes keep their ratio budgets, because a ceiling wide enough for
 * 256 KB of nothing but zero-width space on a slow runner would not be a
 * guarantee about anything.
 *
 * c8 multiplies wall clock by roughly seven here, which is a fact about the
 * instrumentation and not about the hook, so this half stands down under
 * coverage \u2014 and `pnpm test` runs the whole suite under coverage. The
 * uninstrumented step in `.github/workflows/node-tests.yaml` ("Run the hook
 * latency gates uninstrumented") is what makes CI read it; without that step
 * this gate would be local-only.
 */
const REALISTIC_MS = 100;
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
 *   units: Record<string, number>, superlinear: Record<string, number>,
 *   realistic: Record<string, number>,
 *   fold: Record<string, number>, foldUnits: number, foldChanged: boolean}} */
const timing = {
  unit: 0,
  large: {},
  small: {},
  units: {},
  realistic: {},
  superlinear: { from: 0, to: 0 },
  fold: { small: 0, large: 0 },
  foldUnits: 0,
  foldChanged: false,
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
  for (const [entry, { run }] of Object.entries(ENTRIES))
    // Not "html-prose", so `sanitizeText` takes the Layer-1 path the majority of
    // tool results take rather than the markup path only web ingress reaches.
    timing.realistic[entry] = await measure(() =>
      run(REALISTIC_TEXT, "realistic-prose"),
    );
  const { run } = ENTRIES[SUPERLINEAR.entry];
  for (const end of ["from", "to"]) {
    const text = SHAPES[SUPERLINEAR.shape](SUPERLINEAR[end]);
    timing.superlinear[end] = await measure(() => run(text, SUPERLINEAR.shape));
  }
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
    const measured = await unitsFor(fold);
    timing.fold[key] = measured.cost;
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
      const { cheap, budget: heavy } = ENTRIES[entry];
      // `cheap` is the only declaration of which shapes an entry answers
      // cheaply; a shape in neither list yields undefined and fails loud.
      const budget = cheap.includes(shape) ? CHEAP_BUDGET : heavy[shape];
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
      // fast machine and still report green — and pooling the count across
      // entries would hide one entry losing all of its coverage.
      for (const entry of Object.keys(ENTRIES)) {
        const scalable = CASES.filter(
          (c) => c.entry === entry && timing.small[c.name] >= SCALABLE_FLOOR_MS,
        );
        assert.ok(
          scalable.length >= 4,
          `only ${scalable.length} ${entry} cases were timeable at 32 KB: ${scalable.map((c) => c.name).join(", ")}`,
        );
      }
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
        `folding 256 KB of look-alikes took ${timing.foldUnits.toFixed(1)} units (${timing.fold.large.toFixed(1)}ms), budget ${FOLD_BUDGET}`,
      );
    },
  );

  timed("foldConfusables: cost grows with the field length, not faster", () => {
    const growth = timing.fold.large / timing.fold.small;
    assert.ok(
      growth <= SCALING_LIMIT,
      `the fold cost ${growth.toFixed(1)}x for 8x the field, limit ${SCALING_LIMIT}x`,
    );
  });

  timed(`${superlinearName}: the exception is still earning its place`, (t) => {
    // c8 charges every expression it instruments, which is a large cost LINEAR
    // in the input — big enough at these sizes to swamp the super-linear term
    // and make the path look linear. The ceiling above still holds under
    // coverage; this half cannot be read there.
    if (process.env.NODE_V8_COVERAGE) {
      t.skip(
        "c8's instrumentation adds a linear cost that hides the exponent at these sizes",
      );
      return;
    }
    // The other half of the ratchet. A ceiling of 12x on a path that grew
    // linearly would gate nothing at all, so this fails the moment the HTML
    // layer stops being super-linear — and the fix is to delete SUPERLINEAR and
    // let the ordinary scaling gate own it.
    assert.ok(
      superlinearGrowth() > sizeStep,
      `${superlinearName} grew ${superlinearGrowth().toFixed(1)}x for ${sizeStep}x the input — that is linear, so delete SUPERLINEAR and let the ${SCALING_LIMIT}x gate cover it`,
    );
  });
});
