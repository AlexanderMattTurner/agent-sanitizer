/**
 * Latency ceilings for the hook paths a user waits on.
 *
 * `classifyPrompt` runs inside the prompt-submit hook and BLOCKS submission;
 * `sanitizeText` runs inside the tool-output hook and blocks the result reaching
 * the model; `scanText` reads every instruction file before a session starts.
 * Whatever any of them spends is dead wait. A regression there is invisible
 * from the inside — it reads as "the agent is slow" — and the correctness
 * suites are indifferent to it, which is how a per-code-point RegExp scan sat in
 * the carve analysis charging ~250 ms per megabyte, and how the SessionStart
 * scan once cost 30 seconds.
 *
 * Every gate is an ABSOLUTE ceiling in CPU milliseconds on one 256 KB call —
 * larger than most pastes — read through `assertUnderBudget`
 * (`test/helpers/budget.mjs`): one warm-up, one timed run. Each ceiling sits at
 * least ten times above what the shipped code was measured at on the dearest
 * shape it covers, so a loaded or slower runner does not reach it and a path
 * gone super-linear overshoots it at once. A constant-factor slowdown inside
 * that headroom passes: these ceilings promise the user an upper bound, not a
 * benchmark.
 *
 * Uninstrumented only. c8 multiplies these paths' cost by up to ~7x, which is a
 * fact about the instrumentation and not about the hook, so every gate here
 * stands down under coverage — and `pnpm test` runs the whole suite under
 * coverage. The uninstrumented step in `.github/workflows/node-tests.yaml`
 * ("Run the hook latency gates uninstrumented") is what makes CI read them.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { classifyPrompt } from "../src/prompt.mjs";
import { sanitizeText } from "../src/output.mjs";
import { scanText } from "../src/instructions.mjs";
import {
  foldConfusables,
  selectFoldableFindings,
} from "../src/confusables.mjs";
import { assertUnderBudget, grow } from "./helpers/budget.mjs";

const { claudeAdapter } = await import("agent-control-plane-core/claude");
const { judgeSanitizeUserPrompt } =
  await import("../claude-hooks/sanitize-user-prompt.mjs");

const KB = 1024;
const LARGE = 256 * KB;
const cp = (n) => String.fromCodePoint(n);

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
 * The blocking entry points, each with the shapes it answers from bulk passes
 * (`cheap`) and three ceilings, in CPU ms per 256 KB call: `cheapMs` for those
 * shapes, `heavyMs` for every other shape (per-code-point or per-node work),
 * and `markupMs` for the `html-prose` shape, which costs an order of magnitude
 * more than the rest (the HTML parse).
 *
 * Each ceiling is at least ten times the dearest shape it covers, measured
 * uninstrumented on a 4-core development machine (the readings are in the PR
 * that introduced these ceilings, and every run prints its own through
 * `t.diagnostic`), and never under 100 ms, where a single collector pause
 * could reach it. One ceiling per class of shape rather than one per cell, so
 * the cheaper cells in a class carry far more than ten times headroom: a
 * constant-factor slowdown passes, a change of complexity class at 256 KB does
 * not.
 * @type {Record<string, { run: (text: string, shape: string) => unknown,
 *   cheap: string[], cheapMs: number, heavyMs: number,
 *   markupMs?: number }>}
 */
const ENTRIES = {
  classifyPrompt: {
    run: (text) => classifyPrompt(text),
    // Markup is not a prompt-gate concern: the classifier reads invisibles and
    // ANSI, and HTML-shaped text carries neither.
    cheap: ["ascii-prose", "cjk-prose", "emoji-prose", "html-prose"],
    // Dearest: cheap 2.5 ms (cjk-prose), heavy 78 ms (vs-dense).
    cheapMs: 100,
    heavyMs: 1000,
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
    // Dearest: cheap 8.6 ms (payload-scattered), heavy 62 ms (joiner-dense).
    cheapMs: 100,
    heavyMs: 1000,
    // parse5 building a 256 KB fragment, ~460 ms: the dearest cell by far, and
    // it moves with the parser rather than with anything here.
    markupMs: 5000,
  },
  scanText: {
    run: (text) => scanText(text),
    cheap: ["ascii-prose", "cjk-prose", "emoji-prose", "html-prose"],
    // Dearest: cheap 3.7 ms (cjk-prose), heavy 36 ms (payload-run).
    cheapMs: 100,
    heavyMs: 500,
  },
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
/** Measured at ~21 ms. */
const FOLD_CEILING_MS = 500;

/**
 * Ordinary text at 256 KB, through each entry's everyday path. The adversarial
 * shapes above carry their own ceilings; this is the number a user notices on
 * a plain paste or a plain tool result. The dearest entry reads ~6 ms.
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

/**
 * The document a shape's `attempt`-th timed call reads: `size` units, told
 * apart from every other attempt's by a visible number at the end.
 *
 * At the end, not up front: a document's opening decides how the HTML layer
 * reads it. A page of `<p>` lines with a line of text in front cost more than
 * twice what the page alone does, on main and on the carve rewrite alike, so a
 * leading number timed html-prose as a different shape.
 *
 * Not by length. Trimming a shape to a length can leave a partial unit at the
 * end — a dangling joiner, say — that Layer 1 strips, and the stripped text is
 * then exactly the next attempt's document. The carve remembers the last text
 * it analysed, the composition's second pass is what carved the stripped text,
 * and so every call after the first was timed as a memo hit: sanitizeText read
 * an eighth of the cold cost on a 256 KB page of emoji ZWJ sequences.
 * @param {string} shape @param {number} size @param {number} attempt
 * @returns {string}
 */
function attemptDoc(shape, size, attempt) {
  const tail = ` ${attempt}`;
  return SHAPES[shape](size - tail.length) + tail;
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
 * An `it` whose body is a latency ceiling, standing down under c8 (see the
 * header). `assertUnderBudget` stands down under Stryker on its own.
 * @param {string} name
 * @param {(t: import("node:test").TestContext) => Promise<void>} fn
 */
const latency = (name, fn) =>
  it(name, async (t) => {
    if (process.env.NODE_V8_COVERAGE) {
      t.skip(
        "c8 multiplies the cost several-fold; the uninstrumented CI step reads this gate",
      );
      return;
    }
    await fn(t);
  });

/** The fold's input at `size` code units: the text and every glyph offset. */
const foldInput = (/** @type {number} */ size) => {
  const text = foldText(size);
  return { text, findings: foldFindings(text) };
};
const fold = (/** @type {{text: string, findings: any[]}} */ input) =>
  foldConfusables(
    input.text,
    selectFoldableFindings(input.text, input.findings),
  );

describe("hook-path latency", () => {
  for (const { entry, shape, name } of CASES)
    latency(`${name}: 256 KB stays under its ceiling`, async (t) => {
      const { run, cheap, cheapMs, heavyMs, markupMs } = ENTRIES[entry];
      const ceiling = cheap.includes(shape)
        ? cheapMs
        : shape === "html-prose"
          ? markupMs
          : heavyMs;
      await assertUnderBudget(
        t,
        name,
        ceiling,
        (attempt) => attemptDoc(shape, LARGE, attempt),
        (text) => run(text, shape),
      );
    });

  it("the realistic input is the size the ceilings promise", () => {
    // Vacuity guard: a ceiling in milliseconds is trivially met by a shorter
    // input, and REALISTIC_TEXT is built by slicing a repeated unit, so its
    // length is worth asserting rather than assuming.
    assert.equal(REALISTIC_TEXT.length, REALISTIC_SIZE);
  });

  for (const [entry, { run }] of Object.entries(ENTRIES))
    latency(
      `${entry}: 256 KB of ordinary text is answered in under ${REALISTIC_MS}ms`,
      async (t) => {
        // Not "html-prose", so `sanitizeText` takes the Layer-1 path the
        // majority of tool results take rather than the markup path only web
        // ingress reaches.
        await assertUnderBudget(
          t,
          `${entry} on 256 KB of ordinary text`,
          REALISTIC_MS,
          (attempt) => REALISTIC_TEXT.slice(0, REALISTIC_TEXT.length - attempt),
          (text) => run(text, "realistic-prose"),
        );
      },
    );

  latency(
    "the hook entry stays under the ceiling of the classifier it wraps",
    async (t) => {
      // The gate the user actually waits on is the hook, not the library
      // function. Judging adds only constant work, so a clean paste through
      // judgeSanitizeUserPrompt must stay inside the classifier's own ceiling
      // for clean text — this is what fails if the cost ever moves into the
      // hook's own wrapper.
      await assertUnderBudget(
        t,
        "the hook judging a clean 256 KB prompt",
        ENTRIES.classifyPrompt.cheapMs,
        (attempt) =>
          claudeAdapter.parse({
            hook_event_name: "UserPromptSubmit",
            prompt: attemptDoc("ascii-prose", LARGE, attempt),
          }),
        (event) => judgeSanitizeUserPrompt(event),
      );
    },
  );

  it("the fold input really drives the fold", () => {
    // A fold that matched nothing would time an empty loop and pass any
    // ceiling however slow the real fold got.
    const input = foldInput(LARGE);
    assert.notEqual(fold(input), input.text);
  });

  latency(
    "foldConfusables: a glyph-stuffed field stays under its ceiling",
    async (t) => {
      // Built per attempt: enumerating the offsets is the scanner's job, not
      // the fold's, and building them outside the timed run keeps this gate
      // from charging the test's own loop.
      await assertUnderBudget(
        t,
        "folding 256 KB of look-alikes",
        FOLD_CEILING_MS,
        (attempt) => foldInput(LARGE - attempt),
        fold,
      );
    },
  );
});
