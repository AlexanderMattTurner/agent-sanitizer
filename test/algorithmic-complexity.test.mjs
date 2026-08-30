/**
 * The empirical half of the linear-time guarantee (see THREAT-MODEL.md).
 *
 * The static gates — `tests/test_redos_js_static_guard.py` over every shipped
 * JS pattern, and its Python twin — prove no regex here backtracks
 * super-linearly WITHIN one match attempt. They are structurally blind to two
 * other ways this code can go quadratic, and both have shipped:
 *
 *   - an UNANCHORED pattern retried at every start offset, each attempt linear
 *     and none of them backtracking: `(?=.*[A-Z])(?=.*[0-9])` against a long
 *     value carrying neither class, or a `[^>]*$` tail rescanned from every `<`;
 *   - work that is not a regex at all: a string rebuilt once per finding, a
 *     prefix re-sliced inside a loop, a re-walk of an already-walked tree.
 *
 * Neither is visible to a pattern analyzer, and the correctness suites are
 * indifferent to cost, so the only thing that catches them is measuring. Each
 * case below runs one entry point over an adversarial input at two sizes 8x
 * apart and asserts the cost grew like the input, not like its square. Ratios,
 * not milliseconds: machine speed and the coverage instrumentation scale both
 * sides (see `test/helpers/cpu-timing.mjs`).
 *
 * Every shape here reads 5-11x on the implementations that ship. Two of them
 * read 64.0x and 61.1x against the implementations they were written for — the
 * `(?=.*[A-Z])(?=.*[0-9])` mix test on a long lowercase path segment, and a
 * `\d*\.?\d+` channel token on a long digit run — and the overlapping fold read
 * 27.1x against a whole-output rebuild per finding. {@link GROWTH_LIMIT} sits
 * between those two populations.
 *
 * The `sanitizeHtml` case is the one whose defect it does NOT demonstrate: the
 * markup-tail rescan it targets reads 11.3x either way, because parse5 dominates
 * a document this size and the tail the analysis sees is one node's raw source
 * rather than the whole input. It stays as a growth gate on the Layer-2 entry
 * point — a tail scan that went quadratic over a single large node would clear
 * the limit several times over — not as evidence of a defect caught.
 */
import { describe, it, before } from "node:test";
import assert from "node:assert/strict";

import { checkExfilUrl, isHiddenStyle, sanitizeHtml } from "../src/html.mjs";
import { foldConfusables } from "../src/confusables.mjs";
import {
  MUTATION_RUN,
  RESOLUTION_CEILING_MS,
  clockResolutionMs,
  grow,
  measure,
  measurePerCall,
} from "./helpers/cpu-timing.mjs";

const KB = 1024;
const SMALL = 8 * KB;
const LARGE = 64 * KB;

/**
 * LARGE is 8x SMALL, so a linear cost grows 8x and a quadratic one 64x. The
 * limit sits at three times linear: wide enough that a `n log n` pass, a
 * collector run landing on the large side, or a per-call constant that only the
 * small side amortizes cannot manufacture a failure, and far enough under 64x
 * that no quadratic reaches it. Both sides are measured in one process on one
 * machine, so nothing here needs headroom for machine speed.
 */
const GROWTH_LIMIT = 24;

const CYR_A = "а";

/**
 * A path segment the blob detector must read all the way to the end before it
 * can call the value benign: every character is lowercase, so the mix test that
 * separates bulk-encoded bytes from a word-slug finds neither the uppercase nor
 * the digit it looks for. The hyphens are what make it reach that test at all —
 * they are outside the standard-base64 and hex alphabets, so the cheaper
 * whole-segment patterns decline first and only the url-safe arm is left.
 *
 * The PATH, not a query value: a query this long is answered "unusually long
 * query string" before any per-value analysis, so the query route cannot reach
 * the mix test at any size that would show a cost curve.
 * @param {number} n
 * @returns {string}
 */
const lowercaseBlobPath = (n) => `https://e.com/${grow("abcdefg-", n)}`;

/** The same segment WITH the character mix, which the detector reports. */
const mixedBlobPath = (n) => `https://e.com/${grow("aB3defg-", n)}`;

/**
 * One paragraph of prose carrying many `<` and no `>`. The markup-tail analysis
 * runs over a node's whole raw source, so this has to be ONE node: split into
 * paragraphs, each slice is short and no per-offset rescan can show. The comment
 * gives the document something to remove, so the pipeline runs to the end rather
 * than answering null.
 * @param {number} n
 * @returns {string}
 */
const openAngleProse = (n) =>
  `<!--c-->\n\n<p>ok</p>\n\n${grow("a < b < c ", n)}`;

/**
 * A CSS color channel that is one long run of digits — the shape that makes a
 * `\d*\.?\d+` token pattern retry every split of the run before it can fail.
 * Read through the style test directly: an inline style reaches the channel
 * parser only after a parse of the whole document, which would dominate the
 * measurement with parse5's cost rather than the token scan's.
 * @param {number} n
 * @returns {string}
 */
const digitChannel = (n) => `color: rgb(${grow("9", n)}, 0, 0)`;

/**
 * Text of paired Cyrillic look-alikes, and findings that all OVERLAP a fold
 * already applied: the second glyph of each pair folds first, and the finding on
 * the first glyph then covers a byte that fold rewrote. That is the branch that
 * has to read back into the folded output, and the one a whole-output rebuild
 * per finding turns quadratic. An honest scanner does not emit these — an
 * adversarial one is free to, and the fold validates rather than trusts them.
 * @param {number} n
 * @returns {{ text: string, findings: Array<{index: number, char: string, latinEquivalent: string}> }}
 */
function overlappingFolds(n) {
  const text = grow(CYR_A + CYR_A, n);
  const findings = [];
  for (let i = 0; i + 1 < text.length; i += 2) {
    findings.push({ index: i + 1, char: CYR_A, latinEquivalent: "a" });
    findings.push({ index: i, char: `${CYR_A}a`, latinEquivalent: "b" });
  }
  return { text, findings };
}

/**
 * The non-vacuity control for the harness itself: the very pattern this gate was
 * written after, kept here as a specimen. Unanchored with two `.*` lookaheads,
 * so a value carrying neither class costs a full scan at every start offset —
 * quadratic, with no backtracking for a pattern analyzer to find. If this does
 * not read as super-linear, neither would a real regression, and every case
 * above is passing for the wrong reason.
 */
const QUADRATIC_SPECIMEN_RE = /(?=.*[A-Z])(?=.*[0-9])/;

/**
 * The cases. `run` takes an input built by `input(size, attempt)`; `attempt`
 * varies the input by one unit per call so a memo cannot answer for the work
 * (see `measure`). `marker` runs once at a small size and must return true —
 * it is the proof that the input reaches the code the case is about, so a
 * refactor that stops routing this shape through that path fails loudly instead
 * of timing a cheap rejection.
 * @type {Record<string, { input: (size: number, attempt: number) => unknown,
 *   run: (input: any) => unknown, marker: () => boolean }>}
 */
const CASES = {
  "checkExfilUrl/lowercase-blob-path": {
    input: (size, attempt) => lowercaseBlobPath(size - attempt),
    run: (url) => checkExfilUrl(url),
    // Checked at the size the timing is taken at, not at a comfortable one: the
    // whole reason the query route is absent here is that a length gate answers
    // it before the detector runs, and a marker read on a short input would not
    // have seen that. The mixed twin is reported as a blob, so a segment of this
    // length does reach the mix test — where the lowercase twin, correctly,
    // comes back benign.
    marker: () =>
      checkExfilUrl(mixedBlobPath(LARGE)) ===
        "encoded data blob in path segment" &&
      checkExfilUrl(lowercaseBlobPath(LARGE)) === null,
  },
  "sanitizeHtml/open-angle-prose": {
    input: (size, attempt) => openAngleProse(size - attempt),
    run: (text) => sanitizeHtml(text),
    // A document with no HTML tag is answered with null before any analysis
    // runs, so the `<p>` this shape carries is load-bearing.
    marker: () => sanitizeHtml(openAngleProse(512)) !== null,
  },
  "isHiddenStyle/digit-channel": {
    input: (size, attempt) => digitChannel(size - attempt),
    run: (style) => isHiddenStyle(style),
    // White on white is the verdict the channel parser exists to reach, so a
    // true here proves the tokens are being resolved rather than declined.
    marker: () =>
      isHiddenStyle("color: rgb(255, 255, 255); background: rgb(255,255,255)"),
  },
  "foldConfusables/overlapping-findings": {
    input: (size, attempt) => overlappingFolds(size - attempt),
    run: ({ text, findings }) => foldConfusables(text, findings),
    // A fold that changed nothing would time an empty loop, and a fold that
    // never took the overlap branch would time the ordinary one: "b" is the
    // replacement only the overlapping finding can produce.
    marker: () => {
      const { text, findings } = overlappingFolds(64);
      return foldConfusables(text, findings) === "b".repeat(32);
    },
  },
  "control/quadratic-specimen": {
    input: (size, attempt) => grow("abcdefg-", size - attempt),
    run: (text) => QUADRATIC_SPECIMEN_RE.test(text),
    // The specimen answers the question it is asked, so what it measures is the
    // cost of reaching that answer rather than an early bail.
    marker: () =>
      QUADRATIC_SPECIMEN_RE.test("aB3") && !QUADRATIC_SPECIMEN_RE.test("abc"),
  },
};

/** The name of the case that must FAIL the growth limit; every other case must
 * pass it. Kept as a name rather than a flag so the two assertions below read
 * from one declaration. */
const CONTROL = "control/quadratic-specimen";

/**
 * The specimen runs at a quarter of the size the real cases do: 64 KB of a
 * quadratic scan is nearly two seconds per call, and it is measured nine times.
 * The ratio is what the gate reads and it is scale-free, so a smaller pair says
 * exactly as much — but only while both sides stay clear of timer noise, which
 * is the floor a quarter buys and a sixty-fourth (128 bytes) does not.
 */
const CONTROL_SCALE = 1 / 4;

/** @type {Record<string, {small: number, large: number, growth: number}>} */
const timing = {};

before(
  async () => {
    if (MUTATION_RUN) return;
    const resolution = clockResolutionMs();
    assert.ok(
      resolution <= RESOLUTION_CEILING_MS,
      `process.cpuUsage resolves no finer than ${resolution.toFixed(3)}ms on this kernel, so these blocks are quantized to within their own size`,
    );
    for (const [name, { input, run }] of Object.entries(CASES)) {
      const scale = name === CONTROL ? CONTROL_SCALE : 1;
      const large = await measure(
        (attempt) => /** @type {any} */ (input(LARGE * scale, attempt)),
        (built) => run(built),
      );
      const small = await measurePerCall(
        (attempt) => /** @type {any} */ (input(SMALL * scale, attempt)),
        (built) => run(built),
        large.cpu,
      );
      timing[name] = { small, large: large.cpu, growth: large.cpu / small };
    }
  },
  // A quadratic path does not merely exceed the limit, it takes minutes to
  // measure — so an unbounded hook would hang rather than report. This is the
  // ceiling for the whole measured set; a green run is an order of magnitude
  // under it.
  { timeout: 300_000 },
);

/** An `it` whose verdict rests on the timings, and so has none under Stryker.
 * @param {string} name
 * @param {(t: import("node:test").TestContext) => void} fn */
const timed = (name, fn) =>
  it(name, (t) => {
    if (MUTATION_RUN) {
      t.skip(MUTATION_RUN);
      return;
    }
    fn(t);
  });

describe("algorithmic complexity", () => {
  for (const [name, { marker }] of Object.entries(CASES))
    it(`${name}: the input reaches the path this case is about`, () => {
      assert.ok(
        marker(),
        `${name} no longer drives the code it was written for, so its timing means nothing`,
      );
    });

  for (const name of Object.keys(CASES).filter((c) => c !== CONTROL))
    timed(`${name}: cost grows with the input, not with its square`, (t) => {
      const { small, large, growth } = timing[name];
      // Emitted on the green path too: this table is the only place a machine
      // these ratios have never been read on reports its own numbers.
      t.diagnostic(
        `${name}: ${growth.toFixed(1)}x for ${LARGE / SMALL}x the input (${small.toFixed(3)}ms -> ${large.toFixed(3)}ms CPU)`,
      );
      assert.ok(
        growth <= GROWTH_LIMIT,
        `${name} cost ${growth.toFixed(1)}x for ${LARGE / SMALL}x the input, limit ${GROWTH_LIMIT}x`,
      );
    });

  timed("the gate can see a quadratic at all", (t) => {
    // Without this the whole file passes on a machine, a Node version, or a
    // measurement bug that flattens every ratio to noise.
    const { growth } = timing[CONTROL];
    t.diagnostic(`${CONTROL}: ${growth.toFixed(1)}x`);
    assert.ok(
      growth > GROWTH_LIMIT,
      `the deliberately quadratic control grew only ${growth.toFixed(1)}x for ${LARGE / SMALL}x the input — this harness cannot currently detect a quadratic, so every other case here is passing for the wrong reason`,
    );
  });
});
