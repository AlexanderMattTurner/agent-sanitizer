/**
 * The empirical half of the linear-time guarantee (see THREAT-MODEL.md).
 *
 * The static gates — `redos/no-vulnerable` and `regexp/no-super-linear-*` in
 * `eslint.config.mjs`, `test/regex-recheck.test.mjs` over every pattern a
 * shipped module compiles, `tests/test_redos_js_static_guard.py` and its Python
 * twin — decide from the pattern alone that no regex here backtracks
 * super-linearly. They are blind to work that is not a regex at all: a string
 * rebuilt once per finding, a prefix re-sliced inside a loop, a re-walk of an
 * already-walked tree, a parser's own look-back. All of those have shipped, and
 * the correctness suites are indifferent to cost, so the only thing that
 * catches them is measuring.
 *
 * Each case runs one entry point ONCE over an adversarial input, after a
 * warm-up, against an absolute CPU ceiling (`assertUnderBudget` in
 * `test/helpers/budget.mjs`). The size is chosen so the linear implementation
 * costs tens to hundreds of milliseconds and the defect each case was written
 * for costs seconds to minutes: the ceiling sits ten times or more above the
 * first and an order of magnitude or more below the second, so no runner moves
 * a reading across it. A constant-factor slowdown passes, by design.
 *
 * The defects measured against these cases, at their sizes: the unanchored
 * `(?=.*[A-Z])(?=.*[0-9])` blob-mix test (a full rescan from every start offset
 * of the lowercase path), and micromark's unbalanced-label look-back behind one
 * `[` (#386). Both numbers are in the PR that introduced this file's budgets.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  checkExfilUrl,
  detectExfil,
  isHiddenStyle,
  sanitizeHtml,
} from "../src/html.mjs";
import { foldConfusables } from "../src/confusables.mjs";
import { assertUnderBudget, grow } from "./helpers/budget.mjs";

const KB = 1024;

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
 * the mix test at any size worth measuring.
 * @param {number} n
 * @returns {string}
 */
const lowercaseBlobPath = (n) => `https://e.com/${grow("abcdefg-", n)}`;

/** The same segment WITH the character mix, which the detector reports. */
const mixedBlobPath = (n) => `https://e.com/${grow("aB3defg-", n)}`;

/**
 * Many tag openers, then one `>`, then a hidden span. Two parts are
 * load-bearing, and getting either wrong makes the case measure nothing:
 *
 * - the `!` keeps each opener from being a well-formed tag, which is what
 *   leaves the whole run inside ONE inter-node raw slice reaching past the `>`.
 *   With `<ab ` openers the final `<ab >` parses as an html node of its own,
 *   the slice ends before the `>`, and a rescan from every `<` has nothing to
 *   rescan to;
 * - the span is a real inline-html child, and the openers are the raw source
 *   BETWEEN nodes, which is the slice the absorb state is folded over. Without
 *   a child the document has no inline html and the fold never runs.
 * @param {number} n
 * @returns {string}
 */
const unterminatedOpeners = (n) =>
  `hi ${grow("<a! ", n)}><span style="display:none">x</span>`;

/**
 * A CSS color channel that is one long run of digits — the shape that makes a
 * `\d*\.?\d+` token pattern retry every split of the run before it can fail.
 * Read through the style test directly: an inline style reaches the channel
 * parser only after a parse of the whole document, which would dominate the
 * measurement with parse5's cost rather than the token scan's.
 * @param {number} n
 * @returns {string}
 */
const digitChannel = (n) => {
  const huge = grow("9", n);
  // Every channel out of range clamps to 255, so the declaration resolves to
  // white on white — a verdict only reachable if the long token was READ.
  return `color: rgb(${huge},${huge},${huge}); background: rgb(255,255,255)`;
};

// A hide followed by a run of INVALID declarations, each a lexer match the
// cascade could be made to buy.
/** @param {number} n @returns {string} */
const repeatedInvalidDeclarations = (n) =>
  `display:none;${grow("color:bogus-value;", n)}`;

// Nested zero-font-size regions, each inside the visible part of the last: a
// splice that re-judged a region's subtree per level would pay depth per node.
/** @param {number} n @returns {string} */
const nestedInheritedRegions = (n) => {
  const open = '<div style="font-size:0">s<b style="font-size:9px">v';
  const levels = Math.max(1, Math.floor(n / open.length));
  return `${open.repeat(levels)}${"</b></div>".repeat(levels)}`;
};

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

/** A link whose query names a credential — what the marker below reads back. */
const EXFIL_LINK = "[x](https://e.com/?token=${SECRET})";

/**
 * Prose behind ONE `[` that never closes, ending in a markdown link Layer 3
 * reports.
 *
 * The unmatched bracket is the whole case. GFM autolink literals may not start
 * inside an unclosed label, so micromark asks "is there an unbalanced label
 * before here" at every word character — and that question was answered by
 * walking back over every event the document had produced so far, because the
 * walk only memoized the "no" answer. One stray `[` therefore made the answer
 * "yes" forever and turned an ordinary markdown parse quadratic. A JSON array
 * is the everyday shape of it: `[{"a":1},…]` opens a label whose `]` is the
 * last byte of the document, which is how a 59 KB `list_pull_requests` response
 * cost 3.4s (#386).
 *
 * The prose carries no URL of its own so the URL detectors stay O(1) and the
 * parse is what the ratio reads.
 * @param {number} n
 * @returns {string}
 */
const unclosedLabelProse = (n) =>
  `[ ${grow("lorem ipsum dolor sit amet consectetur ", n)}${EXFIL_LINK}`;

/**
 * The cases. Each runs its entry point once, at `size`, on an input built by
 * `input(size, attempt)`; `attempt` varies the input by one unit per call so a
 * memo cannot answer for the work. `ceilingMs` is CPU, at least ten times what
 * the linear implementation costs at `size` on the dearer of an uninstrumented
 * run and the c8 run `pnpm test` makes, and never under 500 ms, where a single
 * collector pause could reach it. `marker` runs once and must return true
 * — it is the proof that the input reaches the code the case is about, so a
 * refactor that stops routing this shape through that path fails loudly instead
 * of timing a cheap rejection.
 * @type {Record<string, { size: number, ceilingMs: number,
 *   input: (size: number, attempt: number) => unknown,
 *   run: (input: any) => unknown, marker: (size) => boolean }>}
 */
const CASES = {
  "checkExfilUrl/lowercase-blob-path": {
    size: 1024 * KB,
    // Measured at 4.4 ms, 4.9 ms under c8.
    ceilingMs: 500,
    input: (size, attempt) => lowercaseBlobPath(size - attempt),
    run: (url) => checkExfilUrl(url),
    // Checked at the size the timing is taken at, not at a comfortable one: the
    // whole reason the query route is absent here is that a length gate answers
    // it before the detector runs, and a marker read on a short input would not
    // have seen that. The mixed twin is reported as a blob, so a segment of this
    // length does reach the mix test — where the lowercase twin, correctly,
    // comes back benign.
    marker: (size) =>
      checkExfilUrl(mixedBlobPath(size)) ===
        "encoded data blob in path segment" &&
      checkExfilUrl(lowercaseBlobPath(size)) === null,
  },
  "sanitizeHtml/unterminated-openers": {
    size: 64 * KB,
    // Measured at 289 ms, 425 ms under c8.
    ceilingMs: 5000,
    input: (size, attempt) => unterminatedOpeners(size - attempt),
    run: (text) => sanitizeHtml(text),
    // The hidden span is removed, which only happens once the walk has reached
    // an inline-html child — and reaching one is what folds the absorb state
    // over the openers before it. A document answered null, or one whose span
    // survived, would be timing a walk that never got there.
    marker: (size) =>
      sanitizeHtml(unterminatedOpeners(size))?.removed.hidden === 1,
  },
  "isHiddenStyle/digit-channel": {
    size: 256 * KB,
    // Measured at 16 ms, 37 ms under c8.
    ceilingMs: 500,
    input: (size, attempt) => digitChannel(size - attempt),
    run: (style) => isHiddenStyle(style),
    // On the measured input at the measured size, not a comfortable stand-in: a
    // length cap added to the declaration parser would leave a short marker
    // green while the timing quietly moved to an early bail.
    marker: (size) => isHiddenStyle(digitChannel(size)),
  },
  "isHiddenStyle/repeated-invalid-declarations": {
    size: 256 * KB,
    // Measured at 77 ms, 68 ms under c8.
    ceilingMs: 1000,
    input: (size, attempt) => repeatedInvalidDeclarations(size - attempt),
    run: (style) => isHiddenStyle(style),
    // Hidden only when the cascade read the leading `display:none` past the
    // whole run: a parse that bailed early would answer false.
    marker: (size) => isHiddenStyle(repeatedInvalidDeclarations(size)),
  },
  "sanitizeHtml/nested-inherited-regions": {
    // 64 KB (~1200 levels), not 256: at ~4900 levels the walk no longer splices
    // every level, which the marker below reports.
    size: 64 * KB,
    // Measured at 197 ms, 2.6 s under c8.
    ceilingMs: 30_000,
    input: (size, attempt) => nestedInheritedRegions(size - attempt),
    run: (text) => sanitizeHtml(text),
    // One hidden `s` per level spliced, every `v` kept: only a scan that split
    // each region at its overriding child gets both.
    marker: (size) => {
      const result = sanitizeHtml(nestedInheritedRegions(size));
      return (
        result !== null &&
        !result.text.includes(">s<") &&
        result.text.includes(">v<")
      );
    },
  },
  "foldConfusables/overlapping-findings": {
    size: 256 * KB,
    // Measured at 56 ms, 102 ms under c8.
    ceilingMs: 2000,
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
  "detectExfil/unclosed-label-prose": {
    size: 256 * KB,
    // Measured at 327 ms, 481 ms under c8.
    ceilingMs: 5000,
    input: (size, attempt) => unclosedLabelProse(size - attempt),
    run: (text) => detectExfil(text),
    // The link at the end is reported, which only happens once the markdown
    // parse has read the whole document. A run that answered null would be
    // timing a gate that declined, not the parse this case is about.
    marker: (size) =>
      detectExfil(unclosedLabelProse(size))?.[0]?.reason ===
      "suspicious query parameter",
  },
};

describe("algorithmic complexity", () => {
  for (const [name, { size, marker }] of Object.entries(CASES))
    it(`${name}: the input reaches the path this case is about`, () => {
      assert.ok(
        marker(size),
        `${name} no longer drives the code it was written for at ${size} units, so its timing means nothing`,
      );
    });

  for (const [name, { size, ceilingMs, input, run }] of Object.entries(CASES))
    it(`${name}: ${size} units stay under ${ceilingMs}ms`, async (t) => {
      await assertUnderBudget(
        t,
        name,
        ceilingMs,
        (attempt) => input(size, attempt),
        run,
      );
    });
});
