/**
 * The counting entry points short-circuit before the per-code-point carve
 * analysis (see countPayloadInvisible / payloadLongRunSample /
 * countEffectiveInvisible). Each short-circuit is only sound if it agrees with
 * the analysis EXACTLY — these feed the prompt gate's block decision, so a count
 * that is merely close is a bypass. Every test here pins a fast path against the
 * slow definition it replaced, expressed in exported API:
 *
 *   countPayloadInvisible(t)   == payload code points in payloadInvisibleView(t)
 *   findLongRuns(t)            == t.matchAll(LONG_RUN_RE)
 *   hasLongRun(t)              == LONG_RUN_RE.test(t)
 *   payloadLongRunSample(t)    == payloadInvisibleView(t).match(LONG_RUN_RE)
 *   countEffectiveInvisible(t) == payload + max(0, cpLen(t) - cpLen(strip(t)) - payload)
 *
 * payloadInvisibleView walks the whole code-point array with no short-circuit,
 * so it is the independent reference, not a restatement.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import { CF_CODEPOINTS } from "../src/cf-charset.mjs";
import {
  BLANK_NON_CF,
  CHECKS,
  LONG_RUN_RE,
  STRIP,
  VS,
  countEffectiveInvisible,
  countPayloadInvisible,
  findLongRuns,
  hasLongRun,
  payloadInvisibleView,
  payloadLongRunSample,
  stripInvisible,
} from "../src/invisible.mjs";

const cp = (n) => String.fromCodePoint(n);
const ZWNJ = cp(0x200c);
const ZWJ = cp(0x200d);
const VS16 = cp(0xfe0f);
const BOM = cp(0xfeff);
const TAG = (s) => [...s].map((c) => cp(0xe0000 + c.charCodeAt(0))).join("");

// Non-global twin of STRIP: `g` makes `.test` stateful across calls.
const STRIP_ONE = new RegExp(STRIP.source, "u");

/** The slow-path payload count: what the carve analysis left unmasked. */
const referencePayload = (text) =>
  [...payloadInvisibleView(text)].filter((ch) => STRIP_ONE.test(ch)).length;

/** The runs the pattern itself matches — what findLongRuns must reproduce
 * without the regex engine (see its header for why it cannot use one). */
const referenceRuns = (text) =>
  [...text.matchAll(new RegExp(LONG_RUN_RE.source, "gu"))].map((match) => ({
    index: match.index,
    text: match[0],
    charCount: [...match[0]].length,
  }));

/** The pre-short-circuit definitions of the two derived entry points. */
const referenceLongRun = (text) =>
  payloadInvisibleView(text).match(new RegExp(LONG_RUN_RE.source, "gu"))?.[0] ??
  null;
const referenceEffective = (text) => {
  const payload = referencePayload(text);
  const surplus = Math.max(
    0,
    [...text].length - [...stripInvisible(text)].length - payload,
  );
  return payload + surplus;
};

// Adversarial and legitimate shapes a homogeneous benchmark string misses: a
// prompt that is mostly joiners, one that is mostly variation selectors, emoji
// ZWJ sequences carrying VS16, joiner-dense multilingual prose, lone surrogates,
// and a leading BOM (preserved by the strip but counted as payload, so the
// surplus term goes negative and must clamp).
const SHAPES = {
  empty: "",
  ascii: "The quick brown fox jumps over the lazy dog.",
  "mostly-zwnj": ZWNJ.repeat(200),
  "mostly-zwj": ZWJ.repeat(200),
  "mostly-joiners-alternating": (ZWJ + ZWNJ).repeat(120),
  "mostly-joiners-cursive": "ب" + (ZWNJ + "ب").repeat(200),
  "mostly-variation-selectors": VS16.repeat(200),
  "mostly-ivs": ("漢" + cp(0xe0100)).repeat(120),
  "mostly-stdvs": ("㐂" + cp(0xfe00)).repeat(120),
  "persian-prose": "می" + ZWNJ + "خواهم چند کتاب بخرم",
  "devanagari-conjunct": ("क्" + ZWJ + "ष").repeat(30),
  "emoji-zwj-vs16": ("\u{1F3F3}" + VS16 + ZWJ + "\u{1F308}").repeat(30),
  family:
    "\u{1F468}" + ZWJ + "\u{1F469}" + ZWJ + "\u{1F467}" + ZWJ + "\u{1F466}",
  keycap: "1" + VS16 + cp(0x20e3),
  "flag-tag-registered": "\u{1F3F4}" + TAG("gbeng") + cp(0xe007f),
  "flag-tag-unterminated": "\u{1F3F4}" + TAG("gbeng"),
  "lone-high-surrogate": "a\uD800" + ZWJ + "b",
  "lone-low-surrogate": "a\uDC00" + VS16 + "b",
  "surrogate-pair-split": "\uD83C" + ZWJ + "\uDF08",
  "leading-bom": BOM + "hello world",
  "bom-only": BOM,
  "interior-bom": "ab" + BOM + "cd",
  "braille-blanks": "⠃⠀".repeat(150),
  "hangul-fillers": ("가" + cp(0x3164)).repeat(150),
  "long-run": "text" + cp(0x200b).repeat(40) + "more",
  "scattered-under-threshold": "a" + (cp(0x00ad) + "a").repeat(9),
  "scattered-over-threshold": "a" + (cp(0x00ad) + "a").repeat(40),
};

// What each shape counted BEFORE the counting entry points were made to skip
// the code-point array: [countPayloadInvisible, countEffectiveInvisible,
// code-point length of payloadLongRunSample, or null for no run]. The
// equivalence tests below tie the fast paths to the carve analysis, but they
// share that analysis with their own reference, so only a recording pins the
// analysis itself — a preserve arm that starts calling a joiner payload (or
// stops) moves both sides equally and is invisible to them. These numbers are
// the gate's behaviour: change one only with a decision to change what blocks.
const BASELINE = {
  empty: [0, 0, null],
  ascii: [0, 0, null],
  "mostly-zwnj": [200, 200, 200],
  "mostly-zwj": [200, 200, 200],
  "mostly-joiners-alternating": [240, 240, 240],
  "mostly-joiners-cursive": [0, 192, null],
  "mostly-variation-selectors": [200, 200, 200],
  "mostly-ivs": [0, 112, null],
  "mostly-stdvs": [120, 120, null],
  "persian-prose": [0, 0, null],
  "devanagari-conjunct": [0, 14, null],
  "emoji-zwj-vs16": [0, 44, null],
  family: [0, 0, null],
  keycap: [0, 0, null],
  "flag-tag-registered": [0, 0, null],
  "flag-tag-unterminated": [5, 5, null],
  "lone-high-surrogate": [1, 1, null],
  "lone-low-surrogate": [1, 1, null],
  "surrogate-pair-split": [1, 2, null],
  "leading-bom": [1, 1, null],
  "bom-only": [1, 1, null],
  "interior-bom": [1, 1, null],
  "braille-blanks": [150, 150, null],
  "hangul-fillers": [150, 150, null],
  "long-run": [40, 40, 40],
  "scattered-under-threshold": [9, 9, null],
  "scattered-over-threshold": [40, 40, null],
};

describe("the counts each shape has always produced", () => {
  it("every shape is recorded", () =>
    assert.deepEqual(Object.keys(BASELINE), Object.keys(SHAPES)));

  for (const [name, text] of Object.entries(SHAPES))
    it(name, () => {
      const sample = payloadLongRunSample(text);
      assert.deepEqual(
        [
          countPayloadInvisible(text),
          countEffectiveInvisible(text),
          sample === null ? null : [...sample].length,
        ],
        BASELINE[name],
      );
    });
});

describe("counting fast paths agree exactly with the carve analysis", () => {
  for (const [name, text] of Object.entries(SHAPES)) {
    it(`${name}: countPayloadInvisible`, () =>
      assert.equal(countPayloadInvisible(text), referencePayload(text)));
    it(`${name}: findLongRuns`, () =>
      assert.deepEqual([...findLongRuns(text)], referenceRuns(text)));
    it(`${name}: hasLongRun`, () =>
      assert.equal(hasLongRun(text), referenceRuns(text).length > 0));
    it(`${name}: payloadLongRunSample`, () =>
      assert.equal(payloadLongRunSample(text), referenceLongRun(text)));
    it(`${name}: countEffectiveInvisible`, () =>
      assert.equal(countEffectiveInvisible(text), referenceEffective(text)));
  }

  // Positive controls: without these the cases above could all pass on inputs
  // that never reach a preserve arm, a long run, or the surplus term at all.
  it("the shapes exercise both verdicts of every fast path", () => {
    const counts = Object.values(SHAPES).map(countPayloadInvisible);
    assert.ok(
      counts.some((n) => n === 0) && counts.some((n) => n > 0),
      "need both a zero and a non-zero payload count",
    );
    const runs = Object.values(SHAPES).map(payloadLongRunSample);
    assert.ok(
      runs.some((r) => r === null) && runs.some((r) => r !== null),
      "need both a long-run hit and a miss",
    );
    assert.ok(
      Object.values(SHAPES).some(
        (t) => countEffectiveInvisible(t) > countPayloadInvisible(t),
      ),
      "need a text whose over-budget joiner surplus is non-zero",
    );
    assert.equal(countPayloadInvisible(BOM), 1);
    assert.equal(
      countEffectiveInvisible(BOM),
      1,
      "a leading BOM is preserved by the strip, so the surplus term must clamp at 0",
    );
  });
});

describe("property: no input separates a fast path from the analysis", () => {
  // Weighted toward the code points that drive the carve-out, so a random draw
  // lands on joiner/selector/tag/blank contexts instead of inert Latin text.
  const NOTABLE = [
    0x200b, 0x200c, 0x200d, 0x200e, 0x2060, 0xfeff, 0x00ad, 0xfe00, 0xfe0e,
    0xfe0f, 0x180b, 0x180e, 0x2800, 0x3164, 0x115f, 0x034f, 0x17b4, 0xe0100,
    0xe0020, 0xe0067, 0xe007f, 0x1f3f4, 0x1f468, 0x1f308, 0x20e3, 0x0628,
    0x0915, 0x094d, 0x6f22, 0x3402, 0xac00, 0x2803, 0xd800, 0xdc00, 0x0041,
    0x0020,
  ].map((n) => String.fromCodePoint(n));
  const arbText = fc
    .array(
      fc.oneof(
        { weight: 8, arbitrary: fc.constantFrom(...NOTABLE) },
        { weight: 1, arbitrary: fc.string({ minLength: 1, maxLength: 3 }) },
        {
          weight: 1,
          arbitrary: fc.string({ unit: "binary", minLength: 1, maxLength: 3 }),
        },
      ),
      { maxLength: 60 },
    )
    .map((chars) => chars.join(""));

  // Single-character draws practically never land ten invisibles in a row, so
  // the long-run properties draw CHUNKS straddling the threshold instead:
  // adjacent chunks merge into one run, and a visible draw between them cuts it.
  const arbRunText = fc
    .array(
      fc.oneof(
        { weight: 3, arbitrary: fc.constantFrom(...NOTABLE) },
        {
          weight: 2,
          arbitrary: fc
            .tuple(
              fc.constantFrom(...NOTABLE.filter((ch) => STRIP_ONE.test(ch))),
              fc.integer({ min: 4, max: 14 }),
            )
            .map(([ch, n]) => ch.repeat(n)),
        },
      ),
      { maxLength: 12 },
    )
    .map((parts) => parts.join(""));
  const arbAnyText = fc.oneof(
    { weight: 1, arbitrary: arbText },
    { weight: 3, arbitrary: arbRunText },
  );

  it("countPayloadInvisible", () =>
    fc.assert(
      fc.property(arbText, (text) =>
        assert.equal(countPayloadInvisible(text), referencePayload(text)),
      ),
      { numRuns: 2000 },
    ));

  it("findLongRuns", () => {
    // Counted, not assumed: a draw distribution that never produced a run of
    // ten would make every assertion below `[] === []`.
    let withRun = 0;
    fc.assert(
      fc.property(arbAnyText, (text) => {
        const runs = referenceRuns(text);
        if (runs.length > 0) withRun++;
        assert.deepEqual([...findLongRuns(text)], runs);
        assert.equal(hasLongRun(text), runs.length > 0);
      }),
      { numRuns: 2000 },
    );
    assert.ok(withRun > 0, "no draw carried a long run");
  });

  it("payloadLongRunSample", () =>
    fc.assert(
      fc.property(arbAnyText, (text) =>
        assert.equal(payloadLongRunSample(text), referenceLongRun(text)),
      ),
      { numRuns: 2000 },
    ));

  it("countEffectiveInvisible", () =>
    fc.assert(
      fc.property(arbText, (text) =>
        assert.equal(countEffectiveInvisible(text), referenceEffective(text)),
      ),
      { numRuns: 2000 },
    ));
});

describe("the code-point lookup classifies exactly what the CHECKS regexes match", () => {
  // The classifier behind the carve analysis is a lookup built from the same
  // three code-point sets as the CHECKS regexes. A code point dropped in that
  // projection is one the scatter gate stops counting, so the agreement is
  // checked over the WHOLE code-point space, not a sample. A lone code point has
  // no neighbours, so no preserve arm can fire and the payload count is exactly
  // 1 whenever the classifier calls it invisible.
  const oneShot = CHECKS.map(([, re]) => new RegExp(re.source, "u"));
  const matchesChecks = (ch) => oneShot.some((re) => re.test(ch));
  // The three sets both the regexes and the lookup are built from. Pinning the
  // scan's hit count to their union is the non-vacuity control: it fails if a
  // regex class silently covers more or fewer code points than its own set
  // (a stray range in a class source), and it moves with the sets.
  const tracked = new Set([
    ...CF_CODEPOINTS,
    ...[...VS].map((ch) => ch.codePointAt(0)),
    ...[...BLANK_NON_CF].map((ch) => ch.codePointAt(0)),
  ]);

  it("agrees on every code point in U+0000..U+10FFFF", () => {
    let invisible = 0;
    for (let n = 0; n <= 0x10ffff; n++) {
      const ch = String.fromCodePoint(n);
      const expected = matchesChecks(ch) ? 1 : 0;
      invisible += expected;
      const actual = countPayloadInvisible(ch);
      if (actual !== expected)
        assert.fail(
          `U+${n.toString(16).toUpperCase()}: expected ${expected}, got ${actual}`,
        );
    }
    assert.equal(invisible, tracked.size);
  });
});
