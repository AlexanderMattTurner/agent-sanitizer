/**
 * The optimized carve analysis answers EXACTLY what the slow one answers.
 *
 * `src/invisible.mjs` reads the document as an `Int32Array` of code points,
 * classifies into `Uint8Array`s, resolves grapheme clusters only around the
 * characters the carve-out could preserve, and lets `countEffectiveInvisible`
 * read its count and its strip off ONE analysis (or its count alone, off a walk
 * that builds no text). Each of those is invisible to
 * the correctness suites — they change what the module COSTS, and a bug in any
 * of them changes what it DECIDES, which is a security verdict the user is
 * shown. So every entry point is differenced here against
 * `./helpers/carve-reference.mjs`, the snapshot of the unoptimized spelling.
 *
 * The generators below are the point of the file: `"x".repeat(n)` exercises the
 * bulk regex path and nothing else. These drive the arms that the fast paths
 * actually touch — the joiner arm on real Persian, the selector arms on emoji
 * and on ideographic variation sequences, the tag arm on subregional flags, the
 * blank-filler budget on Braille and Hangul, plus lone surrogates, a leading
 * BOM, and the negative-surplus case a BOM produces.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import * as fast from "../src/invisible.mjs";
import * as slow from "./helpers/carve-reference.mjs";
import { THREAT_CODEPOINTS } from "./threat-codepoints.mjs";

const cp = (n) => String.fromCodePoint(n);
const ZWNJ = cp(0x200c);
const ZWJ = cp(0x200d);
const VS16 = cp(0xfe0f);
const VS1 = cp(0xfe00);
const IVS = cp(0xe0100);
const BOM = cp(0xfeff);
const ZWSP = cp(0x200b);
const SHY = cp(0x00ad);
const BRAILLE_BLANK = cp(0x2800);
const HANGUL_FILLER = cp(0x3164);
const TAG = (s) => [...s].map((c) => cp(0xe0000 + c.charCodeAt(0))).join("");
const SCOTLAND = "\u{1F3F4}" + TAG("gbsct") + cp(0xe007f);

/** Every exported reading of the carve, taken as one record so a disagreement
 * names which reading disagreed.
 * @param {typeof fast} mod @param {string} text */
const readings = (mod, text) => ({
  strip: mod.stripInvisibleWithReport(text),
  stripUnderBom: mod.stripInvisibleWithReport(text, BOM + text),
  payload: mod.countPayloadInvisible(text),
  effective: mod.countEffectiveInvisible(text),
  view: mod.payloadInvisibleView(text),
  longRun: mod.payloadLongRunSample(text),
  incidental: mod.isIncidentalInvisible(text),
});

/** Carve a different document, so the optimized module's one-entry cache
 * holds nothing of the next text. */
const evict = () => fast.countPayloadInvisible(`${ZWNJ}evict`);

/** @param {string} text @param {string} label */
function assertAgrees(text, label) {
  // The effective count is read two ways: off a strip already built (readings
  // strips first), and, on a cold cache, off a walk that builds no text. The
  // long run likewise: off the carve already in hand (readings), and cold, off
  // the raw text.
  evict();
  const cold = fast.countEffectiveInvisible(text);
  evict();
  const coldRun = fast.payloadLongRunSample(text);
  evict();
  const reference = readings(slow, text);
  assert.deepEqual(
    readings(fast, text),
    reference,
    `${label}: optimized carve disagrees with the reference on ${JSON.stringify(text)}`,
  );
  assert.equal(
    cold,
    reference.effective,
    `${label}: the count-only walk disagrees with the reference on ${JSON.stringify(text)}`,
  );
  assert.equal(
    coldRun,
    reference.longRun,
    `${label}: the cold long-run read disagrees with the reference on ${JSON.stringify(text)}`,
  );
}

// Hand-written shapes, one per arm of the analysis, each named for the arm it
// drives so a failure says which one broke.
const CASES = {
  empty: "",
  ascii: "The quick brown fox jumps over the lazy dog.",
  "persian-zwnj": "می" + ZWNJ + "خواهم به خانه بروم",
  "persian-zwnj-dense": ("می" + ZWNJ + "خواهم ").repeat(40),
  "arabic-harakat-zwnj": "رَ" + ZWNJ + "ب",
  "devanagari-conjunct": "क्" + ZWJ + "ष",
  "devanagari-bare-halant": "्" + ZWJ + "ष",
  "emoji-zwj-vs16": "\u{1F3F3}" + VS16 + ZWJ + "\u{1F308}",
  "emoji-zwj-family": "\u{1F468}" + ZWJ + "\u{1F469}" + ZWJ + "\u{1F467}",
  "emoji-zwj-run": ("\u{1F3F3}" + VS16 + ZWJ + "\u{1F308}").repeat(20),
  "stuffed-vs16": "\u{1F3F3}" + VS16.repeat(6) + ZWJ + "\u{1F308}",
  keycap: "1" + VS16 + cp(0x20e3),
  "keycap-bare": "1" + VS16 + "x",
  "tag-flag": SCOTLAND,
  "tag-flag-run": SCOTLAND.repeat(12),
  "tag-loose": SCOTLAND + TAG("A"),
  "tag-unregistered": "\u{1F3F4}" + TAG("zzzzz") + cp(0xe007f),
  "ivs-cjk": "漢" + IVS,
  "ivs-dense": ("漢" + IVS).repeat(30),
  "ivs-no-base": "a" + IVS,
  // A run spent before a gap is stripped a stretch at a time; the gap reopens
  // it, and a spent cluster may straddle the gap (two harakat in a row).
  "ivs-past-cap-then-gap":
    ("漢" + IVS).repeat(12) + "ab" + ("漢" + IVS).repeat(12),
  "zwnj-past-cap-then-gap":
    ("م" + ZWNJ).repeat(12) + "م ab " + ("م" + ZWNJ).repeat(12),
  "spent-cluster-straddles-gap":
    ("م" + ZWNJ).repeat(12) + "م" + ZWNJ + "ََ" + ZWNJ + "م",
  // Where Unicode 16 and 17 disagree: an Extension J base (new in 17) and a
  // star 17 dropped from Extended_Pictographic. Both modules read the pinned
  // tables, so they agree on every Node; an oracle asking the runtime did not.
  "ivs-extension-j": "\u{323B0}" + IVS,
  "zwj-after-unicode-16-pictograph": "★" + ZWJ + "\u{1F525}",
  "stdvs-registered": "∅" + VS1,
  "stdvs-unregistered": "a" + VS1,
  "braille-blank": "⠓⠑⠇⠇⠕" + BRAILLE_BLANK + "⠺⠕⠗⠇⠙",
  "braille-alternating": ("⠃" + BRAILLE_BLANK).repeat(40),
  "hangul-filler": "한" + HANGUL_FILLER + "글",
  "hangul-alternating": ("가" + HANGUL_FILLER).repeat(40),
  "leading-bom": BOM + "hello world",
  "leading-bom-then-joiner": BOM + "می" + ZWNJ + "خواهم",
  "interior-bom": "hello" + BOM + "world",
  "bom-only": BOM,
  // A leading BOM is preserved by the strip yet counted as payload, so the
  // removed-minus-payload difference goes negative — the clamp in
  // countEffectiveInvisible.
  "negative-surplus": BOM + "plain text with no other invisible",
  "lone-high-surrogate": "a\ud800b",
  "lone-low-surrogate": "a\udc00b",
  "surrogate-pair-split": "\ud83d" + ZWSP + "\ude00",
  "payload-run": ZWSP.repeat(40),
  // A long run is exactly LONG_RUN_THRESHOLD (10) payload code points in a
  // row; a preserved selector in front of nine is not one.
  "payload-run-at-threshold": "a" + ZWSP.repeat(10) + "b",
  "payload-run-under-threshold": "a" + ZWSP.repeat(9) + "b",
  "payload-run-after-preserved": "漢" + IVS + ZWSP.repeat(9) + "b",
  "payload-runs-twice": ("漢" + IVS + ZWSP.repeat(10) + "b ").repeat(3),
  "payload-scattered": ("a" + SHY).repeat(40),
  "over-budget-joiners": ("م" + ZWNJ + "م").repeat(60),
  // Past the cap the joining letters fund the allowance; one sits past the
  // cached planes, where the letter test reads the tables directly.
  "over-budget-joiners-astral": ("م" + ZWNJ + "م").repeat(60) + "\u{20000}",
  // The cluster around a joiner is read off pair verdicts where those cannot
  // depend on context, and off the segmenter everywhere else. These put a mark
  // after the joiner (it joins the cluster), a control before it (GB4), a lone
  // surrogate beside it, and emoji ZWJ sequences between Persian joiners, so a
  // budget that binds lands on clusters read both ways.
  "zwnj-before-harakat": ("مَ" + ZWNJ + "َم ").repeat(80),
  "zwj-after-newline": ("\n" + ZWJ + "م").repeat(40),
  "lone-surrogate-before-zwnj": ("\ud800" + ZWNJ + "م ").repeat(40),
  // Registered glyphs ride outside the budget; their unregistered twins do
  // not. Each runs past the cover allowance, so a misread kind shows up as a
  // strip that one side makes and the other does not.
  "rgi-zwj-dense": ("- \u{1F3F3}" + VS16 + ZWJ + "\u{1F308} ok\n").repeat(100),
  "rgi-zwj-skin-tone": ("\u{1F469}\u{1F3FD}" + ZWJ + "\u{1F4BB} ").repeat(100),
  "rgi-zwj-without-vs16": ("\u{1F3F3}" + ZWJ + "\u{1F308} ").repeat(100),
  "non-rgi-zwj-dense": ("\u{1F600}" + ZWJ + "\u{1F600} ").repeat(100),
  // GB11 fails on the first two, so their joiners stay on the budget: a skin
  // tone with no pictograph before it, and a selector after the joiner. GB11
  // holds on the third. Twenty joiners outrun the floor allowance of 16 while
  // the stray selectors stay under the scatter floor that would strip them all.
  "zwj-after-bare-modifier": ("a\u{1F3FD}" + ZWJ + "\u{1F600} ").repeat(20),
  "zwj-then-vs16": ("\u{1F600}" + ZWJ + VS16 + "\u{1F600} ").repeat(20),
  "zwj-after-vs1": ("\u{1F600}" + VS1 + ZWJ + "\u{1F600} ").repeat(20),
  "text-default-vs16-dense": ("- \u26A0" + VS16 + " careful\n").repeat(100),
  "redundant-vs16-dense": ("- \u{1F600}" + VS16 + " hi\n").repeat(100),
  "zwj-chain-dangling": ("\u{1F468}" + ZWJ + "\u{1F469}" + ZWJ + " ").repeat(
    60,
  ),
  "zwj-chain-after-letter": (
    "a" +
    ZWJ +
    "\u{1F468}" +
    ZWJ +
    "\u{1F469} "
  ).repeat(60),
  "rgi-beside-persian": (
    "می" +
    ZWNJ +
    "خواهم \u{1F468}" +
    ZWJ +
    "\u{1F469}" +
    ZWJ +
    "\u{1F467} "
  ).repeat(60),
  "persian-beside-emoji-zwj": (
    "می" +
    ZWNJ +
    "خواهم \u{1F468}" +
    ZWJ +
    "\u{1F469} "
  ).repeat(60),
  "mixed-everything":
    BOM +
    "می" +
    ZWNJ +
    "خواهم " +
    SCOTLAND +
    " 漢" +
    IVS +
    " " +
    ZWSP.repeat(12),
};

describe("carve analysis: optimized vs reference", () => {
  for (const [name, text] of Object.entries(CASES))
    it(`agrees on ${name}`, () => assertAgrees(text, name));

  it("agrees on every code point of the threat alphabet, in context", () => {
    for (const { cp: point, name } of THREAT_CODEPOINTS) {
      const ch = cp(point);
      for (const [shape, text] of Object.entries({
        alone: ch,
        "between letters": "م" + ch + "م",
        "between emoji": "\u{1F3F3}" + ch + "\u{1F308}",
        "after ideograph": "漢" + ch,
        run: ch.repeat(15),
        "after bom": BOM + "text" + ch,
      }))
        assertAgrees(text, `${name} ${shape}`);
    }
  });
});

// Fast-check over an alphabet built from the pieces the carve-out reasons about,
// so a random draw lands on a joiner beside a cursive letter rather than on a
// uniform code point that can only ever be visible.
const PIECES = [
  "a",
  " ",
  "\n",
  "م",
  "ی",
  "َ",
  "क",
  "्",
  "漢",
  "가",
  "⠃",
  "\u{1F3F3}",
  "\u{1F308}",
  "\u{1F468}",
  "\u{1F469}",
  "\u{1F467}",
  "\u{1F3FD}",
  "\u26A0",
  "\u{1F600}",
  "1",
  ZWNJ,
  ZWJ,
  VS16,
  VS1,
  IVS,
  BOM,
  ZWSP,
  SHY,
  BRAILLE_BLANK,
  HANGUL_FILLER,
  cp(0x20e3),
  cp(0xe0041),
  cp(0xe007f),
  "\u{1F3F4}",
  "\ud800",
  "\udc00",
];

describe("carve analysis: optimized vs reference, under fast-check", () => {
  it("agrees on strings drawn from the carve alphabet", () => {
    fc.assert(
      fc.property(
        fc.array(fc.constantFrom(...PIECES), { maxLength: 220 }),
        (pieces) => assertAgrees(pieces.join(""), "alphabet draw"),
      ),
      { numRuns: 2500 },
    );
  });

  it("agrees on arbitrary unicode strings", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 200, unit: "grapheme" }), (text) =>
        assertAgrees(text, "arbitrary unicode"),
      ),
      { numRuns: 1500 },
    );
  });

  it("agrees on strings that may hold unpaired surrogates", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 200, unit: "binary" }), (text) =>
        assertAgrees(text, "binary string"),
      ),
      { numRuns: 1500 },
    );
  });

  it("agrees when a draw is repeated past the preserve budget", () => {
    fc.assert(
      fc.property(
        fc.array(fc.constantFrom(...PIECES), { minLength: 1, maxLength: 40 }),
        fc.integer({ min: 1, max: 30 }),
        (pieces, repeats) =>
          assertAgrees(pieces.join("").repeat(repeats), "repeated draw"),
      ),
      { numRuns: 600 },
    );
  });
});
