/**
 * Targeted mutation-kill tests for src/invisible.mjs.
 *
 * Each test pins the EXACT behavior at a branch/boundary a currently-surviving
 * Stryker mutant changes, exercised only through the public exported API. The
 * comment above each block names the mutant(s) it targets (line + mutator).
 * All assertions pass on the unmutated source.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  stripInvisible,
  stripInvisibleWithReport,
  payloadInvisibleView,
} from "../src/invisible.mjs";
import { cp } from "./test-helpers.mjs";

const ZWNJ = cp(0x200c);
const ZWJ = cp(0x200d);
const HANGUL_FILLER = cp(0x115f); // a Hangul filler; needs a Hangul anchor to survive

// ─── isCjkIdeograph (\p{Unified_Ideograph} ∪ the compatibility blocks) ─────────
// An ideographic variation selector (U+E0100) is preserved only after a CJK
// ideograph. The property escape leaves no range boundaries to mutate, but the
// two literal compatibility spans still have ends, and a ConditionalExpression
// `false` on the regex test kills the gate outright — so pin one base from each
// source of the union. (The exhaustive set contract lives in
// test/invisible-unicode-tables.test.mjs.)
describe("mutation-kill: isCjkIdeograph union members", () => {
  for (const [label, base] of [
    ["U+9FFF (Unified block end)", 0x9fff],
    ["U+FA6D (compatibility block, near end)", 0xfa6d],
    ["U+2FA1D (compatibility supplement end)", 0x2fa1d],
  ]) {
    it(`preserves an ideographic selector after ${label}`, () => {
      const input = cp(base) + cp(0xe0100);
      const { cleaned, found } = stripInvisibleWithReport(input);
      assert.equal(cleaned, input);
      assert.deepEqual(found, []);
    });
  }
});

// ─── isBrahmicConsonant END boundary (`cp <= end` → `cp < end`) ───────────────
// A ZWJ after a virama is preserved only when the virama sits on a real Brahmic
// consonant. U+0939 (HA) is the LAST of the Devanagari KA–HA span, so the end
// mutant strips the conjunct joiner.
describe("mutation-kill: isBrahmicConsonant end boundary", () => {
  it("preserves a ZWJ conjunct on U+0939 HA (Devanagari KA–HA end)", () => {
    const input = cp(0x939) + cp(0x94d) + ZWJ + cp(0x915);
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, input);
    assert.deepEqual(found, []);
  });
});

// ─── isBrailleCell (\p{Script=Braille} minus the blank itself) ────────────────
// A U+2800 BRAILLE PATTERN BLANK is preserved only next to a real (non-blank)
// Braille cell. Pin both ends of the block so a ConditionalExpression `false`
// on the property test, or a `cp !== BRAILLE_BLANK` → `cp === BRAILLE_BLANK`
// mutant, strips the blank.
describe("mutation-kill: isBrailleCell anchors", () => {
  for (const [label, anchor] of [
    ["first cell U+2801", 0x2801],
    ["last cell U+28FF", 0x28ff],
  ]) {
    it(`preserves a U+2800 blank anchored by the ${label}`, () => {
      const input = cp(anchor) + cp(0x2800);
      const { cleaned, found } = stripInvisibleWithReport(input);
      assert.equal(cleaned, input);
      assert.deepEqual(found, []);
    });
  }
});

// ─── isHangul anchors (\p{Script=Hangul}) ─────────────────────────────────────
// A Hangul filler is preserved only next to a real Hangul jamo/syllable. The
// anchor set is Unicode's own Script=Hangul, so there are no hand-written range
// boundaries left to mutate; what remains worth pinning is that every ASSIGNED
// Hangul block still anchors (a ConditionalExpression `false` mutant on the
// regex test, or a swap to a narrower property, drops them all) and that the
// filler is found on BOTH sides — the anchor sits AFTER the filler here, killing
// `isHangul(prev) || isHangul(next)` → `&&`.
describe("mutation-kill: isHangul anchors across the Hangul blocks", () => {
  const anchors = [
    ["Hangul Jamo start U+1100", 0x1100],
    ["Hangul Jamo end U+11FF", 0x11ff],
    ["Compatibility Jamo start U+3131", 0x3131],
    ["Compatibility Jamo end U+318E", 0x318e],
    ["Jamo Extended-A start U+A960", 0xa960],
    ["Jamo Extended-A end U+A97C", 0xa97c],
    ["Hangul Syllables start U+AC00", 0xac00],
    ["Hangul Syllables end U+D7A3", 0xd7a3],
    ["Jamo Extended-B start U+D7B0", 0xd7b0],
    ["Jamo Extended-B end U+D7FB", 0xd7fb],
    ["Halfwidth Jamo start U+FFA1", 0xffa1],
    ["Halfwidth Jamo end U+FFDC", 0xffdc],
    // Only \p{Script=Hangul} reaches these: the hand-written block table missed
    // the tone marks and the enclosed-Hangul forms entirely.
    ["Hangul tone mark U+302E", 0x302e],
    ["parenthesized Hangul U+3200", 0x3200],
    ["circled Hangul U+326E", 0x326e],
  ];
  for (const [name, anchor] of anchors) {
    it(`preserves a Hangul filler anchored by ${name}`, () => {
      const input = HANGUL_FILLER + cp(anchor);
      const { cleaned, found } = stripInvisibleWithReport(input);
      assert.equal(cleaned, input);
      assert.deepEqual(found, []);
    });
  }

  // Script_Extensions=Hangul is the WRONG property here: it also contains the
  // CJK punctuation Korean shares with Chinese and Japanese, which is not a
  // jamo and must not anchor a filler in otherwise Hangul-free text.
  for (const [name, notAnchor] of [
    ["U+3001 IDEOGRAPHIC COMMA", 0x3001],
    ["U+30FB KATAKANA MIDDLE DOT", 0x30fb],
    ["U+FF61 HALFWIDTH IDEOGRAPHIC FULL STOP", 0xff61],
  ]) {
    it(`strips a Hangul filler next to ${name} (Script_Extensions only)`, () => {
      const { cleaned } = stripInvisibleWithReport(
        HANGUL_FILLER + cp(notAnchor),
      );
      assert.equal(cleaned, cp(notAnchor));
    });
  }
});

// ─── isPreservedJoiner ZWJ single-neighbour rule ──────────────────────────────
// (line 557: `cp === ZWNJ ? lc && rc : lc || rc` — ConditionalExpression `true`
//  and LogicalOperator `lc && rc`). A ZWJ forces a connected form and is kept
//  with a cursive letter on just ONE side. beh (D) · ZWJ · hamza (U): lc=true,
//  rc=false, so `lc || rc` preserves it; a `lc && rc` mutant would strip it.
describe("mutation-kill: ZWJ preserved with a single cursive neighbour", () => {
  it("preserves a ZWJ between beh (cursive) and hamza (non-joining)", () => {
    const input = cp(0x628) + ZWJ + cp(0x621);
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, input);
    assert.deepEqual(found, []);
  });
});

// ─── isCursiveLetter (line 462: ConditionalExpression `false`, StringLiteral) ──
// A ZWNJ between two cursive letters is preserved. beh · ZWNJ · beh (both
// Joining_Type D): if isCursiveLetter is forced false (or its "D" literal is
// blanked), lc/rc collapse to false and the ZWNJ is stripped.
describe("mutation-kill: isCursiveLetter recognizes D-type letters", () => {
  it("preserves a ZWNJ between two beh letters (both Joining_Type D)", () => {
    const input = cp(0x628) + ZWNJ + cp(0x628);
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, input);
    assert.deepEqual(found, []);
  });
});

// ─── payloadInvisibleView (lines 933-935) ─────────────────────────────────────
// Visible code points map to a space, PAYLOAD invisibles pass through verbatim.
// Kills: line 933 `let out = ""` (StringLiteral prefix), line 934 `i <
// cps.length`→`i <= cps.length` (a trailing extra char), line 935
// ConditionalExpression `true` (would echo visibles) and the `" "` StringLiteral
// (would blank them).
describe("mutation-kill: payloadInvisibleView masking", () => {
  it("maps visibles to spaces and keeps a payload ZWSP in place", () => {
    const input = "a" + cp(0x200b) + "b"; // ZWSP is Cf payload (not carve-preserved)
    assert.equal(payloadInvisibleView(input), " " + cp(0x200b) + " ");
  });

  it("returns exactly one space per visible char (length-exact)", () => {
    assert.equal(payloadInvisibleView("ab"), "  ");
  });
});

// ─── stripInvisibleWithReport leading-BOM guard (line 960: Conditional `true`) ─
// hasLeadingBom must be false for text with no leading U+FEFF; a Conditional
// `true` mutant would always slice off the first char and re-prepend a BOM.
describe("mutation-kill: no spurious leading-BOM handling", () => {
  it("leaves BOM-free text and its first char untouched", () => {
    assert.equal(stripInvisible("abc"), "abc");
    const { cleaned } = stripInvisibleWithReport("hello");
    assert.equal(cleaned, "hello");
  });
});

// ─── tag-sequence decode + registration (line 715 arithmetic; preserve path) ──
// A registered subregional flag is preserved verbatim. Tag chars decode as
// `cp − 0xE0000`; a `+ 0xE0000` mutant garbles the payload so it no longer names
// a registered subdivision and the flag's tag run is stripped.
describe("mutation-kill: registered flag tag sequence preserved", () => {
  it("preserves the Scotland flag (🏴 gbsct CANCEL) verbatim", () => {
    const flag =
      cp(0x1f3f4) +
      [..."gbsct"].map((c) => cp(0xe0000 + c.charCodeAt(0))).join("") +
      cp(0xe007f);
    const { cleaned, found } = stripInvisibleWithReport(flag);
    assert.equal(cleaned, flag);
    assert.deepEqual(found, []);
  });
});
