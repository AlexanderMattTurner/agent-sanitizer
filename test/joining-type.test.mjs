/**
 * SSOT contract for the generated Unicode Joining_Type / virama / Brahmic
 * consonant tables.
 *
 * src/joining-type.mjs is generated from the vendored UCD slices by
 * scripts/gen-joining-type.mjs. This test re-derives the tables from the SAME
 * slices and asserts the committed module still agrees — so editing the source
 * data without regenerating (or a Stryker mutant flipping a range bound) fails
 * CI, exactly as an SSOT round-trip should.
 *
 * It checks EVERY covered code point plus the four boundary points around each
 * range (start-1, start, end, end+1). That is non-vacuous where it matters — an
 * off-by-one bound, a dropped range, or a mislabeled type surfaces as a concrete
 * mismatch — without the cost of iterating the full 0x10FFFF space twice. The
 * gaps between ranges all map to the default (U / false) by construction, so the
 * one boundary point on each side of every range pins the transition; sampling
 * the interior of every range then rules out an interior mislabel.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  joiningType,
  isVirama,
  isBrahmicConsonant,
  BRAHMIC_CONSONANT_RANGES,
  UNICODE_VERSION,
} from "../src/joining-type.mjs";
import { deriveTables, loadUcd } from "../scripts/gen-joining-type.mjs";

const { joiningJson, indicJson, consonantJson, version } = loadUcd();
const { joining, virama, brahmic } = deriveTables(
  joiningJson,
  indicJson,
  consonantJson,
);

const MAX_CP = 0x10ffff;

/** Build a code-point → tag lookup Map from derived [start, end, tag?] ranges. */
function referenceMap(ranges, defaultTag) {
  const map = new Map();
  for (const [start, end, tag] of ranges) {
    for (let cp = start; cp <= end; cp++) map.set(cp, tag ?? defaultTag);
  }
  return { get: (cp) => (map.has(cp) ? map.get(cp) : defaultTag) };
}

/**
 * Every code point worth probing for a set of ranges: all covered points (so an
 * interior mislabel is caught) plus the two off-by-one guards on each side of
 * every range (so a shifted bound flips one of them). Clamped to the code space.
 */
function probePoints(ranges) {
  const pts = new Set();
  const add = (cp) => {
    if (cp >= 0 && cp <= MAX_CP) pts.add(cp);
  };
  for (const [start, end] of ranges) {
    add(start - 1);
    add(end + 1);
    for (let cp = start; cp <= end; cp++) add(cp);
  }
  return pts;
}

describe("joining-type generated module", () => {
  it("pins the Unicode version to the pinned ucd-full release", () => {
    assert.equal(UNICODE_VERSION, version);
  });

  it("joiningType matches the derived table on every covered point and range boundary", () => {
    const ref = referenceMap(joining, "U");
    for (const cp of probePoints(joining)) {
      const got = joiningType(cp);
      if (got !== ref.get(cp)) {
        assert.fail(
          `U+${cp.toString(16)}: joiningType=${got} expected ${ref.get(cp)}`,
        );
      }
    }
  });

  it("isVirama matches the derived virama set on every covered point and range boundary", () => {
    const set = new Set();
    for (const [start, end] of virama)
      for (let cp = start; cp <= end; cp++) set.add(cp);
    for (const cp of probePoints(virama)) {
      const got = isVirama(cp);
      if (got !== set.has(cp)) {
        assert.fail(
          `U+${cp.toString(16)}: isVirama=${got} expected ${set.has(cp)}`,
        );
      }
    }
  });

  it("BRAHMIC_CONSONANT_RANGES is exactly the derived script-tagged table", () => {
    // Both the spans AND their script tags: the tag is what
    // test/invisible-unicode-tables.test.mjs checks each span against, so a
    // mislabeled span would quietly weaken that test rather than fail it.
    assert.deepEqual(
      BRAHMIC_CONSONANT_RANGES.map(([script, start, end]) => [
        start,
        end,
        script,
      ]),
      brahmic,
    );
  });

  it("isBrahmicConsonant matches the derived set on every covered point and range boundary", () => {
    const set = new Set();
    for (const [start, end] of brahmic)
      for (let cp = start; cp <= end; cp++) set.add(cp);
    for (const cp of probePoints(brahmic)) {
      const got = isBrahmicConsonant(cp);
      if (got !== set.has(cp))
        assert.fail(
          `U+${cp.toString(16)}: isBrahmicConsonant=${got} expected ${set.has(cp)}`,
        );
    }
  });

  // Hand-checked anchors for the Brahmic table specifically: a consonant, an
  // independent vowel (Script=Devanagari but never a conjunct base — the reason
  // the table cannot just be \p{Script=…}), and a hole INSIDE the old
  // hand-typed KA–HA span that the UCD-derived table correctly excludes.
  for (const [cp, expected, why] of [
    [0x915, true, "DEVANAGARI LETTER KA"],
    [0x905, false, "DEVANAGARI LETTER A (independent vowel)"],
    [0x9b1, false, "Bengali hole inside the old 0995–09B9 span"],
    [0x978, true, "DEVANAGARI LETTER MARWARI DDA (absent from the old table)"],
  ]) {
    it(`isBrahmicConsonant(U+${cp.toString(16)}) === ${expected} — ${why}`, () =>
      assert.equal(isBrahmicConsonant(cp), expected));
  }

  // A few hand-checked anchors so the contract is legible even if the derivation
  // above were somehow tautological: real letters, the joiners themselves, a
  // transparent mark, and viramas from two different Brahmic scripts.
  for (const [cp, type] of [
    [0x628, "D"], // Arabic beh — dual-joining
    [0x627, "R"], // Arabic alef — right-joining
    [0x6cc, "D"], // Persian yeh — dual-joining
    [0x200d, "C"], // ZWJ — join-causing
    [0x200c, "U"], // ZWNJ — non-joining (the default)
    [0x64e, "T"], // Arabic fatha — transparent
    [0x41, "U"], // Latin A — non-joining
  ]) {
    it(`classifies U+${cp.toString(16)} as ${type}`, () =>
      assert.equal(joiningType(cp), type));
  }

  for (const cp of [0x94d, 0x9cd, 0xdca]) {
    it(`treats U+${cp.toString(16)} as a virama`, () =>
      assert.equal(isVirama(cp), true));
  }
  it("does not treat a plain consonant as a virama", () =>
    assert.equal(isVirama(0x915), false));
});
