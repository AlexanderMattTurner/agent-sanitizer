/**
 * The grapheme segmenter is built on FIRST USE, never at import.
 *
 * Constructing an `Intl.Segmenter` loads ICU's segmentation tables and costs
 * ~10 ms — the largest single item in what a hook process spent before it even
 * read its payload — while only text with carve candidates ever asks for a
 * cluster boundary. These hooks run on every tool call, so building it at
 * import charged every call for a segmenter almost none of them used.
 *
 * Driven through the real public entry point against the REAL Intl.Segmenter,
 * subclassed only to count constructions: what is under test is WHEN one is
 * built, so a stand-in that answered segmentation itself would decide the
 * carve outcome and pin nothing.
 */
import { after, test } from "node:test";
import assert from "node:assert/strict";

const RealSegmenter = Intl.Segmenter;
let built = 0;

class CountingSegmenter extends RealSegmenter {
  constructor(...args) {
    super(...args);
    built += 1;
  }
}

/** Text with no invisible code points at all: the carve analysis never runs. */
const NO_CANDIDATES = "plain ascii";

/**
 * An emoji ZWJ sequence: the joiner is a preserve candidate, so the carve
 * analysis has to resolve the cluster it sits in and reaches the segmenter.
 */
const NEEDS_CLUSTERS = "hello \u{1F469}‍\u{1F4BB} world";

Object.defineProperty(Intl, "Segmenter", {
  value: CountingSegmenter,
  configurable: true,
  writable: true,
});
after(() =>
  Object.defineProperty(Intl, "Segmenter", {
    value: RealSegmenter,
    configurable: true,
    writable: true,
  }),
);

// Imported after the patch, and under a query so this file gets its OWN module
// instance: the segmenter is cached per module, so a copy some other import
// already used would have built one before this file could count it.
const { stripInvisibleWithReport } =
  await import("../src/invisible.mjs?segmenter-lazy");

test("importing the module builds no segmenter", () => {
  assert.equal(built, 0);
});

test("text with no carve candidates builds no segmenter", () => {
  assert.equal(stripInvisibleWithReport(NO_CANDIDATES).cleaned, NO_CANDIDATES);
  assert.equal(built, 0);
});

test("the first text that needs clusters builds one, and later text reuses it", () => {
  assert.equal(
    stripInvisibleWithReport(NEEDS_CLUSTERS).cleaned,
    NEEDS_CLUSTERS,
  );
  assert.equal(built, 1);
  stripInvisibleWithReport(`${NEEDS_CLUSTERS}!`);
  assert.equal(built, 1);
});
