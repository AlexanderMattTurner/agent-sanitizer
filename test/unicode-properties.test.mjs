/**
 * The pinned Unicode properties (src/unicode-properties.mjs, generated from the
 * pinned UCD package by scripts/gen-unicode-properties.mjs).
 *
 * Two contracts: the generator renders exactly the tables derived from the
 * package (the module itself is git-ignored and generated at install time), and,
 * on a Node whose own Unicode is the pinned version, every live `\p{…}` names
 * exactly its pinned table — so a package of the wrong Unicode (ucd-full@17.0.0
 * ships Unicode 16) fails here. Only this witness reads the live escape.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  UNICODE_PROPERTIES as derived,
  renderUnicodeProperties,
} from "../scripts/gen-unicode-properties.mjs";
import {
  UNICODE_VERSION as PINNED_VERSION,
  codePointsOf,
  ucdSpans,
} from "../scripts/lib/ucd.mjs";
import * as generated from "../src/unicode-properties.mjs";
import { CF_CODEPOINTS } from "../src/cf-charset.mjs";

describe("src/unicode-properties.mjs is the pinned UCD", () => {
  it("renders a module exporting exactly the derived tables", async () => {
    const rendered = await import(
      `data:text/javascript,${encodeURIComponent(renderUnicodeProperties())}`
    );
    for (const [name, spans] of Object.entries(derived))
      assert.deepEqual(rendered[name], spans, name);
    assert.equal(rendered.UNICODE_VERSION, PINNED_VERSION);
  });

  it("pins the Unicode version of the UCD package", () => {
    assert.equal(generated.UNICODE_VERSION, PINNED_VERSION);
  });

  for (const [name, spans] of Object.entries(derived))
    it(`${name} equals its package-derived spans`, () => {
      assert.deepEqual(generated[name], spans);
      assert.ok(spans.length > 0, `${name} is empty (vacuous)`);
    });

  it("inSpans answers membership at every span boundary", () => {
    const spans = generated.UNIFIED_IDEOGRAPH;
    for (const [start, end] of spans) {
      assert.equal(generated.inSpans(spans, start), true);
      assert.equal(generated.inSpans(spans, end), true);
      assert.equal(generated.inSpans(spans, start - 1), false);
      assert.equal(generated.inSpans(spans, end + 1), false);
    }
    assert.equal(generated.inSpans(spans, -1), false);
  });
});

// ─── Witness: the running Node's live properties ──────────────────────────────
/** @param {string} version "16.0" / "17.0.0" @returns {string} */
const majorMinor = (version) => version.split(".").slice(0, 2).join(".");
const runtime = majorMinor(process.versions.unicode);
const pinned = majorMinor(PINNED_VERSION);

/** Every pinned property, as the live escape that names it and its code points. */
const PINNED = [
  ["\\p{Extended_Pictographic}", codePointsOf(derived.EXTENDED_PICTOGRAPHIC)],
  ["\\p{Emoji_Modifier}", codePointsOf(derived.EMOJI_MODIFIER)],
  [
    "[\\p{Emoji}--\\p{Emoji_Presentation}]",
    codePointsOf(derived.EMOJI_TEXT_DEFAULT),
  ],
  ["\\p{Unified_Ideograph}", codePointsOf(derived.UNIFIED_IDEOGRAPH)],
  ["\\p{Script=Braille}", codePointsOf(derived.SCRIPT_BRAILLE)],
  ["\\p{Script=Hangul}", codePointsOf(derived.SCRIPT_HANGUL)],
  ["\\p{Cf}", [...CF_CODEPOINTS]],
  [
    "\\p{Variation_Selector}",
    codePointsOf(await ucdSpans("Binary_Property/Variation_Selector")),
  ],
];

// Only a runtime on the pinned version can witness the package: membership moves
// BOTH ways between versions, so another runtime skips by name. CI's Node 22 is
// on the pin.
const witnessSkip =
  runtime === pinned
    ? false
    : `this Node's Unicode ${runtime} is not the pinned ${pinned}`;

describe(`pinned properties equal this Node's Unicode ${process.versions.unicode}`, () => {
  for (const [escape, cps] of PINNED)
    it(`${escape} equals the live property`, { skip: witnessSkip }, () => {
      const live = new RegExp(escape, "v");
      const table = new Set(cps);
      const unpinned = [];
      let liveCount = 0;
      for (let cp = 0; cp <= 0x10ffff; cp++) {
        if (cp === 0xd800) cp = 0xe000; // surrogates have no properties here
        if (!live.test(String.fromCodePoint(cp))) continue;
        liveCount++;
        if (!table.has(cp)) unpinned.push(cp.toString(16));
      }
      assert.ok(liveCount > 0, `${escape} has no live members (vacuous)`);
      // live ⊆ pinned and equal sizes is equality.
      assert.deepEqual(unpinned.slice(0, 12), [], "live members not pinned");
      assert.equal(table.size, liveCount, "pinned members not live");
    });
});
