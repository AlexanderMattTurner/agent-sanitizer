/**
 * The pinned Unicode properties (src/unicode-properties.mjs, generated from the
 * vendored UCD slices by scripts/gen-unicode-properties.mjs).
 *
 * Two contracts. The SSOT round-trip: the committed module is byte-for-byte
 * what the generator writes from the slices, and every table equals its
 * slice-derived spans. The witness: wherever the RUNNING Node's own Unicode is
 * the pinned version, every live `\p{…}` escape names exactly the code points of
 * its pinned table — so a slice cut from the wrong file or the wrong Unicode
 * (ucd-full@17.0.0 ships Unicode 16 data), or an extraction that dropped
 * entries, fails here on CI's Node. The carve-out's behaviour never reads the live escape; only this witness
 * does.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { unsandbox } from "./helpers/repo-root.mjs";
import {
  MODULE_PATH,
  deriveUnicodeProperties,
  renderUnicodeProperties,
} from "../scripts/gen-unicode-properties.mjs";
import {
  UNICODE_VERSION as PINNED_VERSION,
  codePointsOf,
  readUcdSlice,
  spansOf,
} from "../scripts/lib/ucd.mjs";
import * as committed from "../src/unicode-properties.mjs";
import { CF_CODEPOINTS } from "../src/cf-charset.mjs";

const derived = deriveUnicodeProperties();

describe("src/unicode-properties.mjs is the pinned UCD", () => {
  it("is byte-identical to a fresh generation", () => {
    assert.equal(
      readFileSync(unsandbox(MODULE_PATH), "utf8"),
      renderUnicodeProperties(),
      "src/unicode-properties.mjs is stale — run `node scripts/gen-unicode-properties.mjs`",
    );
  });

  it("pins the Unicode version every slice was cut from", () => {
    assert.equal(committed.UNICODE_VERSION, PINNED_VERSION);
  });

  for (const [name, spans] of Object.entries(derived))
    it(`${name} equals its slice-derived spans`, () => {
      assert.deepEqual(committed[name], spans);
      assert.ok(spans.length > 0, `${name} is empty (vacuous)`);
    });

  it("inSpans answers membership at every span boundary", () => {
    const spans = committed.UNIFIED_IDEOGRAPH;
    for (const [start, end] of spans) {
      assert.equal(committed.inSpans(spans, start), true);
      assert.equal(committed.inSpans(spans, end), true);
      assert.equal(committed.inSpans(spans, start - 1), false);
      assert.equal(committed.inSpans(spans, end + 1), false);
    }
    assert.equal(committed.inSpans(spans, -1), false);
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
    codePointsOf(
      spansOf(
        readUcdSlice("PropList.Pinned.json").PropList,
        ({ property }) => property === "Variation_Selector",
      ),
    ),
  ],
];

// Only a runtime on the pinned version can witness the slices: membership moves
// BOTH ways between versions (Unicode 17 dropped 672 assigned code points such
// as U+2605 from Extended_Pictographic while adding Extension J ideographs), so
// no subset relation holds across versions. Another runtime skips by name
// rather than asserting a relation that is false; CI's Node 22 is on the pin.
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
