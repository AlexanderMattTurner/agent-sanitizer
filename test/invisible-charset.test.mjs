/**
 * Drift guard: the generated invisible-charset SSOT
 * (`python/agent_sanitizer/data/invisible-charset.json`) must equal what
 * `scripts/gen-invisible-charset.mjs` produces from `src/invisible.mjs` right
 * now. The JSON is what non-JS consumers (the Python `agent-secret-redactor`
 * engine) read instead of forking the invisible-character set; if it drifts from
 * `invisible.mjs`, a key spliced with a newly-added code point escapes one layer.
 *
 * Regenerate with `node scripts/gen-invisible-charset.mjs` when `VS` /
 * `BLANK_NON_CF` change.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  extraCodepoints,
  cfCodepoints,
  charsetDoc,
  cfCharsetModule,
  CF_MODULE_PATH,
  OUTPUT_PATH,
} from "../scripts/gen-invisible-charset.mjs";
import { VS, BLANK_NON_CF, stripInvisible } from "../src/invisible.mjs";
import { CF_CODEPOINTS } from "../src/cf-charset.mjs";
import {
  parseStandardizedVariants,
  loadStandardizedVariantsUcd,
} from "../scripts/gen-standardized-variants.mjs";
import {
  STANDARDIZED_VARIANTS,
  isStandardizedVariant,
  UNICODE_VERSION as SV_UNICODE_VERSION,
} from "../src/standardized-variants.mjs";

describe("invisible-charset SSOT", () => {
  const committed = JSON.parse(readFileSync(OUTPUT_PATH, "utf8"));

  it("committed JSON equals the freshly generated document (full round-trip)", () => {
    assert.deepEqual(committed, charsetDoc());
  });

  it("committed JSON's extra code points equal the freshly generated ones", () => {
    assert.deepEqual(committed.extra_codepoints, extraCodepoints());
  });

  it("committed JSON's Cf code points equal Node's freshly enumerated \\p{Cf}", () => {
    assert.deepEqual(committed.cf_codepoints, cfCodepoints());
  });

  it("covers every VS and BLANK_NON_CF code point (no member dropped)", () => {
    const generated = new Set(extraCodepoints());
    for (const s of [VS, BLANK_NON_CF])
      for (const ch of s)
        assert.ok(
          generated.has(ch.codePointAt(0)),
          `U+${ch.codePointAt(0).toString(16)} missing from the SSOT`,
        );
    // And nothing extra: exactly the union, no more.
    const expected = new Set();
    for (const s of [VS, BLANK_NON_CF])
      for (const ch of s) expected.add(ch.codePointAt(0));
    assert.equal(generated.size, expected.size);
  });
});

// The cross-layer security invariant: the pinned Cf set the JS layer strips
// (src/cf-charset.mjs) is IDENTICAL, member-for-member, to the set the Python
// port reads from the committed JSON. If the two ever diverge, a key spliced with
// a code point one side omits escapes that layer — the exact bug pinning fixes.
describe("Cf charset is pinned identically for JS and Python", () => {
  const committed = JSON.parse(readFileSync(OUTPUT_PATH, "utf8"));

  it("the JS pinned Cf set equals the committed JSON's cf_codepoints", () => {
    // Both artifacts are generated from the same source, so equality is exact
    // (same order, no set-membership fudge) — a stronger contract than ⊆/⊇.
    assert.deepEqual([...CF_CODEPOINTS], committed.cf_codepoints);
  });

  it("the JS layer actually strips a version-delta Cf char (U+13439)", () => {
    // U+13439 (EGYPTIAN HIEROGLYPH beginning of horizontal joiner region) is Cf
    // in Node's Unicode 17 but NOT Cf in the Unicode 14/15 CPython commonly
    // ships. Before pinning, JS stripped it and the live-Cf Python port did not;
    // now both strip it because both read the pinned set.
    assert.ok(CF_CODEPOINTS.includes(0x13439));
    assert.equal(stripInvisible("a\u{13439}b"), "ab");
  });
});

// SSOT round-trip for the standardized variation sequence table backing the
// FE00–FE0D carve-out in invisible.mjs. src/standardized-variants.mjs is
// generated from the vendored UCD slice; re-parsing that slice here and
// asserting the committed module matches makes editing the data without
// regenerating (or a mutant flipping a pair) a hard CI failure.
describe("standardized-variants SSOT", () => {
  const { text, version } = loadStandardizedVariantsUcd();
  const pairs = parseStandardizedVariants(text);

  it("pins the committed module's Unicode version to the vendored slice", () => {
    assert.equal(SV_UNICODE_VERSION, version);
  });

  it("committed table equals the freshly parsed UCD slice", () => {
    assert.deepEqual(STANDARDIZED_VARIANTS, pairs);
  });

  it("is a non-trivial table with only FE00–FE0D selectors", () => {
    assert.ok(pairs.length > 100, "expected a few hundred registered pairs");
    for (const [, selector] of pairs) {
      assert.ok(selector >= 0xfe00 && selector <= 0xfe0d);
    }
  });

  it("isStandardizedVariant accepts every registered pair", () => {
    for (const [base, selector] of pairs)
      assert.ok(
        isStandardizedVariant(base, selector),
        `U+${base.toString(16)} + U+${selector.toString(16)} not recognized`,
      );
  });

  // Hand-checked anchors from StandardizedVariants.txt so the contract stays
  // legible even if the derivation above were somehow tautological.
  for (const [base, selector, note] of [
    [0x30, 0xfe00, "DIGIT ZERO short diagonal stroke form"],
    [0x2205, 0xfe00, "EMPTY SET with long stroke overlay"],
    [0x4e0d, 0xfe00, "U+4E0D → CJK COMPATIBILITY IDEOGRAPH-F967"],
  ]) {
    it(`recognizes the registered sequence U+${base.toString(16)}+VS (${note})`, () =>
      assert.ok(isStandardizedVariant(base, selector)));
  }

  it("rejects an unregistered base or a non-standardized selector", () => {
    assert.ok(!isStandardizedVariant(0x61, 0xfe00), "'a' + VS1 not registered");
    assert.ok(
      !isStandardizedVariant(0x30, 0xfe0d),
      "DIGIT ZERO is registered with VS1, not VS14",
    );
    assert.ok(
      !isStandardizedVariant(0x30, 0xfe0f),
      "VS16 is an emoji presentation selector, never a standardized variant",
    );
  });
});

describe("generated modules are byte-identical to a fresh generation", () => {
  // The SEMANTIC round-trips above compare code points, which is exactly why
  // src/cf-charset.mjs was able to drift from its own generator by whitespace
  // alone and stay green: Prettier repacked the flat number array the generator
  // emitted, and nothing compared bytes. Removing Prettier from the file removed
  // one cause of that drift, not the class — a hand edit, or a change to the
  // generator's template with no regeneration, re-lands the same divergence.
  it("src/cf-charset.mjs matches cfCharsetModule() byte for byte", () => {
    assert.equal(
      readFileSync(CF_MODULE_PATH, "utf8"),
      cfCharsetModule(),
      "src/cf-charset.mjs is stale — run `node scripts/gen-invisible-charset.mjs`",
    );
  });

  it("the charset JSON matches charsetDoc() byte for byte", () => {
    assert.equal(
      readFileSync(OUTPUT_PATH, "utf8"),
      JSON.stringify(charsetDoc(), null, 2) + "\n",
      "the charset JSON is stale — run `node scripts/gen-invisible-charset.mjs`",
    );
  });
});
