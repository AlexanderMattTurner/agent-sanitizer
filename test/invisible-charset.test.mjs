/**
 * The generated invisible-charset SSOT
 * (`python/agent_sanitizer/data/invisible-charset.json`) must carry what
 * `scripts/gen-invisible-charset.mjs` produces from `src/invisible.mjs`. The
 * JSON is what non-JS consumers (the Python `agent-secret-redactor` engine)
 * read instead of forking the invisible-character set; if it disagrees with
 * `invisible.mjs`, a key spliced with a newly-added code point escapes one layer.
 *
 * Nothing here is committed: `pnpm install` generates the JSON and the JS-side
 * tables (`scripts/gen-unicode.mjs`), so these tests check the generated state
 * and the generators' behaviour, not a committed copy against a fresh run.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  extraCodepoints,
  charsetDoc,
  OUTPUT_PATH,
} from "../scripts/gen-invisible-charset.mjs";
import { cfCodepoints, cfCharsetModule } from "../scripts/gen-cf-charset.mjs";
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
import { UNICODE_VERSION as UCD_PACKAGE_VERSION } from "../scripts/lib/ucd.mjs";

describe("invisible-charset SSOT", () => {
  const generated = JSON.parse(readFileSync(OUTPUT_PATH, "utf8"));

  // The JSON is written by an earlier process (`pnpm install`), so this is not a
  // tautology: it fails when `invisible.mjs` moved since the install, and under
  // mutation testing it kills a mutant of `VS` / `BLANK_NON_CF`, because the
  // JSON was generated from the unmutated module.
  it("generated JSON equals the document the generator produces now (full round-trip)", () => {
    assert.deepEqual(generated, charsetDoc());
  });

  it("generated JSON's extra code points equal the live ones", () => {
    assert.deepEqual(generated.extra_codepoints, extraCodepoints());
  });

  it("generated JSON's Cf code points equal the pinned UCD's General_Category=Cf", () => {
    assert.deepEqual(generated.cf_codepoints, cfCodepoints());
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
// port reads from the generated JSON. If the two ever diverge, a key spliced with
// a code point one side omits escapes that layer — the exact bug pinning fixes.
describe("Cf charset is pinned identically for JS and Python", () => {
  const generated = JSON.parse(readFileSync(OUTPUT_PATH, "utf8"));

  it("the JS pinned Cf set equals the generated JSON's cf_codepoints", () => {
    // Both artifacts are generated from the same source, so equality is exact
    // (same order, no set-membership fudge) — a stronger contract than ⊆/⊇.
    assert.deepEqual([...CF_CODEPOINTS], generated.cf_codepoints);
  });

  // The byte comparison against a committed copy is gone with the committed
  // copy; what remains worth pinning is that the generator's output is a module
  // carrying exactly the Cf set it was given.
  it("cfCharsetModule() renders a module exporting exactly the pinned Cf set", async () => {
    const rendered = await import(
      `data:text/javascript,${encodeURIComponent(cfCharsetModule())}`
    );
    assert.ok(cfCodepoints().length > 100, "Cf set is implausibly small");
    assert.deepEqual([...rendered.CF_CODEPOINTS], cfCodepoints());
    assert.equal(rendered.UNICODE_VERSION, UCD_PACKAGE_VERSION);
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
// generated from the hash-pinned UCD file; re-parsing that file here and
// asserting the generated module matches makes editing the data without
// regenerating (or a mutant flipping a pair) a hard CI failure.
describe("standardized-variants SSOT", () => {
  const { text, version } = loadStandardizedVariantsUcd();
  const pairs = parseStandardizedVariants(text);

  it("pins the generated module's Unicode version to the UCD file's", () => {
    assert.equal(SV_UNICODE_VERSION, version);
    assert.equal(version, UCD_PACKAGE_VERSION);
  });

  // The one UCD file not read from the pinned package: bytes other than the
  // pinned download (a tampered cache, another Unicode's copy) must fail
  // rather than regenerate the table from unreviewed data.
  it("refuses a StandardizedVariants.txt that is not the pinned file", () => {
    assert.throws(
      () =>
        loadStandardizedVariantsUcd(
          text.replace(
            /^# StandardizedVariants-[\d.]+\.txt/u,
            "# StandardizedVariants-16.0.0.txt",
          ),
        ),
      /StandardizedVariants\.txt has SHA-256 [0-9a-f]{64}, not the pinned [0-9a-f]{64} for Unicode 17\.0\.0/u,
    );
  });

  // The header proves the pinned bytes are the release the package names.
  it("pins the package's Unicode release of the file", () => {
    assert.equal(
      text.slice(0, text.indexOf("\n")),
      `# StandardizedVariants-${UCD_PACKAGE_VERSION}.txt`,
    );
  });

  it("generated table equals the freshly parsed UCD file", () => {
    assert.deepEqual(STANDARDIZED_VARIANTS, pairs);
  });

  it("is a non-trivial table of variation-selector sequences", () => {
    assert.ok(pairs.length > 100, "expected a few hundred registered pairs");
    for (const [, selector] of pairs)
      assert.match(String.fromCodePoint(selector), /^\p{Variation_Selector}$/u);
  });

  // The emoji presentation selectors belong to the pictograph carve-out, and
  // the UCD keeps their sequences in a different file: one appearing here
  // would mean the fetched file is not StandardizedVariants.txt.
  it("registers no emoji presentation selector", () => {
    for (const [, selector] of pairs)
      assert.ok(selector !== 0xfe0e && selector !== 0xfe0f);
  });

  for (const [name, line] of [
    ["a three-code-point sequence", "0030 FE00 FE01; form; # X"],
    ["a non-hex code point", "00G0 FE00; form; # X"],
    ["a selector that is not a variation selector", "0030 0041; form; # X"],
  ])
    it(`throws on ${name} instead of dropping it`, () => {
      assert.throws(() => parseStandardizedVariants(line), /not a/u);
    });

  // Every selector the UCD file registers a sequence for must survive the
  // parse: a selector range narrower than the file's is how all 60 Mongolian
  // free-variation sequences were silently dropped.
  it("keeps every selector the UCD file registers", () => {
    const inFile = new Set();
    for (const line of text.split("\n")) {
      const seq = line.split("#")[0].split(";")[0].trim().split(/\s+/u);
      if (seq.length === 2) inFile.add(parseInt(seq[1], 16));
    }
    assert.deepEqual(new Set(pairs.map(([, selector]) => selector)), inFile);
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
    [0x1820, 0x180b, "MONGOLIAN LETTER A second form (FVS1)"],
    [0x1820, 0x180c, "MONGOLIAN LETTER A third form (FVS2)"],
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
