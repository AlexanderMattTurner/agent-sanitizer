/**
 * Crash-resistance / no-silent-suppression fuzz targets for `sanitize`.
 * Arbitrary bytes, lone surrogates, and huge inputs must never throw, and any
 * change to the text must carry a warning (content can never vanish silently).
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import { sanitize } from "../src/index.mjs";
import { HIDDEN_PLACEHOLDER } from "../src/html.mjs";
import {
  fcRunOptions,
  cp,
  unicodeChar,
  loneSurrogate,
} from "./test-helpers.mjs";

const INVISIBLE_VALUES = [
  cp(0x200b),
  cp(0x200c),
  cp(0x200d),
  cp(0x2060),
  cp(0x00ad),
  cp(0xfeff),
  cp(0xfe0f),
  cp(0x3164),
  cp(0x2800),
  cp(0x034f), // zero-width combining mark (Mn blank filler)
  cp(0xe0041), // Unicode TAG (deniable-encoding channel)
  cp(0x1f600), // astral (parser totality)
  `${cp(0x1b)}[31m`,
  `${cp(0x1b)}[0m`,
  // An OSC string terminated by BEL — exercises the 7-bit OSC + BEL terminator.
  `${cp(0x1b)}]8;;http://x${cp(0x07)}`,
  // 8-bit C1 forms of the same hazards: a complete CSI sequence, a bare CSI
  // introducer, and the C1 OSC introducer. Seeded explicitly because a uniform
  // 0..0x10FFFF draw lands on U+009B/U+009D only ~1-in-a-million, so the fuzzer
  // never reaches them on its own.
  `${cp(0x9b)}31m`,
  cp(0x9b),
  cp(0x9d),
];

// Every raw ANSI control introducer Layer 1 must guarantee is gone from the
// output. The no-silent-suppression invariant alone can't catch a passthrough
// (an unchanged byte trivially satisfies it), so this is the postcondition that
// turns "output is clean" into a checked property rather than a hope. Covers the
// 7-bit ESC (U+001B), the 8-bit C1 CSI (U+009B), AND the C1 OSC introducer
// (U+009D) — the generator seeds cp(0x9d), so omitting it let an OSC-introducer
// passthrough slip by unchecked.
// eslint-disable-next-line no-control-regex -- asserting the raw introducers are absent is the point
const RAW_INTRODUCER_RE = /[\u001b\u009b\u009d]/;
const STRUCTURAL_TOKENS = [
  '<div style="display:none">',
  "</div>",
  "<span style='visibility:hidden'>",
  "</span>",
  '<a href="x">',
  "![](u?q=)",
  "[t](/p?c=)",
  "${x}",
  "!important",
  "<!-- c -->",
];

const adversarialChar = fc.oneof(
  unicodeChar,
  loneSurrogate,
  fc.constantFrom(...STRUCTURAL_TOKENS, ...INVISIBLE_VALUES),
);
const adversarialInput = fc
  .array(adversarialChar, { maxLength: 300 })
  .map((parts) => parts.join(""));

// Benign body: digits + safe punctuation only — no letters (no HTML keyword
// can form), no invisible/ANSI triggers. Every layer is a guaranteed no-op.
const benignChar = fc.constantFrom(..."0123456789 .,-_/:#%@".split(""));
const benignInput = fc
  .array(benignChar, { minLength: 1, maxLength: 300 })
  .map((parts) => parts.join(""));

const scaleTo = (unit, length) => {
  let out = unit;
  while (out.length < length) out += unit;
  return out.slice(0, length);
};

describe("fuzz: crash resistance and no silent suppression", () => {
  it("never throws on arbitrary bytes / lone surrogates (html path)", async () => {
    await fc.assert(
      fc.asyncProperty(adversarialInput, async (input) => {
        const result = await sanitize(input, { html: true });
        assert.equal(typeof result.cleaned, "string");
        // Postcondition: no raw control introducer (7-bit ESC / 8-bit C1 CSI)
        // survives Layer 1 — the under-stripping invariant the no-silent-
        // suppression check below is structurally blind to.
        assert.doesNotMatch(result.cleaned, RAW_INTRODUCER_RE);
        // Any change must be accompanied by a warning — content can never
        // vanish silently.
        if (result.cleaned !== input) assert.ok(result.warnings.length > 0);
      }),
      fcRunOptions({ numRuns: 150 }),
    );
  });

  it("passes benign non-empty input through unchanged (never silently empties it)", async () => {
    await fc.assert(
      fc.asyncProperty(benignInput, async (input) => {
        const result = await sanitize(input, { html: true });
        assert.equal(result.cleaned, input);
        assert.deepEqual(result.warnings, []);
        assert.ok(result.cleaned.length > 0);
      }),
      fcRunOptions({ numRuns: 100 }),
    );
  });

  it("processes a huge flat input without throwing AND still splices a hidden node buried in it", async () => {
    // A type/length-only assertion passes even if the huge input silently
    // defeated the HTML layer (e.g. a size bail-out), so bury a guaranteed-
    // hidden element deep inside and assert it was still spliced: its secret is
    // gone, a placeholder replaced it, and the change carried a warning.
    const filler = scaleTo("pre [t](/p?c=x) post _ok_ ", 50_000);
    const huge = `${filler}<div style="display:none">SECRETHUGE</div>${filler}`;
    const result = await sanitize(huge, { html: true });
    assert.equal(typeof result.cleaned, "string");
    assert.ok(result.cleaned.length > 0);
    assert.ok(!result.cleaned.includes("SECRETHUGE"));
    assert.ok(result.cleaned.includes(HIDDEN_PLACEHOLDER));
    assert.ok(result.warnings.length > 0);
  });
});
