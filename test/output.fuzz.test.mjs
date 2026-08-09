/**
 * Crash-resistance / idempotence fuzzing of sanitizeText over adversarial
 * unicode / ANSI / surrogate / astral input (Layer 1 only — no redact, no html,
 * no exfilScan). Two invariants:
 *
 *   - it never throws and always returns a string `cleaned`;
 *   - the Layer-1 strip is idempotent: re-sanitizing the cleaned text changes
 *     nothing (a second pass finds no further invisible/ANSI to remove).
 *
 * Inputs are built from code points (never literal control bytes; see
 * CLAUDE.md > Code Style).
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import { sanitizeText } from "../src/output.mjs";
import {
  fcRunOptions,
  cp,
  unicodeChar,
  loneSurrogate,
} from "./test-helpers.mjs";

const runOptions = fcRunOptions({ numRuns: 250 });
const ESC = cp(0x1b);

// ANSI fragments and one representative of every STRIP invisible class, built
// from code points so no literal control byte sits in this file.
const structuralToken = fc.constantFrom(
  ESC,
  `${ESC}[31m`,
  `${ESC}[0m`,
  `${ESC}]8;;http://x${cp(0x07)}`, // OSC-with-BEL
  cp(0x009b), // 8-bit C1 CSI introducer
  cp(0x009d), // 8-bit C1 OSC introducer
  cp(0x200b), // ZWSP
  cp(0x200c), // ZWNJ
  cp(0x200d), // ZWJ
  cp(0xfeff), // BOM
  cp(0x00ad), // soft hyphen
  cp(0xfe0f), // VS-16
  cp(0xe0101), // supplementary VS
  cp(0x034f), // zero-width combining mark (Mn blank filler)
  cp(0x3164), // Hangul filler
  cp(0x2800), // braille blank
  cp(0xe0041), // Unicode TAG (deniable-encoding channel)
  cp(0x1f600), // astral (parser totality)
);
const adversarialChar = fc.oneof(unicodeChar, loneSurrogate, structuralToken);
const adversarialInput = fc
  .array(adversarialChar, { maxLength: 300 })
  .map((parts) => parts.join(""));

describe("fuzz: sanitizeText is crash-resistant and idempotent", () => {
  it("never throws and returns a string on arbitrary adversarial input", async () => {
    await fc.assert(
      fc.asyncProperty(adversarialInput, async (input) => {
        const r = await sanitizeText(input);
        assert.equal(typeof r.cleaned, "string");
        assert.equal(typeof r.modified, "boolean");
        assert.ok(Array.isArray(r.warnings));
      }),
      runOptions,
    );
  });

  it("is idempotent AND actually strips a planted invisible/ANSI payload", async () => {
    // Idempotence alone is vacuously true for a no-op sanitizer, so every case
    // also plants a guaranteed-invisible payload (ZWSP + a red-SGR ANSI run)
    // around the fuzzed body and asserts the FIRST pass removed it (modified,
    // and neither byte survives) — the positive marker proving the strip path
    // ran — before asserting the SECOND pass is a fixed point.
    const ZWSP = cp(0x200b);
    const payload = `${ZWSP}${ESC}[31m`;
    await fc.assert(
      fc.asyncProperty(adversarialInput, async (input) => {
        const first = await sanitizeText(`${payload}${input}${payload}`);
        assert.equal(first.modified, true);
        assert.ok(!first.cleaned.includes(ZWSP));
        assert.ok(!first.cleaned.includes(ESC));

        const second = await sanitizeText(first.cleaned);
        assert.equal(second.cleaned, first.cleaned);
        assert.equal(second.modified, false);
      }),
      runOptions,
    );
  });
});
