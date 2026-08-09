/**
 * Property tests over the pure instruction-scanner logic. scanText and decodeRun
 * take untrusted file content / invisible-char runs, so pin the structural
 * invariants (never-throw, shape, clean->[]) across the real input domain with
 * fast-check rather than only example cases.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import { scanText, decodeRun } from "../src/instructions.mjs";
import {
  fcRunOptions,
  cp,
  unicodeChar,
  loneSurrogate,
} from "./test-helpers.mjs";

// Invisible classes + tag chars (decodeRun's tag branch) + ASCII + newlines.
const invisibleChar = fc.constantFrom(
  cp(0x200b),
  cp(0x200c),
  cp(0x200d),
  cp(0x00ad),
  cp(0xfeff),
  cp(0x2060),
  cp(0xfe0f),
  cp(0x3164),
  cp(0x2800),
  cp(0x034f),
  cp(0xe0001),
  cp(0xe0041),
  cp(0xe0048),
  cp(0xe007f),
  cp(0xe0080),
  "a",
  "Z",
  " ",
  "\n",
);
const adversarialChar = fc.oneof(unicodeChar, loneSurrogate, invisibleChar);
const adversarialText = fc
  .array(adversarialChar, { maxLength: 120 })
  .map((parts) => parts.join(""));

describe("property: scanText invariants", () => {
  it("never throws on arbitrary unicode / astral / lone-surrogate content", () => {
    fc.assert(
      fc.property(adversarialText, (text) => {
        const findings = scanText(text);
        assert.ok(Array.isArray(findings));
        for (const f of findings) {
          assert.ok(f.line === null || typeof f.line === "number");
          assert.equal(typeof f.charCount, "number");
          assert.equal(typeof f.method, "string");
          assert.equal(typeof f.decoded, "string");
        }
      }),
      fcRunOptions(),
    );
  });

  it("content with no invisibles yields [] findings", () => {
    // Visible-only domain: ASCII letters/digits/space/newline can never match
    // STRIP, so scanText must report nothing.
    const visibleText = fc
      .array(fc.constantFrom(..."abcXYZ0129 \n#/-.".split("")), {
        maxLength: 200,
      })
      .map((parts) => parts.join(""));
    fc.assert(
      fc.property(visibleText, (text) => {
        assert.deepEqual(scanText(text), []);
      }),
      fcRunOptions(),
    );
  });
});

describe("property: decodeRun invariants", () => {
  // A run is a string of invisible code points; build it from the invisible
  // domain so each decode branch (tag / zero-width / mixed) is reachable.
  const runOfInvisibles = fc
    .array(
      fc.constantFrom(
        cp(0x200b),
        cp(0x200c),
        cp(0x200d),
        cp(0x00ad),
        cp(0x2060),
        cp(0xfe0f),
        cp(0xe0001),
        cp(0xe0048),
        cp(0xe007f),
        cp(0xe0080),
      ),
      { minLength: 1, maxLength: 60 },
    )
    .map((parts) => parts.join(""));

  it("never throws and always returns {method, decoded} strings", () => {
    fc.assert(
      fc.property(runOfInvisibles, (run) => {
        const { method, decoded } = decodeRun(run);
        assert.equal(typeof method, "string");
        assert.equal(typeof decoded, "string");
        assert.ok(method.length > 0);
      }),
      fcRunOptions(),
    );
  });

  it("never throws on fully arbitrary input (incl. lone surrogates / astral)", () => {
    fc.assert(
      fc.property(adversarialText, (text) => {
        const { method, decoded } = decodeRun(text);
        assert.equal(typeof method, "string");
        assert.equal(typeof decoded, "string");
      }),
      fcRunOptions(),
    );
  });
});
