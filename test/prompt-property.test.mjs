/**
 * Property/composition fuzzer for the pure user-prompt verdict
 * (src/prompt.mjs). The example suite (prompt.test.mjs) pins specific shapes;
 * these GENERALIZE the structural invariants over fuzzed input:
 *
 *   - classifyPrompt NEVER throws on arbitrary unicode / astral / lone-surrogate
 *     input; its action is always one of pass | note | block.
 *   - a block always carries a non-empty string reason; pass/note never do.
 *   - a prompt with no ANSI and invisibles below threshold always passes.
 *
 * Control bytes are built with String.fromCodePoint, never pasted raw.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import { classifyPrompt } from "../src/prompt.mjs";
import { stripAnsiFully } from "../src/layer1.mjs";
import { SCATTERED_THRESHOLD } from "../src/invisible.mjs";
import {
  fcRunOptions,
  cp,
  unicodeChar,
  loneSurrogate,
} from "./test-helpers.mjs";

const runOptions = fcRunOptions({ numRuns: 500 });
const check = (arbitrary, predicate) =>
  fc.assert(fc.property(arbitrary, predicate), runOptions);

const ACTIONS = new Set(["pass", "note", "block"]);

// Payload-capable invisibles across each CHECKS category (Cf zero-widths incl.
// the ZWNJ/ZWJ carve-out boundary, variation selectors, the blank fillers incl.
// the zero-width Mn combining mark and the braille blank, plus a Unicode TAG).
const invisibleChar = fc.constantFrom(
  ...[
    0x200b, 0x200c, 0x200d, 0x2060, 0xfeff, 0x00ad, 0xfe01, 0xfe0f, 0x3164,
    0x2800, 0x034f, 0xe0041,
  ].map((c) => cp(c)),
);
// Both ANSI introducers — 7-bit ESC and 8-bit C1 forms (CSI/OSC) — plus BEL,
// the OSC string terminator. A uniform draw reaches U+009B/U+009D ~1-in-a-million,
// so they MUST be seeded explicitly or the C1 passthrough class is never tested.
const ansiChar = fc.constantFrom(cp(0x1b), cp(0x9b), cp(0x9d), cp(0x07));
const astralChar = fc.constant(cp(0x1f600));
const adversarialChar = fc.oneof(
  unicodeChar,
  loneSurrogate,
  invisibleChar,
  ansiChar,
  astralChar,
);
const adversarialText = fc
  .array(adversarialChar, { maxLength: 80 })
  .map((parts) => parts.join(""));

// Printable ASCII only — no ESC, no invisible — so on its own this is a clean
// pass. (Below the scattered/long-run thresholds, no ANSI.)
const visible = fc
  .array(fc.integer({ min: 0x20, max: 0x7e }))
  .map((codes) => codes.map((code) => String.fromCharCode(code)).join(""));

describe("classifyPrompt (property): totality", () => {
  it("never throws on adversarial unicode; action is always pass | note | block; block carries a non-empty string reason", () => {
    check(
      fc.oneof(adversarialText, fc.string({ unit: "binary" })),
      (prompt) => {
        const verdict = classifyPrompt(prompt);
        assert.ok(ACTIONS.has(verdict.action), `bad action: ${verdict.action}`);
        if (verdict.action === "block") {
          assert.equal(typeof verdict.reason, "string");
          assert.ok(verdict.reason.length > 0, "empty block reason");
        } else {
          assert.equal(verdict.reason, undefined);
        }
      },
    );
  });

  it("empty prompt always passes", () => {
    assert.deepEqual(classifyPrompt(""), { action: "pass" });
  });
});

describe("classifyPrompt (property): clean text below threshold passes", () => {
  it("no ANSI and < SCATTERED_THRESHOLD scattered invisibles (no run) always passes", () => {
    const invBelow = fc.constantFrom(cp(0x200b), cp(0x00ad), cp(0x2060));
    check(
      fc.tuple(
        visible,
        invBelow,
        fc.integer({ min: 0, max: SCATTERED_THRESHOLD - 1 }),
        visible,
      ),
      ([head, inv, count, tail]) => {
        // One invisible between visible 'x' chars: no run reaches the long-run
        // threshold, and the total stays under the scattered threshold.
        const scattered = Array.from({ length: count }, () => `x${inv}`).join(
          "",
        );
        assert.deepEqual(classifyPrompt(head + scattered + tail), {
          action: "pass",
        });
      },
    );
  });
});

// The C1-bypass class: classifyPrompt must never be WEAKER than the sanitizer's
// own ANSI detection. If stripAnsiFully removes anything from `s` (i.e. `s`
// holds a real ANSI control sequence the Layer-1 strip would scrub from the
// model's view), the prompt verdict must surface it (note | block), never pass.
// Pinning the invariant against the sanitizer — not a hard-coded codepoint —
// catches ANY future ANSI-introducer blind spot (the 8-bit C1 CSI/OSC bug this
// branch fixes, and the next one) without naming the byte in advance.
describe("classifyPrompt (property): never weaker than the sanitizer's ANSI detection", () => {
  // Alphabet spanning every ANSI introducer plus the bytes a real sequence
  // needs to COMPLETE: ESC (U+001B), C1 CSI (U+009B), C1 OSC (U+009D), BEL
  // (U+0007, an OSC terminator), ST as ESC + '\\', and the param/final-byte
  // vocabulary. SGR final 'm', cursor final 'A', erase final 'J', and digits/
  // ';' let the generator emit SGR-only, non-SGR CSI, and OSC sequences as well
  // as plain text (the letters/digits that stand alone are ANSI-free input).
  const ESC = cp(0x1b);
  const ansiToken = fc.constantFrom(
    ESC,
    cp(0x9b), // C1 CSI
    cp(0x9d), // C1 OSC
    cp(0x07), // BEL (OSC terminator)
    `${ESC}\\`, // ST (ESC + backslash)
    "[", // CSI opener after a 7-bit ESC
    "]", // OSC opener after a 7-bit ESC
    "m", // SGR final byte
    "A", // cursor-move final byte
    "J", // erase final byte
    "2",
    "0",
    "1",
    ";",
    "a",
    "b",
    "Z",
    "x",
  );
  const ansiFuzzText = fc
    .array(ansiToken, { maxLength: 60 })
    .map((parts) => parts.join(""));

  it("stripAnsiFully(s) !== s implies classifyPrompt(s).action is not 'pass'", () => {
    check(ansiFuzzText, (s) => {
      if (stripAnsiFully(s) !== s) {
        assert.notStrictEqual(
          classifyPrompt(s).action,
          "pass",
          `sanitizer strips ANSI from ${JSON.stringify(s)} but classifyPrompt passed it`,
        );
      }
    });
  });

  // Non-vacuity: the precondition (sanitizer actually strips ANSI) must fire on
  // a meaningful fraction of generated samples, else the implication above holds
  // trivially. Sample the same generator and assert a real hit rate.
  it("precondition fires on a meaningful fraction of generated inputs (non-vacuity)", () => {
    const SAMPLES = 5000;
    const samples = fc.sample(ansiFuzzText, SAMPLES);
    const fires = samples.filter((s) => stripAnsiFully(s) !== s).length;
    const fraction = fires / SAMPLES;
    // Sanity floor far below the empirically observed rate; the point is that
    // the antecedent is exercised on many runs, not that it dominates.
    assert.ok(
      fraction > 0.1,
      `precondition fired on only ${fires}/${SAMPLES} (${(fraction * 100).toFixed(1)}%) — property risks vacuity`,
    );
  });
});
