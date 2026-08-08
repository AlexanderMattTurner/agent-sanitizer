/**
 * Semantic-correctness fuzzing for the prompt classifier.
 *
 * prompt-property.test.mjs fuzzes STRUCTURAL invariants (never throws, action
 * is always pass|note|block, block carries a reason). Those hold even if the
 * classifier escalates a perfectly ordinary developer prompt to note/block —
 * e.g. a prompt containing the plain-text SGR lookalike "[31m", caret-notation
 * "^[[31m", or joiner-dense Persian — or waves a real payload through.
 *
 * This suite fuzzes PRECISION directly: build random prompts that interleave
 * KNOWN-BENIGN constructs (real prose traps that merely LOOK escape-adjacent),
 * KNOWN-INERT constructs (display-only color in both the 7-bit and C1
 * encodings, and 7-bit introducers that complete no sequence), and
 * KNOWN-PAYLOAD constructs (complete non-SGR escapes, C1 string introducers,
 * long invisible runs), then assert the EXACT verdict the module's rules
 * demand for that specific mix:
 *
 *   any payload piece present            -> block
 *   otherwise any inert-ANSI piece present -> note
 *   otherwise (benign-only)              -> pass
 *
 * Pieces are joined with a visible space so invisible runs in adjacent pieces
 * can never merge into an accidental cross-piece long run.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import { classifyPrompt } from "../src/prompt.mjs";
import { LONG_RUN_THRESHOLD } from "../src/invisible.mjs";
import { fcRunOptions, cp } from "./test-helpers.mjs";

const ESC = cp(0x1b);
const BEL = cp(0x07);
const C1_CSI = cp(0x9b); // one-byte `ESC[`
const C1_OSC = cp(0x9d); // one-byte `ESC]`
const C1_DCS = cp(0x90); // device control string introducer
const C1_ST = cp(0x9c); // string terminator
const ZWNJ = cp(0x200c);
const ZWJ = cp(0x200d);

// Benign constructs that must NEVER move the verdict off "pass": prose with
// typographic punctuation, URLs, escape-LOOKALIKE plain text (no raw
// introducer byte anywhere), and joiner-dense content whose ZWNJ/ZWJ/VS16 do
// real rendering work (excluded from the payload-invisible count by the
// carve-out, so no amount of repetition crosses the scattered threshold).
const BENIGN_TOKENS = [
  "café résumé — naïve…",
  "https://example.com/path?q=1&r=2#frag",
  "[31m red [0m", // SGR params without any introducer byte
  "^[[1;32mPASSED^[[0m", // caret-notation paste of colored output
  "\\x1b[31m and \\u001b[0m", // source-code escape literals (backslash text)
  "10mm bolt; 5m cable; 0m", // digit+m words
  cp(0x645) + cp(0x6cc) + ZWNJ + cp(0x62e), // Persian linguistic ZWNJ
  cp(0x915) + cp(0x94d) + ZWJ + cp(0x937), // Devanagari eyelash conjunct
  cp(0x1f468) + ZWJ + cp(0x1f469) + ZWJ + cp(0x1f467) + ZWJ + cp(0x1f466),
  cp(0x2764) + cp(0xfe0f), // heart + emoji presentation selector
];

// INERT escape content: display-only SGR color in both documented encodings,
// plus 7-bit introducers that complete no sequence at all. Alone in a prompt
// each must yield exactly "note" (the pasted-terminal-output carve-out), never
// block — none of them can move the cursor, erase, or open a string.
const INERT_ANSI_TOKENS = [
  `${ESC}[31mred${ESC}[0m`,
  `${ESC}[m`,
  `${ESC}[1;4;38;5;196mloud${ESC}[0m`,
  `${C1_CSI}31mred${C1_CSI}0m`,
  ESC, // lone partial escape: a log line cut mid-sequence
];

// Genuine payload carriers per the module's rules: COMPLETE non-SGR escapes
// (7-bit and C1, including the string introducers Layer 1 strips to nothing),
// raw C1 orphans, and long-run invisible channels. Each one, anywhere in a
// prompt, must block.
const PAYLOAD_TOKENS = [
  `${ESC}[2J`,
  `${ESC}]0;owned${BEL}`,
  `${ESC}[31im`, // SGR-lookalike with a letter param: not SGR
  `${ESC}[12`, // truncated CSI: a stateful parser eats what follows
  `${C1_CSI}2J`,
  `${C1_OSC}0;owned${BEL}`,
  `${C1_DCS}qpayload${C1_ST}`,
  "hi" + cp(0xe0069).repeat(LONG_RUN_THRESHOLD + 2) + "bye", // tag-char run
  cp(0xfe01).repeat(LONG_RUN_THRESHOLD + 2), // variation-selector run
  cp(0x00ad).repeat(LONG_RUN_THRESHOLD + 2), // soft-hyphen run
];

const pieceGen = fc.oneof(
  fc.constantFrom(...BENIGN_TOKENS).map((t) => ({ kind: "benign", t })),
  fc.constantFrom(...INERT_ANSI_TOKENS).map((t) => ({ kind: "inert", t })),
  fc.constantFrom(...PAYLOAD_TOKENS).map((t) => ({ kind: "payload", t })),
  fc
    .array(fc.constantFrom(..."abc XYZ 0123 .,-_/".split("")), {
      minLength: 1,
      maxLength: 12,
    })
    .map((cs) => ({ kind: "benign", t: cs.join("") })),
);

const docGen = fc.array(pieceGen, { minLength: 1, maxLength: 8 });

/** The verdict the module's documented rules demand for this exact mix. */
function expectedAction(pieces) {
  if (pieces.some((p) => p.kind === "payload")) return "block";
  if (pieces.some((p) => p.kind === "inert")) return "note";
  return "pass";
}

describe("semantic-correctness fuzz: classifyPrompt precision on mixed prompts", () => {
  it("every generated mix gets the exact verdict its worst piece dictates", () => {
    fc.assert(
      fc.property(docGen, (pieces) => {
        const prompt = pieces.map((p) => p.t).join(" ");
        const verdict = classifyPrompt(prompt);
        assert.equal(
          verdict.action,
          expectedAction(pieces),
          `prompt=${JSON.stringify(prompt)}`,
        );
      }),
      fcRunOptions({ numRuns: 500 }),
    );
  });

  it("each benign token passes alone and never escalates a benign-only mix", () => {
    for (const t of BENIGN_TOKENS)
      assert.deepEqual(
        classifyPrompt(t),
        { action: "pass" },
        JSON.stringify(t),
      );
  });

  it("each payload token blocks even when drowned in benign and inert content", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...PAYLOAD_TOKENS),
        fc.constantFrom(...BENIGN_TOKENS),
        fc.constantFrom(...INERT_ANSI_TOKENS),
        (bad, benign, inert) => {
          const verdict = classifyPrompt(`${benign} ${inert} ${bad} ${benign}`);
          assert.equal(verdict.action, "block");
          assert.match(verdict.reason, /Resubmit the prompt/);
        },
      ),
      fcRunOptions({ numRuns: 500 }),
    );
  });
});
