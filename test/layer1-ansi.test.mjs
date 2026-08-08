/**
 * Layer 1's ANSI/fixed-point invariants: the three properties that were
 * assertable in principle but false in practice.
 *
 *   1. IDEMPOTENCE of the ANSI<->invisible COMPOSITION, not just of the ANSI
 *      pass. rehydrate.mjs's soundness gate re-cleans text and compares it to
 *      the view the model was shown, so a second `applyLayer1` returning
 *      something different is a correctness bug there, not a cosmetic one.
 *   2. CONTAINMENT: when `isSgrOnly` tells the operator "display-only colour"
 *      (and the strip touched nothing but ANSI), what Layer 1 actually removed
 *      must be exactly the SGR sequences — no visible residue spliced in.
 *   3. The introducer charset is ONE charset: whatever Layer 1 removes as a raw
 *      control introducer must read as non-SGR to `isSgrOnly`.
 *
 * The generators are BIASED toward the shapes that break these (cursive letter,
 * joiner, ANSI fragment) rather than drawing uniformly over 1.1M code points —
 * a uniform draw reaches an ESC essentially never, which is why the
 * pre-existing idempotence property in invisible.test.mjs stayed green over a
 * non-idempotent implementation.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import { applyLayer1, stripAnsiFully } from "../src/layer1.mjs";
// The tokenizer assertions below are about src/ansi.mjs, so name it directly
// rather than reaching it through a re-export layer1.mjs does not otherwise owe.
import { scanAnsi, TOKEN_KIND } from "../src/ansi.mjs";
import {
  isSgrOnly,
  SGR_RE,
  CATEGORY,
  stripInvisible,
} from "../src/invisible.mjs";
import { fcRunOptions, cp } from "./test-helpers.mjs";

const ESC = cp(0x1b);
const CSI = cp(0x9b);
const OSC = cp(0x9d);
const ST = cp(0x9c);
const BEL = cp(0x07);
const ZWJ = cp(0x200d);
const ZWNJ = cp(0x200c);
const ZWSP = cp(0x200b);
const ARABIC_MEEM = cp(0x645);

const hex = (s) => [...s].map((c) => c.codePointAt(0).toString(16)).join(" ");

// ─── Generators ──────────────────────────────────────────────────────────────

// Fragments of the ANSI grammar, drawn as PIECES rather than whole sequences so
// the generator builds torn, reassemblable escapes (`ESC` + invisible + `[0m`)
// as often as intact ones.
const ansiFragment = fc.constantFrom(
  ESC,
  CSI,
  OSC,
  ST,
  BEL,
  cp(0x90),
  cp(0x9f),
  "[",
  "]",
  "(",
  "?",
  ";",
  ":",
  "m",
  "0",
  "31",
  "12345",
  "J",
  "\\",
);

const invisibleChar = fc.constantFrom(ZWSP, ZWJ, ZWNJ, cp(0xfeff), cp(0xfe0f));
const visibleChar = fc.constantFrom("a", "x", " ", ARABIC_MEEM, cp(0x1f600));

// The shape that actually breaks idempotence: a cursive letter and a joiner (so
// the linguistic carve-out PRESERVES the joiner on the first pass) flanking an
// ANSI fragment, so removing the fragment can make two preserved joiners
// adjacent — a run the invisible pass then treats as a payload channel.
const reconstitutionUnit = fc
  .tuple(
    fc.constantFrom(ARABIC_MEEM, cp(0x628), cp(0x1f469)),
    fc.constantFrom(ZWJ, ZWNJ, ""),
    fc.constantFrom(ZWSP, ""),
    ansiFragment,
    fc.constantFrom(ZWJ, ZWNJ, ""),
    fc.constantFrom(ARABIC_MEEM, cp(0x62c), cp(0x1f466)),
  )
  .map((parts) => parts.join(""));

const reconstitutionText = fc
  .array(reconstitutionUnit, { minLength: 1, maxLength: 6 })
  .map((units) => units.join(""));

const ansiText = fc
  .array(fc.oneof(ansiFragment, invisibleChar, visibleChar), { maxLength: 40 })
  .map((parts) => parts.join(""));

// Text whose ONLY escape content is display-only colour, in both encodings and
// with both parameter separators — the domain the "SGR-only" carve-out is
// supposed to cover, including the long parameter runs the stripper's old
// four-digit cap could not match.
const sgrSequence = fc
  .tuple(fc.constantFrom(ESC + "[", CSI), fc.stringMatching(/^[0-9;:]*$/))
  .map(([intro, params]) => `${intro}${params}m`);

const sgrOnlyText = fc
  .array(fc.oneof(sgrSequence, visibleChar), { maxLength: 20 })
  .map((parts) => parts.join(""));

// The same, with invisible chars BETWEEN the sequences (never inside one, which
// would tear it into a non-SGR fragment): the carve-out's real input is pasted
// terminal output, which carries both.
const sgrWithInvisibleText = fc
  .array(fc.oneof(sgrSequence, visibleChar, invisibleChar), { maxLength: 20 })
  .map((parts) => parts.join(""));

// ─── scanAnsi: one token per raw introducer ──────────────────────────────────

describe("scanAnsi", () => {
  const kinds = (text) => scanAnsi(text).map((token) => token.kind);

  it("classifies each sequence form", () => {
    assert.deepEqual(kinds(`${ESC}[31mred${ESC}[0m`), ["sgr", "sgr"]);
    assert.deepEqual(kinds(`${CSI}31m`), ["sgr"]);
    assert.deepEqual(kinds(`${ESC}[2J`), ["csi"]);
    assert.deepEqual(kinds(`${ESC}(B`), ["csi"]);
    assert.deepEqual(kinds(`${ESC}]0;title${BEL}`), ["osc"]);
    assert.deepEqual(kinds(`${OSC}0;title${ST}`), ["osc"]);
    assert.deepEqual(kinds(`${ESC}]0;title${ESC}\\`), ["osc"]);
    assert.deepEqual(kinds(`${ESC}]unterminated`), ["osc"]);
    assert.deepEqual(kinds(`${OSC}nested${OSC}x`), ["osc", "osc"]);
    // Introducers that complete nothing, split three ways: a lone ESC (inert),
    // an ESC that OPENED a CSI it never finished (a terminal keeps eating the
    // following text as parameters), and the C1 string introducers the sequence
    // grammar never names. Only the first is quiet.
    assert.deepEqual(kinds(ESC), ["orphan-introducer"]);
    assert.deepEqual(kinds(`${ESC} x`), ["orphan-introducer"]);
    assert.deepEqual(kinds(`${ESC}[12`), ["orphan-csi-introducer"]);
    assert.deepEqual(kinds(`${ESC}[`), ["orphan-csi-introducer"]);
    assert.deepEqual(kinds(cp(0x90) + cp(0x9e)), [
      "orphan-c1-introducer",
      "orphan-c1-introducer",
    ]);
  });

  it("ends an OSC string before an interior ESC so the text after it survives", () => {
    // The abort arm: the interior ESC starts a NEW sequence rather than being
    // swallowed as OSC body — otherwise one ESC deletes the document tail.
    const input = `${ESC}]title${ESC}[0mafter`;
    const tokens = scanAnsi(input);
    assert.deepEqual(
      tokens.map((token) => token.kind),
      [TOKEN_KIND.OSC, TOKEN_KIND.SGR],
    );
    assert.equal(tokens[0].end, tokens[1].start);
    assert.equal(stripAnsiFully(input), "after");
  });

  it("reports disjoint, ordered, non-empty spans", () => {
    fc.assert(
      fc.property(ansiText, (text) => {
        let previousEnd = 0;
        for (const token of scanAnsi(text)) {
          assert.ok(
            token.start >= previousEnd,
            "tokens overlap or are unordered",
          );
          assert.ok(token.end > token.start, "token span is empty");
          assert.ok(token.end <= text.length, "token span runs past the input");
          previousEnd = token.end;
        }
      }),
      fcRunOptions(),
    );
  });
});

// ─── Defect 1: idempotence of the ANSI<->invisible composition ───────────────

describe("applyLayer1 idempotence", () => {
  it("re-cleans the reconstitution shape to itself (regression)", () => {
    // م ZWJ ESC ZWSP [ m ZWJ م — the invisible pass strips the ZWSP, which
    // reconstitutes `ESC[m`; removing THAT sequence makes the two ZWJs
    // adjacent. The old pipeline ran no invisible pass after its ANSI
    // re-strip, so the first call returned the joiner pair and only the second
    // stripped it: `645 200d 200d 645`, then `645 645`.
    const input = `${ARABIC_MEEM}${ZWJ}${ESC}${ZWSP}[m${ZWJ}${ARABIC_MEEM}`;
    const once = applyLayer1(input);
    const twice = applyLayer1(once.cleaned);

    assert.equal(hex(once.cleaned), "645 645");
    assert.deepEqual(once.found, [CATEGORY.CF, CATEGORY.ANSI]);
    assert.equal(twice.cleaned, once.cleaned);
    // Nothing left to remove, so the re-clean reports no finding at all — the
    // `found` disagreement between the two calls goes with the text one.
    assert.deepEqual(twice.found, []);
  });

  it("is idempotent over the reconstitution shape", () => {
    fc.assert(
      fc.property(reconstitutionText, (text) => {
        const once = applyLayer1(text).cleaned;
        assert.equal(applyLayer1(once).cleaned, once);
      }),
      fcRunOptions(),
    );
  });

  it("is idempotent over free-form ANSI + invisible interleavings", () => {
    fc.assert(
      fc.property(ansiText, (text) => {
        const once = applyLayer1(text).cleaned;
        assert.equal(applyLayer1(once).cleaned, once);
      }),
      fcRunOptions(),
    );
  });

  it("sweeps every raw introducer even when the pass bound is exhausted", () => {
    // `ESC[` xN + `m` xN reconstitutes exactly ONE sequence per pass, so it
    // outruns any fixed bound by construction — the no-introducer guarantee has
    // to come from the final unconditional sweep, not from the loop converging.
    const depth = 40;
    const { cleaned, found } = applyLayer1(
      `${ESC}[`.repeat(depth) + "m".repeat(depth),
    );
    for (const char of cleaned) {
      const code = char.codePointAt(0);
      assert.ok(
        code !== 0x1b && (code < 0x80 || code > 0x9f),
        `control introducer U+${code.toString(16)} survived the bound`,
      );
    }
    assert.deepEqual(found, [CATEGORY.ANSI]);
  });
});

// ─── Defect 2: the SGR predicate and the stripper share one grammar ──────────

describe("isSgrOnly containment", () => {
  // Each of these is a legitimate, display-only sequence the two grammars used
  // to disagree about: the stripper's four-digit parameter cap rejected them,
  // so it spliced the sequence's visible tail into the model's view while
  // isSgrOnly still reported the input as colour-only.
  const contained = [
    ["long parameter run", `hello${ESC}[12345mworld`, "helloworld"],
    ["leading colon sub-parameter", `hi${ESC}[:0mthere`, "hithere"],
    ["colon-form truecolor", `${ESC}[38:2:255:0:0mred${ESC}[0m`, "red"],
    ["C1 long parameter run", `a${CSI}12345mb`, "ab"],
  ];

  for (const [name, input, expected] of contained) {
    it(`${name}: what was removed is exactly the SGR match set`, () => {
      const { cleaned, found } = applyLayer1(input);
      assert.equal(isSgrOnly(input), true);
      assert.deepEqual(found, [CATEGORY.ANSI]);
      assert.equal(cleaned, input.replace(SGR_RE, ""));
      assert.equal(cleaned, expected);
    });
  }

  it("holds over generated SGR-only text", () => {
    fc.assert(
      fc.property(sgrOnlyText, (text) => {
        // Non-vacuity: this domain really is SGR-only, so the implication below
        // is exercised on every case rather than skipped.
        assert.equal(isSgrOnly(text), true);
        assert.equal(applyLayer1(text).cleaned, text.replace(SGR_RE, ""));
      }),
      fcRunOptions(),
    );
  });

  it("holds with invisible chars interleaved between the colour sequences", () => {
    // Stated against the ANSI strip alone, so the invisible pass's own removals
    // need not be excluded first: colour-only text loses exactly its colour to
    // the stripper, whatever else is in it.
    fc.assert(
      fc.property(sgrWithInvisibleText, (text) => {
        assert.equal(isSgrOnly(text), true);
        assert.equal(stripAnsiFully(text), text.replace(SGR_RE, ""));
      }),
      fcRunOptions(),
    );
  });

  it("still denies a non-SGR escape, in either encoding", () => {
    for (const text of [
      `${ESC}[2J`,
      `${CSI}2J`,
      `${ESC}]0;t${BEL}`,
      `${OSC}0;t${ST}`,
      `${ESC}[`,
      ESC,
      cp(0x90),
    ])
      assert.equal(isSgrOnly(text), false, `expected non-SGR: ${hex(text)}`);
  });
});

// ─── Defect 3: one control-introducer charset, three consumers ───────────────

describe("shared control-introducer charset", () => {
  // Behavioural, not a source grep: a refactor that widened or narrowed one
  // copy of the class would show up here as a code point Layer 1 deletes while
  // isSgrOnly still calls it colour-only — the exact shape of the
  // suppressed-warning bug.
  it("every code point Layer 1 strips as an introducer reads as non-SGR", () => {
    const stripped = [];
    for (let code = 0; code <= 0x2ff; code++) {
      const char = cp(code);
      // Only the raw-introducer class is in scope: an invisible char is removed
      // by a different pass and says nothing about the ANSI grammar.
      if (stripInvisible(char) !== char) continue;
      if (applyLayer1(`a${char}b`).cleaned === `a${char}b`) continue;
      stripped.push(code);
      assert.equal(
        isSgrOnly(char),
        false,
        `U+${code.toString(16)} is stripped by Layer 1 but reads as SGR-only`,
      );
    }
    // Non-vacuity: the sampled range must contain the WHOLE introducer class,
    // or the loop above proves nothing.
    assert.deepEqual(stripped, [
      0x1b,
      ...Array.from({ length: 0x20 }, (_, i) => 0x80 + i),
    ]);
  });
});
