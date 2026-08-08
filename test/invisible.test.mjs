/**
 * Unit + property tests for the zero-dependency invisible-char core.
 * Driven from the SSOT lists (CHECKS, BLANK_NON_CF, VS, LINGUISTIC_SCRIPTS) so
 * a dropped/added enumerated member surfaces as a failing or non-compiling
 * test, not merely a coverage gap.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import {
  stripInvisible,
  stripInvisibleWithReport,
  isSgrOnly,
  STRIP,
  SGR_RE,
  CHECKS,
  CATEGORY,
  CATEGORY_LABELS,
  VS,
  BLANK_NON_CF,
  ZERO_WIDTH_MN,
  LONG_RUN_RE,
  LONG_RUN_THRESHOLD,
  SCATTERED_THRESHOLD,
  CONSECUTIVE_JOINER_CAP,
  CONSECUTIVE_SELECTOR_CAP,
  TOTAL_PRESERVED_JOINER_BUDGET,
  PRESERVED_JOINER_PER_VISIBLE,
  PRESERVE_HARD_CAP,
  LINGUISTIC_SCRIPTS,
  describeStripped,
  payloadInvisibleView,
} from "../src/invisible.mjs";
import { applyLayer1, stripAnsiFully } from "../src/layer1.mjs";
import { fcRunOptions, cp } from "./test-helpers.mjs";

const ZWNJ = cp(0x200c);
const ZWJ = cp(0x200d);
const CANCEL_TAG = cp(0xe007f);

/** A subregional-flag emoji tag sequence: WAVING BLACK FLAG + tag chars for the
 * ASCII `code` + CANCEL TAG. `tagCode("gbsct")` builds 🏴 Scotland. */
const tagCode = (code) =>
  cp(0x1f3f4) +
  [...code].map((c) => cp(0xe0000 + c.charCodeAt(0))).join("") +
  CANCEL_TAG;

/** Count occurrences of a single-char needle in a string (joiner counting). */
const countOf = (s, ch) => s.split(ch).length - 1;

// ─── stripInvisible: core classes ────────────────────────────────────────────

describe("stripInvisible: core classes", () => {
  for (const [name, input, expected] of [
    [
      "preserves single leading BOM, strips interior BOM + soft hyphen",
      `${cp(0xfeff)}a${cp(0xfeff)}b${cp(0x00ad)}c`,
      `${cp(0xfeff)}abc`,
    ],
    [
      "strips a leading soft hyphen entirely (no BOM branch)",
      `${cp(0x00ad)}abc`,
      "abc",
    ],
    [
      "strips a run of soft hyphens",
      `mal${cp(0x00ad).repeat(3)}ware`,
      "malware",
    ],
    ["returns empty string unchanged", "", ""],
    // Guards the VS set against a build that folds to a string of literal ASCII
    // (e.g. "undefined"): that would turn the char class into {u,n,d,e,f,i} and
    // start eating ordinary prose.
    [
      "leaves benign ASCII prose untouched",
      "defined unfixed key",
      "defined unfixed key",
    ],
  ]) {
    it(name, () => assert.equal(stripInvisible(input), expected));
  }

  // BLANK_NON_CF: one entry per member so dropping any member surfaces as a
  // failing test (100% line coverage fires the whole char class on a single
  // match — a dropped member is invisible to coverage alone).
  for (const ch of BLANK_NON_CF) {
    const hex = ch.codePointAt(0).toString(16).toUpperCase().padStart(4, "0");
    it(`strips blank-rendering filler U+${hex} (non-Cf)`, () => {
      const { cleaned, found } = stripInvisibleWithReport(`a${ch}b`);
      assert.equal(cleaned, "ab");
      assert.deepEqual(found, [CATEGORY.BLANK_FILLERS]);
    });
  }

  // Variation selectors are not category Cf, so the dedicated VS set — not
  // \p{Cf} — must catch them. Pin each sub-range's first, a mid entry, and last
  // so a truncated or off-by-one range survives in the output.
  for (const codePoint of [0xfe00, 0xfe0f, 0xe0100, 0xe0101, 0xe01ef]) {
    const hex = codePoint.toString(16).toUpperCase();
    it(`strips variation selector U+${hex}`, () => {
      const { cleaned, found } = stripInvisibleWithReport(`a${cp(codePoint)}b`);
      assert.equal(cleaned, "ab");
      assert.deepEqual(found, [CATEGORY.VARIATION_SELECTORS]);
    });
  }

  it("preserves a single leading BOM with nothing else to strip", () => {
    const input = `${cp(0xfeff)}clean leading bom`;
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, input);
    assert.deepEqual(found, []);
  });

  // One case per CHECKS category: the code reported must name exactly that
  // category, and every code must carry a human label. Drives from the SSOT so
  // a renamed/dropped category fails here.
  const categorySample = {
    [CATEGORY.CF]: cp(0x200b), // ZWSP
    [CATEGORY.VARIATION_SELECTORS]: cp(0xfe0f),
    [CATEGORY.BLANK_FILLERS]: cp(0x3164),
  };
  for (const [code] of CHECKS) {
    it(`reports the "${code}" category by its code`, () => {
      const sample = categorySample[code];
      assert.ok(sample, `no sample wired for CHECKS category "${code}"`);
      assert.ok(CATEGORY_LABELS[code], `no human label for category "${code}"`);
      const { cleaned, found } = stripInvisibleWithReport(`x${sample}y`);
      assert.equal(cleaned, "xy");
      assert.deepEqual(found, [code]);
    });
  }
});

// CATEGORY_LABELS is exported as the complete code→label map consumers use to
// render `found`. Library code only ever reads four of its entries, so without
// this guard a dropped or empty label for the other categories would ship
// silently. Drive off the CATEGORY SSOT and assert the key sets match exactly.
describe("CATEGORY_LABELS completeness", () => {
  const codes = Object.values(CATEGORY);
  for (const code of codes) {
    it(`maps "${code}" to a non-empty human label`, () => {
      assert.equal(typeof CATEGORY_LABELS[code], "string");
      assert.ok(CATEGORY_LABELS[code].length > 0);
    });
  }
  it("has no label without a matching CATEGORY code", () => {
    assert.deepEqual(Object.keys(CATEGORY_LABELS).sort(), [...codes].sort());
  });
});

// ─── ZWNJ/ZWJ linguistic carve-out ───────────────────────────────────────────
// "می‌خ" — ZWNJ between Arabic letters (Persian).
const PERSIAN = cp(0x645) + cp(0x6cc) + ZWNJ + cp(0x62e);
// "क्‍ष" — ZWJ between Devanagari virama and consonant.
const DEVANAGARI = cp(0x915) + cp(0x94d) + ZWJ + cp(0x937);
// 👨‍👩‍👧‍👦 — a four-person family emoji ZWJ sequence (no variation selectors).
const FAMILY =
  cp(0x1f468) + ZWJ + cp(0x1f469) + ZWJ + cp(0x1f467) + ZWJ + cp(0x1f466);

// Two representative letters per script for the carve-out preserve test.
const SCRIPT_LETTERS = {
  Arabic: [0x645, 0x62e],
  Devanagari: [0x915, 0x937],
  Bengali: [0x995, 0x99a],
  Gurmukhi: [0x0a15, 0x0a17],
  Gujarati: [0x0a95, 0x0a97],
  Oriya: [0x0b15, 0x0b17],
  Tamil: [0x0b95, 0x0b99],
  Telugu: [0x0c15, 0x0c17],
  Kannada: [0x0c95, 0x0c97],
  Malayalam: [0x0d15, 0x0d17],
  Sinhala: [0x0d9a, 0x0d9c],
};

// Brahmic viramas. A ZWNJ/ZWJ in an Indic script does real rendering work only
// immediately AFTER the virama (explicit halant / half-form), so a valid sample
// must include it. Arabic is cursive (letters join directly) and has no virama,
// so it is absent here — presence in this map is the "is Brahmic" signal.
const SCRIPT_VIRAMA = {
  Devanagari: 0x94d,
  Bengali: 0x9cd,
  Gurmukhi: 0xa4d,
  Gujarati: 0xacd,
  Oriya: 0xb4d,
  Tamil: 0xbcd,
  Telugu: 0xc4d,
  Kannada: 0xccd,
  Malayalam: 0xd4d,
  Sinhala: 0xdca,
};

// Build a linguistically valid `letter (joiner letter){n}` sample: cursive
// scripts join letter-to-letter; Brahmic scripts insert the virama before each
// joiner. Used to drive the per-script preserve cases from the SSOT.
function joinedChain(script, letters, joiner, n) {
  const virama = SCRIPT_VIRAMA[script];
  let s = cp(letters[0]);
  for (let k = 0; k < n; k++) {
    if (virama !== undefined) s += cp(virama);
    s += joiner + cp(letters[(k + 1) % letters.length]);
  }
  return s;
}

describe("stripInvisible: ZWNJ/ZWJ linguistic carve-out", () => {
  for (const [name, sample, joinerAt] of [
    ["Persian ZWNJ between Arabic letters", PERSIAN, 2],
    ["Devanagari ZWJ between letters", DEVANAGARI, 2],
    ["emoji ZWJ family sequence", FAMILY, 2],
  ]) {
    it(`preserves ${name} unchanged`, () => {
      const { cleaned, found } = stripInvisibleWithReport(sample);
      assert.equal(cleaned, sample);
      assert.deepEqual(found, []);
      const code = cleaned.codePointAt(joinerAt);
      assert.ok(
        code === 0x200c || code === 0x200d,
        `join control gone: U+${code.toString(16)}`,
      );
    });
  }

  // Drive one preserve-case per script in LINGUISTIC_SCRIPTS (both joiners):
  // line coverage hits the whole character class on a single match (Arabic),
  // leaving the others unverified, so iterate the SSOT — a script added without
  // a representative-letter mapping throws here.
  for (const script of LINGUISTIC_SCRIPTS) {
    const letters = SCRIPT_LETTERS[script];
    assert.ok(
      letters,
      `no representative letters wired for script "${script}"`,
    );
    for (const joiner of [ZWNJ, ZWJ]) {
      const label = joiner === ZWNJ ? "ZWNJ" : "ZWJ";
      const where =
        SCRIPT_VIRAMA[script] === undefined ? "letters" : "a virama";
      it(`preserves a ${label} after ${where} in ${script}`, () => {
        const sample = joinedChain(script, letters, joiner, 1);
        const { cleaned, found } = stripInvisibleWithReport(sample);
        assert.equal(cleaned, sample);
        assert.deepEqual(found, []);
      });
    }
  }

  it("preserves a carve-out joiner after a leading BOM", () => {
    const { cleaned, found } = stripInvisibleWithReport(cp(0xfeff) + PERSIAN);
    assert.equal(cleaned, cp(0xfeff) + PERSIAN);
    assert.deepEqual(found, []);
  });

  it("preserves a skin-tone + ZWJ + component emoji sequence", () => {
    // 👨🏻‍🦰 = man + skin-tone modifier + ZWJ + red-hair component: the ZWJ has a
    // modifier on its left and a pictograph component on its right.
    const redHair = cp(0x1f468) + cp(0x1f3fb) + ZWJ + cp(0x1f9b0);
    const { cleaned, found } = stripInvisibleWithReport(redHair);
    assert.equal(cleaned, redHair);
    assert.deepEqual(found, []);
  });

  // Emoji ZWJ sequences carry a VS16 (U+FE0F) presentation selector between the
  // base pictograph and the ZWJ (and often trailing). The joiner's immediate left
  // neighbor is then the selector, not the pictograph — the carve-out must look
  // past the selector, and keep the selector itself, or the whole emoji is split
  // into separate glyphs and falsely flagged. Regression for that bug.
  for (const [name, sample] of [
    ["rainbow flag", cp(0x1f3f3) + cp(0xfe0f) + ZWJ + cp(0x1f308)],
    [
      "eye in speech bubble (trailing VS16)",
      cp(0x1f441) + cp(0xfe0f) + ZWJ + cp(0x1f5e8) + cp(0xfe0f),
    ],
    ["heart on fire", cp(0x2764) + cp(0xfe0f) + ZWJ + cp(0x1f525)],
  ]) {
    it(`preserves the ${name} emoji ZWJ sequence unchanged`, () => {
      const { cleaned, found } = stripInvisibleWithReport(sample);
      assert.equal(cleaned, sample);
      assert.deepEqual(found, []);
    });
  }

  for (const [name, selector] of [
    ["VS16 (emoji presentation)", cp(0xfe0f)],
    ["VS15 (text presentation)", cp(0xfe0e)],
  ]) {
    it(`preserves a standalone pictograph + ${name} with no ZWJ/ZWNJ anywhere in the document`, () => {
      // Regression: stripInvisibleWithReport used to route on "does the WHOLE
      // document contain a ZWNJ/ZWJ" and fall back to a bulk strip (no
      // presentation-selector carve-out at all) when it didn't — so "I ❤️
      // pizza" / "I ❤︎ pizza", which have a selector but no joiner anywhere,
      // had that selector stripped. Also regression for a narrower follow-up
      // bug: the carve-out itself recognized only VS16, so VS15 was still
      // stripped even once routed through it.
      const sample = `I ${cp(0x2764)}${selector} pizza`;
      const { cleaned, found } = stripInvisibleWithReport(sample);
      assert.equal(cleaned, sample);
      assert.deepEqual(found, []);
    });

    it(`preserves an emoji-modifier base + ${name} (fuzz counterexample 🏻︎)`, () => {
      // Regression pin for an unseeded fast-check counterexample: the carve-out
      // preserves a presentation selector after ANY pictograph-class base,
      // including a standalone skin-tone modifier (U+1F3FB, \\p{Emoji_Modifier}
      // but also a visible swatch glyph) — the residual-allowlist property must
      // model that, not just ZWNJ/ZWJ.
      const sample = `${cp(0x1f3fb)}${selector}`;
      const { cleaned, found } = stripInvisibleWithReport(sample);
      assert.equal(cleaned, sample);
      assert.deepEqual(found, []);
    });
  }

  it("keeps one emoji selector but strips a stuffed VS16 run", () => {
    // A real emoji keeps ONE selector after the pictograph; a run of them is a
    // hidden channel. Every selector past the first has a selector on its left,
    // so it is stripped and reported — while the ZWJ join still survives.
    const input = cp(0x1f3f3) + cp(0xfe0f).repeat(4) + ZWJ + cp(0x1f308);
    const expected = cp(0x1f3f3) + cp(0xfe0f) + ZWJ + cp(0x1f308);
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, expected);
    assert.deepEqual(found, [CATEGORY.VARIATION_SELECTORS]);
  });

  // Keycap sequences (1️⃣ #️⃣ *️⃣ … 9️⃣) are `base + VS16 (U+FE0F) + U+20E3
  // COMBINING ENCLOSING KEYCAP`, where base is a digit, `#`, or `*` — none of
  // which is Extended_Pictographic or Emoji_Modifier. Regression: the
  // presentation-selector carve-out only recognized a pictograph/modifier
  // base, so the VS16 in every keycap failed the carve-out and was stripped
  // as a bare junk selector, corrupting the glyph (splitting "1️⃣" into a bare
  // "1" + a dangling combining keycap mark).
  for (const [name, base] of [
    ["digit 1", "1"],
    ["digit 0", "0"],
    ["digit 9", "9"],
    ["hash", "#"],
    ["asterisk", "*"],
  ]) {
    it(`preserves the VS16 in a keycap sequence (${name})`, () => {
      const input = `${base}${cp(0xfe0f)}${cp(0x20e3)}`;
      const { cleaned, found } = stripInvisibleWithReport(input);
      assert.equal(cleaned, input);
      assert.deepEqual(found, []);
    });
  }

  it("strips a keycap base + VS16 with NO trailing combining keycap (fail closed)", () => {
    // A keycap base + VS16 with nothing after it is NOT a complete keycap glyph;
    // it is a bare presentation selector spliced after ordinary text — the top
    // low-effort VS-smuggling shape. The carve-out fails CLOSED: preservation
    // requires the mandatory U+20E3 keycap terminator, so this VS16 is stripped.
    const input = `1${cp(0xfe0f)}`;
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, "1");
    assert.deepEqual(found, [CATEGORY.VARIATION_SELECTORS]);
  });

  it("strips a VS15 after a lone digit with no keycap (fail closed)", () => {
    // Same fail-closed rule for the text-presentation selector: `9` + VS15 with
    // no U+20E3 is a hidden selector, not a glyph.
    const input = `9${cp(0xfe0e)}`;
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, "9");
    assert.deepEqual(found, [CATEGORY.VARIATION_SELECTORS]);
  });

  it("does not widen the ZWJ emoji-sequence carve-out to keycap bases", () => {
    // The keycap fix is scoped to the presentation-selector check only. A
    // digit followed by ZWJ is never a legitimate emoji ZWJ sequence (the
    // ZWJ's left neighbour must be a pictograph/modifier), so it must still
    // be stripped as payload.
    const input = `1${ZWJ}a`;
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, "1a");
    assert.deepEqual(found, [CATEGORY.CF]);
  });

  // Payload contexts: each is still stripped AND reported in `found`.
  for (const [name, input, expected] of [
    ["ZWNJ between Latin", `a${ZWNJ}b`, "ab"],
    ["ZWJ between Latin (no emoji on the left)", `a${ZWJ}b`, "ab"],
    [
      "ZWNJ with an Arabic left but a Latin right",
      `${cp(0x645)}${ZWNJ}x`,
      `${cp(0x645)}x`,
    ],
    [
      "leading ZWNJ before an Arabic letter",
      `${ZWNJ}${cp(0x645)}${cp(0x6cc)}`,
      `${cp(0x645)}${cp(0x6cc)}`,
    ],
    [
      "trailing ZWNJ after an Arabic letter",
      `${cp(0x645)}${cp(0x6cc)}${ZWNJ}`,
      `${cp(0x645)}${cp(0x6cc)}`,
    ],
    [
      "ZWJ with an emoji left but a non-emoji right",
      `${cp(0x1f468)}${ZWJ}x`,
      `${cp(0x1f468)}x`,
    ],
    [
      "ZWNJ between two emoji (ZWNJ never joins emoji)",
      `${cp(0x1f468)}${ZWNJ}${cp(0x1f469)}`,
      `${cp(0x1f468)}${cp(0x1f469)}`,
    ],
    [
      "a long ZWJ run between Arabic letters",
      `${cp(0x645)}${ZWJ.repeat(12)}${cp(0x62e)}`,
      `${cp(0x645)}${cp(0x62e)}`,
    ],
  ]) {
    it(`strips ${name} and reports it`, () => {
      const { cleaned, found } = stripInvisibleWithReport(input);
      assert.equal(cleaned, expected);
      assert.deepEqual(found, [CATEGORY.CF]);
    });
  }

  // The scatter floor (SCATTERED_THRESHOLD = 30) is a boundary on PAYLOAD
  // invisibles — the hidden bytes left after the join-type gate exempts joiners
  // that do real rendering work. 29 payload keep the carve-out enabled, 30
  // disable it wholesale (even a meaningful joiner is then stripped). Both sides
  // are pinned so a `<`→`<=`/`>` mutant can't survive. A gate-passing Persian
  // ZWNJ is NOT payload, so we pad the floor with a non-joiner invisible class
  // (interior BOMs): the ZWNJ survives at 29 payload, is stripped at 30.
  const interiorBom = cp(0xfeff); // Cf, strippable, always payload (never a joiner)

  it(`keeps a legit joiner just under the payload floor (${SCATTERED_THRESHOLD - 1} payload)`, () => {
    const word = cp(0x645) + ZWNJ + cp(0x62e);
    // word (1 gate-passing joiner, exempt) + a real char + (floor-1) BOMs: the
    // BOMs are the only payload counted, one short of the floor.
    const input = word + "x" + interiorBom.repeat(SCATTERED_THRESHOLD - 1);
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, word + "x"); // joiner preserved, interior BOMs gone
    assert.deepEqual(found, [CATEGORY.CF]); // the BOM padding is reported
    assert.equal(countOf(cleaned, ZWNJ), 1);
  });

  it("strips the joiner too once payload invisibles reach the floor", () => {
    const word = cp(0x645) + ZWNJ + cp(0x62e);
    // floor BOMs = floor payload → carve-out off wholesale, the joiner stripped
    // even though it is meaningful (threshold-evasion catch).
    const input = word + "x" + interiorBom.repeat(SCATTERED_THRESHOLD);
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, cp(0x645) + cp(0x62e) + "x");
    assert.deepEqual(found, [CATEGORY.CF]);
    assert.equal(countOf(cleaned, ZWNJ), 0);
  });

  it("exempts a gate-passing joiner from the floor but counts payload classes", () => {
    // 29 variation selectors (payload) + a meaningful Arabic ZWNJ (exempt): only
    // 29 payload, under the floor, so the ZWNJ survives while every VS is
    // stripped. This is the precision win over counting TOTAL invisibles.
    const input =
      cp(0xfe0f).repeat(SCATTERED_THRESHOLD - 1) + cp(0x645) + ZWNJ + cp(0x62e);
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, cp(0x645) + ZWNJ + cp(0x62e));
    assert.deepEqual(found, [CATEGORY.VARIATION_SELECTORS]);
  });

  it("non-joiner payload still trips the floor and then strips the joiner", () => {
    // 30 variation selectors (payload) reach the floor: carve-out off, so even
    // the meaningful ZWNJ is stripped and both classes are reported.
    const input =
      cp(0xfe0f).repeat(SCATTERED_THRESHOLD) + cp(0x645) + ZWNJ + cp(0x62e);
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, cp(0x645) + cp(0x62e));
    assert.deepEqual(found, [CATEGORY.CF, CATEGORY.VARIATION_SELECTORS]);
  });

  it("keeps a legit joiner while stripping every other invisible class", () => {
    // Carve path (a joiner is present) must still strip the non-joiner classes —
    // a stray ZWSP (Cf), a variation selector, and a Hangul blank filler — and
    // report each category, while the Persian ZWNJ survives.
    const input =
      PERSIAN +
      cp(0x200b) + // ZWSP (Cf)
      `a${cp(0xfe0f)}b` + // VS-16
      `c${cp(0x3164)}d`; // Hangul filler
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, PERSIAN + "abcd");
    assert.deepEqual(found, [
      CATEGORY.CF,
      CATEGORY.VARIATION_SELECTORS,
      CATEGORY.BLANK_FILLERS,
    ]);
  });
});

// ─── Joining_Type gate: real prose kept, rendering-inert joiners stripped ─────
// The carve-out preserves a joiner only where it does real cursive-rendering
// work (decided from Unicode Joining_Type), not merely because both neighbours
// are letters of a linguistic script. This both KEEPS dense real prose and
// STRIPS a joiner that changes nothing on screen — the covert-channel case the
// old "two script letters" check waved through.
describe("stripInvisible: Joining_Type-driven precision", () => {
  it("preserves a multi-word Persian sentence with several ZWNJ, un-flagged", () => {
    // "نمی‌دانم کتاب‌ها را می‌خوانم" — the ZWNJ is spliced in explicitly (not
    // hidden in the literal) so its position is reviewable. Each sits at a
    // genuine cursive-join boundary (yeh|dal, beh|heh, yeh|khah): real formal
    // prose, preserved byte-identical.
    const sentence =
      "نمی" +
      ZWNJ +
      "دانم" +
      " " +
      "کتاب" +
      ZWNJ +
      "ها" +
      " " +
      "را" +
      " " +
      "می" +
      ZWNJ +
      "خوانم";
    const { cleaned, found } = stripInvisibleWithReport(sentence);
    assert.equal(cleaned, sentence);
    assert.deepEqual(found, []);
    assert.equal(countOf(cleaned, ZWNJ), 3);
  });

  it("preserves a ZWNJ separated from its letters by a transparent harakat", () => {
    // beh + fatha (U+064E, Transparent) + ZWNJ + heh: the combining mark does not
    // break the join, so the effective neighbours are still two joining letters.
    const input = cp(0x628) + cp(0x64e) + ZWNJ + cp(0x647);
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, input);
    assert.deepEqual(found, []);
  });

  // Conservative gate: a ZWNJ between two CURSIVE letters is preserved, even
  // where the pair happens to be rendering-inert (reh is right-joining, so it
  // arguably never connects forward). Deciding inertness needs the full
  // directional join algorithm; getting it subtly wrong would strip real content,
  // so the gate preserves any joiner flanked by cursive letters and leans on the
  // caps for the covert channel — "prefer the false negative, let it pass."
  it("preserves a ZWNJ between two cursive Arabic letters (reh · ZWNJ · beh)", () => {
    const input = cp(0x631) + ZWNJ + cp(0x628); // reh (R) · ZWNJ · beh (D)
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, input);
    assert.deepEqual(found, []);
  });

  // A ZWNJ next to a NON-joining letter still does no work and is stripped: the
  // gate needs a cursive letter on both sides, and hamza is Joining_Type U.
  it("strips a ZWNJ adjacent to a non-joining letter (beh · ZWNJ · hamza)", () => {
    const input = cp(0x628) + ZWNJ + cp(0x621); // beh (D) · ZWNJ · hamza (U)
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, cp(0x628) + cp(0x621));
    assert.deepEqual(found, [CATEGORY.CF]);
  });

  // A joiner whose effective neighbour is ANOTHER joiner is a run — a zero-width
  // payload channel, not a single rendering join — so BOTH are stripped even
  // between two real cursive letters. Adjacent (not alternating) joiners, so the
  // run-rejection (`isJoinControl(left) || isJoinControl(right)`) fires on each.
  it("strips a run of adjacent ZWNJ between two cursive letters", () => {
    const input = cp(0x628) + ZWNJ + ZWNJ + cp(0x628); // beh · ZWNJ ZWNJ · beh
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, cp(0x628) + cp(0x628));
    assert.deepEqual(found, [CATEGORY.CF]);
  });
});

// ─── isSgrOnly / SGR_RE ──────────────────────────────────────────────────────

describe("isSgrOnly", () => {
  it("is true when every ESC belongs to an SGR color sequence", () => {
    assert.equal(isSgrOnly(`${cp(0x1b)}[32mhello${cp(0x1b)}[0m`), true);
  });
  it("is true for text with no ESC at all", () =>
    assert.equal(isSgrOnly("plain text"), true));
  it("is false when a non-SGR escape (cursor move) is present", () =>
    assert.equal(isSgrOnly(`${cp(0x1b)}[2J`), false));
  it("is false for a lone/partial escape", () =>
    assert.equal(isSgrOnly(`${cp(0x1b)}[`), false));
  it("SGR_RE matches a color sequence", () =>
    assert.equal(`${cp(0x1b)}[31mx`.replace(SGR_RE, ""), "x"));

  // C1 (8-bit) encodings: a single U+009B (CSI) stands in for `ESC [`. isSgrOnly
  // must judge these exactly as their 7-bit twins, never letting a C1 introducer
  // pass unseen (the bug: an ESC-only test was blind to U+009B).
  it("is true for a C1-introduced SGR color sequence", () =>
    assert.equal(isSgrOnly(`${cp(0x9b)}31mhi${cp(0x9b)}0m`), true));
  it("is false for a C1-introduced cursor move", () =>
    assert.equal(isSgrOnly(`${cp(0x9b)}2J`), false));
  it("is false for a lone C1 CSI introducer", () =>
    assert.equal(isSgrOnly(cp(0x9b)), false));
  it("SGR_RE matches a C1-introduced color sequence", () =>
    assert.equal(`${cp(0x9b)}31mx`.replace(SGR_RE, ""), "x"));

  // C1 OSC (U+009D) is an Operating System Command string, not SGR. A residual
  // C1-OSC introducer must read as NOT SGR-only (the S1 residual: the test only
  // knew U+009B, so a string whose sole introducer was U+009D slipped through as
  // "SGR-only"). The paired SGR case stays true to prove the widening did not
  // over-reject genuine color.
  it("is false for a C1-OSC (U+009D) string", () =>
    assert.equal(isSgrOnly(`${cp(0x9d)}0;title${cp(0x07)}`), false));
  it("stays true for a genuine 7-bit SGR color string", () =>
    assert.equal(isSgrOnly(`${cp(0x1b)}[31mred${cp(0x1b)}[0m`), true));

  // The other C1 string introducers (DCS/SOS/PM/APC) and C1 ST are NOT SGR, so
  // a residual one must read as NOT SGR-only — exactly as U+009B/U+009D do. One
  // case per member so narrowing the introducer range (away from the full C1
  // block) can't pass: each member would then slip through as "SGR-only".
  for (const c1 of [0x90, 0x98, 0x9c, 0x9e, 0x9f]) {
    it(`is false for a residual C1 introducer U+${c1.toString(16).toUpperCase()}`, () =>
      assert.equal(isSgrOnly(`${cp(c1)}payload`), false));
  }

  // ITU T.416 colon-separated SGR sub-parameters (tmux/kitty/mintty truecolor,
  // e.g. `ESC[38:2:255:0:0m`) are pure display-only SGR — legitimate, benign
  // content. Regression: SGR_RE's parameter class only allowed `;`, so a
  // colon-form sequence was misread as non-SGR (isSgrOnly false) and, before
  // the CSI_BRANCH digit fix, left junk residue behind after stripping.
  it("is true for a 7-bit colon-form truecolor SGR sequence", () =>
    assert.equal(
      isSgrOnly(`${cp(0x1b)}[38:2:255:0:0mred${cp(0x1b)}[0m`),
      true,
    ));
  it("is true for a C1-introduced colon-form truecolor SGR sequence", () =>
    assert.equal(isSgrOnly(`${cp(0x9b)}38:2:255:0:0mred${cp(0x9b)}0m`), true));
  it("SGR_RE strips a colon-form truecolor sequence, leaving only the text", () =>
    assert.equal(
      `${cp(0x1b)}[38:2:255:0:0mred${cp(0x1b)}[0m`.replace(SGR_RE, ""),
      "red",
    ));
});

// ─── LONG_RUN_RE ─────────────────────────────────────────────────────────────

describe("LONG_RUN_RE", () => {
  it(`matches a run of exactly LONG_RUN_THRESHOLD (${LONG_RUN_THRESHOLD}) invisibles`, () => {
    LONG_RUN_RE.lastIndex = 0;
    assert.equal(LONG_RUN_RE.test(cp(0x200b).repeat(LONG_RUN_THRESHOLD)), true);
  });
  it("does not match a run one short of the threshold", () => {
    LONG_RUN_RE.lastIndex = 0;
    assert.equal(
      LONG_RUN_RE.test(cp(0x200b).repeat(LONG_RUN_THRESHOLD - 1)),
      false,
    );
  });
});

// ─── Zero-width combining marks (Mn) ─────────────────────────────────────────
// These render with no advance width yet are category Mn, so \p{Cf} misses them
// and only the enumerated ZERO_WIDTH_MN set catches them. One case per member
// (drive off the SSOT so a dropped entry fails here), plus a guard that a
// VISIBLE combining mark is never swept.
describe("zero-width Mn marks", () => {
  for (const ch of ZERO_WIDTH_MN) {
    const hex = ch.codePointAt(0).toString(16).toUpperCase().padStart(4, "0");
    it(`strips zero-width Mn mark U+${hex}`, () => {
      const { cleaned, found } = stripInvisibleWithReport(`a${ch}b`);
      assert.equal(cleaned, "ab");
      assert.deepEqual(found, [CATEGORY.BLANK_FILLERS]);
    });
  }

  it("every ZERO_WIDTH_MN member is part of BLANK_NON_CF", () => {
    for (const ch of ZERO_WIDTH_MN) assert.ok(BLANK_NON_CF.includes(ch));
  });

  // U+0301 COMBINING ACUTE ACCENT has visible width — it must be left intact;
  // only zero-advance Mn marks are payload-capable.
  it("preserves a visible combining mark (U+0301)", () => {
    const input = `e${cp(0x0301)}`;
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, input);
    assert.deepEqual(found, []);
  });
});

// ─── Consecutive-joiner cap (hidden-channel collapse) ────────────────────────
// An attacker alternates `letter joiner letter joiner …` so every joiner is, in
// isolation, in a "linguistic" context AND the total stays under the scatter
// floor — a multi-bit zero-width channel that survived both clean and scan. The
// cap collapses it: at most CONSECUTIVE_JOINER_CAP joiners survive in one
// uninterrupted joined run, the surplus stripped as payload.
describe("consecutive-joiner cap", () => {
  const AR1 = cp(0x645);
  const AR2 = cp(0x62e);

  it(`caps preserved ZWNJ in an alternating Arabic run at ${CONSECUTIVE_JOINER_CAP}`, () => {
    const input = (AR1 + ZWNJ).repeat(CONSECUTIVE_JOINER_CAP + 12) + AR2;
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(countOf(cleaned, ZWNJ), CONSECUTIVE_JOINER_CAP);
    assert.deepEqual(found, [CATEGORY.CF]);
  });

  it(`strips EVERY ZWJ of an over-cap emoji run (one cluster, atomic)`, () => {
    // An emoji ZWJ run is a SINGLE grapheme cluster, and the preserve budget is
    // charged per cluster: over the cap, the whole cluster's joiners go, rather
    // than the first CONSECUTIVE_JOINER_CAP surviving and carving one grapheme
    // in half. The visible pictographs are untouched either way.
    const input =
      cp(0x1f468) + (ZWJ + cp(0x1f469)).repeat(CONSECUTIVE_JOINER_CAP + 12);
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(countOf(cleaned, ZWJ), 0);
    assert.equal(
      cleaned,
      cp(0x1f468) + cp(0x1f469).repeat(CONSECUTIVE_JOINER_CAP + 12),
    );
    assert.deepEqual(found, [CATEGORY.CF]);
  });

  it("preserves exactly CONSECUTIVE_JOINER_CAP joiners (boundary, none stripped)", () => {
    const input = (AR1 + ZWNJ).repeat(CONSECUTIVE_JOINER_CAP) + AR2;
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, input);
    assert.deepEqual(found, []);
  });

  it("a single linguistic joiner per word is preserved (cap resets at a gap)", () => {
    const word = AR1 + ZWNJ + AR2;
    const input = `${word} ${word} ${word}`;
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, input);
    assert.deepEqual(found, []);
  });

  it("the four-person family emoji (3 ZWJ) is under the cap and preserved", () => {
    const { cleaned, found } = stripInvisibleWithReport(FAMILY);
    assert.equal(cleaned, FAMILY);
    assert.deepEqual(found, []);
    assert.equal(countOf(cleaned, ZWJ), 3);
  });
});

// ─── Document-wide preserved-joiner budget (covert-channel collapse) ──────────
// The consecutive cap resets at every genuine gap, so an attacker who puts each
// joiner in its OWN cluster — `letter joiner letter letter` repeated, double
// letters forming the gap that resets joinerRun — preserves one joiner per
// cluster, threading an arbitrary number through while each sits in a per-char
// "linguistic" context AND the total stays under the scatter floor. That was a
// silent multi-bit zero-width channel: every joiner preserved, `found` empty.
// TOTAL_PRESERVED_JOINER_BUDGET caps the document-wide preserved count (never
// reset at a gap): the surplus is stripped AND reported.
describe("document-wide preserved-joiner budget", () => {
  const AR1 = cp(0x645);
  const AR2 = cp(0x62e);

  // One joiner per cluster, clusters separated by a double-letter gap so the
  // consecutive cap (per-cluster) never trips — only the document-wide budget
  // can catch this. N joiners chosen above the budget but below the scatter
  // floor (so the floor is NOT what trips), proving the budget is the gate.
  const N = TOTAL_PRESERVED_JOINER_BUDGET + 9; // 25 — the PoC payload size
  assert.ok(
    N < SCATTERED_THRESHOLD,
    "covert-channel case must stay under the scatter floor",
  );
  // cluster = `letter joiner letter` then a second letter as the gap opener.
  const cluster = AR1 + ZWNJ + AR2 + AR2;
  const covert = cluster.repeat(N);

  it("caps preserved joiners at the budget across separated clusters", () => {
    const { cleaned, found } = stripInvisibleWithReport(covert);
    assert.equal(countOf(covert, ZWNJ), N); // input really has N joiners
    assert.equal(
      countOf(cleaned, ZWNJ),
      TOTAL_PRESERVED_JOINER_BUDGET,
      "preserved joiner count must not exceed the budget",
    );
    assert.deepEqual(found, [CATEGORY.CF]); // the surplus strip is reported
  });

  it("alternating ZWNJ/ZWJ between Arabic letters is capped and flagged", () => {
    // Closest to the literal PoC: N alternating joiners, each between two Arabic
    // letters, clusters gap-separated. Mix the two joiner code points to prove
    // the budget counts both.
    let s = "";
    for (let k = 0; k < N; k++) {
      const j = k % 2 === 0 ? ZWNJ : ZWJ;
      s += AR1 + j + AR2 + AR2;
    }
    const { cleaned, found } = stripInvisibleWithReport(s);
    const preserved = countOf(cleaned, ZWNJ) + countOf(cleaned, ZWJ);
    assert.equal(preserved, TOTAL_PRESERVED_JOINER_BUDGET);
    assert.deepEqual(found, [CATEGORY.CF]);
  });

  it("standalone presentation selectors (no joiner in the document) share the same budget", () => {
    // The budget counts every preserved item — joiners AND presentation
    // selectors — across the whole document, not per-kind. N gap-separated
    // pictograph+VS16 pairs with NO ZWNJ/ZWJ anywhere still hit the same cap:
    // over-strip beats under-strip even for a purely selector-dense document.
    const pictographPlusSelector = cp(0x2764) + cp(0xfe0f) + " ";
    const input = pictographPlusSelector.repeat(N);
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(countOf(input, cp(0xfe0f)), N);
    assert.equal(
      countOf(cleaned, cp(0xfe0f)),
      TOTAL_PRESERVED_JOINER_BUDGET,
      "preserved selector count must not exceed the shared budget",
    );
    assert.deepEqual(found, [CATEGORY.VARIATION_SELECTORS]);
  });

  it("preserves exactly the budget at the boundary (none stripped, not flagged)", () => {
    // Exactly TOTAL_PRESERVED_JOINER_BUDGET joiners, one per gap-separated
    // cluster: all preserved, nothing reported. Pins the `<` boundary so a
    // `<`→`<=` mutant (off-by-one over-strip) dies here.
    const input = cluster.repeat(TOTAL_PRESERVED_JOINER_BUDGET);
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, input);
    assert.deepEqual(found, []);
    assert.equal(countOf(cleaned, ZWNJ), TOTAL_PRESERVED_JOINER_BUDGET);
  });

  it("the budget sits below the scatter floor so it is the operative gate", () => {
    assert.ok(TOTAL_PRESERVED_JOINER_BUDGET < SCATTERED_THRESHOLD);
  });

  it("raises the allowance proportionally in long text (above the floor)", () => {
    // The budget is not a flat constant: it scales at 1 preserved joiner per
    // PRESERVED_JOINER_PER_VISIBLE visible chars, never below the floor. Give
    // each gap-separated joiner MORE than that much visible padding, and more
    // than TOTAL_PRESERVED_JOINER_BUDGET of them survive — this is what keeps
    // genuinely long formal Persian/Indic prose from being clipped at 16.
    const joiners = TOTAL_PRESERVED_JOINER_BUDGET + 4;
    const pad = " word".repeat(PRESERVED_JOINER_PER_VISIBLE); // ample visible text
    const input = (AR1 + ZWNJ + AR2 + pad).repeat(joiners);
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.ok(joiners > TOTAL_PRESERVED_JOINER_BUDGET);
    assert.equal(countOf(cleaned, ZWNJ), joiners); // all preserved, none clipped
    assert.deepEqual(found, []);
  });
});

// ─── The preserve budget is charged per GRAPHEME CLUSTER, never per code point ─
// A budget accounted per code point can fall due part-way through one cluster
// and carve a single grapheme in half: with the document budget exhausted after
// the 6th family emoji's first ZWJ, 👨‍👩‍👧‍👦 came out as 👨‍👩👧👦 — three glyphs where
// the author wrote one, and a "budget" whose own invariant did not hold for the
// thing it protects. Charging the whole cluster at once makes that impossible by
// construction.
describe("preserve budget: grapheme clusters are indivisible", () => {
  const FAMILY_CLUSTER =
    cp(0x1f468) + ZWJ + cp(0x1f469) + ZWJ + cp(0x1f467) + ZWJ + cp(0x1f466);
  const FAMILY_BARE = cp(0x1f468) + cp(0x1f469) + cp(0x1f467) + cp(0x1f466);
  // 3 ZWJ per family against the 16-unit document budget: 5 families fit (15),
  // the 6th needs 3 more and does not.
  const FAMILIES_THAT_FIT = 5;

  const clustersOf = (text) =>
    Array.from(
      new Intl.Segmenter("en", { granularity: "grapheme" }).segment(text),
      (s) => s.segment,
    );

  /**
   * Assert no grapheme cluster of `input` survives half-carved: each must appear
   * in the output either byte-identical or with EVERY tracked invisible removed.
   * Only valid for inputs whose invisibles are all carve-PRESERVABLE (a payload
   * invisible is unconditionally stripped, which is a legitimate third outcome).
   */
  const assertNoPartialCarve = (input) => {
    let rest = stripInvisible(input);
    for (const cluster of clustersOf(input)) {
      const bare = cluster.replace(STRIP, "");
      if (rest.startsWith(cluster)) rest = rest.slice(cluster.length);
      else if (rest.startsWith(bare)) rest = rest.slice(bare.length);
      else
        assert.fail(
          `cluster ${JSON.stringify(cluster)} was partially carved; output continues ${JSON.stringify(rest.slice(0, 16))}`,
        );
    }
    assert.equal(
      rest,
      "",
      "output has trailing text no input cluster explains",
    );
  };

  for (const n of [FAMILIES_THAT_FIT, FAMILIES_THAT_FIT + 1, 8, 12]) {
    it(`carves ${n} family emoji all-or-nothing per cluster`, () => {
      const input = FAMILY_CLUSTER.repeat(n);
      const kept = Math.min(n, FAMILIES_THAT_FIT);
      assert.equal(
        stripInvisible(input),
        FAMILY_CLUSTER.repeat(kept) + FAMILY_BARE.repeat(n - kept),
      );
      assertNoPartialCarve(input);
    });
  }

  it("reports the strip once the budget cuts a whole cluster", () => {
    const { found } = stripInvisibleWithReport(
      FAMILY_CLUSTER.repeat(FAMILIES_THAT_FIT + 1),
    );
    assert.deepEqual(found, [CATEGORY.CF]);
  });

  it("is idempotent across the budget cut (no malformed remnant to re-strip)", () => {
    const once = stripInvisible(FAMILY_CLUSTER.repeat(FAMILIES_THAT_FIT + 1));
    assert.equal(stripInvisible(once), once);
  });

  it("keeps multi-preservable clusters whole under the CONSECUTIVE caps too", () => {
    // 🏳️‍🌈 is VS16 + ZWJ inside ONE cluster: two preservables that must rise and
    // fall together no matter which limit bites.
    const rainbow = cp(0x1f3f3) + cp(0xfe0f) + ZWJ + cp(0x1f308);
    for (const n of [1, 6, 9, 20]) assertNoPartialCarve(rainbow.repeat(n));
  });

  it("judges each cluster on the run its own leading gap resets", () => {
    // Two adjacent 6-pictograph ZWJ sequences, 5 joiners each. The second
    // cluster opens with a pictograph directly after the first cluster's — a
    // genuine gap, which resets the consecutive-joiner run. Judging cluster 2
    // on the STALE count (5 + 5 > 8) would strip all five of its joiners even
    // though 10 preserved chars sit well inside the document budget (16): a
    // false positive on legitimate joined text.
    const cluster = cp(0x1f468) + (ZWJ + cp(0x1f469)).repeat(5);
    const input = cluster + cluster;
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, input);
    assert.deepEqual(found, []);
    assert.equal(countOf(cleaned, ZWJ), 10);
    assert.ok(10 <= TOTAL_PRESERVED_JOINER_BUDGET, "must fit the budget");
    assert.ok(5 < CONSECUTIVE_JOINER_CAP, "each cluster must fit the run cap");
  });

  it("does not clip vocalised Arabic: a harakat still opens a fresh run", () => {
    // Regression on the cluster rewrite: `beh + fatha + ZWNJ` is ONE cluster,
    // and the harakat closes a genuine gap inside it. Charging per cluster must
    // not lose that reset, or 12 ordinary words would be clipped to the
    // consecutive-joiner cap (8) — legitimate text mangled by an accounting
    // change. The document-wide budget (16) is the only limit in play here.
    const unit = cp(0x628) + cp(0x64e) + ZWNJ;
    const input = unit.repeat(12) + cp(0x628);
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, input);
    assert.deepEqual(found, []);
    assert.ok(12 > CONSECUTIVE_JOINER_CAP, "case must exceed the run cap");
  });

  it("keeps a subregional flag's tag run whole (tags are cluster-internal)", () => {
    const flag =
      cp(0x1f3f4) +
      [..."gbsct"].map((c) => cp(0xe0000 + c.charCodeAt(0))).join("") +
      CANCEL_TAG;
    for (const n of [1, 2, 3, 5]) assertNoPartialCarve(flag.repeat(n));
  });
});

// ─── Precision negatives: real multilingual text is preserved un-flagged ──────
// The budget must NOT mangle or flag legitimate short multilingual content. A
// handful of genuine joiners — a Persian/Indic compound word, an emoji ZWJ
// sequence — stay byte-identical with an empty `found`.
describe("budget precision: legitimate joiners preserved and un-flagged", () => {
  // A short compound per script (1 joiner) plus a longer one (3 joiners): all
  // well under the budget, so none is stripped or flagged. Driven off the
  // LINGUISTIC_SCRIPTS SSOT so a new script without representative letters fails.
  const SCRIPT_LETTERS = {
    Arabic: [0x645, 0x62e],
    Devanagari: [0x915, 0x937],
    Bengali: [0x995, 0x99a],
    Gurmukhi: [0x0a15, 0x0a17],
    Gujarati: [0x0a95, 0x0a97],
    Oriya: [0x0b15, 0x0b17],
    Tamil: [0x0b95, 0x0b99],
    Telugu: [0x0c15, 0x0c17],
    Kannada: [0x0c95, 0x0c97],
    Malayalam: [0x0d15, 0x0d17],
    Sinhala: [0x0d9a, 0x0d9c],
  };
  for (const script of LINGUISTIC_SCRIPTS) {
    const [a, b] = SCRIPT_LETTERS[script];
    assert.ok(a !== undefined, `no representative letters for ${script}`);
    it(`a 1-3 joiner ${script} compound is preserved un-flagged`, () => {
      // " word1 word2 " with 1 then 3 joiners — 4 joiners total, under budget.
      const w1 = joinedChain(script, [a, b], ZWNJ, 1);
      const w2 = joinedChain(script, [a, b], ZWNJ, 3);
      const input = `${w1} ${w2}`;
      const { cleaned, found } = stripInvisibleWithReport(input);
      assert.equal(cleaned, input);
      assert.deepEqual(found, []);
    });
  }

  it("a family emoji ZWJ sequence is preserved un-flagged", () => {
    const { cleaned, found } = stripInvisibleWithReport(FAMILY);
    assert.equal(cleaned, FAMILY);
    assert.deepEqual(found, []);
  });

  it("several distinct emoji ZWJ sequences together stay under budget", () => {
    // Three family emoji (9 ZWJ total) separated by spaces: a realistic message,
    // still under the 16-joiner budget — preserved verbatim, no flag.
    const input = `${FAMILY} ${FAMILY} ${FAMILY}`;
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, input);
    assert.deepEqual(found, []);
  });
});

// ─── Emoji tag sequences (subregional flags) ──────────────────────────────────
// A subregional flag is 🏴 (U+1F3F4) + tag chars (U+E0020–U+E007E) + CANCEL
// (U+E007F). Only that exact grammar is preserved; every other tag char stays
// stripped (tags are the top ASCII-smuggling vector, so preservation fails
// closed on a malformed/partial run).
describe("stripInvisible: emoji tag sequences (subregional flags)", () => {
  for (const [name, code] of [
    ["Scotland", "gbsct"],
    ["Wales", "gbwls"],
    ["England", "gbeng"],
  ]) {
    it(`preserves the ${name} flag tag sequence verbatim`, () => {
      const flag = tagCode(code);
      const { cleaned, found } = stripInvisibleWithReport(`a ${flag} b`);
      assert.equal(cleaned, `a ${flag} b`);
      assert.deepEqual(found, []);
    });
  }

  it("strips a tag run missing the CANCEL terminator (bare flag remains)", () => {
    // 🏴 + tag chars but NO U+E007F: malformed, so the tag chars are stripped
    // and only the visible flag base survives (fail closed).
    const input = cp(0x1f3f4) + cp(0xe0067) + cp(0xe0062) + cp(0xe0073);
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, cp(0x1f3f4));
    assert.deepEqual(found, [CATEGORY.CF]);
  });

  it("strips a bare CANCEL with no tag base or tag chars before it", () => {
    const input = `x${CANCEL_TAG}y`;
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, "xy");
    assert.deepEqual(found, [CATEGORY.CF]);
  });

  it("strips 🏴 immediately followed by CANCEL (no tag char between)", () => {
    // Grammar needs ≥1 tag char before CANCEL; 🏴 + CANCEL is malformed.
    const input = cp(0x1f3f4) + CANCEL_TAG;
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, cp(0x1f3f4));
    assert.deepEqual(found, [CATEGORY.CF]);
  });

  it("strips loose tag chars not anchored to a flag base", () => {
    // The classic ASCII-smuggling channel: tag chars with no 🏴 tag_base.
    const input = "Q" + cp(0xe0041) + cp(0xe0070) + "K";
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, "QK");
    assert.deepEqual(found, [CATEGORY.CF]);
  });

  it("preserves the flag but strips a trailing loose tag char after CANCEL", () => {
    const flag = tagCode("gbsct");
    const input = flag + cp(0xe0041); // extra tag char past the terminator
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, flag);
    assert.deepEqual(found, [CATEGORY.CF]);
  });

  // A grammatically-valid tag run whose payload is NOT a registered subdivision
  // is the ASCII-smuggling channel: tag chars decode to ASCII (cp − 0xE0000), so
  // a well-formed 🏴 … CANCEL run can spell arbitrary text. Only a registered GB
  // subdivision payload is preserved; every other run fails closed.
  for (const [name, payload] of [
    ["a short ASCII word", "hi"],
    ["an injection phrase", "ignore"],
    ["a US-state-shaped payload", "usca"],
    ["a near-miss of a real subdivision", "gbxyz"],
  ]) {
    it(`strips a grammar-valid tag run with a non-subdivision payload (${name})`, () => {
      const input = `a ${tagCode(payload)} b`;
      const { cleaned, found } = stripInvisibleWithReport(input);
      // Only the visible flag base survives; every tag char + CANCEL is stripped.
      assert.equal(cleaned, `a ${cp(0x1f3f4)} b`);
      assert.deepEqual(found, [CATEGORY.CF]);
    });
  }

  it("strips a grammar-valid tag run that exceeds the tag-char cap", () => {
    // Payload "gbengland" is a registered-prefix but 9 tag chars (> the ≤6 cap),
    // so it fails closed even though it starts with a real subdivision code.
    const input = tagCode("gbengland");
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, cp(0x1f3f4));
    assert.deepEqual(found, [CATEGORY.CF]);
  });

  it("preserves a real England/Scotland/Wales flag next to a stripped fake flag (precision)", () => {
    // The registered flag survives byte-for-byte; the adjacent fake-payload flag
    // loses its tag run — precision counter-case to the strip assertions above.
    const real = tagCode("gbeng");
    const fake = tagCode("ignore");
    const { cleaned, found } = stripInvisibleWithReport(`${real} ${fake}`);
    assert.equal(cleaned, `${real} ${cp(0x1f3f4)}`);
    assert.deepEqual(found, [CATEGORY.CF]);
  });

  it("is idempotent on a mixed valid/invalid tag document", () => {
    const input = `${tagCode("gbsct")} ${cp(0x1f3f4)}${cp(0xe0067)} tail`;
    const once = stripInvisible(input);
    assert.equal(stripInvisible(once), once);
  });

  it("is idempotent on a non-subdivision fake-flag run", () => {
    const once = stripInvisible(`x ${tagCode("ignorerules")} y`);
    assert.equal(stripInvisible(once), once);
  });

  it("atomically strips a well-formed flag once the preserve budget overruns", () => {
    // Each 🏴gbsct sequence spends 6 tag units of the document-wide preserve
    // budget (TOTAL_PRESERVED_JOINER_BUDGET = 16). Two flags fit (12 ≤ 16); the
    // third's whole tag run overruns (18 > 16) and is stripped ATOMICALLY —
    // never left as a malformed partial run — leaving only its bare flag base.
    // Total tag chars (18) stay under the scatter floor, so this exercises the
    // budget cut specifically, not the floor.
    const flag = tagCode("gbsct");
    const { cleaned, found } = stripInvisibleWithReport(
      `${flag} ${flag} ${flag}`,
    );
    assert.equal(cleaned, `${flag} ${flag} ${cp(0x1f3f4)}`);
    assert.deepEqual(found, [CATEGORY.CF]);
  });
});

// ─── Standardized variation sequences (U+FE00–U+FE0D) ─────────────────────────
// A selector in U+FE00–U+FE0D is preserved ONLY after a base that forms a
// registered standardized variation sequence (per the generated UCD table);
// every unregistered base+selector is stripped as a hidden VS.
describe("stripInvisible: standardized variation sequences", () => {
  for (const [name, base, selector] of [
    ["EMPTY SET + VS1", 0x2205, 0xfe00],
    ["DIGIT ZERO + VS1", 0x30, 0xfe00],
    ["U+4E0D + VS1 (CJK compatibility)", 0x4e0d, 0xfe00],
  ]) {
    it(`preserves the registered sequence ${name}`, () => {
      const input = cp(base) + cp(selector);
      const { cleaned, found } = stripInvisibleWithReport(`x${input}y`);
      assert.equal(cleaned, `x${input}y`);
      assert.deepEqual(found, []);
    });
  }

  it("strips an FE00 selector after an unregistered base", () => {
    // 'a' + VS1 is not a registered sequence.
    const input = `a${cp(0xfe00)}b`;
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, "ab");
    assert.deepEqual(found, [CATEGORY.VARIATION_SELECTORS]);
  });

  it("strips a wrong-selector variant of a registered base", () => {
    // DIGIT ZERO is registered with VS1 (FE00), not VS14 (FE0D).
    const input = cp(0x30) + cp(0xfe0d);
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, cp(0x30));
    assert.deepEqual(found, [CATEGORY.VARIATION_SELECTORS]);
  });

  it("strips a stuffed run after a registered base, keeping only the first", () => {
    // EMPTY SET + VS1 (registered) + 3 more VS1: only the first is adjacent to
    // the base; the rest each sit behind a selector, so they are stripped.
    const input = cp(0x2205) + cp(0xfe00).repeat(4);
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, cp(0x2205) + cp(0xfe00));
    assert.deepEqual(found, [CATEGORY.VARIATION_SELECTORS]);
  });
});

// ─── Ideographic variation sequences (VS17–VS256, U+E0100–U+E01EF) ────────────
// A selector in U+E0100–U+E01EF is preserved ONLY after a CJK ideograph (the
// registry-faithful structural gate for an ideographic variation sequence).
describe("stripInvisible: ideographic variation sequences", () => {
  for (const [name, base] of [
    ["U+845B 葛 (Unified)", 0x845b],
    ["U+4E00 一 (Unified, block start)", 0x4e00],
    ["U+3400 (Extension A start)", 0x3400],
    ["U+20000 (Extension B start)", 0x20000],
    ["U+FA0E (Compatibility Ideographs)", 0xfa0e],
  ]) {
    it(`preserves an ideographic selector after ${name}`, () => {
      const input = cp(base) + cp(0xe0100);
      const { cleaned, found } = stripInvisibleWithReport(`【${input}】`);
      assert.equal(cleaned, `【${input}】`);
      assert.deepEqual(found, []);
    });
  }

  it("preserves the whole E0100–E01EF selector range after a CJK base", () => {
    for (const sel of [0xe0100, 0xe0101, 0xe01ef]) {
      const input = cp(0x845b) + cp(sel);
      assert.equal(
        stripInvisible(input),
        input,
        `selector U+${sel.toString(16)}`,
      );
    }
  });

  it("strips an ideographic selector after a non-CJK base", () => {
    const input = `a${cp(0xe0100)}b`;
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, "ab");
    assert.deepEqual(found, [CATEGORY.VARIATION_SELECTORS]);
  });

  it("strips an ideographic selector after a Latin letter that looks like a base", () => {
    // A ZWJ/selector run without a CJK anchor stays payload.
    const input = cp(0x1f3f3) + cp(0xe0100); // pictograph, not a CJK ideograph
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, cp(0x1f3f3));
    assert.deepEqual(found, [CATEGORY.VARIATION_SELECTORS]);
  });
});

// ─── Carve-out hardening: absolute preserve cap, selector run cap, virama base ─
// Three tightenings that close covert channels the earlier carve-out left open:
// an absolute ceiling on the preserve budget (so cover text can't scale it), a
// consecutive-run cap on ideographic/standardized variation selectors (so a
// per-character variation-selected CJK run can't smuggle bits), and a real
// Brahmic-consonant requirement before a virama (so a bare halant + ZWJ is not
// mistaken for a conjunct). Each strip assertion is paired with a preserve one.
describe("stripInvisible: preserve budget has an absolute hard cap", () => {
  const ZWNJ_CH = cp(0x200c);
  const countOf = (s, ch) => s.split(ch).length - 1;

  it(`never preserves more than PRESERVE_HARD_CAP joiners no matter how much cover text`, () => {
    // 200 space-separated Persian ZWNJ words: each ZWNJ is meaningful (so none
    // counts toward the scatter floor) and every gap resets the per-cluster cap,
    // so ONLY the document-wide limit bounds the total. visibleLen ≈ 800 ⇒
    // ceil(visibleLen / PER_VISIBLE) = 100, which WITHOUT the hard cap would
    // preserve 100; the cap holds it to PRESERVE_HARD_CAP (64).
    const unit = cp(0x645) + cp(0x6cc) + ZWNJ_CH + cp(0x62e) + " ";
    const { cleaned, found } = stripInvisibleWithReport(unit.repeat(200));
    assert.equal(countOf(cleaned, ZWNJ_CH), PRESERVE_HARD_CAP);
    assert.deepEqual(found, [CATEGORY.CF]);
  });

  it("preserves every joiner when the count sits under the hard cap (precision)", () => {
    // 40 words ⇒ 40 ZWNJ, below PRESERVE_HARD_CAP (64) and below ceil(160/8)=20?
    // visibleLen ≈ 160 ⇒ ceil/8 = 20, floored to TOTAL_PRESERVED_JOINER_BUDGET…
    // 40 would still overrun that floor, so pad each gap to keep the allowance
    // above 40: 20-space gaps ⇒ visibleLen ≈ 40*23 = 920 ⇒ allowance 64, so all
    // 40 survive. Counter-case proving the cap only clips the SURPLUS.
    const unit = cp(0x645) + cp(0x6cc) + ZWNJ_CH + cp(0x62e) + " ".repeat(20);
    const { cleaned, found } = stripInvisibleWithReport(unit.repeat(40));
    assert.equal(countOf(cleaned, ZWNJ_CH), 40);
    assert.deepEqual(found, []);
  });
});

describe("stripInvisible: consecutive variation-selector run cap", () => {
  const IVS = cp(0xe0100);
  const IDEO = cp(0x845b);
  const countOf = (s, ch) => s.split(ch).length - 1;

  it("caps a per-character variation-selected CJK run at CONSECUTIVE_SELECTOR_CAP", () => {
    // `葛󠄀葛󠄀…` — every ideograph carries an IVS, an unbroken selector run with no
    // gap. Each IVS is individually a valid ideographic variation sequence, so
    // only the consecutive-run cap bounds the channel: past the cap the surplus
    // selectors are stripped (the ideographs, being visible, all survive).
    const runLen = CONSECUTIVE_SELECTOR_CAP + 6;
    const { cleaned, found } = stripInvisibleWithReport(
      (IDEO + IVS).repeat(runLen),
    );
    assert.equal(countOf(cleaned, IVS), CONSECUTIVE_SELECTOR_CAP);
    assert.equal(countOf(cleaned, IDEO), runLen); // no ideograph is ever dropped
    assert.deepEqual(found, [CATEGORY.VARIATION_SELECTORS]);
  });

  it("preserves a short variation-selected run under the cap (precision)", () => {
    // Exactly CONSECUTIVE_SELECTOR_CAP selected ideographs: all survive verbatim.
    const input = (IDEO + IVS).repeat(CONSECUTIVE_SELECTOR_CAP);
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, input);
    assert.deepEqual(found, []);
  });

  it("resets the selector run at a genuine visible gap", () => {
    // A space between two capped runs resets the counter, so each half preserves
    // up to the cap independently — proof the reset (not just the cap) works.
    const half = (IDEO + IVS).repeat(CONSECUTIVE_SELECTOR_CAP);
    const { cleaned, found } = stripInvisibleWithReport(`${half}  ${half}`);
    assert.equal(countOf(cleaned, IVS), CONSECUTIVE_SELECTOR_CAP * 2);
    assert.deepEqual(found, []);
  });
});

describe("stripInvisible: virama joiner requires a real consonant base", () => {
  const VIRAMA = cp(0x94d); // Devanagari virama
  const CONSONANT = cp(0x915); // Devanagari KA

  it("strips a bare virama + ZWJ with no consonant base (fail closed)", () => {
    // The virama itself (a combining mark) is not payload and remains; only the
    // ZWJ, which does no conjunct work without a consonant, is stripped.
    const { cleaned, found } = stripInvisibleWithReport(VIRAMA + ZWJ);
    assert.equal(cleaned, VIRAMA);
    assert.deepEqual(found, [CATEGORY.CF]);
  });

  it("strips a virama + ZWJ whose base is a non-Brahmic (ASCII) letter", () => {
    const { cleaned, found } = stripInvisibleWithReport(`a${VIRAMA}${ZWJ}b`);
    assert.equal(cleaned, `a${VIRAMA}b`);
    assert.deepEqual(found, [CATEGORY.CF]);
  });

  it("strips a leading virama + ZWJ before a consonant (base is on the wrong side)", () => {
    const { cleaned, found } = stripInvisibleWithReport(
      VIRAMA + ZWJ + CONSONANT,
    );
    assert.equal(cleaned, VIRAMA + CONSONANT);
    assert.deepEqual(found, [CATEGORY.CF]);
  });

  it("preserves a real consonant + virama + ZWJ + consonant conjunct (precision)", () => {
    const conjunct = CONSONANT + VIRAMA + ZWJ + cp(0x937);
    const { cleaned, found } = stripInvisibleWithReport(conjunct);
    assert.equal(cleaned, conjunct);
    assert.deepEqual(found, []);
  });
});

// ─── Blank-filler carve-out (Braille / archaic Hangul) ────────────────────────
// U+2800 and the Hangul fillers are preserved only next to a real,
// script-appropriate visible neighbour; a run (whose neighbours are fillers) or
// an out-of-context filler is stripped. Zero-width Mn marks are never preserved.
describe("stripInvisible: blank-filler carve-out", () => {
  it("preserves a Braille blank between real Braille cells", () => {
    const input = cp(0x2803) + cp(0x2800) + cp(0x2801);
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, input);
    assert.deepEqual(found, []);
  });

  it("preserves a Hangul filler between Hangul syllables", () => {
    const input = cp(0xac00) + cp(0x3164) + cp(0xac01);
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, input);
    assert.deepEqual(found, []);
  });

  it("strips a Braille blank in non-Braille context", () => {
    const input = `a${cp(0x2800)}b`;
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, "ab");
    assert.deepEqual(found, [CATEGORY.BLANK_FILLERS]);
  });

  it("strips a Hangul filler in non-Hangul context", () => {
    const input = `c${cp(0x3164)}d`;
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, "cd");
    assert.deepEqual(found, [CATEGORY.BLANK_FILLERS]);
  });

  it("strips a run of Braille blanks down to the anchored ends only", () => {
    // Neighbours of the interior blanks are themselves blanks (not cells), so
    // only the two blanks touching a real cell survive — the run-length gate.
    const input = cp(0x2803) + cp(0x2800).repeat(5) + cp(0x2801);
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, cp(0x2803) + cp(0x2800) + cp(0x2800) + cp(0x2801));
    assert.deepEqual(found, [CATEGORY.BLANK_FILLERS]);
  });

  it("strips a run of adjacent Hangul fillers — a filler can't anchor another", () => {
    // Two U+3164 fillers touching only each other and non-Hangul text: neither
    // has a real Hangul neighbour, so the "a filler cannot anchor another filler"
    // guard rejects the self-anchor and the whole run is stripped (covert-channel
    // collapse — mirrors the Braille run-length gate).
    const input = `c${cp(0x3164)}${cp(0x3164)}d`;
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, "cd");
    assert.deepEqual(found, [CATEGORY.BLANK_FILLERS]);
  });

  it("never preserves a zero-width Mn mark even beside its own script", () => {
    // U+034F CGJ between Hangul is still stripped — Mn zero-widths have no
    // anchored blank-filler use.
    const input = cp(0xac00) + cp(0x034f) + cp(0xac01);
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, cp(0xac00) + cp(0xac01));
    assert.deepEqual(found, [CATEGORY.BLANK_FILLERS]);
  });

  it("preserves a filler anchored on ONE side only, at either edge", () => {
    // The counterexample a property run found (seed -1494323434): every fixed
    // case above anchors the filler on BOTH sides, so a filler at the very start
    // or end of the text — one neighbour, and it is the string edge — went
    // untested. Pinned here so the coverage no longer depends on a lucky seed.
    for (const filler of [0x115f, 0x1160, 0x3164, 0xffa0]) {
      for (const input of [cp(filler) + cp(0xac00), cp(0xac00) + cp(filler)]) {
        const { cleaned, found } = stripInvisibleWithReport(input);
        assert.equal(cleaned, input, JSON.stringify(input));
        assert.deepEqual(found, [], JSON.stringify(input));
      }
      // Positive marker: the SAME filler with no Hangul anywhere is stripped, so
      // the assertions above pin the anchor rule and not a blanket exemption.
      const orphan = `a${cp(filler)}b`;
      const { cleaned, found } = stripInvisibleWithReport(orphan);
      assert.equal(cleaned, "ab", JSON.stringify(orphan));
      assert.deepEqual(found, [CATEGORY.BLANK_FILLERS], JSON.stringify(orphan));
    }
  });

  it("leaves ordinary Korean prose completely untouched", () => {
    // The negative corpus CLAUDE.md asks every detector to carry: real text in
    // the script this carve-out serves must produce ZERO findings, so the
    // carve-out cannot be tightened into mangling legitimate content.
    const corpus = [
      "안녕하세요, 반갑습니다.",
      "한국어 텍스트를 처리합니다",
      "서울특별시 강남구",
      "훈민정음(訓民正音)은 1443년에 창제되었다.",
      "김치찌개 2인분 주세요!",
    ];
    for (const text of corpus) {
      const { cleaned, found } = stripInvisibleWithReport(text);
      assert.equal(cleaned, text, JSON.stringify(text));
      assert.deepEqual(found, [], JSON.stringify(text));
    }
  });

  it("a blank filler between two joiners does not hide the joiner run (idempotent)", () => {
    // م ZWJ <blank> ZWJ م — the blank is payload; stripping it makes the two
    // joiners adjacent. The joiner-run must be detected in a SINGLE pass (both
    // joiners stripped) so a second pass changes nothing. effectiveNeighbor
    // steps over the removable blank to see the run up front.
    for (const blank of [cp(0x2800), cp(0x115f), cp(0x3164)]) {
      const joiner = cp(0x200d);
      const input = cp(0x645) + joiner + blank + joiner + cp(0x645);
      const once = stripInvisible(input);
      assert.equal(once, cp(0x645) + cp(0x645), JSON.stringify(input));
      assert.equal(stripInvisible(once), once);
    }
  });
});

// ─── Interior BOM after an ANSI strip (applyLayer1, L4) ───────────────────────
describe("applyLayer1: leading-BOM is decided from the original text", () => {
  it("strips a BOM that was interior before the ANSI strip", () => {
    // `ESC[m` + U+FEFF + text: the BOM is interior in the original, so even
    // though the ANSI strip leaves it at index 0 it must be stripped, not kept.
    const input = `${cp(0x1b)}[m${cp(0xfeff)}hello`;
    const { cleaned } = applyLayer1(input);
    assert.equal(cleaned, "hello");
    assert.equal(cleaned.charCodeAt(0), "h".charCodeAt(0));
  });

  it("still preserves a genuinely leading BOM", () => {
    const input = `${cp(0xfeff)}${cp(0x1b)}[mhello`;
    const { cleaned } = applyLayer1(input);
    assert.equal(cleaned, `${cp(0xfeff)}hello`);
  });
});

// ─── ZWJ emoji sequence with a selector after the ZWJ (L5) ────────────────────
describe("stripInvisible: ZWJ right-neighbour steps over a selector", () => {
  it("preserves the ZWJ when a selector sits between it and the next pictograph", () => {
    // base ZWJ VS16 pictograph: the ZWJ's real right neighbour is the pictograph,
    // found by stepping over the selector (rightNonSelector). The ZWJ is kept;
    // the stray VS16 (whose own left neighbour is the ZWJ, not a pictograph) is
    // still stripped — the fix rescues the joiner, not a misplaced selector.
    const input = cp(0x1f3f3) + ZWJ + cp(0xfe0f) + cp(0x1f308);
    const { cleaned, found } = stripInvisibleWithReport(input);
    assert.equal(cleaned, cp(0x1f3f3) + ZWJ + cp(0x1f308));
    assert.deepEqual(found, [CATEGORY.VARIATION_SELECTORS]);
    assert.equal(countOf(cleaned, ZWJ), 1);
  });
});

// ─── LONG_RUN injection probe ignores preserved invisibles (L6) ───────────────
describe("payloadInvisibleView + describeStripped: preserved runs don't alert", () => {
  it("payloadInvisibleView masks preserved chars and keeps payload", () => {
    const flag = tagCode("gbsct");
    const view = payloadInvisibleView(flag + cp(0x200b));
    // The flag's tag chars are masked to spaces; only the ZWSP payload remains.
    assert.equal(view.includes(cp(0xe0067)), false);
    assert.equal(view.includes(cp(0x200b)), true);
  });

  it("no LONG RUN marker when masking a preserved flag breaks an otherwise-long run", () => {
    // A registered flag (6 preserved invisibles) immediately followed by 9 ZWSP
    // payload: UNMASKED the 15 consecutive invisibles would trip LONG_RUN, but
    // payloadInvisibleView masks the preserved flag chars to spaces, leaving only
    // the 9 ZWSP (< LONG_RUN_THRESHOLD) — so the injection marker must NOT fire.
    const deAnsi = tagCode("gbsct") + cp(0x200b).repeat(LONG_RUN_THRESHOLD - 1);
    const note = describeStripped([CATEGORY.CF], deAnsi);
    assert.doesNotMatch(note, /LONG RUN/);
  });

  it("still marks a genuine long payload run", () => {
    const deAnsi = cp(0x200b).repeat(LONG_RUN_THRESHOLD + 2);
    const note = describeStripped([CATEGORY.CF], deAnsi);
    assert.match(note, /LONG RUN/);
  });
});

// ─── Layer 1: OSC strings + C1 sequences (no payload survives) ────────────────
// OSC strings carry attacker-controlled text (titles, hyperlink URLs) between an
// introducer and a terminator. The fix consumes the WHOLE string for every
// terminator form (ST `ESC\`, C1 ST U+009C, legacy BEL) and for the 8-bit C1
// OSC introducer, and drops an unterminated introducer's remainder (fail-closed).
describe("applyLayer1: OSC strings and C1 sequences", () => {
  const ESC = cp(0x1b);
  const BEL = cp(0x07);
  const ST = ESC + "\\";
  const C1_ST = cp(0x9c);
  const C1_OSC = cp(0x9d);
  const C1_CSI = cp(0x9b);

  for (const [name, input, expected] of [
    [
      "OSC title terminated by ST (ESC\\)",
      `before${ESC}]0;TITLE${ST}after`,
      "beforeafter",
    ],
    [
      "OSC title terminated by C1 ST",
      `before${ESC}]0;TITLE${C1_ST}after`,
      "beforeafter",
    ],
    [
      "OSC title terminated by BEL",
      `before${ESC}]0;TITLE${BEL}after`,
      "beforeafter",
    ],
    [
      "OSC hyperlink (URL payload) terminated by ST",
      `${ESC}]8;;https://evil/leak${ST}`,
      "",
    ],
    ["unterminated OSC consumes to end-of-string", `${ESC}]0;UNTERMINATED`, ""],
    [
      "C1 OSC introducer (U+009D) terminated by C1 ST",
      `x${C1_OSC}0;SECRET${C1_ST}y`,
      "xy",
    ],
    ["C1 OSC introducer terminated by ST", `x${C1_OSC}0;SECRET${ST}y`, "xy"],
    ["C1 CSI SGR color sequence", `a${C1_CSI}31mred${C1_CSI}0mb`, "aredb"],
    ["C1 CSI cursor/erase sequence", `a${C1_CSI}2Jb`, "ab"],
  ]) {
    it(`removes the whole sequence: ${name}`, () => {
      const { cleaned } = applyLayer1(input);
      assert.equal(cleaned, expected);
    });
  }

  // DCS/SOS/PM/APC are the other ECMA-48 string controls. The OSC/CSI grammar
  // does not consume them, so the residual C1 sweep is what guarantees their
  // introducer and terminator never survive into the model's view (the body
  // text remains — it is now equally visible to a human, the point of the fix).
  const C1_DCS = cp(0x90);
  const C1_SOS = cp(0x98);
  const C1_PM = cp(0x9e);
  const C1_APC = cp(0x9f);
  for (const [name, input] of [
    ["7-bit DCS (ESC P … ST)", `before${ESC}P1;2;3|PAYLOAD${ST}after`],
    ["7-bit APC (ESC _ … ST)", `x${ESC}_hidden-cmd${ST}y`],
    ["7-bit PM (ESC ^ … ST)", `x${ESC}^secret${ST}y`],
    ["7-bit SOS (ESC X … ST)", `x${ESC}Xboo${ST}y`],
    ["8-bit DCS (U+0090 … C1 ST)", `x${C1_DCS}PAYLOAD${C1_ST}y`],
    ["8-bit APC (U+009F … C1 ST)", `x${C1_APC}hidden-cmd${C1_ST}y`],
    ["8-bit PM (U+009E … C1 ST)", `x${C1_PM}secret${C1_ST}y`],
    ["8-bit SOS (U+0098 … C1 ST)", `x${C1_SOS}boo${C1_ST}y`],
    ["unterminated 8-bit APC", `x${C1_APC}dangling-payload`],
  ]) {
    it(`leaves no C1 control for the string control: ${name}`, () => {
      const { cleaned } = applyLayer1(input);
      for (const ch of cleaned) {
        const code = ch.codePointAt(0);
        assert.ok(
          (code < 0x80 || code > 0x9f) && code !== 0x1b,
          `control U+${code.toString(16)} survived in ${name}`,
        );
      }
    });
  }

  it("leaves no raw control introducer for any of the OSC/C1 cases", () => {
    for (const input of [
      `${ESC}]0;t${ST}`,
      `${ESC}]0;t${C1_ST}`,
      `${ESC}]0;t${BEL}`,
      `${ESC}]0;unterminated`,
      `${C1_OSC}0;t${C1_ST}`,
      `${C1_CSI}31mx${C1_CSI}0m`,
    ]) {
      const { cleaned } = applyLayer1(input);
      assert.ok(!cleaned.includes(cp(0x1b)), "ESC survived");
      assert.ok(!cleaned.includes(cp(0x9b)), "C1 CSI survived");
      assert.ok(!cleaned.includes(cp(0x9d)), "C1 OSC survived");
    }
  });

  // The deliberate bounded-intro / negated-body design keeps the ANSI grammar
  // linear; an adversarial never-completing string must not blow up.
  //
  // We assert a GENEROUS ABSOLUTE wall-clock bound on one pass over a large
  // adversarial input, not a ratio of two timings. The old ratio test
  // (big / small < 40) divided by a tiny ~20k-char `small` denominator: under
  // CI load spikes that denominator is so small and noisy that genuinely-linear
  // code spikes the ratio past the threshold, producing false reds (it flaked
  // #37 while passing locally). An absolute bound has no noisy denominator yet
  // still catches the ReDoS class with a huge margin: linear stripping of this
  // 400k-char input is single-digit milliseconds, whereas catastrophic /
  // quadratic backtracking on a never-terminating n=200000 input would run for
  // tens of seconds — orders of magnitude past 2000ms. So 2000ms cleanly
  // separates linear-with-headroom from any super-linear blowup.
  it("OSC/CSI stripping stays linear on adversarial never-terminating input", () => {
    const n = 200000;
    const input = `${ESC}]` + ";".repeat(n) + `${ESC}[` + ";#".repeat(n);
    const t0 = process.hrtime.bigint();
    applyLayer1(input);
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    assert.ok(
      ms < 2000,
      `applyLayer1 on a ${input.length}-char adversarial input took ${ms.toFixed(1)}ms (>= 2000ms suggests super-linear backtracking)`,
    );
  });
});

// ─── stripAnsiFully: CSI final-byte grammar + OSC interior-ESC abort ─────────

describe("stripAnsiFully: CSI digits are never a final byte", () => {
  // Per ECMA-48, CSI final bytes occupy 0x40–0x7E; digits are PARAMETER bytes
  // and can never terminate a sequence. Regression: the final-byte class used
  // to include `\d`, so an incomplete `ESC[` swallowed following visible
  // digits as if they were the sequence's final byte, deleting real content
  // (`ESC[2024 report` used to become ` report` — "2024" gone).
  it("does not swallow visible digits after an incomplete CSI intro", () => {
    const cleaned = stripAnsiFully(`${cp(0x1b)}[2024 report`);
    assert.ok(
      cleaned.includes("2024 report"),
      `visible digits were swallowed: ${JSON.stringify(cleaned)}`,
    );
  });

  it("applyLayer1 sweeps the residual ESC but the digits/report text survive intact", () => {
    // The incomplete `ESC[` itself never completes a valid CSI sequence (no
    // valid final byte follows), so CSI_BRANCH does not match it at all; the
    // final residual-sweep in applyLayer1 removes the bare ESC control byte,
    // exactly like the existing "nested split (incomplete residual)" case in
    // sanitize.test.mjs — the ASCII `[` is not a control byte, so a stray
    // bracket may remain, but nothing user-visible past the intro is lost.
    const { cleaned, found } = applyLayer1(`${cp(0x1b)}[2024 report`);
    assert.ok(!cleaned.includes(cp(0x1b)), "ESC survived");
    assert.equal(cleaned, "[2024 report");
    assert.ok(found.includes(CATEGORY.ANSI));
  });

  it("still fully removes a genuine (complete) CSI sequence with numeric params", () => {
    // Negative case: a real, TERMINATED CSI sequence (color 32m) must still be
    // removed in full — the digit-exclusion only affects an incomplete/dangling
    // intro, not a properly closed sequence.
    assert.equal(stripAnsiFully(`${cp(0x1b)}[32mhello${cp(0x1b)}[0m`), "hello");
  });

  it("still fully removes a cursor-move/erase CSI sequence (non-SGR hazard)", () => {
    assert.equal(stripAnsiFully(`${cp(0x1b)}[2Jhello`), "hello");
  });

  // `=`, `<`, `>` (0x3C–0x3F minus `?`) are private PARAMETER-prefix bytes per
  // ECMA-48 § 5.4, never final bytes; `~` (0x7E) IS a real final byte (vt220
  // function-key sequences, e.g. Delete = `ESC[3~`) and must still match.
  it("still removes a vt220 function-key sequence ending in `~`", () => {
    assert.equal(stripAnsiFully(`${cp(0x1b)}[3~hello`), "hello");
  });
});

describe("stripAnsiFully: an interior bare ESC aborts an OSC string in place", () => {
  // Per ECMA-48/xterm, a bare ESC that is not the start of a valid ST (`ESC\`)
  // aborts the OSC string in progress — the terminal starts processing that
  // ESC as a NEW sequence. Regression: OSC_BRANCH's only fallback for "no
  // terminator found yet" was `[\s\S]*$` (consume to end-of-string), which
  // fired on an interior bare ESC too, deleting the entire rest of the
  // document instead of just the OSC's own (now-abandoned) body.
  it("does not delete the rest of the document when a bare ESC interrupts an OSC body", () => {
    const cleaned = stripAnsiFully(
      `${cp(0x1b)}]0;title${cp(0x1b)}[0m the rest of the legit document`,
    );
    assert.equal(cleaned, " the rest of the legit document");
  });

  it("aborts at a nested bare C1-OSC introducer (U+009D) the same way", () => {
    const C1_OSC = cp(0x9d);
    const cleaned = stripAnsiFully(`${cp(0x1b)}]0;title${C1_OSC}rest`);
    // The outer OSC body is aborted at the nested introducer (left for the
    // engine's next match attempt); the inner introducer then starts its own
    // (unterminated) OSC match, which is fail-closed-consumed to EOS.
    assert.equal(cleaned, "");
  });

  it("still consumes a genuinely unterminated OSC string to end-of-string (fail closed)", () => {
    // Negative case: no ST/BEL/interior-ESC/nested-intro anywhere — the only
    // safe behavior for a truly dangling OSC introducer is to drop the whole
    // dangling remainder, exactly as before this fix.
    assert.equal(stripAnsiFully(`${cp(0x1b)}]0;UNTERMINATED`), "");
  });

  it("still consumes a properly ST-terminated OSC string in full (no change from the fix)", () => {
    assert.equal(
      stripAnsiFully(`before${cp(0x1b)}]0;TITLE${cp(0x1b)}\\after`),
      "beforeafter",
    );
  });
});

describe("SGR_RE / CSI param grammar: colon-form sub-parameters", () => {
  // ITU T.416 colon-separated SGR sub-parameters (tmux/kitty/mintty truecolor)
  // must be recognized by the CSI grammar too, not just SGR_RE, so a fully
  // stripped colon-form sequence leaves no junk residue.
  it("stripAnsiFully removes a colon-form truecolor CSI sequence in full", () => {
    assert.equal(
      stripAnsiFully(`${cp(0x1b)}[38:2:255:0:0mred${cp(0x1b)}[0m`),
      "red",
    );
  });

  it("hex-dump hygiene: SGR_RE's source contains no raw invisible C1 byte", () => {
    // Regression for a raw U+009B literal that once sat between `|` and `)` in
    // the SGR_RE source (undetectable by eye in an editor/diff) instead of the
    // explicit `\x9b` escape. Assert on the actual regex source string, not a
    // grep over the file, so a refactor that reintroduces a raw byte fails
    // here even if the surrounding text changes.
    assert.ok(
      !SGR_RE.source.includes(cp(0x9b)),
      "SGR_RE.source contains a raw literal U+009B byte, not an escape",
    );
    // Positive marker: the escaped form must still be present and functional.
    assert.equal(`${cp(0x9b)}31mx`.replace(SGR_RE, ""), "x");
  });
});

// ─── Property tests over the real input domain ───────────────────────────────

// Any single code point except the surrogate range (so .map(fromCodePoint)
// never throws); lone surrogates are injected separately.
const unicodeChar = fc
  .integer({ min: 0, max: 0x10ffff })
  .filter((c) => c < 0xd800 || c > 0xdfff)
  .map((c) => String.fromCodePoint(c));
const loneSurrogate = fc
  .integer({ min: 0xd800, max: 0xdfff })
  .map((c) => String.fromCharCode(c));
// Every invisible class, joiner-using script letters, emoji parts, ASCII.
const invisibleChar = fc.constantFrom(
  ...Array.from(BLANK_NON_CF),
  ...Array.from(VS),
  cp(0x200b),
  cp(0x200c),
  cp(0x200d),
  cp(0x00ad),
  cp(0xfeff),
  cp(0x2060),
);
const scriptChar = fc.constantFrom(
  cp(0x645),
  cp(0x62e),
  cp(0x915),
  cp(0x937),
  cp(0x1f468),
  cp(0x1f469),
  cp(0x1f3fb),
  "a",
  "Z",
  " ",
);
const adversarialChar = fc.oneof(
  unicodeChar,
  loneSurrogate,
  invisibleChar,
  scriptChar,
);
const adversarialText = fc
  .array(adversarialChar, { maxLength: 80 })
  .map((parts) => parts.join(""));

describe("property: stripInvisible invariants", () => {
  it("never throws on lone surrogates / astral input", () => {
    fc.assert(
      fc.property(adversarialText, (text) => {
        assert.equal(typeof stripInvisible(text), "string");
      }),
      fcRunOptions(),
    );
  });

  it("is idempotent: strip(strip(x)) === strip(x)", () => {
    fc.assert(
      fc.property(adversarialText, (text) => {
        const once = stripInvisible(text);
        assert.equal(stripInvisible(once), once);
      }),
      fcRunOptions(),
    );
  });

  it("output is a subsequence of the input (deletion only)", () => {
    fc.assert(
      fc.property(adversarialText, (text) => {
        // Compared at the UTF-16 code-UNIT level, not code points: deleting a
        // char between two lone surrogates can join them into a valid astral
        // pair, so the property holds per code unit but not per code point.
        const out = stripInvisible(text);
        let i = 0;
        for (let k = 0; k < out.length; k++) {
          const unit = out.charCodeAt(k);
          while (i < text.length && text.charCodeAt(i) !== unit) i++;
          assert.ok(i < text.length, "output not a subsequence of input");
          i++;
        }
      }),
      fcRunOptions(),
    );
  });

  it("`found` is exactly the set of categories that actually changed the text", () => {
    fc.assert(
      fc.property(adversarialText, (text) => {
        const { cleaned, found } = stripInvisibleWithReport(text);
        // Every reported category must really be a CHECKS code.
        const codes = new Set(CHECKS.map(([code]) => code));
        for (const f of found) assert.ok(codes.has(f), `bogus code: ${f}`);
        // found non-empty ⇔ the text changed (a strip happened). A preserved
        // joiner leaves text === cleaned AND found empty.
        assert.equal(found.length > 0, cleaned !== text);
      }),
      fcRunOptions(),
    );
  });

  it("a BOM is preserved only when leading", () => {
    fc.assert(
      fc.property(adversarialText, (text) => {
        const cleaned = stripInvisible(text);
        const hadLeadingBom = text.charCodeAt(0) === 0xfeff;
        // No interior BOM ever survives.
        const interior = cleaned.slice(1);
        assert.ok(!interior.includes(cp(0xfeff)), "interior BOM survived");
        // A leading BOM survives iff the input led with one.
        assert.equal(cleaned.charCodeAt(0) === 0xfeff, hadLeadingBom);
      }),
      fcRunOptions(),
    );
  });

  it("STRIP-matchable chars are gone unless preserved by the carve-out", () => {
    fc.assert(
      fc.property(adversarialText, (text) => {
        const cleaned = stripInvisible(text);
        // After stripping, the only STRIP-class chars left must be ZWNJ/ZWJ
        // (carve-out), a presentation selector kept on a pictograph/modifier
        // base (the carve-out preserves VS15/VS16 directly after one — 🏻︎ is
        // a visible glyph, not a hidden selector run), a blank filler anchored
        // to a script-appropriate visible neighbour, or a single leading BOM.
        const selectorBase = /^[\p{Extended_Pictographic}\p{Emoji_Modifier}]$/u;
        // The blank-filler carve-out, stated as the SPEC rather than copied
        // from the implementation: U+2800 survives beside a real Braille cell
        // and a Hangul filler beside a real jamo/syllable — one anchor on
        // EITHER side is enough, which is the case the fixed-corpus tests above
        // (both of which anchor on both sides) never covered. A filler cannot
        // anchor another filler, so a run still fails.
        const blankFillers = new Set([0x115f, 0x1160, 0x3164, 0xffa0]);
        const anchorsHangul = (ch) =>
          !!ch &&
          !blankFillers.has(/** @type {number} */ (ch.codePointAt(0))) &&
          /\p{Script=Hangul}/u.test(ch);
        const anchorsBraille = (ch) =>
          !!ch &&
          ch.codePointAt(0) !== 0x2800 &&
          /\p{Script=Braille}/u.test(ch);
        for (let i = 0; i < cleaned.length; i++) {
          const ch = cleaned[i];
          STRIP.lastIndex = 0;
          if (!STRIP.test(ch)) continue;
          const code = cleaned.codePointAt(i);
          // The base before a selector may be an astral pair: step back two
          // units when the preceding unit is a low surrogate.
          const baseStart =
            i >= 2 && /[\uDC00-\uDFFF]/.test(cleaned[i - 1]) ? i - 2 : i - 1;
          const keptSelector =
            (code === 0xfe0e || code === 0xfe0f) &&
            i > 0 &&
            selectorBase.test(cleaned.slice(baseStart, i));
          const prev = cleaned[i - 1] ?? "";
          const next = cleaned[i + 1] ?? "";
          const keptFiller =
            (code === 0x2800 &&
              (anchorsBraille(prev) || anchorsBraille(next))) ||
            (blankFillers.has(/** @type {number} */ (code)) &&
              (anchorsHangul(prev) || anchorsHangul(next)));
          const ok =
            code === 0x200c ||
            code === 0x200d ||
            keptSelector ||
            keptFiller ||
            (code === 0xfeff && i === 0);
          assert.ok(ok, `unexpected residual invisible U+${code.toString(16)}`);
        }
      }),
      fcRunOptions(),
    );
  });
});

// applyLayer1 over a domain that ALSO includes raw ANSI introducers/terminators
// — ESC, the C1 string introducers DCS/SOS/CSI/OSC/PM/APC (U+0090/0098/009B/
// 009D/009E/009F), C1 ST (U+009C), BEL, the 7-bit string-intro letters
// (`P X ] ^ _`), and `[ ; m 0` — so the property exercises the whole control
// grammar, not just invisible chars or the OSC/CSI subset.
const ansiChar = fc.constantFrom(
  cp(0x1b),
  cp(0x90),
  cp(0x98),
  cp(0x9b),
  cp(0x9c),
  cp(0x9d),
  cp(0x9e),
  cp(0x9f),
  cp(0x07),
  "P",
  "X",
  "[",
  "]",
  "^",
  "_",
  ";",
  "m",
  "0",
);
const layer1Text = fc
  .array(fc.oneof(adversarialChar, ansiChar), { maxLength: 80 })
  .map((parts) => parts.join(""));

describe("property: applyLayer1 invariants", () => {
  it("never throws on adversarial ANSI + invisible + surrogate input", () => {
    fc.assert(
      fc.property(layer1Text, (text) => {
        const { cleaned } = applyLayer1(text);
        assert.equal(typeof cleaned, "string");
      }),
      fcRunOptions(),
    );
  });

  // The guarantee is no RAW control introducer survives — 7-bit ESC and the
  // WHOLE 8-bit C1 block, not just the CSI/OSC the grammar names. Asserting the
  // entire U+0080–U+009F range is what catches a DCS/SOS/PM/APC introducer (or
  // its body's terminator) the OSC/CSI branches never matched.
  it("no raw control introducer (ESC or any C1 U+0080–U+009F) survives, for any input", () => {
    fc.assert(
      fc.property(layer1Text, (text) => {
        const { cleaned } = applyLayer1(text);
        assert.ok(!cleaned.includes(cp(0x1b)), "ESC survived");
        for (const ch of cleaned) {
          const code = ch.codePointAt(0);
          assert.ok(
            code < 0x80 || code > 0x9f,
            `C1 control U+${code.toString(16)} survived`,
          );
        }
      }),
      fcRunOptions(),
    );
  });

  it("is idempotent: applyLayer1(applyLayer1(x)) === applyLayer1(x)", () => {
    fc.assert(
      fc.property(layer1Text, (text) => {
        const once = applyLayer1(text).cleaned;
        assert.equal(applyLayer1(once).cleaned, once);
      }),
      fcRunOptions(),
    );
  });
});
