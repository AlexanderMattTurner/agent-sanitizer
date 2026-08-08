/**
 * Contract tests for the Unicode script data behind src/invisible.mjs's
 * carve-outs.
 *
 * The carve-out decides whether an invisible does real rendering work from the
 * script of its neighbour. That question is answered by Unicode's own tables, so
 * the module asks the runtime for them (`\p{Unified_Ideograph}`,
 * `\p{Script=Hangul}`, `\p{Script=Braille}`) instead of carrying transcribed
 * ranges that go stale one Unicode revision at a time. These tests pin the
 * derivation END-TO-END through the public API: for every code point in a scan
 * window, "does the carve-out treat this as an anchor?" must equal "does the
 * property hold?". A drift, a swapped property, or a re-introduced literal table
 * fails here.
 *
 * The one table that CANNOT be derived — the Brahmic consonant spans, whose UCD
 * property (Indic_Syllabic_Category) JS RegExp does not expose — is instead
 * pinned by the strongest contract that IS derivable: every assigned code point
 * in each span belongs to the script the span names and is a letter.
 *
 * Every set comparison also asserts non-emptiness: two empty sets are equal, and
 * a vacuous contract guards nothing.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { stripInvisible, BRAHMIC_CONSONANT_RANGES } from "../src/invisible.mjs";
import { cp } from "./test-helpers.mjs";

const IVS17 = cp(0xe0100); // an ideographic variation selector
const HANGUL_FILLER = cp(0x115f);
const BRAILLE_BLANK = cp(0x2800);
const HANGUL_FILLERS = new Set([0x115f, 0x1160, 0x3164, 0xffa0]);

/** Every code point of `ranges` (inclusive), skipping the surrogate block.
 * @param {readonly (readonly [number, number])[]} ranges
 * @returns {number[]} */
const expand = (ranges) => {
  const out = [];
  for (const [start, end] of ranges)
    for (let c = start; c <= end; c++)
      if (c < 0xd800 || c > 0xdfff) out.push(c);
  return out;
};

/**
 * Compare an observed anchor set against a property-derived one over a scan
 * window, reporting the first few discrepancies in each direction and refusing
 * to pass on two empty sets.
 * @param {number[]} window
 * @param {(ch: string) => boolean} observed  via the public API
 * @param {(ch: string) => boolean} expected  via a Unicode property escape
 */
function assertAnchorSetsAgree(window, observed, expected) {
  const hex = (c) => `U+${c.toString(16).toUpperCase()}`;
  const missing = []; // property says anchor, carve-out disagrees
  const extra = []; // carve-out says anchor, property disagrees
  let anchors = 0;
  for (const c of window) {
    const ch = String.fromCodePoint(c);
    const exp = expected(ch);
    if (exp) anchors++;
    if (exp === observed(ch)) continue;
    (exp ? missing : extra).push(hex(c));
  }
  assert.deepEqual(missing.slice(0, 12), [], "property-only anchors");
  assert.deepEqual(extra.slice(0, 12), [], "carve-out-only anchors");
  assert.ok(anchors > 0, "scan window contains no anchors at all (vacuous)");
}

// ─── CJK ideographs (the base of an ideographic variation sequence) ───────────
// Derived set: \p{Unified_Ideograph} plus the two CJK Compatibility Ideograph
// BLOCKS (not Unified_Ideograph, and JS exposes no \p{Block=…}; block bounds are
// immutable under Unicode's stability policy).
const UNIFIED_PLUS_COMPAT =
  /[\p{Unified_Ideograph}\u{F900}-\u{FAFF}\u{2F800}-\u{2FA1F}]/u;
const CJK_SCAN = expand([
  [0x2e00, 0xffff], // radicals, Kangxi, Ext A, URO, compatibility ideographs
  [0x20000, 0x334ff], // Ext B–J and the compatibility supplement
]);

describe("Unicode contract: CJK ideograph anchors", () => {
  it("equal \\p{Unified_Ideograph} ∪ the compatibility-ideograph blocks", () => {
    assertAnchorSetsAgree(
      CJK_SCAN,
      (ch) => stripInvisible(ch + IVS17).includes(IVS17),
      (ch) => UNIFIED_PLUS_COMPAT.test(ch),
    );
  });

  it("cover every ASSIGNED code point the retired hand-written table listed", () => {
    // The table that shipped before the derivation. Its block spans included
    // unassigned padding (U+FA6E, U+2B81E, …) which cannot occur in real text;
    // what matters is that no ASSIGNED character it recognised was lost.
    const retired = expand([
      [0x3400, 0x4dbf],
      [0x4e00, 0x9fff],
      [0xf900, 0xfaff],
      [0x20000, 0x2a6df],
      [0x2a700, 0x2b73f],
      [0x2b740, 0x2b81f],
      [0x2b820, 0x2ceaf],
      [0x2ceb0, 0x2ebef],
      [0x2ebf0, 0x2ee5f],
      [0x2f800, 0x2fa1f],
      [0x30000, 0x3134f],
      [0x31350, 0x323af],
    ]);
    const unassigned = /\p{General_Category=Unassigned}/u;
    const lost = retired.filter((c) => {
      const ch = String.fromCodePoint(c);
      return !unassigned.test(ch) && !UNIFIED_PLUS_COMPAT.test(ch);
    });
    assert.deepEqual(lost, []);
    assert.ok(retired.length > 90_000, "retired table sample is non-vacuous");
  });

  it("add the Extension J ideographs the hand-written table went stale on", () => {
    // The drift the derivation eliminates: the literal table stopped at
    // Extension H, so U+323B0–U+33479 (Unicode 17) could not anchor an IVS.
    for (const c of [0x323b0, 0x33479]) {
      const base = cp(c);
      const input = base + IVS17;
      assert.equal(stripInvisible(input), input, `U+${c.toString(16)}`);
    }
  });

  it("hold only Han letters inside the literal compatibility blocks", () => {
    // The one part of the CJK gate that stays literal, so it gets the drift
    // guard: a future Unicode assigning a non-Han character inside either block
    // fails here instead of silently widening what can anchor a selector.
    const hanLetter = /[\p{Script=Han}&&\p{General_Category=Letter}]/v;
    const unassigned = /\p{General_Category=Unassigned}/u;
    const blocks = expand([
      [0xf900, 0xfaff],
      [0x2f800, 0x2fa1f],
    ]);
    const assigned = blocks.filter(
      (c) => !unassigned.test(String.fromCodePoint(c)),
    );
    const notHanLetter = assigned.filter(
      (c) => !hanLetter.test(String.fromCodePoint(c)),
    );
    assert.deepEqual(notHanLetter, []);
    assert.ok(assigned.length > 0, "compatibility blocks are all unassigned?");
  });
});

// ─── Hangul and Braille anchors ───────────────────────────────────────────────
describe("Unicode contract: blank-filler anchors", () => {
  const BMP = expand([[0x0000, 0xffff]]);

  it("Hangul filler anchors equal \\p{Script=Hangul} minus the fillers", () => {
    assertAnchorSetsAgree(
      BMP,
      (ch) => stripInvisible(HANGUL_FILLER + ch).includes(HANGUL_FILLER),
      (ch) =>
        /\p{Script=Hangul}/u.test(ch) &&
        !HANGUL_FILLERS.has(/** @type {number} */ (ch.codePointAt(0))),
    );
  });

  it("Braille blank anchors equal \\p{Script=Braille} minus the blank", () => {
    assertAnchorSetsAgree(
      BMP,
      (ch) => stripInvisible(ch + BRAILLE_BLANK).includes(BRAILLE_BLANK),
      (ch) => /\p{Script=Braille}/u.test(ch) && ch !== BRAILLE_BLANK,
    );
  });
});

// ─── Brahmic consonants (kept literal — no property escape expresses them) ────
describe("Unicode contract: Brahmic consonant spans", () => {
  const unassigned = /\p{General_Category=Unassigned}/u;

  it("are non-empty and name a script each", () => {
    assert.ok(BRAHMIC_CONSONANT_RANGES.length > 0);
    for (const [script, start, end] of BRAHMIC_CONSONANT_RANGES) {
      assert.equal(typeof script, "string");
      assert.ok(start < end, `${script} span is empty or inverted`);
    }
  });

  for (const [script, start, end] of BRAHMIC_CONSONANT_RANGES) {
    const label = `${script} U+${start.toString(16).toUpperCase()}–U+${end
      .toString(16)
      .toUpperCase()}`;
    it(`holds only ${script} letters: ${label}`, () => {
      const inScript = new RegExp(
        `[\\p{Script=${script}}&&\\p{General_Category=Letter}]`,
        "v",
      );
      const assigned = expand([[start, end]]).filter(
        (c) => !unassigned.test(String.fromCodePoint(c)),
      );
      const foreign = assigned.filter(
        (c) => !inScript.test(String.fromCodePoint(c)),
      );
      assert.deepEqual(
        foreign.map((c) => `U+${c.toString(16).toUpperCase()}`),
        [],
      );
      assert.ok(assigned.length > 0, `${label} is entirely unassigned`);
    });
  }

  it("stay TIGHTER than \\p{Script=…}: an independent vowel is not a conjunct base", () => {
    // Why the spans cannot simply become \p{Script=Devanagari}: that set also
    // holds the independent vowels, which a virama never attaches to, so a
    // vowel + halant + ZWJ would become a preserved (and therefore usable)
    // zero-width channel.
    const A = cp(0x0905); // DEVANAGARI LETTER A, an independent vowel
    const VIRAMA = cp(0x094d);
    const ZWJ = cp(0x200d);
    assert.equal(
      stripInvisible(A + VIRAMA + ZWJ + cp(0x0915)),
      A + VIRAMA + cp(0x0915),
    );
    // …while the same shape on a real consonant IS preserved.
    const KA = cp(0x0915);
    const conjunct = KA + VIRAMA + ZWJ + KA;
    assert.equal(stripInvisible(conjunct), conjunct);
  });
});

// ─── Negative corpus: legitimate multi-script text, zero findings ─────────────
// The direction that matters. Every entry is ordinary human text; a sanitizer
// that rewrites any of it has removed content the model needed.
describe("negative corpus: legitimate multi-script text is untouched", () => {
  const CORPUS = {
    "Chinese prose": "维基百科是一个多语言的百科全书协作计划。",
    "Japanese prose with kana and kanji":
      "東京都は日本の首都であり、人口は約一千四百万人です。",
    "Japanese with an ideographic variation sequence": `葛${IVS17}城市は奈良県にあります。`,
    "Traditional Chinese with a compatibility ideograph":
      "北大寺、﨑陽、龍谷。",
    "Korean prose": "한국어 위키백과는 누구나 참여할 수 있는 백과사전입니다.",
    "Korean with jamo": "한글의 자모는 ㄱ, ㄴ, ㄷ 그리고 ㅏ, ㅑ 입니다.",
    "Hindi (Devanagari) with conjuncts":
      "हिन्दी भारत की सबसे अधिक बोली जाने वाली भाषा है।",
    "Marathi with an explicit ZWJ half-form": "क्‍ष रचना",
    "Bengali prose": "বাংলা ভাষা দক্ষিণ এশিয়ার একটি প্রধান ভাষা।",
    "Tamil prose": "தமிழ் மொழி உலகின் மிகப் பழமையான மொழிகளில் ஒன்று.",
    "Kannada prose": "ಕನ್ನಡ ಭಾಷೆ ಕರ್ನಾಟಕದ ಅಧಿಕೃತ ಭಾಷೆಯಾಗಿದೆ.",
    "Sinhala prose": "සිංහල භාෂාව ශ්‍රී ලංකාවේ ප්‍රධාන භාෂාවකි.",
    "Persian with a ZWNJ": "کتاب‌های خوب را می‌خوانم.",
    // The harakat sits in the SAME grapheme cluster as the ZWNJ that follows
    // its letter, so this is the shape the cluster-charged budget must not clip.
    "vocalised Persian with a ZWNJ": "مِیْ‌خوانم و کِتاب‌هایِ خوب",
    "emoji ZWJ family and couple": "👨‍👩‍👧‍👦 and 👩‍❤️‍👨 at the park",
    "emoji ZWJ profession with skin tone": "👩🏽‍🚒 👨🏿‍💻 👩‍🔬",
    "flag ZWJ sequences": "🏳️‍🌈 🏴‍☠️ 🏳️‍⚧️",
    // Two flags = 12 tag chars, inside the 16-char document preserve budget. A
    // third overruns it and is stripped — pre-existing budget behaviour this PR
    // does not change (test/invisible.test.mjs pins it).
    "subregional flags": "🏴󠁧󠁢󠁳󠁣󠁴󠁿 and 🏴󠁧󠁢󠁷󠁬󠁳󠁿",
    keycaps: "1️⃣ 2️⃣ 3️⃣ #️⃣ *️⃣",
    "Braille with blank cells": "⠓⠑⠇⠇⠕⠀⠺⠕⠗⠇⠙",
    "mixed-script sentence":
      "The 東京 office ships 한국어 and हिन्दी builds 👩‍💻 daily.",
  };

  for (const [name, text] of Object.entries(CORPUS)) {
    it(`leaves ${name} byte-identical`, () => {
      assert.equal(stripInvisible(text), text);
    });
  }
});
