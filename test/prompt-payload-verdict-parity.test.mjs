/**
 * One payload verdict, four surfaces. The prompt gate, the instruction-file
 * scanner and the write path each decide "is this invisible content a covert
 * channel", and all three read `payloadVerdict`; this pins that the surfaces
 * AGREE:
 *
 *   - a negative corpus of real-world script and emoji text (each joiner or
 *     selector doing rendering work) that every surface leaves alone, Layer 1
 *     included — the precision half. Its emoji documents run well past the
 *     carve-out's cover allowance, which a registered glyph's own invisibles
 *     no longer draw on;
 *   - a stego corpus every surface catches — the recall half, without which
 *     the negative half passes on a verdict that never says yes. Its emoji
 *     entries are the same shapes with the registration taken away.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { payloadVerdict } from "../src/invisible.mjs";
import { scanText } from "../src/instructions.mjs";
import { classifyPrompt } from "../src/prompt.mjs";
import { applyLayer1 } from "../src/layer1.mjs";
import { sanitizeAuthoredContent } from "../claude-hooks/lib/authored-content.mjs";

const s = (...codePoints) => String.fromCodePoint(...codePoints);
const ZWNJ = s(0x200c);
const PROSE = "This is a perfectly ordinary sentence of prose. ";
const FAMILY = s(0x1f468, 0x200d, 0x1f469, 0x200d, 0x1f467, 0x200d, 0x1f466);
const SCOTLAND = s(
  0x1f3f4,
  0xe0067,
  0xe0062,
  0xe0073,
  0xe0063,
  0xe0074,
  0xe007f,
);
const WALES = s(0x1f3f4, 0xe0067, 0xe0062, 0xe0077, 0xe006c, 0xe0073, 0xe007f);
const ENGLAND = s(
  0x1f3f4,
  0xe0067,
  0xe0062,
  0xe0065,
  0xe006e,
  0xe0067,
  0xe007f,
);
const CHECKED = `- ${s(0x2714, 0xfe0f)} done\n`;
const RAINBOW = s(0x1f3f3, 0xfe0f, 0x200d, 0x1f308);
// Balinese KA, adeg-adeg (the virama), ZWJ, KA: a conjunct request on every
// unit, so each joiner is individually legitimate and only the count is not.
const BALINESE_CONJUNCT = s(0x1b13, 0x1b44, 0x200d, 0x1b13);
// Formal Persian: a ZWNJ in roughly one word in three, which is ordinary
// orthography (the plural suffix, the verb prefix), not a channel.
const PERSIAN = `ما می${ZWNJ}خواهیم این کتاب${ZWNJ}ها را به دانش${ZWNJ}آموزان بدهیم و آن${ZWNJ}ها خوشحال می${ZWNJ}شوند. `;

/** @type {ReadonlyArray<[string, string]>} */
const LEGITIMATE = [
  [
    "emoji ZWJ sequences",
    `${s(0x1f469, 0x200d, 0x1f4bb)} wrote it; ${s(0x1f468, 0x200d, 0x1f373)} ate. `.repeat(
      4,
    ),
  ],
  [
    "ten family emoji in prose",
    PROSE.repeat(5) + `${PROSE}${FAMILY} `.repeat(10),
  ],
  ["subdivision flags", `Scotland ${SCOTLAND} and Wales ${WALES} play today.`],
  [
    "keycaps",
    Array.from(
      { length: 9 },
      (_, i) => `${s(0x31 + i, 0xfe0f, 0x20e3)} step`,
    ).join("\n"),
  ],
  ["a checklist of thirty emoji-style ticks", CHECKED.repeat(30)],
  // Every invisible below is part of a glyph's spelling: an RGI flag's tags,
  // the VS16 a text-default emoji needs, a ZWJ between two pictographs. Each
  // document holds more of them than the cover allowance admits.
  ["thirty rainbow-flag lines", `- ${RAINBOW} pride\n`.repeat(30)],
  ["a hundred rainbow flags in a row", RAINBOW.repeat(100)],
  [
    "a fixture table of subdivision flags",
    `| ${SCOTLAND} | ${ENGLAND} | ${WALES} |\n`.repeat(30),
  ],
  ["sixty family emoji lines", `- ${FAMILY} home\n`.repeat(60)],
  [
    "a hundred skin-toned ZWJ sequences",
    `${s(0x1f469, 0x1f3fd, 0x200d, 0x1f4bb)} codes. `.repeat(100),
  ],
  ["a hundred warning lines", `- ${s(0x26a0, 0xfe0f)} careful\n`.repeat(100)],
  // Not RGI, but GB11 joins any two pictographs (THREAT-MODEL.md's residual).
  [
    "an unregistered ZWJ chain on every line",
    `- ${s(0x1f600, 0x200d, 0x1f600)} hi\n`.repeat(100),
  ],
  [
    "a hundred keycaps",
    Array.from(
      { length: 100 },
      (_, i) => `${s(0x30 + (i % 10), 0xfe0f, 0x20e3)} step`,
    ).join("\n"),
  ],
  [
    "a flag-and-family changelog in Persian",
    `${PERSIAN}${RAINBOW} ${FAMILY} ${SCOTLAND}\n`.repeat(40),
  ],
  ["a long Persian paragraph", PERSIAN.repeat(100)],
  [
    "Arabic with a display ZWJ",
    `هذا نص عربي عادي يستخدم ${s(0x644, 0x200d)} للعرض فقط. `.repeat(3),
  ],
  [
    "Bengali RA with ya-phala",
    `${s(0x9b0, 0x200d, 0x9cd, 0x9af, 0x9be, 0x9ac)} বাহিনী এবং শব্দ। `.repeat(
      5,
    ),
  ],
  [
    "Devanagari half forms",
    `${s(0x915, 0x94d, 0x200d, 0x937)} और ${s(0x930, 0x94d, 0x200d, 0x92f)} शब्द। `.repeat(
      5,
    ),
  ],
  [
    "Sinhala yansaya",
    `${s(0xdc1, 0xdca, 0x200d, 0xdbb, 0xdd3)} ලංකාව `.repeat(5),
  ],
  [
    "CJK ideographic variation sequences",
    `${s(0x845b, 0xe0100)}飾区と${s(0x8fbb, 0xe0100)}さん。`.repeat(5),
  ],
  [
    "Hindi prose with explicit half forms",
    `हिन्दी में ${s(0x915, 0x94d, 0x200d, 0x937)} और ${s(0x924, 0x94d, 0x200d, 0x930)} जैसे आधे रूप लिखे जाते हैं। `.repeat(
      20,
    ),
  ],
  [
    // "Om Swastyastu" with adeg-adeg conjuncts, then a ZWJ-requested form.
    "Balinese prose",
    `${s(0x1b12, 0x1b01, 0x1b32, 0x1b44, 0x1b2f, 0x1b32, 0x1b44, 0x1b22, 0x1b44, 0x1b2c, 0x1b32, 0x1b44, 0x1b22, 0x1b38)} ${s(0x1b27, 0x1b44, 0x200d, 0x1b2d, 0x1b1a)} `.repeat(
      20,
    ),
  ],
  [
    "Mongolian free variation selectors",
    `${s(0x1820, 0x180b)} ${s(0x1820, 0x180c)} `.repeat(5),
  ],
];

/** @type {ReadonlyArray<[string, string]>} */
const STEGO = [
  [
    "a tag-character run",
    `hi ${Array.from({ length: 20 }, (_, i) => s(0xe0041 + i)).join("")} bye`,
  ],
  [
    "a ZWNJ between every Persian letter",
    `${s(0x628)}${ZWNJ}`.repeat(200) + s(0x628),
  ],
  ["zero-width spaces scattered through text", `a${s(0x200b)}`.repeat(40)],
  ["a Balinese conjunct chain", BALINESE_CONJUNCT.repeat(300)],
  // The emoji shapes of the negative corpus with the glyph removed: a VS16 on
  // an emoji that already presents as one changes nothing on screen, and a
  // ZWJ after a bare skin tone joins no pictograph.
  [
    "a redundant VS16 on every line",
    `- ${s(0x1f600, 0xfe0f)} hi\n`.repeat(100),
  ],
  [
    "a ZWJ after a bare skin tone on every line",
    `- x${s(0x1f3fd, 0x200d, 0x1f600)} hi\n`.repeat(100),
  ],
];

/** @param {string} text */
const authored = (text) => sanitizeAuthoredContent("Write", { content: text });

describe("payload verdict parity: legitimate text is left alone everywhere", () => {
  for (const [name, text] of LEGITIMATE)
    it(name, () => {
      assert.equal(payloadVerdict(text).payloadCapable, false);
      assert.deepEqual(scanText(text), []);
      assert.deepEqual(classifyPrompt(text), { action: "pass" });
      assert.equal(authored(text), null);
      assert.deepEqual(applyLayer1(text), {
        cleaned: text,
        deAnsi: text,
        found: [],
        ansiKinds: [],
      });
    });

  it("Braille art is no payload on any verdict surface", () => {
    // Layer 1's blank-filler run cap still trims its runs of U+2800; that is
    // a separate policy from the payload verdict and is not asserted here.
    const art = `${s(0x2800, 0x2800, 0x28ff, 0x28ff, 0x2800, 0x2800)}\n`.repeat(
      8,
    );
    assert.equal(payloadVerdict(art).payloadCapable, false);
    assert.deepEqual(scanText(art), []);
    assert.deepEqual(classifyPrompt(art), { action: "pass" });
    assert.equal(authored(art), null);
  });
});

describe("payload verdict parity: a covert channel is caught everywhere", () => {
  for (const [name, text] of STEGO)
    it(name, () => {
      assert.equal(payloadVerdict(text).payloadCapable, true);
      assert.notDeepEqual(scanText(text), []);
      assert.equal(classifyPrompt(text).action, "block");
      assert.deepEqual(authored(text)?.changed, [
        "content (invisible characters)",
      ]);
      assert.notEqual(applyLayer1(text).cleaned, text);
    });
});

describe("payload verdict: a gate keeps one run, not one per run", () => {
  // Short runs of ten zero-width spaces, one visible byte apart: every run is a
  // payload run, so a verdict that materialized them all would hold one record
  // and one substring per eleven bytes of hostile input.
  const text = `${s(0x200b).repeat(10)}x`.repeat(2000);

  it("returns only the first run", () => {
    const verdict = payloadVerdict(text);
    assert.deepEqual(Object.keys(verdict).sort(), [
      "firstRun",
      "invisibleCount",
      "payloadCapable",
    ]);
    assert.deepEqual(verdict.firstRun, {
      index: 0,
      text: s(0x200b).repeat(10),
      charCount: 10,
    });
    assert.equal(verdict.payloadCapable, true);
  });

  it("reports no run for text that has none", () => {
    assert.equal(payloadVerdict(PERSIAN).firstRun, null);
  });
});
