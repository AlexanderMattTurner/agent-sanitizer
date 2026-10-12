/**
 * One payload verdict, four surfaces. The prompt gate, the instruction-file
 * scanner and the write path each decide "is this invisible content a covert
 * channel". The prompt gate and the write path read `payloadVerdict`; this
 * pins that the surfaces AGREE:
 *
 *   - a negative corpus of real-world script and emoji text (each joiner or
 *     selector doing rendering work) that every surface leaves alone, Layer 1
 *     and the scanner included — the precision half;
 *   - a stego corpus the verdict, the prompt gate and the write path catch —
 *     the recall half, without which the negative half passes on a verdict
 *     that never says yes. The scanner keeps its own count (see below).
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
const CHECKED = `- ${s(0x2714, 0xfe0f)} done\n`;
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
      // scanText is not held to this half: it counts only carve-out payload,
      // not the over-budget joiner surplus, so it misses a ZWNJ-per-letter
      // channel. Routing it through payloadVerdict needs the emoji-dense
      // budget false positive fixed first, or it flags flag-emoji documents.
      assert.equal(payloadVerdict(text).payloadCapable, true);
      assert.equal(classifyPrompt(text).action, "block");
      assert.deepEqual(authored(text)?.changed, [
        "content (invisible characters)",
      ]);
      assert.notEqual(applyLayer1(text).cleaned, text);
    });
});
