#!/usr/bin/env node
/**
 * Generate src/unicode-properties.mjs from the vendored UCD slices under
 * scripts/data/ (see ./lib/ucd.mjs for why every version-dependent property is
 * pinned rather than read from the runtime).
 *
 * The invisible-char carve-out decides whether an invisible does rendering work
 * from the Unicode properties of its neighbours: an emoji joiner needs an
 * Extended_Pictographic (or Emoji_Modifier) on its left and a pictograph on its
 * right, an ideographic variation selector needs a Unified_Ideograph base, and a
 * blank filler needs a Braille or Hangul neighbour. Whether a preserved one
 * draws on the cover budget reads two more: a VS16 completing a text-default
 * emoji (Emoji but not Emoji_Presentation) and a ZWJ inside an RGI emoji ZWJ
 * sequence are part of a registered glyph, and are exempt. Each of those sets grows
 * with Unicode, so a live `\p{…}` made the carve-out on Node 22.22 (Unicode 16)
 * strip the Extension J ideograph sequences Node 22.23 (Unicode 17) preserved.
 * This compiles them into range tables instead.
 *
 * test/unicode-properties.test.mjs re-derives from the same slices and fails if
 * the committed module drifts.
 *
 * Run from the repo root: `node scripts/gen-unicode-properties.mjs`. The output
 * is already in Prettier's format, so it is committed exactly as written.
 */
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import {
  UNICODE_VERSION,
  codePointsOf,
  readUcdSlice,
  spansOf,
} from "./lib/ucd.mjs";

/**
 * The range tables, by the export name each gets in the generated module.
 * Pure over the slices so the contract test compares it with the module.
 * @returns {Record<string, Array<[number, number]>>}
 */
export function deriveUnicodeProperties() {
  const emoji = readUcdSlice("emoji-data.Pinned.json")["emoji-data"];
  const propList = readUcdSlice("PropList.Pinned.json").PropList;
  const scripts = readUcdSlice("Scripts.Pinned.json").Scripts;
  /** @param {Array<{ range: string[] }>} entries @param {string} key @param {string} value */
  const where = (entries, key, value) =>
    spansOf(entries, (entry) => entry[key] === value);
  const presentation = new Set(
    codePointsOf(where(emoji, "property", "Emoji_Presentation")),
  );
  return {
    EXTENDED_PICTOGRAPHIC: where(emoji, "property", "Extended_Pictographic"),
    EMOJI_MODIFIER: where(emoji, "property", "Emoji_Modifier"),
    EMOJI_TEXT_DEFAULT: spansOfCodePoints(
      codePointsOf(where(emoji, "property", "Emoji")).filter(
        (cp) => !presentation.has(cp),
      ),
    ),
    UNIFIED_IDEOGRAPH: where(propList, "property", "Unified_Ideograph"),
    SCRIPT_BRAILLE: where(scripts, "script", "Braille"),
    SCRIPT_HANGUL: where(scripts, "script", "Hangul"),
  };
}

/**
 * Ascending code points as merged `[start, end]` spans.
 * @param {number[]} cps
 * @returns {Array<[number, number]>}
 */
function spansOfCodePoints(cps) {
  /** @type {Array<[number, number]>} */
  const spans = [];
  for (const cp of cps) {
    const last = spans[spans.length - 1];
    if (last && cp === last[1] + 1) last[1] = cp;
    else spans.push([cp, cp]);
  }
  return spans;
}

const ZWJ = 0x200d;
const VS16 = 0xfe0f;

/**
 * Every RGI emoji ZWJ sequence as the key src/invisible.mjs looks its chains up
 * by: the sequence's components, lowercase hex, space-separated, with the
 * joiners, the VS16s and the skin-tone modifiers left out. Sorted and unique.
 *
 * Leaving the VS16s out lets a sequence written without them (common, and
 * rendered the same by most platforms) find its entry; the VS16s themselves are
 * exempt on their own rule, which this checks covers every VS16 an RGI sequence
 * holds. Leaving the modifiers out folds each sequence's five skin tones into
 * one entry; a modifier is a visible code point, so nothing about the joiners'
 * exemption turns on it.
 * @returns {string[]}
 */
export function deriveRgiEmojiZwjKeys() {
  const { EMOJI_MODIFIER, EMOJI_TEXT_DEFAULT } = deriveUnicodeProperties();
  const modifiers = new Set(codePointsOf(EMOJI_MODIFIER));
  const textDefault = new Set(codePointsOf(EMOJI_TEXT_DEFAULT));
  const keys = new Set();
  for (const { sequence } of readUcdSlice("emoji-zwj-sequences.Rgi.json")[
    "emoji-zwj-sequences"
  ]) {
    const cps = sequence.split(" ").map((hex) => parseInt(hex, 16));
    cps.forEach((cp, i) => {
      if (cp === VS16 && !textDefault.has(cps[i - 1]))
        throw new Error(
          `RGI sequence ${sequence}: VS16 after a non-text-default U+${cps[i - 1]?.toString(16)}`,
        );
    });
    const components = cps.filter(
      (cp) => cp !== ZWJ && cp !== VS16 && !modifiers.has(cp),
    );
    if (components.length < 2 || !cps.includes(ZWJ))
      throw new Error(`RGI sequence ${sequence} is not a ZWJ chain`);
    keys.add(components.map((cp) => cp.toString(16)).join(" "));
  }
  return [...keys].sort();
}

/** @param {Array<[number, number]>} spans */
const rows = (spans) =>
  spans
    .map(
      ([start, end]) => `  [0x${start.toString(16)}, 0x${end.toString(16)}],`,
    )
    .join("\n");

/** Build the full source text of src/unicode-properties.mjs. */
export function renderUnicodeProperties() {
  const tables = Object.entries(deriveUnicodeProperties())
    .map(
      ([name, spans]) =>
        `/** @type {ReadonlyArray<readonly [number, number]>} */\nexport const ${name} = [\n${rows(spans)}\n];`,
    )
    .join("\n\n");
  const keys = deriveRgiEmojiZwjKeys()
    .map((key) => `  ${JSON.stringify(key)},`)
    .join("\n");
  return `/**
 * GENERATED by scripts/gen-unicode-properties.mjs from the pinned UCD ${UNICODE_VERSION} — DO NOT EDIT.
 *
 * The Unicode properties src/invisible.mjs's carve-out reads, PINNED so the
 * carve-out answers the same on every Node whatever its ICU's Unicode version.
 * Regenerate with \`node scripts/gen-unicode-properties.mjs\`;
 * test/unicode-properties.test.mjs fails if this drifts from the vendored slices.
 */

export const UNICODE_VERSION = ${JSON.stringify(UNICODE_VERSION)};

// GENERATED UCD data, not hand-written logic: each table is the sorted, merged
// [start, end] spans of one property. Pinned by the SSOT round-trip in
// test/unicode-properties.test.mjs, so Stryker skips the numeric literals.
// Stryker disable all
${tables}

/**
 * Every RGI emoji ZWJ sequence (emoji-zwj-sequences.txt), keyed by its
 * components in lowercase hex without the joiners, VS16s or skin-tone modifiers.
 * @type {ReadonlyArray<string>}
 */
export const RGI_EMOJI_ZWJ_KEYS = [
${keys}
];
// Stryker restore all

/**
 * True when \`cp\` lies in one of \`spans\` (sorted, non-overlapping). A negative
 * \`cp\` — the "no neighbour" sentinel — lies in none.
 * @param {ReadonlyArray<readonly [number, number]>} spans
 * @param {number} cp
 * @returns {boolean}
 */
export function inSpans(spans, cp) {
  let lo = 0;
  let hi = spans.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (cp < spans[mid][0]) hi = mid - 1;
    else if (cp > spans[mid][1]) lo = mid + 1;
    else return true;
  }
  return false;
}
`;
}

export const MODULE_PATH = fileURLToPath(
  new URL("../src/unicode-properties.mjs", import.meta.url),
);

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  writeFileSync(MODULE_PATH, renderUnicodeProperties());
  console.log(`wrote ${MODULE_PATH} (Unicode ${UNICODE_VERSION})`);
}
