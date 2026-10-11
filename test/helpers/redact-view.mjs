/**
 * A fake redactor map for rehydrate fixtures, shaped exactly like the real
 * engine's: offsets in CODE POINTS, carried in a FileView branded
 * `"codePoint"`. The brand runs view-map's own range and ordering checks in
 * that space, so the fixture states its unit instead of implying it; rehydrate
 * then converts to UTF-16 itself (toUtf16View), as it does for the real map.
 */
import { makeFileView, occurrences } from "../../src/view-map.mjs";

/**
 * Build a redactMap view from already-Layer-1-cleaned text: replace each
 * secret occurrence with its placeholder, emitting ordered (placeholder,
 * original, start) pairs at their code-point view offsets.
 * @param {string} cleaned
 * @param {{value: string, placeholder: string}[]} secrets
 * @returns {import("../../src/view-map.mjs").FileView<"codePoint">}
 */
export function mkView(cleaned, secrets) {
  const hits = [];
  for (const { value, placeholder } of secrets)
    for (const index of occurrences(cleaned, value))
      hits.push({ index, value, placeholder });
  hits.sort((a, b) => a.index - b.index);

  let text = "";
  let last = 0;
  const pairs = [];
  for (const { index, value, placeholder } of hits) {
    text += cleaned.slice(last, index);
    pairs.push({ placeholder, original: value, start: [...text].length });
    text += placeholder;
    last = index + value.length;
  }
  text += cleaned.slice(last);
  return makeFileView(text, pairs, "codePoint");
}
