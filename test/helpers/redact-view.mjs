/**
 * A fake redactor map for rehydrate fixtures, shaped like the real engine's:
 * offsets in CODE POINTS, in a FileView branded `"codePoint"` so view-map's
 * range checks run in that space.
 */
import { makeFileView, occurrences } from "../../src/view-map.mjs";

/**
 * Build a redactMap view from Layer-1-cleaned text: replace each secret
 * occurrence with its placeholder, emitting ordered pairs at code-point offsets.
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
