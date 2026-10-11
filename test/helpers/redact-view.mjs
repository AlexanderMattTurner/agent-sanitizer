/**
 * A fake redactor map for rehydrate fixtures, shaped exactly like the real
 * engine's: offsets in CODE POINTS. rehydrate brands the map `"codePoint"` and
 * converts it to UTF-16 itself (view-map.mjs's toUtf16View), so a fixture
 * emitting UTF-16 starts is fed through the conversion as if it were code
 * points — invisible on ASCII text, a mis-anchored pair on the first astral
 * character before a secret.
 */
import { occurrences } from "../../src/view-map.mjs";

/**
 * Build a redactMap view from already-Layer-1-cleaned text: replace each
 * secret occurrence with its placeholder, emitting ordered (placeholder,
 * original, start) pairs at their code-point view offsets.
 * @param {string} cleaned
 * @param {{value: string, placeholder: string}[]} secrets
 * @returns {{text: string, pairs: {placeholder: string, original: string, start: number}[]}}
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
  return { text, pairs };
}
