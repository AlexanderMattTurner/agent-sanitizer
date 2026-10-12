/**
 * The pinned Unicode Character Database every generator reads.
 *
 * Unicode property membership changes between Unicode versions, and a live
 * `\p{…}` escape answers from whatever ICU the running Node bundles — so the
 * same package version used to strip a different `Cf` set, anchor a different
 * set of CJK ideographs, and generate different tables on two patch releases of
 * one supported Node line. Every property whose membership can move is instead
 * read from the vendored slices under `scripts/data/` (see its README), all cut
 * from ONE Unicode release by scripts/extract-ucd-slices.mjs, and compiled into committed data modules. The
 * runtime's own Unicode version then decides nothing.
 *
 * test/unicode-property-pin.test.mjs fails on a live property escape in
 * `src/`, `claude-hooks/` or a `scripts/gen-*.mjs` generator.
 */
import { readFileSync } from "node:fs";

// The Unicode version of every vendored scripts/data slice.
// Bump it together with a re-extraction of ALL the slices: a mixed set would
// answer some properties from one version and some from another.
export const UNICODE_VERSION = "17.0.0";

/**
 * Read + parse a vendored UCD slice under scripts/data/.
 * @param {string} name
 * @returns {any}
 */
export function readUcdSlice(name) {
  return JSON.parse(
    readFileSync(new URL(`../data/${name}`, import.meta.url), "utf8"),
  );
}

/**
 * Parse a UCD JSON `range` field (`["0640"]` or `["0883","0885"]`) into a
 * numeric `[start, end]` pair.
 * @param {string[]} range
 * @returns {[number, number]}
 */
export function parseRange(range) {
  const start = parseInt(range[0], 16);
  const end = parseInt(range[1] ?? range[0], 16);
  return [start, end];
}

/**
 * The sorted, merged `[start, end]` spans of the slice entries `select` keeps.
 * @param {Array<{ range: string[] }>} entries
 * @param {(entry: any) => boolean} select
 * @returns {Array<[number, number]>}
 */
export function spansOf(entries, select) {
  const sorted = entries
    .filter(select)
    .map(({ range }) => parseRange(range))
    .sort((a, b) => a[0] - b[0]);
  /** @type {Array<[number, number]>} */
  const merged = [];
  for (const [start, end] of sorted) {
    const last = merged[merged.length - 1];
    if (last && start <= last[1] + 1) last[1] = Math.max(last[1], end);
    else merged.push([start, end]);
  }
  return merged;
}

/**
 * Every code point of `spans`, ascending.
 * @param {ReadonlyArray<readonly [number, number]>} spans
 * @returns {number[]}
 */
export function codePointsOf(spans) {
  const out = [];
  for (const [start, end] of spans)
    for (let c = start; c <= end; c++) out.push(c);
  return out;
}
