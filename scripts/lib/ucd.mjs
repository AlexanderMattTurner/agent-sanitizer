/**
 * The pinned Unicode Character Database every generator reads: the exact-pinned
 * `@unicode/unicode-17.0.0` devDependency.
 *
 * Unicode property membership changes between Unicode versions, and a live
 * `\p{…}` escape answers from whatever ICU the running Node bundles — so the
 * same package version used to strip a different `Cf` set, anchor a different
 * set of CJK ideographs, and generate different tables on two patch releases of
 * one supported Node line. Every property whose membership can move is instead
 * read from this one package and compiled into committed data modules, which a
 * drift test regenerates and compares. The runtime's own Unicode version then
 * decides nothing. test/unicode-property-pin.test.mjs fails on a live property
 * escape in `src/`, `claude-hooks/` or a `scripts/gen-*.mjs` generator.
 */
const PACKAGE = "@unicode/unicode-17.0.0";

export const UNICODE_VERSION = PACKAGE.slice("@unicode/unicode-".length);

/** Every value name of every property the package carries, by property. */
export const PROPERTY_VALUES = /** @type {Record<string, string[]>} */ (
  (await import(PACKAGE)).default
);

/**
 * The sorted, merged `[start, end]` spans of one property value, named as the
 * package lays it out: `"Binary_Property/Extended_Pictographic"`,
 * `"Script/Braille"`, `"General_Category/Format"`.
 * @param {string} path
 * @returns {Promise<Array<[number, number]>>}
 */
export async function ucdSpans(path) {
  /** @type {Array<{ begin: number, end: number }>} end-exclusive */
  const ranges = (await import(`${PACKAGE}/${path}/ranges.mjs`)).default;
  /** @type {Array<[number, number]>} */
  const merged = [];
  for (const { begin, end } of [...ranges].sort((a, b) => a.begin - b.begin)) {
    const last = merged[merged.length - 1];
    if (last && begin <= last[1] + 1) last[1] = Math.max(last[1], end - 1);
    else merged.push([begin, end - 1]);
  }
  if (merged.length === 0) throw new Error(`${PACKAGE}/${path} is empty`);
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
