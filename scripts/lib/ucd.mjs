/**
 * The pinned Unicode Character Database every generator reads: the exact-pinned
 * `@unicode/unicode-17.0.0` devDependency.
 *
 * A live `\p{…}` answers from the running Node's ICU, so the same release once
 * stripped a different `Cf` set on two patch releases of one Node line. Every
 * property whose membership can move is read from this package instead and
 * compiled into committed modules that drift tests regenerate and compare;
 * test/unicode-property-pin.test.mjs fails on a live property escape. To move
 * to a new Unicode, bump the package and `pnpm install` (see gen-unicode.mjs).
 */
const PACKAGE = "@unicode/unicode-17.0.0";

export const UNICODE_VERSION = PACKAGE.slice("@unicode/unicode-".length);

/** Every value name of every property the package carries, by property. */
export const PROPERTY_VALUES = /** @type {Record<string, string[]>} */ (
  (await import(PACKAGE)).default
);

/**
 * The sorted, merged `[start, end]` spans of one property value, named as the
 * package lays it out: `"Binary_Property/Extended_Pictographic"`.
 * @param {string} path
 * @returns {Promise<Array<[number, number]>>}
 */
export async function ucdSpans(path) {
  /** @type {Array<{ begin: number, end: number }>} end-exclusive */
  const ranges = (await import(`${PACKAGE}/${path}/ranges.mjs`)).default;
  const spans = spansOf(
    codePointsOf(ranges.map(({ begin, end }) => [begin, end - 1])).sort(
      (a, b) => a - b,
    ),
  );
  if (spans.length === 0) throw new Error(`${PACKAGE}/${path} is empty`);
  return spans;
}

/**
 * Every code point of `spans`.
 * @param {ReadonlyArray<readonly [number, number]>} spans
 * @returns {number[]}
 */
export function codePointsOf(spans) {
  const out = [];
  for (const [start, end] of spans)
    for (let c = start; c <= end; c++) out.push(c);
  return out;
}

/**
 * Ascending, distinct code points as merged `[start, end]` spans.
 * @param {number[]} cps
 * @returns {Array<[number, number]>}
 */
export function spansOf(cps) {
  /** @type {Array<[number, number]>} */
  const spans = [];
  for (const cp of cps) {
    const last = spans[spans.length - 1];
    if (last && cp === last[1] + 1) last[1] = cp;
    else spans.push([cp, cp]);
  }
  return spans;
}
