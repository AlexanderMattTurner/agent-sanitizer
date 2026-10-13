/**
 * Generate src/joining-type.mjs from the pinned UCD package (see
 * scripts/lib/ucd.mjs).
 *
 * The invisible-char carve-out preserves ZWNJ/ZWJ only where they do real
 * rendering work. That is a SYNTACTIC property of the neighbouring characters,
 * not a guess from a count: a ZWNJ suppresses a cursive join, so it is
 * meaningful exactly at a join boundary (Arabic-family scripts), and an
 * Indic joiner is meaningful only immediately after a virama. Both facts live
 * in the UCD:
 *   - Joining_Type                           → the cursive join algorithm.
 *   - Indic_Syllabic_Category = Virama       → the Indic joiner trigger.
 *   - Indic_Syllabic_Category = Consonant    → the base a virama may sit on.
 *   - Script of each virama                  → whose consonants count.
 *
 * ECMAScript regex exposes neither property, so we compile the three range
 * tables into a data module; `test/joining-type.test.mjs` re-derives them from
 * the same package. The module is git-ignored and generated at install, pack and
 * build time (scripts/gen-unicode.mjs), never committed.
 *
 * Run: `pnpm gen:joining-type`.
 */
import { fileURLToPath } from "node:url";

import {
  PROPERTY_VALUES,
  UNICODE_VERSION,
  codePointsOf,
  ucdSpans,
} from "./lib/ucd.mjs";
import { writeGenerated } from "./lib/write-generated.mjs";

/** The Joining_Type values the table carries, by tag; U is the default. The
 * package lists only ArabicShaping.txt's explicit entries (see loadUcd). */
const JOINING_TAGS = {
  Join_Causing: "C",
  Dual_Joining: "D",
  Right_Joining: "R",
  Left_Joining: "L",
  Transparent: "T",
};

/** Merge adjacent/overlapping same-type ranges and sort by start.
 * @param {Array<[number, number, string]>} ranges  [start, end, tag]
 * @returns {Array<[number, number, string]>}
 */
function normalize(ranges) {
  const sorted = [...ranges].sort((a, b) => a[0] - b[0]);
  /** @type {Array<[number, number, string]>} */
  const merged = [];
  for (const [start, end, tag] of sorted) {
    const last = merged[merged.length - 1];
    if (last && last[2] === tag && start <= last[1] + 1) {
      last[1] = Math.max(last[1], end);
      continue;
    }
    merged.push([start, end, tag]);
  }
  return merged;
}

/**
 * @typedef {{ range: [number, number], script: string }} ScriptSpan
 * @typedef {{
 *   joining: Array<[number, number, string]>,
 *   virama: Array<[number, number]>,
 *   consonant: Array<[number, number]>,
 *   scripts: ScriptSpan[],
 *   version: string,
 * }} Ucd
 */

/**
 * Derive the three range tables from the loaded UCD. Pure so the contract test
 * can call it on the same inputs and compare with the generated module.
 * @param {Ucd} ucd
 * @returns {{ joining: Array<[number, number, string]>, virama: Array<[number, number]>, brahmic: Array<[number, number, string]> }}
 */
export function deriveTables({ joining, virama, consonant, scripts }) {
  return {
    joining: normalize(joining),
    virama,
    brahmic: deriveBrahmic(consonant, viramaScripts(virama, scripts), scripts),
  };
}

/**
 * The scripts whose consonants count as a virama base: exactly those owning an
 * Indic_Syllabic_Category=Virama code point (Khmer's coeng and Thai's phinthu
 * are not Virama, so they stay out). Throws on a virama with no Script rather
 * than silently dropping its script's consonants.
 * @param {ReadonlyArray<readonly [number, number]>} virama
 * @param {ScriptSpan[]} scripts
 * @returns {string[]} script names, sorted
 */
export function viramaScripts(virama, scripts) {
  const names = new Set();
  for (const [start, end] of virama)
    for (let cp = start; cp <= end; cp++) {
      const span = scripts.find(
        ({ range }) => cp >= range[0] && cp <= range[1],
      );
      if (!span)
        throw new Error(`virama U+${cp.toString(16)} has no Script entry`);
      names.add(span.script);
    }
  return [...names].sort();
}

/**
 * Script-tagged consonant spans: every Indic_Syllabic_Category=Consonant code
 * point whose Script is one of `wantedScripts`, merged into runs. Script comes
 * from the pinned package, never the runtime's `\p{Script=…}`.
 * @param {ReadonlyArray<readonly [number, number]>} consonant
 * @param {string[]} wantedScripts
 * @param {ScriptSpan[]} scripts
 * @returns {Array<[number, number, string]>}
 */
function deriveBrahmic(consonant, wantedScripts, scripts) {
  const wanted = new Set(wantedScripts);
  /** @type {Map<number, string>} */
  const scriptOf = new Map();
  for (const { range, script } of scripts)
    if (wanted.has(script))
      for (const cp of codePointsOf([range])) scriptOf.set(cp, script);
  /** @type {Array<[number, number, string]>} */
  const tagged = [];
  for (const cp of codePointsOf(consonant)) {
    const name = scriptOf.get(cp);
    if (name !== undefined) tagged.push([cp, cp, name]);
  }
  return normalize(tagged);
}

/** Load the pinned UCD properties the generator and the contract test read.
 * @returns {Promise<Ucd>} */
export async function loadUcd() {
  /** @type {Array<[number, number, string]>} */
  const joining = [];
  for (const [value, tag] of Object.entries(JOINING_TAGS))
    for (const [start, end] of await ucdSpans(`Joining_Type/${value}`))
      joining.push([start, end, tag]);
  // DerivedJoiningType.txt: a code point ArabicShaping.txt does not list is T
  // when its General_Category is Mn, Me or Cf, and U otherwise.
  const listed = new Set(
    codePointsOf([
      ...joining.map(
        ([start, end]) => /** @type {[number, number]} */ ([start, end]),
      ),
      ...(await ucdSpans("Joining_Type/Non_Joining")),
    ]),
  );
  for (const category of ["Nonspacing_Mark", "Enclosing_Mark", "Format"])
    for (const cp of codePointsOf(
      await ucdSpans(`General_Category/${category}`),
    ))
      if (!listed.has(cp)) joining.push([cp, cp, "T"]);
  /** @type {ScriptSpan[]} */
  const scripts = [];
  for (const script of PROPERTY_VALUES.Script)
    for (const range of await ucdSpans(`Script/${script}`))
      scripts.push({ range, script });
  return {
    joining,
    virama: await ucdSpans("Indic_Syllabic_Category/Virama"),
    consonant: await ucdSpans("Indic_Syllabic_Category/Consonant"),
    scripts,
    version: UNICODE_VERSION,
  };
}

/** Render a `[start, end, "T"]` / `[start, end]` row as hex-literal source. */
function row(cols) {
  const hex = (n) => `0x${n.toString(16)}`;
  const [start, end, tag] = cols;
  const cells =
    tag === undefined
      ? [hex(start), hex(end)]
      : [hex(start), hex(end), JSON.stringify(tag)];
  return `  [${cells.join(", ")}],`;
}

/** Build the full source text of src/joining-type.mjs. */
export function render({ joining, virama, brahmic, version }) {
  return `/**
 * GENERATED by scripts/gen-joining-type.mjs from the pinned UCD ${version} at install
 * time; git-ignored, never committed — DO NOT EDIT.
 *
 * Unicode Joining_Type, Indic virama and Brahmic consonant range tables backing
 * the ZWNJ/ZWJ carve-out in invisible.mjs. Regenerate with \`pnpm gen:joining-type\`
 * (\`pnpm install\` does).
 */

export const UNICODE_VERSION = ${JSON.stringify(version)};

// The two range tables below are GENERATED UCD data, not hand-written logic.
// Their correctness is pinned by the SSOT round-trip in
// test/joining-type.test.mjs (re-derive from the pinned UCD, then assert
// every covered code point and range boundary matches) — a far stronger and
// faster guard than mutation. Mutating ~550 numeric literals is pathologically
// slow (the shard was cancelled at ~19 min) and redundant, so Stryker skips
// them; the lookup logic below is still mutated normally.
// Stryker disable all
// [start, end, Joining_Type] sorted by start, non-overlapping. Types present:
// C (join-causing), D (dual), R (right), L (left), T (transparent). Any code
// point absent here has Joining_Type U (non-joining) — the default.
/** @type {Array<[number, number, string]>} */
const JOINING_RANGES = [
${joining.map(row).join("\n")}
];

// [start, end] Indic_Syllabic_Category = Virama ranges, sorted by start.
/** @type {Array<[number, number]>} */
const VIRAMA_RANGES = [
${virama.map(row).join("\n")}
];

// [start, end, Script] Indic_Syllabic_Category = Consonant ranges restricted to
// the scripts that own a virama — the only bases a virama attaches to. Keyed
// by script name so the contract test can check each span against the script
// it claims.
/** @type {ReadonlyArray<readonly [string, number, number]>} */
export const BRAHMIC_CONSONANT_RANGES = [
${brahmic.map(([start, end, tag]) => `  [${JSON.stringify(tag)}, 0x${start.toString(16).padStart(4, "0")}, 0x${end.toString(16).padStart(4, "0")}],`).join("\n")}
];
// Stryker restore all

/**
 * Binary search: the tag of the range containing \`cp\`, or \`fallback\`.
 * @param {Array<[number, number, string?]>} ranges
 * @param {number} cp
 * @param {string|boolean} fallback
 * @returns {string|boolean}
 */
function lookup(ranges, cp, fallback) {
  let lo = 0;
  let hi = ranges.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const [start, end, tag] = ranges[mid];
    if (cp < start) hi = mid - 1;
    else if (cp > end) lo = mid + 1;
    else return tag ?? true;
  }
  return fallback;
}

/**
 * The Unicode Joining_Type of a code point: "C", "D", "R", "L", "T", or "U"
 * (the non-joining default) for anything not in the cursive tables.
 * @param {number} cp
 * @returns {string}
 */
export function joiningType(cp) {
  return /** @type {string} */ (lookup(JOINING_RANGES, cp, "U"));
}

/**
 * True when \`cp\` is an Indic virama (the only position where a ZWNJ/ZWJ is
 * linguistically meaningful in Brahmic scripts).
 * @param {number} cp
 * @returns {boolean}
 */
export function isVirama(cp) {
  return /** @type {boolean} */ (lookup(VIRAMA_RANGES, cp, false));
}

/**
 * True when \`cp\` is a Brahmic consonant — the only base a virama attaches to,
 * and therefore the only base after which a ZWJ/ZWNJ is a real conjunct
 * request rather than a zero-width payload. A binary search, like
 * \`lookup\`: the spans are sorted and disjoint, and the carve analysis asks
 * this of every visible code point of a long document, where a scan of all the
 * spans per code point was the dominant cost.
 * @param {number} cp
 * @returns {boolean}
 */
export function isBrahmicConsonant(cp) {
  let lo = 0;
  let hi = BRAHMIC_CONSONANT_RANGES.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const [, start, end] = BRAHMIC_CONSONANT_RANGES[mid];
    if (cp < start) hi = mid - 1;
    else if (cp > end) lo = mid + 1;
    else return true;
  }
  return false;
}
`;
}

// When run directly, (re)write the generated module.
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const ucd = await loadUcd();
  const { joining, virama, brahmic } = deriveTables(ucd);
  const out = fileURLToPath(
    new URL("../src/joining-type.mjs", import.meta.url),
  );
  writeGenerated(
    out,
    render({ joining, virama, brahmic, version: ucd.version }),
  );
  console.log(
    `wrote ${out}: ${joining.length} joining ranges, ${virama.length} virama ranges, ` +
      `${brahmic.length} Brahmic consonant ranges (Unicode ${ucd.version})`,
  );
}
