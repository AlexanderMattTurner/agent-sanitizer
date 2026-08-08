/**
 * Generate src/joining-type.mjs from vendored slices of the Unicode Character
 * Database (scripts/data/*.json, extracted from ucd-full — see UNICODE_VERSION).
 *
 * The invisible-char carve-out preserves ZWNJ/ZWJ only where they do real
 * rendering work. That is a SYNTACTIC property of the neighbouring characters,
 * not a guess from a count: a ZWNJ suppresses a cursive join, so it is
 * meaningful exactly at a join boundary (Arabic-family scripts), and an
 * Indic joiner is meaningful only immediately after a virama. Both facts live
 * in the UCD:
 *   - Joining_Type (DerivedJoiningType.txt) → the cursive join algorithm.
 *   - Indic_Syllabic_Category = Virama       → the Indic joiner trigger.
 *   - Indic_Syllabic_Category = Consonant    → the base a virama may sit on.
 *
 * ECMAScript regex exposes neither property (`\p{Joining_Type=…}` and
 * `\p{Indic_Syllabic_Category=…}` are not in the supported set), so we compile
 * the three range tables into a committed, runtime-dependency-free data module.
 * The UCD slices are vendored (~20 KB) rather than pulled as a 250 MB dev
 * dependency at build time: they are pinned data, so committing them keeps the
 * generator and the contract test hermetic with no install cost.
 * `test/joining-type.test.mjs` re-derives from the same vendored slices and
 * asserts the committed module still matches — a drift fails CI, as an SSOT
 * contract should — and hand-checked anchors pin the data itself.
 *
 * Run: `pnpm gen:joining-type` (then `pnpm format` to prettify the output).
 */
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

// Unicode version of the vendored scripts/data/*.json slices (ucd-full@17.0.0,
// matching Node 22's bundled ICU). Bump both together when regenerating.
const UNICODE_VERSION = "17.0.0";

/** Read + parse a vendored UCD slice under scripts/data/. */
const readData = (name) =>
  JSON.parse(readFileSync(new URL(`./data/${name}`, import.meta.url), "utf8"));

/**
 * Parse a UCD JSON `range` field (`["0640"]` or `["0883","0885"]`) into a
 * numeric `[start, end]` pair.
 * @param {string[]} range
 * @returns {[number, number]}
 */
function parseRange(range) {
  const start = parseInt(range[0], 16);
  const end = parseInt(range[1] ?? range[0], 16);
  return [start, end];
}

/** Merge adjacent/overlapping same-type ranges and sort by start. Keeps the
 * table minimal so the binary search in the runtime module is tight.
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
 * Derive the three range tables from parsed `ucd-full` JSON payloads. Pure so the
 * contract test can call it on the same inputs and compare with the committed
 * module.
 * @param {{DerivedJoiningType: Array<{range: string[], type: string}>}} joiningJson
 * @param {{IndicSyllabicCategory: Array<{range: string[], syllabicCategory: string}>}} indicJson
 * @param {{IndicSyllabicCategory: Array<{range: string[], syllabicCategory: string}>}} consonantJson
 * @returns {{ joining: Array<[number, number, string]>, virama: Array<[number, number]>, brahmic: Array<[number, number, string]> }}
 */
export function deriveTables(joiningJson, indicJson, consonantJson) {
  const joining = normalize(
    joiningJson.DerivedJoiningType.map(({ range, type }) => {
      const [start, end] = parseRange(range);
      return /** @type {[number, number, string]} */ ([start, end, type]);
    }),
  );
  const virama = normalize(
    indicJson.IndicSyllabicCategory.filter(
      (e) => e.syllabicCategory === "Virama",
    ).map((e) => {
      const [start, end] = parseRange(e.range);
      return /** @type {[number, number, string]} */ ([start, end, "V"]);
    }),
  ).map(([start, end]) => /** @type {[number, number]} */ ([start, end]));
  return { joining, virama, brahmic: deriveBrahmic(consonantJson) };
}

/**
 * The scripts whose consonants the ZWJ/ZWNJ carve-out recognises as a virama
 * base. Restricted, not "every Indic_Syllabic_Category=Consonant": widening the
 * set would preserve joiners in scripts the carve-out has never covered, which
 * is a behaviour change about which text is legible, not a drift fix. This list
 * is exactly the set the previous hand-written table named — what changed is
 * that the SPANS inside each script are now the UCD's, not a hand-typed
 * KA–HA approximation that swept up the holes between the real consonants.
 */
const BRAHMIC_SCRIPTS = [
  "Devanagari",
  "Bengali",
  "Gurmukhi",
  "Gujarati",
  "Oriya",
  "Tamil",
  "Telugu",
  "Kannada",
  "Malayalam",
  "Sinhala",
];

/**
 * Script-tagged consonant spans: every Indic_Syllabic_Category=Consonant code
 * point that also has Script= one of {@link BRAHMIC_SCRIPTS}, merged into runs.
 * Script comes from the ENGINE's own `\p{Script=…}` (ECMAScript does expose
 * that one), so the two halves of the join are both properties, never a block
 * range guessed from a chart.
 * @param {{IndicSyllabicCategory: Array<{range: string[], syllabicCategory: string}>}} consonantJson
 * @returns {Array<[number, number, string]>}
 */
function deriveBrahmic(consonantJson) {
  const isScript = Object.fromEntries(
    BRAHMIC_SCRIPTS.map((name) => [
      name,
      new RegExp(`\\p{Script=${name}}`, "u"),
    ]),
  );
  /** @type {Array<[number, string]>} */
  const tagged = [];
  for (const entry of consonantJson.IndicSyllabicCategory) {
    if (entry.syllabicCategory !== "Consonant") continue;
    const [start, end] = parseRange(entry.range);
    for (let cp = start; cp <= end; cp++) {
      const char = String.fromCodePoint(cp);
      for (const name of BRAHMIC_SCRIPTS)
        if (isScript[name].test(char)) tagged.push([cp, name]);
    }
  }
  tagged.sort((left, right) => left[0] - right[0]);
  return normalize(
    tagged.map(
      ([cp, name]) => /** @type {[number, number, string]} */ ([cp, cp, name]),
    ),
  );
}

/** Load the vendored UCD slices used by the generator and the contract test. */
export function loadUcd() {
  return {
    joiningJson: readData("DerivedJoiningType.json"),
    indicJson: readData("IndicSyllabicCategory.Virama.json"),
    consonantJson: readData("IndicSyllabicCategory.Consonant.json"),
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
 * GENERATED by scripts/gen-joining-type.mjs from ucd-full@${version} — DO NOT EDIT.
 *
 * Unicode Joining_Type, Indic virama and Brahmic consonant range tables backing
 * the ZWNJ/ZWJ carve-out in invisible.mjs. Regenerate with \`pnpm gen:joining-type\`;
 * test/joining-type.test.mjs fails if this drifts from the pinned UCD.
 */

export const UNICODE_VERSION = ${JSON.stringify(version)};

// The two range tables below are GENERATED UCD data, not hand-written logic.
// Their correctness is pinned by the SSOT round-trip in
// test/joining-type.test.mjs (re-derive from the vendored slices, then assert
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
// the Brahmic scripts the joiner carve-out covers — the only bases a virama
// attaches to. Keyed by script name so the contract test can check each span
// against the script it claims.
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
 * request rather than a zero-width payload.
 * @param {number} cp
 * @returns {boolean}
 */
export function isBrahmicConsonant(cp) {
  for (const [, start, end] of BRAHMIC_CONSONANT_RANGES)
    if (cp >= start && cp <= end) return true;
  return false;
}
`;
}

// When run directly, (re)write the committed module.
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { joiningJson, indicJson, consonantJson, version } = loadUcd();
  const { joining, virama, brahmic } = deriveTables(
    joiningJson,
    indicJson,
    consonantJson,
  );
  const out = fileURLToPath(
    new URL("../src/joining-type.mjs", import.meta.url),
  );
  writeFileSync(out, render({ joining, virama, brahmic, version }));
  console.log(
    `wrote ${out}: ${joining.length} joining ranges, ${virama.length} virama ranges, ` +
      `${brahmic.length} Brahmic consonant ranges (Unicode ${version})`,
  );
}
