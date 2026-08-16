/**
 * SSOT for the *threat alphabet* the property/fuzz suites must seed.
 *
 * The fuzz-coverage gate (fuzz-coverage.test.mjs) already proves every parser of
 * untrusted input HAS a fast-check target. But "has a target" is not "the target
 * feeds it the dangerous bytes": a uniform 0..0x10FFFF draw lands on U+009B only
 * ~1-in-a-million, so a suite can run a million cases and never once exercise the
 * C1 CSI passthrough class the U+009B bug actually shipped in. That is the same
 * "enumerated alphabet misses a member" trap the one-case-per-member tests guard
 * against, lifted to the fuzz-input domain: an alphabet that omits a threat
 * member silently can't catch a regression in it.
 *
 * So this module enumerates the threat code points, and the gate asserts each
 * in-scope suite's SOURCE references every member it is responsible for (by any
 * hex/escape spelling). The members are tied to invisible.mjs's CHECKS/CATEGORY
 * so a NEW detector category there forces a representative here (the
 * `every CATEGORY has a representative` test below), and the per-suite IN_SCOPE
 * map records, with a reason, exactly which members each suite owes — a carve-out
 * is a documented choice, never an accident.
 */
import { CATEGORY } from "../src/invisible.mjs";

/**
 * The threat alphabet. Each entry is a single code point a sanitizer-facing fuzz
 * suite may need to seed explicitly (the fuzzer will not reach it by chance).
 * `category` ties invisible-class members to a CATEGORY code so the coverage of
 * src/invisible.mjs's detector set is auditable; ANSI-introducer / structural
 * members carry their own descriptive category string.
 * @type {ReadonlyArray<{ cp: number, name: string, category: string }>}
 */
export const THREAT_CODEPOINTS = Object.freeze(
  [
    // ── ANSI / C1 control introducers (terminal-escape channel) ──────────────
    { cp: 0x1b, name: "ESC (7-bit ANSI introducer)", category: "ansi" },
    {
      cp: 0x9b,
      name: "C1 CSI (8-bit control sequence introducer)",
      category: "ansi",
    },
    {
      cp: 0x9d,
      name: "C1 OSC (8-bit operating system command)",
      category: "ansi",
    },
    { cp: 0x07, name: "BEL (OSC string terminator)", category: "ansi" },
    // ── one representative per src/invisible.mjs CHECKS category ──────────────
    { cp: 0x200b, name: "ZERO WIDTH SPACE (Cf)", category: CATEGORY.CF },
    {
      cp: 0xfe0f,
      name: "VARIATION SELECTOR-16",
      category: CATEGORY.VARIATION_SELECTORS,
    },
    {
      cp: 0x3164,
      name: "HANGUL FILLER (blank, Lo)",
      category: CATEGORY.BLANK_FILLERS,
    },
    {
      cp: 0x2800,
      name: "BRAILLE PATTERN BLANK (So)",
      category: CATEGORY.BLANK_FILLERS,
    },
    {
      cp: 0x034f,
      name: "COMBINING GRAPHEME JOINER (zero-width Mn)",
      category: CATEGORY.BLANK_FILLERS,
    },
    // ── ZWNJ/ZWJ joiners (linguistic carve-out boundary) ─────────────────────
    { cp: 0x200c, name: "ZERO WIDTH NON-JOINER (Cf)", category: CATEGORY.CF },
    { cp: 0x200d, name: "ZERO WIDTH JOINER (Cf)", category: CATEGORY.CF },
    // ── Unicode TAG block (deniable-encoding channel) ────────────────────────
    { cp: 0xe0041, name: "TAG LATIN CAPITAL LETTER A", category: CATEGORY.CF },
    // ── malformed / astral domain (parser totality) ──────────────────────────
    { cp: 0xd800, name: "lone high surrogate", category: "surrogate" },
    { cp: 0x1f600, name: "GRINNING FACE (astral)", category: "astral" },
  ].map(Object.freeze),
);

const byCp = new Map(THREAT_CODEPOINTS.map((entry) => [entry.cp, entry]));

/**
 * Look up a threat entry by code point; throws on an unknown cp so an IN_SCOPE
 * typo fails loudly rather than silently widening a suite's exemption.
 * @param {number} cp
 * @returns {{ cp: number, name: string, category: string }}
 */
export function threat(cp) {
  const entry = byCp.get(cp);
  if (!entry) throw new Error(`unknown threat code point 0x${cp.toString(16)}`);
  return entry;
}

const ALL = THREAT_CODEPOINTS.map((entry) => entry.cp);

// Invisible-only members (everything that is not an ANSI introducer or a
// pure-parser-totality member): the set a transform that *only* strips invisible
// characters (no ANSI, no astral fuzzing of its own) is responsible for.
const INVISIBLE_MEMBERS = THREAT_CODEPOINTS.filter(
  (entry) =>
    entry.category !== "ansi" &&
    entry.category !== "surrogate" &&
    entry.category !== "astral",
).map((entry) => entry.cp);

/**
 * Per-suite responsibility map: which THREAT_CODEPOINTS members each property/
 * fuzz suite must seed. `"all"` means the whole alphabet; an array names the
 * in-scope subset. Every exclusion (a member present in the alphabet but absent
 * from a suite's list) is justified inline — a carve-out is a choice, not a miss.
 * A suite absent from here must appear in {@link OUT_OF_SCOPE} with its reason;
 * the gate asserts the two together cover every discovered fast-check suite.
 * @type {Readonly<Record<string, number[] | "all">>}
 */
export const IN_SCOPE = Object.freeze({
  // The top-level prompt verdict and the two whole-pipeline fuzzers see raw
  // untrusted text end to end, so they owe the entire alphabet.
  "prompt-property.test.mjs": "all",
  "sanitize.fuzz.test.mjs": "all",
  "output.fuzz.test.mjs": "all",

  // sanitizeText/sanitizeValue (Layer 1 over text + JSON leaves): every
  // invisible + every ANSI introducer applies; astral & lone surrogate are
  // exercised through its unicodeChar/loneSurrogate arbitraries, so include
  // them too — the whole alphabet is in scope.
  "output-property.test.mjs": "all",

  // The instruction scanner decodes invisible RUNS (zero-width + TAG channels)
  // and never interprets ANSI (ESC/C1 are a terminal concern handled upstream
  // in Layer 1), so the ANSI introducers are out of scope; astral is reached via
  // its unicodeChar arbitrary. It owes every invisible member plus the surrogate
  // totality probe.
  "instructions-property.test.mjs": [...INVISIBLE_MEMBERS, 0xd800],
});

/**
 * The other half of the same partition: every fast-check suite that is NOT
 * gated for domain coverage, and the reason it owes nothing.
 *
 * IN_SCOPE alone is one-directional. It proves each listed suite seeds what it
 * owes, and says nothing about a suite nobody listed — so a new fuzz target for
 * a raw-byte entry point can land with an input domain that never reaches the
 * dangerous bytes, which is the U+009B trap this module exists to close. The
 * gate asserts IN_SCOPE and OUT_OF_SCOPE together cover the discovered suites,
 * so a new suite forces a human to pick a side.
 * @type {Readonly<Record<string, string>>}
 */
export const OUT_OF_SCOPE = Object.freeze({
  // ── post-Layer-1 consumers: Layer 1 strips every invisible and ANSI byte
  // before these layers run, so seeding the alphabet here tests a state the
  // layer never sees. Surrogate/astral totality rides in on fc.string().
  "exfil-property.test.mjs":
    "Layer 3 reads URL and markdown link destinations, which Layer 1 has already cleaned",
  "html-exfil-semantic-fuzz.test.mjs":
    "Layer 3 precision over whole documents, downstream of the same strip",
  "html-property.test.mjs":
    "the HTML parser runs post-Layer-1, and no alphabet member carries markup meaning",
  "html-semantic-fuzz.test.mjs":
    "hidden-element splice precision, downstream of the same strip",
  "html.test.mjs":
    "exact-verdict HTML unit tests, downstream of the same strip",

  // ── offset and table engines: their input is a resolved offset, a needle or
  // a confusable glyph table, never raw untrusted bytes.
  "confusables-property.test.mjs":
    "folds against an injected scanner over a confusable glyph table",
  "confusables-semantic-fuzz.test.mjs":
    "fold precision over genuine non-Latin words versus confusable lookalikes",
  "confusable-host-property.test.mjs":
    "reads hostnames the WHATWG URL parser already resolved, not raw text",
  "splice-property.test.mjs":
    "splices ranges and needle matches an earlier layer resolved",
  "view-map-property.test.mjs":
    "offset algebra between the disk, cleaned and redacted views",
  "rehydrate-property.test.mjs":
    "re-anchors an Edit against a view the pipeline already produced",
  "rehydrate-semantic-fuzz.test.mjs":
    "re-anchoring precision over the same already-produced views",

  // ── differentials and fast paths: each pins one implementation against
  // another over the alphabet its own subject defines.
  "ansi-pattern-parity.test.mjs":
    "differentials the shipped escape regex against the scanner over the ANSI grammar",
  "invisible-differential.test.mjs":
    "differentials the optimized carve analysis against the slow one",
  "invisible-fast-path.test.mjs":
    "pins each counting short-circuit against the analysis it replaces",
  "invisible-property.test.mjs":
    "fuzzes the ZWNJ/ZWJ carve-out over its own joiner and emoji alphabet",
  "invisible-semantic-fuzz.test.mjs":
    "carve-out precision over that same joiner alphabet",
  "invisible.test.mjs":
    "unit tests driven from the CHECKS/VS/BLANK_NON_CF SSOT",
  "layer1-ansi.test.mjs":
    "Layer 1's own idempotence and containment invariants over the ANSI grammar",

  // ── precision suites whose structural sibling carries the domain gate.
  "instructions-semantic-fuzz.test.mjs":
    "instructions-property.test.mjs is the gated suite for this entry point",
  "output-semantic-fuzz.test.mjs":
    "output-property.test.mjs is the gated suite for this entry point",
  "prompt-semantic-fuzz.test.mjs":
    "prompt-property.test.mjs is the gated suite for this entry point",

  // ── whole-process compositions over text the gated entry points produce.
  "claude-hooks-layer-pipeline.test.mjs":
    "asserts the PreToolUse layer ORDER on what the hook emits",
  "claude-hooks-roundtrip.fuzz.test.mjs":
    "fuzzes the sanitize to edit to rehydrate loop, whose input is sanitized text",
  "cli.test.mjs": "pins the CLI I/O envelope against sanitize as its oracle",
});

// Round-trip guard data: every cp named in IN_SCOPE must be a real alphabet
// member (catches a stale exclusion list drifting from THREAT_CODEPOINTS).
export const IN_SCOPE_MEMBERS = Object.freeze(
  Object.fromEntries(
    Object.entries(IN_SCOPE).map(([file, list]) => [
      file,
      list === "all" ? [...ALL] : list,
    ]),
  ),
);

/**
 * Every accepted source spelling of a code point, for diagnostics (the error
 * message lists what it looked for). The gate MATCHES with `spellingMatches`,
 * which adds the hex-digit boundaries these bare strings lack. Kept the examples
 * (`0x9b`, `0x009b`, ``, `\u{9b}`, `\x9b`), case-insensitively.
 * @param {number} cp
 * @returns {string[]}
 */
export function acceptedSpellings(cp) {
  const hex = cp.toString(16);
  const spellings = new Set([
    `0x${hex}`, // 0x9b, 0x200b, 0xe0041
    `0x${hex.padStart(2, "0")}`, // 0x07 (even when hex is "7")
    `0x${hex.padStart(4, "0")}`, // 0x009b, 0x0007
    `\\u{${hex}}`, // \u{9b}, \u{1f600}
  ]);
  if (cp <= 0xffff) spellings.add(`\\u${hex.padStart(4, "0")}`); // BMP-only \uXXXX escape
  if (cp <= 0xff) spellings.add(`\\x${hex.padStart(2, "0")}`); // \x1b, \x07
  return [...spellings];
}

const HEX = "0-9a-f";
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * True when `source` (lower-cased, comment/import-stripped) spells `cp` in any
 * accepted form. Each spelling is anchored so a hex run can't be a PREFIX of a
 * longer literal: `0x7` must NOT match inside `0x7e`, `0x9b` must NOT match
 * inside `0x9bc`. The non-brace forms therefore require a non-hex-digit (or end
 * of string) on the trailing side; the `0x`/`\x`/`\u` lead already blocks a
 * digit gluing on the left.
 * @param {number} cp
 * @param {string} source  already lower-cased
 * @returns {boolean}
 */
export function spellingMatches(cp, source) {
  return acceptedSpellings(cp).some((spelling) => {
    // `\u{…}` is self-delimited by its closing brace; the rest need a boundary.
    const needsBoundary = !spelling.endsWith("}");
    const re = new RegExp(
      escapeRe(spelling.toLowerCase()) + (needsBoundary ? `(?![${HEX}])` : ""),
    );
    return re.test(source);
  });
}
