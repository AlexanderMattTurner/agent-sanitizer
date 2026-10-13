#!/usr/bin/env node
/**
 * Generate src/standardized-variants.mjs from the UCD StandardizedVariants.txt,
 * fetched from unicode.org and pinned by SHA-256.
 *
 * The carve-out preserves a variation selector only after a base that forms a
 * *registered* standardized variation sequence with it; that registry is
 * normative UCD data, never a hand-rolled list. The output is a `.mjs` module
 * rather than JSON because the pinned eslint rejects import attributes and the
 * Python-CLI esbuild bundle does not inline a `createRequire` JSON read.
 * test/invisible-charset.test.mjs re-parses the file and fails on drift.
 *
 * The file comes from unicode.org, not a package: the pinned `@unicode/unicode-*`
 * package has no StandardizedVariants data, and `ucd-full@17.0.0` ships
 * Unicode 16's copy, which lacks 47 of Unicode 17's sequences. The URL follows
 * the package's Unicode version, so a package bump with no new pin fails loudly
 * instead of mixing two Unicodes. `pnpm install` fetches it (CI included) into a
 * cache outside the tree; the drift test reads only that verified cache, so the
 * default suite never touches the network.
 *
 * Run: `node scripts/gen-standardized-variants.mjs`.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { UNICODE_VERSION, ucdSpans } from "./lib/ucd.mjs";

// Variation_Selector from the pinned package, not the runtime's
// `\p{Variation_Selector}` (see ./lib/ucd.mjs).
const VARIATION_SELECTOR_SPANS = await ucdSpans(
  "Binary_Property/Variation_Selector",
);

/** @param {number} cp @returns {boolean} */
const isVariationSelector = (cp) =>
  VARIATION_SELECTOR_SPANS.some(([start, end]) => cp >= start && cp <= end);

const HEX_CODE_POINT = /^[0-9A-F]{4,6}$/u;

/**
 * Parse StandardizedVariants.txt (`BASE SELECTOR; description; # NAME` lines)
 * into a sorted `[base, selector]` table, keeping every data line. Throws on a
 * line that is not two hex code points ending in a Variation_Selector, so a
 * format change fails the build instead of dropping sequences.
 * @param {string} text
 * @returns {Array<[number, number]>}
 */
export function parseStandardizedVariants(text) {
  /** @type {Array<[number, number]>} */
  const pairs = [];
  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (line === "" || line.startsWith("#")) continue;
    const seq = line.split(";")[0].trim().split(/\s+/u);
    if (seq.length !== 2 || !seq.every((hex) => HEX_CODE_POINT.test(hex)))
      throw new Error(`not a base + selector sequence: ${line}`);
    const [base, selector] = seq.map((hex) => parseInt(hex, 16));
    if (!isVariationSelector(selector))
      throw new Error(`not a variation selector: ${line}`);
    pairs.push([base, selector]);
  }
  pairs.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  return pairs;
}

/**
 * SHA-256 of StandardizedVariants.txt for UNICODE_VERSION. Bumping the
 * `@unicode/unicode-*` package fails the pin check until this is replaced:
 * fetch the URL below for the new version, read the file's header, and pin
 * `sha256sum` of it here.
 */
const PINNED_SHA256 =
  "f55100b2fb11d3d75a37b8c1ab752192dbd1c4b12328c5ec6b38e3807c0ca597";

const SOURCE_URL = `https://www.unicode.org/Public/${UNICODE_VERSION}/ucd/StandardizedVariants.txt`;

/** Outside the tree, so the fetched input is never committed. */
const CACHE_PATH = fileURLToPath(
  new URL(
    `../node_modules/.cache/agent-sanitizer-ucd/StandardizedVariants-${UNICODE_VERSION}.txt`,
    import.meta.url,
  ),
);

/** @param {string | Buffer} bytes @returns {string} */
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

/**
 * Ensure CACHE_PATH holds the pinned file, downloading it on a miss. A cached
 * copy that fails the pin is re-fetched; a download that fails it throws. The
 * download is staged in the cache directory and renamed, so a concurrent reader
 * sees the whole file or none.
 * @returns {string} CACHE_PATH
 */
export function fetchStandardizedVariants() {
  if (
    existsSync(CACHE_PATH) &&
    sha256(readFileSync(CACHE_PATH)) === PINNED_SHA256
  )
    return CACHE_PATH;
  mkdirSync(dirname(CACHE_PATH), { recursive: true });
  const stage = mkdtempSync(join(dirname(CACHE_PATH), "fetch-"));
  const staged = join(stage, "StandardizedVariants.txt");
  try {
    // curl rather than fetch(): it honours HTTPS_PROXY and the system CA store,
    // which Node's fetch does not without opt-in flags.
    execFileSync(
      "curl",
      [
        "--fail",
        "--location",
        "--silent",
        "--show-error",
        "--retry",
        "5",
        "--retry-all-errors",
        "--retry-delay",
        "3",
        "--connect-timeout",
        "30",
        "--max-time",
        "120",
        "--output",
        staged,
        SOURCE_URL,
      ],
      { stdio: ["ignore", "inherit", "inherit"] },
    );
    const got = sha256(readFileSync(staged));
    if (got !== PINNED_SHA256)
      throw new Error(
        `${SOURCE_URL} has SHA-256 ${got}, not the pinned ${PINNED_SHA256} — refusing it`,
      );
    renameSync(staged, CACHE_PATH);
  } finally {
    rmSync(stage, { recursive: true, force: true });
  }
  return CACHE_PATH;
}

/** Read the pinned UCD file used by the generator and the contract test,
 * refusing any bytes whose SHA-256 is not the pin for the package's Unicode.
 * @param {string} [text] the file's contents; a test passes its own */
export function loadStandardizedVariantsUcd(text = readCached()) {
  const got = sha256(text);
  if (got !== PINNED_SHA256)
    throw new Error(
      `StandardizedVariants.txt has SHA-256 ${got}, not the pinned ${PINNED_SHA256} for Unicode ${UNICODE_VERSION}`,
    );
  return { text, version: UNICODE_VERSION };
}

/** The cached download; never fetches, so the drift test stays offline. */
function readCached() {
  if (!existsSync(CACHE_PATH))
    throw new Error(
      `${CACHE_PATH} is missing — run \`pnpm install\` or \`node scripts/gen-standardized-variants.mjs\` to fetch it`,
    );
  return readFileSync(CACHE_PATH, "utf8");
}

/** Render one `[base, selector]` row as hex-literal source. */
function row([base, selector]) {
  return `  [0x${base.toString(16)}, 0x${selector.toString(16)}],`;
}

/** Build the full source text of src/standardized-variants.mjs. */
export function render({ pairs, version }) {
  return `/**
 * GENERATED by scripts/gen-standardized-variants.mjs from UCD
 * StandardizedVariants.txt (Unicode ${version}) — DO NOT EDIT.
 *
 * Registered standardized variation sequences: a base code point followed by the
 * variation selector the UCD registers for it. invisible.mjs preserves such a
 * selector only when the immediately preceding base appears here; every other
 * one is stripped as a hidden-payload byte. Regenerate with
 * \`node scripts/gen-standardized-variants.mjs\`;
 * test/invisible-charset.test.mjs fails if this drifts from the pinned UCD.
 */

export const UNICODE_VERSION = ${JSON.stringify(version)};

// The table below is GENERATED UCD data, not hand-written logic. Its correctness
// is pinned by the SSOT round-trip in test/invisible-charset.test.mjs (re-parse
// the vendored file, then assert every pair matches) — a stronger and faster
// guard than mutating a few hundred numeric literals, so Stryker skips them.
// Stryker disable all
/** @type {Array<[number, number]>} [base, selector], sorted by base then selector. */
export const STANDARDIZED_VARIANTS = [
${pairs.map(row).join("\n")}
];
// Stryker restore all

// A base can be an astral code point (up to ~U+2A600), so multiply by 0x110000
// (past the whole code space) to pack (base, selector) into one collision-free
// integer key — well within Number.MAX_SAFE_INTEGER.
const KEY_STRIDE = 0x110000;
const VARIANT_KEYS = new Set(
  STANDARDIZED_VARIANTS.map(([base, selector]) => base * KEY_STRIDE + selector),
);

/**
 * True when \`base\` followed by \`selector\` is a registered standardized
 * variation sequence.
 * @param {number} base
 * @param {number} selector
 * @returns {boolean}
 */
export function isStandardizedVariant(base, selector) {
  return VARIANT_KEYS.has(base * KEY_STRIDE + selector);
}
`;
}

// When run directly, (re)write the committed module.
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  fetchStandardizedVariants();
  const { text, version } = loadStandardizedVariantsUcd();
  const pairs = parseStandardizedVariants(text);
  const out = fileURLToPath(
    new URL("../src/standardized-variants.mjs", import.meta.url),
  );
  writeFileSync(out, render({ pairs, version }));
  console.log(`wrote ${out}: ${pairs.length} standardized variation sequences`);
}
