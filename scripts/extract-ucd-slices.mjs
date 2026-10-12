#!/usr/bin/env node
/**
 * Cut the vendored scripts/data/*.json slices from the official UCD text files.
 *
 * Usage: download, for the version in ./lib/ucd.mjs, these files from
 * https://www.unicode.org/Public/<version>/ucd/ into ONE directory —
 * DerivedJoiningType.txt and DerivedGeneralCategory.txt (from extracted/),
 * emoji-data.txt (from emoji/), IndicSyllabicCategory.txt, PropList.txt,
 * Scripts.txt and StandardizedVariants.txt — then run
 * `node scripts/extract-ucd-slices.mjs <that directory>` and the generators.
 *
 * Each slice keeps one entry per UCD data line, in the JSON shape the ucd-full
 * npm package uses (`{ range: [start, end?], <field>: value }`), and only the
 * values the generators read, so the vendored data stays small. Every input
 * file's header must name the pinned version: a mixed set would answer some
 * properties from one Unicode and some from another (see ./lib/ucd.mjs).
 */
import { copyFileSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { UNICODE_VERSION } from "./lib/ucd.mjs";

/**
 * The data lines of a UCD text file as `[range, value]`, comments stripped.
 * Throws when the header does not name UNICODE_VERSION.
 * @param {string} dir @param {string} file
 * @returns {Array<{ range: string[], value: string }>}
 */
export function readUcdText(dir, file) {
  const text = readFileSync(join(dir, file), "utf8");
  const header = text.slice(0, text.indexOf("\n\n"));
  // The UCD files name themselves `# <Name>-17.0.0.txt` on line 1; emoji-data.txt
  // has no version in its name and carries a `# Version: 17.0` line instead.
  const stem = file.replace(/\.txt$/, "");
  const majorMinor = UNICODE_VERSION.split(".").slice(0, 2).join(".");
  const named = header.startsWith(`# ${stem}-${UNICODE_VERSION}.txt\n`);
  const versioned = header.split("\n").includes(`# Version: ${majorMinor}`);
  if (!named && !versioned)
    throw new Error(`${file} is not Unicode ${UNICODE_VERSION}:\n${header}`);
  const entries = [];
  for (const line of text.split("\n")) {
    const data = line.split("#")[0].trim();
    if (data === "") continue;
    const [codes, value] = data.split(";").map((field) => field.trim());
    const range = codes.split("..");
    if (range.length > 2 || value === undefined || value === "")
      throw new Error(`${file}: not a range ; value line: ${line}`);
    entries.push({ range, value });
  }
  return entries;
}

/**
 * The slices, by output file name.
 * @param {string} dir
 * @returns {Record<string, object>}
 */
export function cutSlices(dir) {
  /** @param {string} file @param {string} field @param {(value: string) => boolean} keep */
  const slice = (file, field, keep) =>
    readUcdText(dir, file)
      .filter(({ value }) => keep(value))
      .map(({ range, value }) => ({ range, [field]: value }));
  const indic = readUcdText(dir, "IndicSyllabicCategory.txt");
  const scripts = readUcdText(dir, "Scripts.txt");
  const spanOf = ({ range }) => [
    parseInt(range[0], 16),
    parseInt(range[1] ?? range[0], 16),
  ];
  // The scripts that own a virama, read off each virama's Script entry.
  const viramaScripts = new Set();
  for (const entry of indic) {
    if (entry.value !== "Virama") continue;
    const [start, end] = spanOf(entry);
    for (let cp = start; cp <= end; cp++) {
      const owner = scripts.find((s) => {
        const [from, to] = spanOf(s);
        return cp >= from && cp <= to;
      });
      if (!owner) throw new Error(`virama U+${cp.toString(16)} has no Script`);
      viramaScripts.add(owner.value);
    }
  }
  const keepScripts = new Set([...viramaScripts, "Braille", "Hangul"]);
  const indicSlice = (category) => ({
    IndicSyllabicCategory: indic
      .filter(({ value }) => value === category)
      .map(({ range, value }) => ({ range, syllabicCategory: value })),
  });
  return {
    "DerivedJoiningType.json": {
      DerivedJoiningType: slice("DerivedJoiningType.txt", "type", () => true),
    },
    "IndicSyllabicCategory.Virama.json": indicSlice("Virama"),
    "IndicSyllabicCategory.Consonant.json": indicSlice("Consonant"),
    "Scripts.Pinned.json": {
      Scripts: slice("Scripts.txt", "script", (v) => keepScripts.has(v)),
    },
    "DerivedGeneralCategory.Cf.json": {
      DerivedGeneralCategory: slice(
        "DerivedGeneralCategory.txt",
        "category",
        (v) => v === "Cf",
      ),
    },
    "PropList.Pinned.json": {
      PropList: slice(
        "PropList.txt",
        "property",
        (v) => v === "Unified_Ideograph" || v === "Variation_Selector",
      ),
    },
    "emoji-data.Pictographic.json": {
      "emoji-data": slice(
        "emoji-data.txt",
        "property",
        (v) => v === "Extended_Pictographic" || v === "Emoji_Modifier",
      ),
    },
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const dir = process.argv[2];
  if (!dir) throw new Error("usage: extract-ucd-slices.mjs <ucd text dir>");
  const out = fileURLToPath(new URL("./data/", import.meta.url));
  for (const [name, doc] of Object.entries(cutSlices(dir)))
    writeFileSync(join(out, name), JSON.stringify(doc) + "\n");
  readUcdText(dir, "StandardizedVariants.txt"); // version check only
  copyFileSync(
    join(dir, "StandardizedVariants.txt"),
    join(out, "StandardizedVariants.txt"),
  );
  console.log(
    `wrote ${out} slices for Unicode ${UNICODE_VERSION}; run \`pnpm format\` and the generators`,
  );
}
