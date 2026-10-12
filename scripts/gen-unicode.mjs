#!/usr/bin/env node
/**
 * Regenerate every committed module compiled from the pinned UCD package
 * (./lib/ucd.mjs). `pnpm install` runs this through `prepare`, so bumping the
 * `@unicode/unicode-*` devDependency rewrites the tables in the same install,
 * and the diff shows up in `git status` to be committed with the bump.
 *
 * Under CI it writes nothing: the drift tests (test/unicode-properties,
 * test/joining-type, test/invisible-charset) compare the COMMITTED modules with
 * a fresh generation, and regenerating them first would make that comparison
 * compare a file with itself.
 */
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

/** In dependency order: gen-invisible-charset imports src/invisible.mjs, which
 * imports the three modules the generators before it write. */
const GENERATORS = [
  "gen-unicode-properties.mjs",
  "gen-joining-type.mjs",
  "gen-standardized-variants.mjs",
  "gen-invisible-charset.mjs",
];

if (process.env.CI)
  console.log("gen-unicode: CI, so the drift tests check the committed tables");
else
  for (const script of GENERATORS)
    execFileSync(
      process.execPath,
      [fileURLToPath(new URL(script, import.meta.url))],
      { stdio: "inherit" },
    );
