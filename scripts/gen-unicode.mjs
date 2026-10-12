#!/usr/bin/env node
/**
 * Regenerate every module compiled from the pinned UCD package. `pnpm install`
 * runs this through `prepare`, so a package bump rewrites the tables in the
 * same install. Under CI it writes nothing: the drift tests compare the
 * COMMITTED modules with a fresh generation, which regenerating first would
 * make vacuous.
 */
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

// gen-invisible-charset last: it imports src/invisible.mjs, which reads the rest.
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
