#!/usr/bin/env node
/**
 * Regenerate every module compiled from the pinned UCD package. `pnpm install`
 * runs this through `prepare`, so a package bump rewrites the tables in the
 * same install. Under CI it writes nothing to the tree: the drift tests compare
 * the COMMITTED modules with a fresh generation, which regenerating first would
 * make vacuous. It still fetches the hash-pinned StandardizedVariants.txt into
 * its out-of-tree cache, the input those tests generate from without a network.
 */
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { fetchStandardizedVariants } from "./gen-standardized-variants.mjs";

// gen-invisible-charset last: it imports src/invisible.mjs, which reads the rest.
const GENERATORS = [
  "gen-unicode-properties.mjs",
  "gen-joining-type.mjs",
  "gen-standardized-variants.mjs",
  "gen-invisible-charset.mjs",
];

fetchStandardizedVariants();

if (process.env.CI)
  console.log("gen-unicode: CI, so the drift tests check the committed tables");
else
  for (const script of GENERATORS)
    execFileSync(
      process.execPath,
      [fileURLToPath(new URL(script, import.meta.url))],
      { stdio: "inherit" },
    );
