#!/usr/bin/env node
/**
 * Generate every module compiled from the pinned UCD package. None of them is
 * committed: `pnpm install` runs this through `prepare` and `npm pack`/`publish`
 * through `prepack`, so a checkout, a tarball and a wheel all carry tables
 * generated from the package the lockfile pins, and a package bump needs no
 * regeneration commit. It also fetches the hash-pinned StandardizedVariants.txt
 * into its out-of-tree cache (node_modules/.cache), the input that generator
 * reads.
 */
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { fetchStandardizedVariants } from "./gen-standardized-variants.mjs";

// gen-invisible-charset last: it imports src/invisible.mjs, which reads every
// module the others write (cf-charset included, hence gen-cf-charset before it).
const GENERATORS = [
  "gen-unicode-properties.mjs",
  "gen-joining-type.mjs",
  "gen-standardized-variants.mjs",
  "gen-cf-charset.mjs",
  "gen-invisible-charset.mjs",
];

fetchStandardizedVariants();

for (const script of GENERATORS)
  execFileSync(
    process.execPath,
    [fileURLToPath(new URL(script, import.meta.url))],
    { stdio: "inherit" },
  );
