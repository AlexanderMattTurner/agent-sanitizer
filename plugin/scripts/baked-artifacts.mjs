/**
 * The plugin's build outputs: every file an installed plugin needs that no
 * source branch tracks. `pnpm build:plugin`, `pnpm build:redactor` and
 * `build-hook-binaries.mjs` write them into a checkout, where `.gitignore`
 * keeps them out of commits; the release workflow
 * (`.github/workflows/plugin-dist.yaml`) builds them from the tagged tree and
 * commits exactly this list onto the `plugin-dist` branch the marketplace
 * installs from.
 *
 * `node plugin/scripts/baked-artifacts.mjs` prints the list, one repo-relative
 * path per line, for the bake scripts to read.
 */
import { relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { MANIFEST_PATH } from "./build-hook-binaries.mjs";
import {
  BUNDLE_PATH,
  FAIL_OPEN_LIB_PATH,
  NODE_FLOOR_LIB_PATH,
  REQUIREMENTS_IN_PATH,
} from "./build-plugin.mjs";
import { PYZ_PATH, WHEEL_PATH } from "./build-redactor-pyz.mjs";

const ROOT = resolve(fileURLToPath(import.meta.url), "..", "..", "..");

/** Repo-relative, `/`-separated paths of every baked artifact. */
export const BAKED_ARTIFACTS = Object.freeze(
  [
    BUNDLE_PATH,
    MANIFEST_PATH,
    REQUIREMENTS_IN_PATH,
    FAIL_OPEN_LIB_PATH,
    NODE_FLOOR_LIB_PATH,
    PYZ_PATH,
    WHEEL_PATH,
  ].map((path) => relative(ROOT, path).split("\\").join("/")),
);

if (process.argv[1] === fileURLToPath(import.meta.url))
  process.stdout.write(`${BAKED_ARTIFACTS.join("\n")}\n`);
