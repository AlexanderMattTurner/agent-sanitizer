#!/usr/bin/env node
/**
 * Run Stryker over every mutated `.mjs` — the shipped surface plus the
 * `.hooks/lib/` tooling — unsharded (the local `pnpm test:mutation` entry
 * point).
 *
 * `stryker.conf.json` deliberately carries NO `mutate` key. It used to say
 * `src/*.mjs`, which silently excluded the entire Claude-hook layer and the
 * published CLI from the mutation gate; a hardcoded list is exactly the thing
 * that goes stale. The spec is computed from `scripts/shipped-sources.mjs`
 * instead and passed on the command line, the same way
 * `.github/scripts/run-mutation-shard.sh` passes its per-shard slice. A bare
 * `stryker run` would fall back to Stryker's own `{src,lib}/**` default, so this
 * wrapper — not the config file — is the supported way to run it whole.
 *
 * Usage: node scripts/mutate.mjs [extra stryker args]
 */
import { spawnSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { findRepoRoot, mutatedSources } from "./shipped-sources.mjs";

/** The Stryker `--mutate` spec covering the whole mutated surface.
 * @param {string} repoRoot @returns {string} */
export const mutateSpec = (repoRoot) => mutatedSources(repoRoot).join(",");

// Importable without side effects: the contract test asserts what this wrapper
// would pass, and must not launch a multi-hour mutation run to do it.
if (
  process.argv[1] &&
  realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  const repoRoot = findRepoRoot();
  const result = spawnSync(
    join(repoRoot, "node_modules", ".bin", "stryker"),
    ["run", "--mutate", mutateSpec(repoRoot), ...process.argv.slice(2)],
    { cwd: repoRoot, stdio: "inherit" },
  );
  if (result.error) throw result.error;
  process.exit(result.status ?? 1);
}
