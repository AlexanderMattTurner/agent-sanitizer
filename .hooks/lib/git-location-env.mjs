/**
 * An environment with git's repository-location overrides removed.
 *
 * The names come from `config/git-location-vars.json`, which the Python half
 * (`tests/_helpers.py`) reads too — one list, so a name added for one caller
 * reaches the other. A second copy would go stale silently: the suites keep
 * inheriting the override, and their commits land in the developer's real repo
 * with no error at all.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

export const GIT_LOCATION_VARS = JSON.parse(
  readFileSync(join(repoRoot, "config", "git-location-vars.json"), "utf8"),
).vars;

/** `env` minus every name in {@link GIT_LOCATION_VARS}. */
export function envWithoutGitLocation(env) {
  return Object.fromEntries(
    Object.entries(env).filter(([key]) => !GIT_LOCATION_VARS.includes(key)),
  );
}
