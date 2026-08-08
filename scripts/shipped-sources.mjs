#!/usr/bin/env node
/**
 * Single source of truth for "which `.mjs` files does this package ship?".
 *
 * The coverage floor, the mutation gate and the type-check all used to hardcode
 * `src/` while more than half of the published `exports` map — every
 * `./claude-hooks/*` subpath — plus the `sanitize-cli` bin live outside it. A
 * new early return in `claude-hooks/lib/hook-io.mjs`, or a whole new untested
 * `claude-hooks/lib/*.mjs`, therefore produced a green "100% coverage" run: the
 * percentage was computed over a file set that excluded it.
 *
 * Deriving the checked set from the package manifest instead means the gates
 * follow whatever the package actually publishes. Add a shipped module and it is
 * covered, mutated and type-checked with no config to remember.
 *
 * Usage:
 *   import { shippedSources } from "./shipped-sources.mjs";
 *   node scripts/shipped-sources.mjs   → one repo-relative path per line
 */
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { dirname, join, posix } from "node:path";
import { fileURLToPath } from "node:url";

/** Files whose coverage/mutation scope is `src/`: the library proper. */
export const SRC_SCOPE = "src/";

/**
 * Resolve one `files` entry into the `.mjs` paths it publishes.
 *
 * Only the two shapes the manifest actually uses are understood — a literal
 * path and a single trailing `dir/<star>.ext` — and anything else with a `*`
 * throws rather than silently resolving to nothing. A glob shape this function
 * quietly dropped would remove files from every gate at once, which is exactly
 * the fail-open this module exists to close.
 *
 * @param {string} repoRoot absolute path to the repository root
 * @param {string} entry one `package.json` `files` entry
 * @returns {string[]} repo-relative POSIX paths ending in `.mjs`
 */
function expandFilesEntry(repoRoot, entry) {
  const starIndex = entry.indexOf("*");
  if (starIndex === -1) {
    if (!entry.endsWith(".mjs")) return [];
    statSync(join(repoRoot, entry)); // throws when a listed file is missing
    return [entry];
  }

  const dir = posix.dirname(entry);
  const base = posix.basename(entry);
  if (dir.includes("*") || !/^\*\.[A-Za-z0-9]+$/.test(base)) {
    throw new Error(
      `shipped-sources: unsupported glob in package.json "files": ${entry}. ` +
        `Only a literal path or a trailing "dir/*.ext" is understood; teach ` +
        `expandFilesEntry the new shape rather than letting it resolve to nothing.`,
    );
  }
  if (base !== "*.mjs") return [];
  return readdirSync(join(repoRoot, dir))
    .filter((name) => name.endsWith(".mjs"))
    .map((name) => posix.join(dir, name));
}

/**
 * The subset of the manifest these gates read.
 * @typedef {{ files?: string[],
 *   exports?: Record<string, string | Record<string, string>>,
 *   bin?: Record<string, string> }} Manifest
 */

/** Every `.mjs` target named by an `exports` subpath, plus every `bin` target.
 * @param {Manifest} pkg
 * @returns {string[]} */
function manifestEntryPoints(pkg) {
  const targets = [];
  for (const subpath of Object.values(pkg.exports ?? {})) {
    // A subpath may name its file directly instead of via a conditions object.
    const files =
      typeof subpath === "string" ? [subpath] : Object.values(subpath);
    targets.push(...files);
  }
  targets.push(...Object.values(pkg.bin ?? {}));
  return targets
    .map((target) => target.replace(/^\.\//, ""))
    .filter((target) => target.endsWith(".mjs"));
}

/**
 * The sorted, de-duplicated list of shipped `.mjs` files.
 *
 * @param {string} repoRoot absolute path to the repository root
 * @returns {string[]} repo-relative POSIX paths, sorted
 */
export function shippedSources(repoRoot) {
  const pkg = /** @type {Manifest} */ (
    JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8"))
  );
  const packed = new Set(
    (pkg.files ?? []).flatMap((entry) => expandFilesEntry(repoRoot, entry)),
  );

  // An exports/bin target outside `files` is promised to consumers but never
  // packed: the tarball resolves the subpath to nothing. Fail loudly here so the
  // gate set and the published surface cannot disagree.
  const unpacked = manifestEntryPoints(pkg).filter((f) => !packed.has(f));
  if (unpacked.length > 0) {
    throw new Error(
      `shipped-sources: package.json exports/bin name ${unpacked.join(", ")}, ` +
        `which package.json "files" does not pack.`,
    );
  }

  return [...packed].sort();
}

/** The shipped sources under `src/` (the 100%-coverage scope).
 * @param {string} repoRoot @returns {string[]} */
export const srcScope = (repoRoot) =>
  shippedSources(repoRoot).filter((f) => f.startsWith(SRC_SCOPE));

/** The shipped sources outside `src/`: the Claude-hook layer and the CLI.
 * @param {string} repoRoot @returns {string[]} */
export const hookScope = (repoRoot) =>
  shippedSources(repoRoot).filter((f) => !f.startsWith(SRC_SCOPE));

/** Repo root, resolved from git so this works from any cwd. */
export const findRepoRoot = () =>
  execFileSync("git", ["rev-parse", "--show-toplevel"], {
    encoding: "utf8",
    cwd: dirname(fileURLToPath(import.meta.url)),
  }).trim();

if (
  process.argv[1] &&
  realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  process.stdout.write(`${shippedSources(findRepoRoot()).join("\n")}\n`);
}
