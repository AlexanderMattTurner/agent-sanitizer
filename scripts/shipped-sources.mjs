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
 *   node scripts/shipped-sources.mjs   → the MUTATED set, one path per line
 *
 * The CLI prints the mutation scope rather than the shipped subset the module
 * is named for: see the block above it for why that is the shape with no scope
 * decision in it.
 */
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { dirname, join, posix } from "node:path";
import { fileURLToPath } from "node:url";

/** Files whose coverage/mutation scope is `src/`: the library proper. */
export const SRC_SCOPE = "src/";

/**
 * THIRD-PARTY code this package ships verbatim, held to a different bar.
 *
 * `src/vendor/gfm-autolink-literal.mjs` is a copy of one of `remark-gfm`'s
 * micromark extensions carrying a performance fix (see its header). It ships,
 * so it must be packed and type-checked; it is not ours, so a 100% coverage
 * floor and a mutation ratchet would measure upstream's branch structure rather
 * than this repo's tests, and every mutant of a parser arm no fixture reaches
 * would survive by construction.
 *
 * What replaces those gates is stronger for a copy: `test/gfm-autolink-parity`
 * parses the same documents through this tree's assembly and through the
 * published `remark-gfm`, and asserts identical trees. Upstream is the oracle,
 * so the check cannot go stale the way a golden table does.
 *
 * A file lands here only when it is an unmodified-except-for-a-named-fix copy
 * of a published package. Code this repo wrote goes under `src/` and takes the
 * floor with it.
 */
export const VENDOR_SCOPE = "src/vendor/";

/**
 * Repo TOOLING that is mutation-gated despite shipping to nobody.
 *
 * `.hooks/lib/` holds the modules the pre-commit hook derives its guard-pair
 * map with. Nothing there is published, so `shippedSources` — which reads the
 * package manifest — cannot see it, and it was outside every gate: a resolver
 * arm could stop resolving and the only signal would be guards quietly not
 * running. It has a node suite that exercises it (`test/guard-pairs.test.mjs`),
 * which is the whole precondition for mutating something.
 *
 * DIRECTORY-scoped, not repo-wide, and deliberately: `.hooks/run-guard-pairs.mjs`
 * one level up is covered only by `tests/test_hook_fail_closed.py`, and Stryker
 * runs the tap runner over `test/**` — pytest never executes, so every mutant
 * there would survive by construction and the score would measure the runner
 * rather than the tests.
 */
export const TOOLING_SCOPE = ".hooks/lib/";

/**
 * Every `.mjs` under `TOOLING_SCOPE`, derived from the directory.
 *
 * Derived rather than listed for the same reason the shipped set is: a new
 * module here joins the mutation gate the moment it is committed, and
 * `test/shipped-gates.test.mjs` fails the build if the shard matrix has not
 * been taught about it.
 *
 * @param {string} repoRoot absolute path to the repository root
 * @returns {string[]} repo-relative POSIX paths, sorted
 */
export const toolingSources = (repoRoot) =>
  // RECURSIVE, matching both the docstring and `mutation.yaml`'s
  // `.hooks/lib/**/*.mjs` trigger. A shallow read would leave a module at
  // `.hooks/lib/sub/x.mjs` out of the mutated set — so no shard would name it,
  // the contract test (tooling ⊆ mutated) would stay green, and the gate would
  // run over a file it never mutates. That is the silent ungating this scope
  // exists to close. `replace(/\\/g, "/")` keeps the entries POSIX on Windows.
  readdirSync(join(repoRoot, TOOLING_SCOPE), { recursive: true })
    .map((entry) => entry.toString().replace(/\\/g, "/"))
    // A suite is not a mutation target: Stryker judges a mutant by whether the
    // tests kill it, so mutating a test measures nothing and its mutants survive
    // by construction. The directory is read recursively, so a suite committed
    // beside a module here would otherwise join the mutated set.
    .filter((name) => name.endsWith(".mjs") && !name.endsWith(".test.mjs"))
    .map((name) => posix.join(TOOLING_SCOPE, name))
    .sort();

/**
 * Everything the mutation gate mutates: the shipped surface plus the tooling.
 *
 * De-duplicated because the two halves are only disjoint by convention — a
 * `.hooks/lib/*.mjs` added to the manifest would otherwise appear twice and the
 * shard contract test would fail on a set-vs-list mismatch instead of on the
 * real problem, which `test/shipped-gates.test.mjs` asserts directly.
 *
 * @param {string} repoRoot @returns {string[]} */
export const mutatedSources = (repoRoot) =>
  [...new Set([...shippedSources(repoRoot), ...toolingSources(repoRoot)])]
    .filter((f) => !f.startsWith(VENDOR_SCOPE))
    .sort();

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
  shippedSources(repoRoot).filter(
    (f) => f.startsWith(SRC_SCOPE) && !f.startsWith(VENDOR_SCOPE),
  );

/** The shipped sources under {@link VENDOR_SCOPE}: gated by parity, not coverage.
 * @param {string} repoRoot @returns {string[]} */
export const vendorScope = (repoRoot) =>
  shippedSources(repoRoot).filter((f) => f.startsWith(VENDOR_SCOPE));

/**
 * The shipped prefixes outside `src/`: the Claude-hook layer and the CLI.
 *
 * The scope NAMES what it claims, and `.github/scripts/aggregate-mutation.mjs`
 * builds its mutation scopes from this same constant, so the coverage split and
 * the mutation split cannot disagree. A `!startsWith(SRC_SCOPE)` catch-all would
 * claim every future top-level shipped directory by construction, applying
 * coverage floors and a mutation ratchet measured on files it has nothing to do
 * with; naming the prefixes leaves such a path claimed by nobody, which
 * `hookScope` refuses to return silently.
 */
export const HOOK_SCOPE_PREFIXES = ["claude-hooks/", "bin/"];

/** The shipped sources under `HOOK_SCOPE_PREFIXES`.
 * @param {string} repoRoot @returns {string[]} */
export const hookScope = (repoRoot) => {
  const shipped = shippedSources(repoRoot);
  const claimed = (/** @type {string} */ f) =>
    f.startsWith(SRC_SCOPE) || HOOK_SCOPE_PREFIXES.some((p) => f.startsWith(p));
  // VENDOR_SCOPE sits under SRC_SCOPE, so `claimed` already covers it; the
  // scope it is excluded from is the coverage floor and the mutation ratchet,
  // which `srcScope` and `mutatedSources` drop it from.
  const unclaimed = shipped.filter((f) => !claimed(f));
  if (unclaimed.length > 0) {
    throw new Error(
      `shipped-sources: shipped but in no gated scope: ${unclaimed.join(", ")}. ` +
        `Add the prefix to HOOK_SCOPE_PREFIXES so these files get a coverage ` +
        `floor and a mutation ratchet rather than none.`,
    );
  }
  return shipped.filter((f) =>
    HOOK_SCOPE_PREFIXES.some((p) => f.startsWith(p)),
  );
};

/** Repo root, resolved from git so this works from any cwd. */
export const findRepoRoot = () =>
  execFileSync("git", ["rev-parse", "--show-toplevel"], {
    encoding: "utf8",
    cwd: dirname(fileURLToPath(import.meta.url)),
  }).trim();

// The CLI prints the MUTATED set, a superset of the shipped one the module is
// named for. Its one consumer is the mutation dry-run oracle, which has to
// instrument everything the shard matrix does or it passes on exactly the
// commits where a shard is about to die; printing the superset makes that hold
// by construction, with no scope for the shell to choose and none to police.
// Every other consumer imports the export it wants.
if (
  process.argv[1] &&
  realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  process.stdout.write(`${mutatedSources(findRepoRoot()).join("\n")}\n`);
}
