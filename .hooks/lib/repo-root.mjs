/**
 * The repo's REAL root, even when the importing test runs inside Stryker's
 * sandbox.
 *
 * Stryker copies the project to `<repoRoot>/.stryker-tmp/sandbox-XXXXXX/` and
 * rewrites every file in the `--mutate` set there, so a test that resolves its
 * own directory sees INSTRUMENTED sources: `const LAZY_LOADERS = {` arrives as
 * `const LAZY_LOADERS = stryMutAct_9fa48("0") ? {} : (…`. A suite whose subject
 * is the source that SHIPS has to climb back out.
 *
 * `git rev-parse --show-toplevel` is not the way to do it. It appears to work —
 * the sandbox sits INSIDE the checkout, so git walks up past `.stryker-tmp` and
 * answers with the real root — and that is exactly the problem: the escape is
 * silent, invisible in the source, and true only for as long as the sandbox
 * stays inside the repo. Stryker's `tempDirName` is configurable. Deriving the
 * root from this module's own location instead makes the intent readable and
 * depends on nothing but the path.
 *
 * Outside a sandbox the two agree, which is why the difference never shows up
 * in a local run.
 */
import { resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

/** The path segment Stryker interposes between the real root and the copy. */
export const SANDBOX_MARKER = `${sep}.stryker-tmp${sep}sandbox-`;

/**
 * The same path in the real checkout: the `.stryker-tmp/sandbox-XXXXXX`
 * segment removed, everything below it kept.
 *
 * Removing the segment rather than truncating at it is what makes this work for
 * a FILE as well as for a root. `…/sandbox-abc123` becomes the repo root, and
 * `…/sandbox-abc123/src/index.mjs` becomes `<repoRoot>/src/index.mjs` — which is
 * what a caller comparing a resolved module path against the root needs. A path
 * outside a sandbox is returned unchanged.
 *
 * @param {string} somePath an absolute path inside the checkout or a copy
 * @returns {string}
 */
export function unsandbox(somePath) {
  const at = somePath.indexOf(SANDBOX_MARKER);
  if (at === -1) return somePath;
  const root = somePath.slice(0, at);
  // What follows the marker is `<id>` or `<id>/<rest>`; only `<rest>` survives.
  const afterId = somePath.slice(at + SANDBOX_MARKER.length).indexOf(sep);
  return afterId === -1
    ? root
    : root + somePath.slice(at + SANDBOX_MARKER.length + afterId);
}

/** Absolute path to the real repo root, sandbox or not. No trailing separator. */
export const repoRoot = unsandbox(
  // A directory URL carries a trailing separator; `resolve` drops it so callers
  // can join, compare and print this value without a doubled separator.
  resolve(fileURLToPath(new URL("../..", import.meta.url))),
);
