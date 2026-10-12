/**
 * `path.matchesGlob`, or a plain-language failure where it does not exist.
 *
 * `engines.node` is `>=22`, but `path.matchesGlob` only landed in 22.5.0. The
 * suites that use it are repo tooling (never published), so the fix is to name
 * the Node they need rather than to hand-roll a glob matcher: a second glob
 * grammar beside Node's own is exactly the approximation these suites exist to
 * catch the runner disagreeing with. Imported statically, a missing export
 * reads as "does not provide an export named 'matchesGlob'" and sends the
 * reader to the wrong file.
 */
import * as nodePath from "node:path";

export const MATCHES_GLOB_MIN_NODE = "22.5.0";

/** `pathModule.matchesGlob`, or a throw naming the Node this repo's tests need. */
export function requireMatchesGlob(
  pathModule = nodePath,
  nodeVersion = process.version,
) {
  if (typeof pathModule.matchesGlob !== "function")
    throw new Error(
      `path.matchesGlob is missing on Node ${nodeVersion}: the repo's tests ` +
        `need Node >= ${MATCHES_GLOB_MIN_NODE} (the published package still ` +
        `runs on engines.node, which is lower).`,
    );
  return pathModule.matchesGlob;
}

export const matchesGlob = requireMatchesGlob();
