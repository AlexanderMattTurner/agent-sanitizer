/**
 * Glob patterns rewritten for the Node releases whose `fs.globSync` cannot see
 * a dot-named segment after a `**`.
 *
 * Before 22.22.1, 24.13.1 and 25.4.0, and on every 23.x, globSync matches
 * NOTHING for a `**` directly followed by a dot-named segment
 * (nodejs/node#61012): `**\/.claude/*.md` finds no file, so an instruction scan
 * reports clean over files it never read. On those releases each such pattern
 * is rewritten into forms the broken walker answers; on every other release
 * patterns pass through untouched, so a fixed Node keeps its own semantics.
 */

// The first release of each affected line that carries the fix. 23.x never got
// one; every line from 26 on was cut after it landed.
const FIXED_IN = new Map([
  [22, [22, 1]],
  [24, [13, 1]],
  [25, [4, 0]],
]);
const FIRST_FIXED_MAJOR = 26;

// A `**` segment directly followed by a dot-named one, at the pattern start or
// after a `/`, or opening a brace alternative.
const DOT_AFTER_GLOBSTAR = /(?:^|[/{,])\*\*\/(?=\.)/;

// A dot segment after `**/` that the rewrite cannot reach: escaped, or opening
// an alternative of a brace set.
const HIDDEN_DOT_AFTER_GLOBSTAR = /\*\*\/(?:\\\.|\{(?:[^{}]*,)?\.)/;

/**
 * Whether the globSync of Node `version` (`process.versions.node`'s shape)
 * misses a dot-named segment after a `**`.
 * @param {string} version
 * @returns {boolean}
 */
export function globstarSkipsDotSegments(version) {
  const [major, minor, patch] = version.split(".").map(Number);
  if (major >= FIRST_FIXED_MAJOR) return false;
  const fixed = FIXED_IN.get(major);
  if (!fixed) return true;
  const [fixedMinor, fixedPatch] = fixed;
  return minor < fixedMinor || (minor === fixedMinor && patch < fixedPatch);
}

/**
 * `pattern` as patterns the broken globSync answers.
 *
 * Each `**\/` before a dot segment spans zero directories or one or more:
 * dropping it is the first case and `**\/*\/` the second, and neither puts a
 * dot segment straight after a `**`. A `*` never matches a dot-named directory,
 * so the halves can match less than a fixed Node does (which enters a dot
 * directory named like the segment after `**`), never more. A dot segment the
 * rewrite cannot reach throws rather than silently matching nothing.
 * @param {string} pattern
 * @returns {string[]}
 */
export function expandDotGlobstar(pattern) {
  const match = DOT_AFTER_GLOBSTAR.exec(pattern);
  if (match) {
    const head = pattern.slice(0, match.index + match[0].indexOf("*"));
    const tail = pattern.slice(match.index + match[0].length);
    return [`${head}${tail}`, `${head}**/*/${tail}`].flatMap(expandDotGlobstar);
  }
  if (HIDDEN_DOT_AFTER_GLOBSTAR.test(pattern))
    throw new Error(
      `glob ${JSON.stringify(pattern)} puts a dot-named segment after "**" in a ` +
        `form this Node's globSync matches nothing for (nodejs/node#61012); ` +
        `spell the segment plainly or run Node >= 22.22.1, 24.13.1 or 25.4.0.`,
    );
  return [pattern];
}

/**
 * `patterns` ready for this runtime's globSync: rewritten by
 * {@link expandDotGlobstar} on an affected Node, untouched otherwise.
 * @param {string[]} patterns
 * @param {string} [version]  defaults to the running Node
 * @returns {string[]}
 */
export function compatGlobs(patterns, version = process.versions.node) {
  return globstarSkipsDotSegments(version)
    ? patterns.flatMap(expandDotGlobstar)
    : patterns;
}
