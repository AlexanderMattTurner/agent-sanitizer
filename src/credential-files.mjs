/**
 * The credential-FILE path matcher, built from the vocabulary that
 * `agent-sanitizer/credential-files` publishes (the JSON the Python twin reads).
 * `nameGlobs` match the leaf name, `pathGlobs` the whole posix path (each begins
 * `*` `/`), `directories` any component. Matching is case-insensitive by a glob
 * walk with no regular expression, so no path can make it backtrack. A match says
 * a path is credential-shaped, not that it holds a secret. The spec is validated
 * on first use: a throw at load would abort before the caller's fail-closed catch.
 */
import packagedSpec from "../python/agent_sanitizer/secrets/data/credential-files.json" with { type: "json" };

// Lower-case only, because the path is lower-cased before it is compared.
const NAME_GLOB_RE = /^[a-z0-9_.*-]+$/;
const PATH_GLOB_RE = /^\*\/[a-z0-9_.*/-]+$/;
const DIRECTORY_RE = /^[a-z0-9_.-]+$/;
const LITERAL_RE = /[a-z0-9_.-]/;

/** @typedef {{ nameGlobs: string[], pathGlobs: string[], directories: string[] }} CredentialFiles */

/** `spec[field]` as a validated, de-duplicated array, or throw naming `field`.
 * @param {Record<string, unknown> | undefined} spec @param {string} field
 * @param {RegExp} shape @returns {string[]} */
function entries(spec, field, shape) {
  const value = spec?.[field];
  if (!Array.isArray(value) || value.length === 0)
    throw new Error(`credential-files.json: ${field} is empty or missing`);
  // A glob of wildcards alone matches every path; `..` would flag every climb.
  const bad = value.filter(
    (item) =>
      typeof item !== "string" ||
      !shape.test(item) ||
      !LITERAL_RE.test(item) ||
      item === "." ||
      item === "..",
  );
  if (bad.length)
    throw new Error(
      `credential-files.json: bad entr(ies) ${JSON.stringify(bad)} in ${field}`,
    );
  return [...new Set(value)];
}

/** Validate `spec` and return it; throws rather than degrade, because an empty
 * list matches nothing and a wildcard-only glob matches everything.
 * @param {Record<string, unknown>} spec @returns {CredentialFiles} */
export function parseCredentialFiles(spec) {
  return {
    nameGlobs: entries(spec, "nameGlobs", NAME_GLOB_RE),
    pathGlobs: entries(spec, "pathGlobs", PATH_GLOB_RE),
    directories: entries(spec, "directories", DIRECTORY_RE),
  };
}

let /** @type {CredentialFiles | undefined} */ _packaged;
/** The validated packaged vocabulary, memoized.
 * @returns {CredentialFiles} */
export function credentialFiles() {
  return (_packaged ??= parseCredentialFiles(packagedSpec));
}

/** Whether `glob` (a-z 0-9 _ . - and `*`) matches all of `text`, in code points.
 * It retries from the last `*`, so it is O(glob x text) with no exponential case.
 * @param {string} glob @param {string[]} text @returns {boolean} */
function globMatches(glob, text) {
  let g = 0;
  let t = 0;
  let star = -1;
  let resume = 0;
  while (t < text.length) {
    if (glob[g] === "*") {
      star = g++;
      resume = t;
    } else if (glob[g] === text[t]) {
      g++;
      t++;
    } else if (star >= 0) {
      g = star + 1;
      t = ++resume;
    } else return false;
  }
  while (glob[g] === "*") g++;
  return g === glob.length;
}

/** A predicate: is this path a credential file, or inside a credential directory?
 *
 * The path is lower-cased, `.` and empty components are dropped, and each `..`
 * removes its parent. `~` is an ordinary component, so `~/.pgpass` matches.
 * Build the predicate once: it closes over the parsed vocabulary.
 * @param {{ spec?: Record<string, unknown> }} [options]
 * @returns {(path: string) => boolean} */
export function credentialPathMatcher(options = {}) {
  const vocabulary = options.spec
    ? parseCredentialFiles(options.spec)
    : credentialFiles();
  const directories = new Set(vocabulary.directories);
  return (path) => {
    const parts = [];
    for (const part of path.toLowerCase().split("/")) {
      if (part === "..") parts.pop();
      else if (part !== "" && part !== ".") parts.push(part);
    }
    if (parts.length === 0) return false;
    if (parts.some((part) => directories.has(part))) return true;
    const leaf = Array.from(/** @type {string} */ (parts.at(-1)));
    if (vocabulary.nameGlobs.some((glob) => globMatches(glob, leaf)))
      return true;
    const posix = Array.from(`/${parts.join("/")}`);
    return vocabulary.pathGlobs.some((glob) => globMatches(glob, posix));
  };
}
