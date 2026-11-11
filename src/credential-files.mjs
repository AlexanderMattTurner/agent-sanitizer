/**
 * The credential-FILE vocabulary, and the path matcher built from it.
 *
 * `agent-sanitizer/credential-files` publishes the paths that hold a secret as
 * data, and `agent-sanitizer/credential-files-matcher` (this module) builds the
 * predicate from it. Two consumers once kept their own lists, one of leaf-name
 * patterns and one of substrings over command text, and the lists disagreed:
 * `cat ~/.pgpass` was flagged by neither. The words are shared here, and so is
 * the rule:
 *
 * * `nameGlobs` match the path's leaf name;
 * * `pathGlobs` match the whole posix path and begin with a star and a slash, so
 *   the tool directory may sit anywhere in it;
 * * `directories` match any path component, so a whole directory is covered.
 *
 * Matching is case-insensitive. It is a glob walk with no regular expression, so
 * a path a caller does not choose cannot make it backtrack. A match reports that
 * a path is credential-shaped, not that it holds a secret.
 *
 * The vocabulary is `python/agent_sanitizer/secrets/data/credential-files.json`,
 * the same file the Python matcher reads. It arrives through ONE static JSON
 * import, which a bundler inlines (the plugin ships no `python/` directory), and
 * it is validated lazily, on first use rather than at load: a throw at load would
 * abort before the caller's fail-closed catch installs.
 */
import packagedSpec from "../python/agent_sanitizer/secrets/data/credential-files.json" with { type: "json" };

const FILE_LABEL = "credential-files.json";

// Lower-case only, because the path is lower-cased before it is compared: an
// upper-case glob would never match, so it is refused rather than left inert.
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
    throw new Error(`${FILE_LABEL}: ${field} is empty or missing`);
  const bad = value.filter(
    (item) =>
      typeof item !== "string" ||
      !shape.test(item) ||
      // A glob of wildcards alone matches every path, and `..` would flag every
      // path that climbs a directory.
      !LITERAL_RE.test(item) ||
      item === "." ||
      item === "..",
  );
  if (bad.length)
    throw new Error(
      `${FILE_LABEL}: bad entr(ies) ${JSON.stringify(bad)} in ${field}`,
    );
  return [...new Set(value)];
}

/** Validate `spec` and return it: the JavaScript twin of
 * `agent_sanitizer.secrets.parse_credential_files`, over the same file.
 *
 * A malformed spec throws rather than degrading. An empty list matches nothing
 * (every credential file passes) and a glob of wildcards alone matches everything.
 * @param {Record<string, unknown>} spec @returns {CredentialFiles} */
export function parseCredentialFiles(spec) {
  return {
    nameGlobs: entries(spec, "nameGlobs", NAME_GLOB_RE),
    pathGlobs: entries(spec, "pathGlobs", PATH_GLOB_RE),
    directories: entries(spec, "directories", DIRECTORY_RE),
  };
}

/** @type {CredentialFiles | undefined} */
let _packaged;
/** The validated packaged vocabulary, memoized.
 * @returns {CredentialFiles} */
export function credentialFiles() {
  return (_packaged ??= parseCredentialFiles(packagedSpec));
}

/** Whether `glob` (a-z 0-9 _ . - and `*` only) matches all of `text`, counting
 * code points. The walk remembers the last `*` and retries from there, so it is
 * O(glob x text) with no exponential case.
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
 * A path matches when any one holds, case-insensitively:
 *
 * * its leaf name matches a `nameGlobs` entry;
 * * its posix path matches a `pathGlobs` entry. A relative path is matched as if a
 *   `/` preceded it, so `.docker/config.json` meets a glob that is a star, a slash, then
 *   `.docker/config.json`;
 * * any of its components is in `directories`.
 *
 * `~` is an ordinary component, so `~/.pgpass` matches without expansion. The
 * returned predicate closes over the parsed vocabulary, so build it once.
 * @param {{ spec?: Record<string, unknown> }} [options]
 * @returns {(path: string) => boolean} */
export function credentialPathMatcher(options = {}) {
  const vocabulary = options.spec
    ? parseCredentialFiles(options.spec)
    : credentialFiles();
  const directories = new Set(vocabulary.directories);
  return (path) => {
    const parts = path
      .toLowerCase()
      .split("/")
      .filter((part) => part !== "" && part !== ".");
    if (parts.length === 0) return false;
    if (parts.some((part) => directories.has(part))) return true;
    const leaf = Array.from(/** @type {string} */ (parts.at(-1)));
    if (vocabulary.nameGlobs.some((glob) => globMatches(glob, leaf)))
      return true;
    const posix = Array.from(`/${parts.join("/")}`);
    return vocabulary.pathGlobs.some((glob) => globMatches(glob, posix));
  };
}
