/**
 * The credential-noun vocabulary, and the NAME matcher built from it.
 *
 * `agent-sanitizer/credential-names` publishes the vocabulary as data so a
 * consumer derives its matcher from one list instead of forking one. That shares
 * the words but not the RULE, and the rule is where the mistakes are: whether a
 * noun must be the name's trailing segment or may sit anywhere in it, whether the
 * comparison folds case, whether a multi-word noun is compared as one run, and
 * whether the walk stays linear in the name's length. A consumer that renders the
 * vocabulary into one alternation regex gets a pattern with polynomial
 * backtracking on a long name; one that anchors on the trailing segment alone
 * matches nothing at all for `DEPLOY_TOKEN_ORG` or `OAUTH_TOKEN_FALLBACK_4`.
 *
 * So the mechanics live here and the POLICY stays the caller's, selected by
 * `scope`. The two scopes are not interchangeable and neither is a better
 * default:
 *
 * * `"trailing"` — the noun is the name's last underscore-delimited run. What a
 *   REDACTOR wants: it decides what to cut out of text a human will read, where
 *   over-matching mangles legitimate output.
 * * `"any-segment"` — the noun is any whole run of the name's segments. What an
 *   env-var SCRUB wants: it decides what a subprocess may inherit, where the two
 *   error directions are not symmetric — an unstripped credential leaks
 *   silently, an over-stripped variable breaks the command loudly.
 *
 * Matching is set membership over the name's underscore-delimited runs, never an
 * alternation of the nouns: 28 prefix-sharing renderings (`API_KEY`, `APIKEY`,
 * `ACCESS_KEY`, …) compile to a pattern a redos analyzer measures as polynomial,
 * and a matcher a hostile variable NAME can stall has a denial-of-service in
 * front of it. The run length is bounded by the longest noun, so the walk is
 * linear in the name's segment count rather than quadratic.
 *
 * The vocabulary itself is `python/agent_sanitizer/secrets/data/credential-names.json`
 * — the same file the Python renderings read and the same file the
 * `agent-sanitizer/credential-names` subpath exports, so the ecosystems cannot
 * drift apart on the words either.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const DATA_FILE = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "python",
  "agent_sanitizer",
  "secrets",
  "data",
  "credential-names.json",
);

const FILE_LABEL = "credential-names.json";
const ENV_NAME_USE = "env-name";
const FIELD_VALUE_USE = "field-value";
const KNOWN_USES = new Set([ENV_NAME_USE, FIELD_VALUE_USE]);

// a-z0-9 only is what lets a part interpolate into a consumer's pattern
// unescaped. Anchored with ^…$ over a single character class, so a part carrying
// a newline is rejected here rather than accepted and then rejected by the Python
// validator applying the same rule to the same file.
const PART_RE = /^[a-z0-9]+$/;

/** @param {string[]} values @returns {string[]} `values` without duplicates, first-occurrence order kept. */
function dedupe(values) {
  return [...new Set(values)];
}

/** The whole-name forms of `parts`: underscore-joined and bare-joined, upper-cased.
 *
 * Both are emitted because both spellings occur in the wild (`API_KEY` and
 * `APIKEY`) and a matcher comparing underscore-delimited runs sees them as
 * different tokens. A single-part noun collapses to one form.
 * @param {string[]} parts @returns {string[]} */
function segmentForms(parts) {
  return dedupe([parts.join("_").toUpperCase(), parts.join("").toUpperCase()]);
}

/** `value` as a validated array of noun parts, or throw naming `field`.
 * @param {unknown} value @param {string} field @returns {string[]} */
function parts(value, field) {
  if (!Array.isArray(value) || value.length === 0)
    throw new Error(`${FILE_LABEL}: ${field} is empty or missing`);
  const bad = value.filter(
    (part) => typeof part !== "string" || !PART_RE.test(part),
  );
  if (bad.length)
    throw new Error(
      `${FILE_LABEL}: bad part(s) ${JSON.stringify(bad)} in ${field}`,
    );
  return value;
}

/** `value` as a validated non-empty subset of the known uses, or throw.
 *
 * An unknown use is a refusal, not a skip: silently ignoring it would drop the
 * noun from every rendering, which is how a credential noun becomes inert.
 * @param {unknown} value @param {string} field @returns {Set<string>} */
function uses(value, field) {
  if (!Array.isArray(value) || value.length === 0)
    throw new Error(`${FILE_LABEL}: ${field} is empty or missing`);
  const unknown = value.filter((use) => !KNOWN_USES.has(use)).sort();
  if (unknown.length)
    throw new Error(
      `${FILE_LABEL}: unknown use(s) ${JSON.stringify(unknown)} in ${field}`,
    );
  return new Set(value);
}

/** @typedef {{ segments: string[], fieldNamePatterns: string[], nonSecretSegments: string[] }} CredentialNames */

/** Validate `spec` and return its renderings — the JavaScript twin of
 * `agent_sanitizer.secrets.parse_credential_names`, over the same file.
 *
 * A malformed spec throws rather than degrading. An empty list would render an
 * alternation that matches nothing (every credential forwarded verbatim) and a
 * part carrying a regex metacharacter one that matches everything (all output
 * blanked), so neither may reach a consumer's matcher.
 * @param {Record<string, unknown>} spec @returns {CredentialNames} */
export function parseCredentialNames(spec) {
  const nouns = spec?.nouns;
  if (!Array.isArray(nouns) || nouns.length === 0)
    throw new Error(`${FILE_LABEL}: nouns is empty or missing`);
  /** @type {string[]} */
  const segments = [];
  /** @type {string[]} */
  const fieldNamePatterns = [];
  nouns.forEach((noun, index) => {
    if (typeof noun !== "object" || noun === null || Array.isArray(noun))
      throw new Error(`${FILE_LABEL}: nouns[${index}] is not an object`);
    const nounParts = parts(noun.parts, `nouns[${index}].parts`);
    const nounUses = uses(noun.uses, `nouns[${index}].uses`);
    if (nounUses.has(ENV_NAME_USE)) segments.push(...segmentForms(nounParts));
    if (nounUses.has(FIELD_VALUE_USE))
      fieldNamePatterns.push(nounParts.join("[_-]?"));
  });

  const suffixes = spec?.nonSecretSuffixes;
  if (!Array.isArray(suffixes) || suffixes.length === 0)
    throw new Error(`${FILE_LABEL}: nonSecretSuffixes is empty or missing`);
  const nonSecretSegments = suffixes.flatMap((suffix, index) =>
    segmentForms(parts(suffix, `nonSecretSuffixes[${index}]`)),
  );

  // A vocabulary that renders nothing for one matcher would hand that consumer an
  // empty set, which matches nothing and forwards every credential.
  if (!segments.length)
    throw new Error(`${FILE_LABEL}: no noun is marked ${ENV_NAME_USE}`);
  if (!fieldNamePatterns.length)
    throw new Error(`${FILE_LABEL}: no noun is marked ${FIELD_VALUE_USE}`);
  return {
    segments: dedupe(segments),
    fieldNamePatterns: dedupe(fieldNamePatterns),
    nonSecretSegments: dedupe(nonSecretSegments),
  };
}

/** @type {CredentialNames | undefined} */
let _packaged;
/** The validated renderings of the packaged vocabulary, memoized.
 *
 * Read lazily, never at module load: a static importer that crashed at LOAD would
 * abort before its own fail-closed catch installs, and a guardrail that fails to
 * load is a guardrail that fails OPEN. Deferring to first use routes a missing or
 * corrupt data file into the caller's catch instead.
 * @returns {CredentialNames} */
export function credentialNames() {
  return (_packaged ??= parseCredentialNames(
    JSON.parse(readFileSync(DATA_FILE, "utf8")),
  ));
}

/** @typedef {"trailing" | "any-segment"} CredentialNameScope */

/** A predicate: does this env-var NAME hold a credential?
 *
 * `scope` selects the rule — `"trailing"` for a redactor (the noun must be the
 * name's last run), `"any-segment"` for an env scrub (the noun may be any run).
 * See this module's header for why that choice belongs to the caller.
 *
 * `declineNonSecret` applies the vocabulary's `nonSecretSuffixes`: a name ending
 * in one holds an identifier or a public key (`AWS_ACCESS_KEY_ID`), not a secret.
 * Leave it on for a redactor, where redacting an identifier out of output is a
 * visible defect; turn it off for a scrub whose failure to strip is the worse
 * error. It is applied to the name's trailing run under both scopes, because a
 * non-secret marker only means anything at the end of a name.
 *
 * The returned predicate closes over the parsed vocabulary, so build it once and
 * reuse it — the parse and validation are not repeated per name.
 *
 * @param {{ scope?: CredentialNameScope, declineNonSecret?: boolean, spec?: Record<string, unknown> }} [options]
 * @returns {(name: string) => boolean} */
export function credentialNameMatcher(options = {}) {
  const { scope = "trailing", declineNonSecret = true, spec } = options;
  if (scope !== "trailing" && scope !== "any-segment")
    throw new Error(
      `credentialNameMatcher: unknown scope ${JSON.stringify(scope)}`,
    );
  const vocabulary = spec ? parseCredentialNames(spec) : credentialNames();
  const nouns = new Set(vocabulary.segments);
  const nonSecret = new Set(vocabulary.nonSecretSegments);
  // The longest noun's run length. A run longer than this can match no noun, so
  // bounding the walk here is what keeps it linear in the name's segment count —
  // without it a 2000-underscore name costs quadratic time.
  const maxRun = Math.max(
    ...vocabulary.segments.map((noun) => noun.split("_").length),
  );
  /** @param {string[]} words @returns {string[]} */
  const trailingRuns = (words) =>
    Array.from({ length: Math.min(maxRun, words.length) }, (_, i) =>
      words.slice(words.length - (i + 1)).join("_"),
    );
  return (name) => {
    const words = name.toUpperCase().split("_");
    if (
      declineNonSecret &&
      trailingRuns(words).some((run) => nonSecret.has(run))
    )
      return false;
    if (scope === "trailing")
      return trailingRuns(words).some((run) => nouns.has(run));
    for (let start = 0; start < words.length; start++)
      for (let span = 1; span <= maxRun && start + span <= words.length; span++)
        if (nouns.has(words.slice(start, start + span).join("_"))) return true;
    return false;
  };
}
