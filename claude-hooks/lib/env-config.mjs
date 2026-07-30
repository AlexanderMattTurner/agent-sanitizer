/**
 * The env-bound secret vocabulary the Layer-4 pre-gate and the redactor client
 * share, so the set of variable names whose VALUES get masked has one definition
 * instead of a copy per hook that can silently drift.
 *
 * The credential-NAME vocabulary comes from the published
 * `credential-names.json` — the same file `agent_sanitizer.secrets` renders in
 * Python — so the JavaScript pre-gate and the Python redactor recognize the same
 * set of credential-bearing variable names. A rendered second copy is what let
 * this matcher fall twelve segments behind the engine.
 *
 * The JSON configs are imported as modules, not read from disk at call time:
 * esbuild inlines them into the plugin bundle (which ships with no config
 * directory beside it) and Node resolves them natively from the package when the
 * hooks run from source. Their VALIDATION stays lazy — a malformed credential
 * vocabulary throws on first use, inside the consuming hook's fail-closed catch,
 * rather than at module load where a throw would abort before that catch installs
 * and let the harness pass the tool output through UNSANITIZED (fail OPEN).
 */
import credentialNames from "../../python/agent_sanitizer/secrets/data/credential-names.json" with { type: "json" };
import inferenceKeys from "../config/inference-key-vars.json" with { type: "json" };
import scrubbed from "../config/scrubbed-env-vars.json" with { type: "json" };

/**
 * The inference-provider key env vars. Their values authenticate the agent to a
 * model backend, so they are masked like any other credential.
 * @returns {string[]}
 */
export function inferenceKeyVars() {
  return inferenceKeys.vars;
}

/**
 * The placeholder floor: a candidate value shorter than this is too short to be a
 * real secret and is skipped by the env-bound redaction pre-gate.
 * @returns {number}
 */
export function minEnvSecretLen() {
  return inferenceKeys.min_secret_len;
}

// A rendered vocabulary token. Restricting it to A-Z/0-9/_ is what lets the
// regexes below interpolate it unescaped: a stray metacharacter (or an empty
// list, which would make the match regex accept nothing and leak every forwarded
// credential) fails closed here instead of silently under-matching. Digits are
// admitted because a noun part may legitimately carry one (the vocabulary's parts
// are `[a-z0-9]+`); a digit cannot be a metacharacter, so it is safe to embed.
const CRED_TOKEN_RE = /^[A-Z0-9_]+$/;

const VOCAB_LABEL = "credential-names.json";

// Names ending in a credential noun whose value is not a secret. SSH_AUTH_SOCK
// holds a filesystem path, and redacting it would strip the agent socket out of
// tool output. Site-independent (anyone running an ssh-agent has it), so it lives
// with the consumer rather than in the published vocabulary, which describes
// which WORDS name a secret and cannot know about a specific variable.
const EXCLUDE_NAMES = ["SSH_AUTH_SOCK"];

// Which noun renderings apply to a variable NAME (the other use, `field-value`,
// feeds the redactor's `field = value` matcher and is not a name matcher).
const ENV_NAME_USE = "env-name";

/**
 * The whole-name forms of `parts`: underscore-joined and bare-joined, upper-cased.
 * Both are emitted because both spellings occur in the wild (`API_KEY`, `APIKEY`)
 * and a matcher anchored on underscore-delimited segments sees them as different
 * tokens; a single-part noun collapses to one form. Mirrors the Python renderer
 * (`_segment_forms` in agent_sanitizer/secrets/credential_names.py) so the two
 * ecosystems derive the same vocabulary from the same file.
 * @param {string[]} parts
 * @returns {string[]}
 */
function segmentForms(parts) {
  return [
    ...new Set([parts.join("_").toUpperCase(), parts.join("").toUpperCase()]),
  ];
}

/**
 * Render the published credential-noun vocabulary into the name-matcher spec:
 * the credential segments, and the trailing suffixes that mark a
 * credential-shaped name as holding a non-secret.
 *
 * The vocabulary is the SINGLE source both ecosystems read — a curated second
 * copy of these renderings is what let this matcher fall twelve segments behind
 * the engine, so a variable named `…_ACCESS_TOKEN` was never recognized as
 * credential-bearing and its value was never handed to the redactor.
 * @param {Record<string, any>} spec
 * @returns {{ segments: string[], excludeSuffixes: string[], excludeNames: string[] }}
 */
export function deriveCredentialVocabulary(spec) {
  const nouns = spec?.nouns;
  const nonSecret = spec?.nonSecretSuffixes;
  if (!Array.isArray(nouns) || !Array.isArray(nonSecret))
    throw new Error(`${VOCAB_LABEL}: nouns/nonSecretSuffixes missing`);
  const segments = [];
  for (const noun of nouns)
    if (Array.isArray(noun?.uses) && noun.uses.includes(ENV_NAME_USE))
      segments.push(...segmentForms(parts(noun.parts, "nouns[].parts")));
  const excludeSuffixes = nonSecret.flatMap((suffix) =>
    segmentForms(parts(suffix, "nonSecretSuffixes[]")).map(
      (form) => `_${form}`,
    ),
  );
  return {
    segments: [...new Set(segments)],
    excludeSuffixes: [...new Set(excludeSuffixes)],
    excludeNames: EXCLUDE_NAMES,
  };
}

/**
 * `value` as a validated non-empty array of lower-case noun parts, or throw. A
 * malformed part must not render into a token that silently under-matches.
 * @param {unknown} value
 * @param {string} field
 * @returns {string[]}
 */
function parts(value, field) {
  if (!Array.isArray(value) || value.length === 0)
    throw new Error(`${VOCAB_LABEL}: ${field} is empty or missing`);
  for (const part of value)
    if (typeof part !== "string" || !/^[a-z0-9]+$/u.test(part))
      throw new Error(`${VOCAB_LABEL}: bad part ${part} in ${field}`);
  return value;
}

/**
 * The validated token list under `field`, or throw. An absent, empty, or
 * metacharacter-bearing list must not degrade into a pattern that matches nothing,
 * which would leak every forwarded credential.
 * @param {Record<string, unknown>} spec
 * @param {string} field
 * @returns {string[]}
 */
function credentialTokens(spec, field) {
  const group = spec[field];
  if (!Array.isArray(group) || group.length === 0)
    throw new Error(`${VOCAB_LABEL}: ${field} is empty or missing`);
  for (const token of group)
    if (typeof token !== "string" || !CRED_TOKEN_RE.test(token))
      throw new Error(`${VOCAB_LABEL}: bad token ${token} in ${field}`);
  return group;
}

/**
 * Validate a rendered name-matcher spec and build its match/exclude regexes. Pure
 * and exported so the fail-closed paths can be driven directly with a bad spec.
 * @param {Record<string, unknown>} spec
 * @returns {{ match: RegExp, exclude: RegExp }}
 */
export function buildCredentialNameRes(spec) {
  const segments = credentialTokens(spec, "segments");
  const excludeSuffixes = credentialTokens(spec, "excludeSuffixes");
  const excludeNames = credentialTokens(spec, "excludeNames");
  return {
    match: new RegExp(`(?:^|_)(?:${segments.join("|")})$`, "i"),
    exclude: new RegExp(
      `(?:${excludeSuffixes.join("|")})$|^(?:${excludeNames.join("|")})$`,
      "i",
    ),
  };
}

/** @type {{ match: RegExp, exclude: RegExp } | undefined} */
let _credentialNameRes;
/**
 * The credential-var-NAME regexes, memoized after the first build. Matching by
 * trailing segment lets the redaction set self-populate with any token the
 * process actually holds; a curated list drifts. The curated sets
 * (inferenceKeyVars + scrubbed vars) stay the guaranteed floor; this only ADDS
 * lookalikes.
 * @returns {{ match: RegExp, exclude: RegExp }}
 */
function credentialNameRes() {
  if (_credentialNameRes !== undefined) return _credentialNameRes;
  return (_credentialNameRes = buildCredentialNameRes(
    deriveCredentialVocabulary(credentialNames),
  ));
}

/**
 * True when `name` looks like a credential-bearing variable (and isn't a known
 * non-secret lookalike).
 * @param {string} name
 * @returns {boolean}
 */
export function looksLikeCredentialVar(name) {
  const res = credentialNameRes();
  return res.match.test(name) && !res.exclude.test(name);
}

/**
 * Credential-shaped env-var names present in `env` with a value long enough to be
 * a real secret (the min_secret_len floor the daemon also applies), beyond the
 * curated set. Reads the live environment so a newly-forwarded token is redacted
 * without a code change.
 * @param {Record<string, string | undefined>} [env]
 * @returns {string[]}
 */
export function dynamicSecretVars(env = process.env) {
  const floor = minEnvSecretLen();
  return Object.keys(env).filter(
    (name) => looksLikeCredentialVar(name) && (env[name]?.length ?? 0) >= floor,
  );
}

// Operator-supplied additions to the env-bound redaction set, comma-separated.
// The name-shape heuristic above only catches vars whose trailing segment reads
// as a credential (`…_TOKEN`, `…_KEY`); a deployment that forwards a secret under
// a name of its own choosing (`GLOVEBOX_ATTESTATION_SEED`) has no way to reach
// the set without this.
const EXTRA_SECRET_VARS_ENV = "_AGENT_SANITIZER_EXTRA_SECRET_VARS";

// Digits allowed here but not in CRED_TOKEN_RE: that one gates regex-interpolated
// name SEGMENTS, while these are whole variable names an operator typed, and real
// ones carry digits (`AWS_S3_KEY2`). Both exclude metacharacters.
const EXTRA_TOKEN_RE = /^[A-Z0-9_]+$/;

/**
 * The operator-declared extra secret variable names, or throw. A malformed entry
 * fails CLOSED — dropping it silently would leave the operator believing a
 * forwarded credential is masked while its value flows to the model verbatim.
 * @param {Record<string, string | undefined>} [env]
 * @returns {string[]}
 */
export function extraSecretVars(env = process.env) {
  const raw = env[EXTRA_SECRET_VARS_ENV];
  if (raw === undefined || raw.trim() === "") return [];
  const tokens = raw.split(",").map((token) => token.trim());
  for (const token of tokens)
    if (!EXTRA_TOKEN_RE.test(token))
      throw new Error(
        `${EXTRA_SECRET_VARS_ENV}: ${JSON.stringify(token)} is not a variable name ` +
          "(expected comma-separated [A-Z0-9_] names)",
      );
  return tokens;
}

/**
 * The env-bound redaction set: the UNION of the inference keys, the curated host
 * credentials, any credential-shaped var present in the environment, and the
 * operator's declared extras. The redactor binds the same union; every consumer
 * (the sanitize-output pre-gate, the redactor client's per-request env snapshot)
 * must mirror it exactly, else a credential value would never trip the daemon.
 * @param {Record<string, string | undefined>} [env]
 * @returns {string[]}
 */
export function envBoundSecretVars(env = process.env) {
  return [
    ...new Set([
      ...inferenceKeyVars(),
      ...scrubbed.vars,
      ...dynamicSecretVars(env),
      ...extraSecretVars(env),
    ]),
  ];
}
