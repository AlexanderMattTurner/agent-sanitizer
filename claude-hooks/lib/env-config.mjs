/**
 * The env-bound secret vocabulary the Layer-4 pre-gate and the redactor client
 * share, so the set of variable names whose VALUES get masked has one definition
 * instead of a copy per hook that can silently drift.
 *
 * The three JSON configs are imported as modules, not read from disk at call
 * time: esbuild inlines them into the plugin bundle (which ships with no
 * config directory beside it) and Node resolves them natively from the package
 * when the hooks run from source. Their VALIDATION stays lazy — a malformed
 * credential vocabulary throws on first use, inside the consuming hook's
 * fail-closed catch, rather than at module load where a throw would abort before
 * that catch installs and let the harness pass the tool output through
 * UNSANITIZED (fail OPEN).
 */
import credentialVarNames from "../config/credential-var-names.json" with { type: "json" };
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

// A token from credential-var-names.json. Restricting it to A-Z/_ is what lets
// the regexes below interpolate it unescaped: a stray metacharacter (or an empty
// list, which would make the match regex accept nothing and leak every forwarded
// credential) fails closed here instead of silently under-matching.
const CRED_TOKEN_RE = /^[A-Z_]+$/;

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
    throw new Error(`credential-var-names.json: ${field} is empty or missing`);
  for (const token of group)
    if (typeof token !== "string" || !CRED_TOKEN_RE.test(token))
      throw new Error(
        `credential-var-names.json: bad token ${token} in ${field}`,
      );
  return group;
}

/**
 * Validate a credential-var-names spec and build its match/exclude regexes. Pure
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
  return (_credentialNameRes = buildCredentialNameRes(credentialVarNames));
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
