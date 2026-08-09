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
// The package's own subpath, so the bundle resolves it through the pinned
// engine alias and an external consumer resolves the same specifier.
import { credentialNameMatcher } from "agent-sanitizer/credential-names-matcher";

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
 * Host-supplied secret-vocabulary source, consulted before the package configs.
 * Null (the default) keeps the package derivation.
 * @type {{ minSecretLen?: number, extraVars?: string[] } | null}
 */
let hostEnvConfigSource = null;

const HOST_SOURCE_LABEL = "configureEnvConfigSource";

const HOST_SOURCE_KEYS = ["minSecretLen", "extraVars"];

/**
 * Adopt a host's own secret config in place of the package's: `minSecretLen`
 * replaces the placeholder floor, and `extraVars` are unioned into the
 * env-bound redaction set. This seam is what lets a host whose credential
 * registry already names its forwarded secrets (and their length floor) drive
 * the packaged helpers from that registry instead of forking this module —
 * a fork is the drift channel that lets the two redaction sets silently
 * disagree. Unset fields keep their package derivation; `undefined` and `null`
 * both restore it entirely. Like the missing-package remedy seam there is no
 * too-late window: the source is consulted at each helper call, never resolved
 * at module scope, so a later call steers every later answer. A malformed
 * source — a non-object, a key this seam does not read, a bad field — throws
 * on first use, not here (see {@link hostSource}).
 * @param {{ minSecretLen?: number, extraVars?: string[] } | null} source
 *   host config, or null to restore the package derivation
 * @returns {void}
 */
export function configureEnvConfigSource(source) {
  hostEnvConfigSource = source ?? null;
}

/**
 * The stored host source with its shape validated, or null when unconfigured.
 * Shape errors — a non-object source, a key this seam does not read — throw
 * HERE, on first use inside the consuming hook's fail-closed catch, never at
 * configure time: a top-level throw in a bundle entry would kill the hook
 * before that catch installs (fail OPEN), and silently ignoring the problem
 * is worse — a typo'd `minSecretLength: 32` must not leave the helpers
 * running at the package floor while the host believes it configured 32.
 * @returns {{ minSecretLen?: number, extraVars?: string[] } | null}
 */
function hostSource() {
  const source = hostEnvConfigSource;
  if (source === null) return null;
  if (typeof source !== "object")
    throw new Error(
      `${HOST_SOURCE_LABEL}: source must be an object, got ${typeof source}`,
    );
  for (const key of Object.keys(source))
    if (!HOST_SOURCE_KEYS.includes(key))
      throw new Error(
        `${HOST_SOURCE_LABEL}: unknown key ${JSON.stringify(key)}; it reads ` +
          `${HOST_SOURCE_KEYS.join(" and ")}`,
      );
  return source;
}

/**
 * The placeholder floor: a candidate value shorter than this is too short to be a
 * real secret and is skipped by the env-bound redaction pre-gate. A malformed
 * host floor throws rather than degrading to the package's — a host that set 32
 * must not silently run at a laxer floor, and a non-positive one would admit
 * empty placeholders as secrets.
 * @returns {number}
 */
export function minEnvSecretLen() {
  const hostLen = hostSource()?.minSecretLen;
  if (hostLen === undefined) return inferenceKeys.min_secret_len;
  if (!Number.isInteger(hostLen) || hostLen <= 0)
    throw new Error(
      `${HOST_SOURCE_LABEL}: minSecretLen must be a positive integer, got ${JSON.stringify(hostLen)}`,
    );
  return hostLen;
}

/**
 * The host's declared extra secret variable names, or throw. A malformed entry
 * fails CLOSED, same contract as {@link extraSecretVars}: dropping it silently
 * would leave the host believing a forwarded credential is masked while its
 * value flows to the model verbatim.
 * @returns {string[]}
 */
function hostExtraSecretVars() {
  const vars = hostSource()?.extraVars;
  if (vars === undefined) return [];
  if (!Array.isArray(vars))
    throw new Error(`${HOST_SOURCE_LABEL}: extraVars must be an array`);
  for (const name of vars)
    if (typeof name !== "string" || !EXTRA_TOKEN_RE.test(name))
      throw new Error(
        `${HOST_SOURCE_LABEL}: ${JSON.stringify(name)} is not a variable name ` +
          "(expected [A-Z0-9_] names)",
      );
  return vars;
}

/** @type {((name: string) => boolean) | undefined} */
let _credentialRule;
/**
 * The credential-var-NAME predicate, memoized after the first build. Matching by
 * trailing segment lets the redaction set self-populate with any token the
 * process actually holds; a curated list drifts. The curated sets
 * (inferenceKeyVars + scrubbed vars) stay the guaranteed floor; this only ADDS
 * lookalikes.
 *
 * credentialNameMatcher is the package's one credential-name decision. A second
 * derivation here is how this module came to apply the vocabulary's non-secret
 * runs only when something preceded them, so a variable named exactly
 * `PUBLIC_KEY` was reported credential-bearing and its value cut out of every
 * tool output carrying it. One decision means the two cannot disagree again.
 * @returns {(name: string) => boolean}
 */
function credentialRule() {
  if (_credentialRule !== undefined) return _credentialRule;
  return (_credentialRule = credentialNameMatcher({
    spec: credentialNames,
    scope: "trailing",
    declineNonSecret: true,
  }));
}

/**
 * True when `name` looks like a credential-bearing variable (and isn't a known
 * non-secret lookalike).
 * @param {string} name
 * @returns {boolean}
 */
export function looksLikeCredentialVar(name) {
  return credentialRule()(name);
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

// These are whole variable names an operator typed, and real ones carry digits
// (`AWS_S3_KEY2`); metacharacters stay excluded so a malformed entry fails
// closed rather than widening the set.
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

// The one switch for the whole secret layer (Layer 4). Secret redaction is
// OPT-IN: it spawns a Python daemon, rewrites the model's view of tool output,
// and gates the write path (rehydration denies, the placeholder-write
// carve-out) — machinery whose false positives cost real work, so it engages
// only when an operator asked for it. Every secret-layer call site consults
// THIS predicate; a second reading of the variable is the drift channel that
// would let one hook redact while another passes placeholders through.
export const SECRETS_ENABLED_ENV = "AGENT_SANITIZER_SECRETS_ENABLED";

/**
 * True when the operator opted into the secret-redaction layer. `=== "1"`
 * matches the other public knobs (`AGENT_SANITIZER_*_DISABLED`): any other
 * value — unset, "true", "yes" — keeps the layer off, so a typo can only fail
 * toward the default (no secret machinery), never silently enable it.
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} [env]
 * @returns {boolean}
 */
export function secretsEnabled(env = process.env) {
  return env[SECRETS_ENABLED_ENV] === "1";
}

/**
 * The env-bound redaction set: the UNION of the inference keys, the curated host
 * credentials, any credential-shaped var present in the environment, the
 * operator's declared extras, and the host's configured extras. The redactor
 * binds the same union; every consumer (the sanitize-output pre-gate, the
 * redactor client's per-request env snapshot) must mirror it exactly, else a
 * credential value would never trip the daemon.
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
      ...hostExtraSecretVars(),
    ]),
  ];
}
