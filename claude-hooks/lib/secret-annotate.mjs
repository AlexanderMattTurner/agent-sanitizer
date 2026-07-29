/**
 * Layer-4 pre-gate helpers for env-bound secrets. The redaction transport (the
 * daemon call) stays with the sanitize-output hook; this module owns only the
 * cheap, deterministic checks around it.
 */
import { minEnvSecretLen, envBoundSecretVars } from "./env-config.mjs";

// Zero-width / format (Cf) characters an attacker can splice between a value's
// characters to break an exact-substring pre-gate while the daemon's redactor
// still matches across them. This is a curated subset of the common bidi /
// zero-width controls, NOT an exact copy of the daemon's full dynamic Cf set — it
// is a defense-in-depth backstop, because Layer 1 (applyLayer1) strips every Cf
// splice from the text BEFORE this pre-gate runs, so hasEnvBoundSecret already
// sees the plain value. A run of zero-or-more is allowed at each interior gap, so
// the plain value still matches (a superset of `includes`). Required literals
// between every gap keep the pattern linear — no ReDoS.
const ENV_INVIS_RUN =
  "[\\u200b\\u200c\\u200d\\u2060\\ufeff\\u00ad\\u180e\\u200e\\u200f\\u202a-\\u202e\\u2066-\\u2069]*";

/**
 * Regex matching `value` tolerating invisible chars spliced between its
 * characters (mirrors the engine's env-value regex). Code-point split so
 * an astral character is escaped whole, not as two surrogate halves.
 * @param {string} value
 * @returns {RegExp}
 */
export function envValueRegex(value) {
  return new RegExp(
    [...value]
      .map((ch) => ch.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
      .join(ENV_INVIS_RUN),
  );
}

/**
 * True when tool output contains the literal value of a configured env-bound
 * secret. The shape-based secret hint can't match a prefix-less key or a host
 * credential, so the pre-gate must also fire on the value itself — otherwise
 * the engine's env-bound redaction never runs. Invisible-tolerant so a
 * value with spliced Cf chars (which the daemon still redacts) trips it too.
 * @param {string} text
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {boolean}
 */
export function hasEnvBoundSecret(text, env = process.env) {
  const minLen = minEnvSecretLen();
  return envBoundSecretVars().some((name) => {
    const value = env[name];
    // Code-point length to match envValueRegex's code-point split — an astral
    // char counts once, not as two UTF-16 units, so minLen means the same thing
    // on both sides of the gate.
    return (
      value && [...value].length >= minLen && envValueRegex(value).test(text)
    );
  });
}
