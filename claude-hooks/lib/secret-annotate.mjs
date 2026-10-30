/**
 * Layer-4 pre-gate helpers for env-bound secrets. The redaction transport (the
 * daemon call) stays with the sanitize-output hook; this module owns only the
 * cheap, deterministic checks around it.
 */
import { minEnvSecretLen, envBoundSecretVars } from "./env-config.mjs";

// The generated cross-language charset SSOT, imported as a module like
// env-config.mjs's JSON configs: esbuild inlines it into the plugin bundle
// (which ships with no data directory beside it) and Node resolves it from the
// package when the hooks run from source. A DATA import, deliberately not a
// static `agent-sanitizer/invisible` import — a top-level package import in a
// hook lib aborts the process before the consuming hook's fault-posture catch
// installs, so the output passes with no warning at all.
import charset from "../../python/agent_sanitizer/data/invisible-charset.json" with { type: "json" };

// Invisible characters an attacker can splice between a value's characters to
// break an exact-substring pre-gate while the daemon's redactor still matches
// across them. Built from the SAME pinned charset Layer 1 strips and the daemon
// tolerates (`_env_value_spans` in agent_sanitizer.secrets.engine), not
// a hand-curated subset: a subset pre-gate silently under-matches whenever this
// gate runs on text Layer 1 has not already stripped, and a value spliced with a
// code point in the gap then never reaches the daemon at all.
const ENV_INVIS_RE = new RegExp(
  "[" +
    [...new Set([...charset.cf_codepoints, ...charset.extra_codepoints])]
      .map((cp) => `\\u{${cp.toString(16)}}`)
      .join("") +
    "]",
  "gu",
);

/**
 * `s` with every charset invisible removed.
 * @param {string} s
 * @returns {string}
 */
const stripInvisibles = (s) => s.replace(ENV_INVIS_RE, "");

/**
 * True when tool output contains the literal value of a configured env-bound
 * secret. The shape-based secret hint can't match a prefix-less key or a host
 * credential, so the pre-gate must also fire on the value itself — otherwise
 * the engine's env-bound redaction never runs. Invisible-tolerant so a
 * value with spliced Cf chars (which the daemon still redacts) trips it too.
 *
 * Both sides are stripped and compared as substrings, which is exactly
 * equivalent: the value's visible characters appear contiguously in the
 * stripped text iff they appear in the original separated only by invisibles.
 * It is linear and independent of the value's length — a regex with an
 * invisible class at every gap grows ~4 KB per character, and a long secret (a
 * PEM key) overflows V8's regex size limit and throws on every output.
 *
 * Callers pass post-Layer-1 text: terminal escapes are already gone, so a value
 * split by one is contiguous here. Raw text spliced with an escape is not
 * matched.
 * @param {string} text
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {boolean}
 */
export function hasEnvBoundSecret(text, env = process.env) {
  const minLen = minEnvSecretLen();
  /** @type {string | undefined} */
  let strippedText;
  return envBoundSecretVars(env).some((name) => {
    const value = env[name];
    // Code-point length, so an astral char counts once, not as two UTF-16 units.
    if (!value || [...value].length < minLen) return false;
    const needle = stripInvisibles(value);
    // A value made only of invisibles has no visible character to anchor on:
    // match it exactly rather than as the empty string, which matches anything.
    if (needle === "") return text.includes(value);
    strippedText ??= stripInvisibles(text);
    return strippedText.includes(needle);
  });
}
