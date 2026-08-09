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
// hook lib aborts the process before the consuming hook's fail-closed catch
// installs, which is a fail OPEN on the module that withholds secrets.
import charset from "../../python/agent_sanitizer/data/invisible-charset.json" with { type: "json" };

// Invisible characters an attacker can splice between a value's characters to
// break an exact-substring pre-gate while the daemon's redactor still matches
// across them. Built from the SAME pinned charset Layer 1 strips and the daemon
// tolerates (`invisible_run_pattern` in agent_sanitizer.secrets.invisible
// builds the same shape from the same set), not a hand-curated subset: a subset
// pre-gate silently under-matches whenever this gate runs on text Layer 1 has
// not already stripped (the module is exported and callable on its own), and a
// value spliced with a code point in the gap then never reaches the daemon at
// all. A run of zero-or-more is allowed at each interior gap, so the plain
// value still matches (a superset of `includes`). The required literals between
// every gap are what bound the match — a `*` gap is never adjacent to another
// gap, so there is no ambiguity to backtrack over and no ReDoS. (The class size
// is irrelevant to that: a character class matches in O(1) whether it holds one
// member or all 435.)
const ENV_INVIS_RUN =
  "[" +
  [...new Set([...charset.cf_codepoints, ...charset.extra_codepoints])]
    .sort((a, b) => a - b)
    .map((cp) => `\\u{${cp.toString(16)}}`)
    .join("") +
  "]*";

/**
 * Regex matching `value` tolerating invisible chars spliced between its
 * characters (mirrors the engine's env-value regex). Code-point split so
 * an astral character is escaped whole, not as two surrogate halves — and the
 * `u` flag, which the astral `\u{…}` class members in {@link ENV_INVIS_RUN}
 * require.
 * Memoized per distinct value: {@link ENV_INVIS_RUN} renders ~435 code points
 * as ~4 KB of source and is joined at EVERY interior gap, so a 20-char secret
 * compiles a ~75 KB pattern — and `hasEnvBoundSecret` builds one per configured
 * var on every PostToolUse output. Env values are stable for the process's
 * lifetime, so the cache is bounded by the number of distinct values. Sharing an
 * instance is safe because the regex carries no `g`/`y` flag, hence no
 * `lastIndex` state to leak between calls.
 * @param {string} value
 * @returns {RegExp}
 */
export function envValueRegex(value) {
  let re = ENV_VALUE_REGEX_CACHE.get(value);
  if (re === undefined) {
    re = new RegExp(
      [...value]
        .map((ch) => ch.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
        .join(ENV_INVIS_RUN),
      "u",
    );
    ENV_VALUE_REGEX_CACHE.set(value, re);
  }
  return re;
}

/** value → compiled matcher; see {@link envValueRegex}. */
const ENV_VALUE_REGEX_CACHE = new Map();

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
