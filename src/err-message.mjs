/**
 * The message of a caught value, which is `unknown` under strict mode.
 *
 * PROBLEM CLASS — rendering a caught error as text. The library's warnings and
 * every hook's failure reason read this one definition, so a wrapped failure
 * reads "outer: root" everywhere rather than "outer" in some copies.
 * Dependency-free: the hooks import it relatively and must keep it when the
 * agent-sanitizer package failed to load.
 */

/**
 * Message from a caught value, with one level of cause chain appended when the
 * cause is itself an Error.
 * @param {unknown} err
 * @returns {string}
 */
export function errMessage(err) {
  if (!(err instanceof Error)) return String(err);
  const cause = err.cause instanceof Error ? `: ${err.cause.message}` : "";
  return err.message + cause;
}
