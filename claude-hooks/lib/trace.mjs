/**
 * Opt-in structured trace channel for the hooks. When _AGENT_SANITIZER_TRACE
 * names a level (info|debug; off/empty disables), each call appends one JSON line
 *   {"ts":<epoch_ms>,"level":"info","event":"<name>",...<fields>}
 * to the sink — the file named by _AGENT_SANITIZER_TRACE_FILE, else stderr. The
 * point is that every defense layer announces it ENGAGED, so a missing
 * announcement is loud. It is best-effort: a sink it can't write never throws, so
 * dropping a trace() onto a hook path costs nothing and risks nothing.
 *
 * METADATA ONLY — never pass a tool_input body or secret material as a field; the
 * channel is not redaction-aware.
 */

import { appendFileSync } from "node:fs";

/** Trace-channel event names. */
export const TraceEvent = Object.freeze({
  HOOK_RAN: "hook_ran",
  SCAN_INVISIBLE_CHARS_RAN: "scan_invisible_chars_ran",
});

const LEVELS = Object.freeze({ off: 0, info: 1, debug: 2 });

/**
 * Numeric verbosity from _AGENT_SANITIZER_TRACE: 0 off, 1 info, 2 debug.
 * Unknown, empty, or "off" → 0.
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {number}
 */
export function traceThreshold(env = process.env) {
  const value = (env._AGENT_SANITIZER_TRACE ?? "").toLowerCase();
  if (value === "debug" || value === "2") return LEVELS.debug;
  if (["info", "1", "true", "on"].includes(value)) return LEVELS.info;
  return LEVELS.off;
}

/**
 * Emit one JSON trace line for `event` at `level` (default "info") carrying the
 * metadata `fields`. No-op when the channel is below `level`; best-effort on write.
 * @param {string} event
 * @param {Record<string, unknown>} [fields]
 * @param {"info"|"debug"} [level]
 * @returns {void}
 */
export function trace(event, fields = {}, level = "info") {
  // info|debug are the only real levels; anything else (a producer typo) clamps
  // to info for BOTH the gate and the recorded field, so a line never carries a
  // level outside {info,debug} for a reader to bucket on.
  const lvl = level === "debug" ? "debug" : "info";
  if (traceThreshold() < LEVELS[lvl]) return;
  const line =
    JSON.stringify({ ts: Date.now(), level: lvl, event, ...fields }) + "\n";
  const file = process.env._AGENT_SANITIZER_TRACE_FILE;
  try {
    if (file) appendFileSync(file, line);
    else process.stderr.write(line);
  } catch {
    // best-effort: a trace we can't write must never break a hook.
  }
}
