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
 *
 * The sink is INJECTABLE. A host that already runs a trace channel under its own
 * environment variables — and a detector that reds when a defense layer stops
 * announcing itself — passes its own {@link TraceFn} to each hook's entry point
 * (`cliMain`, or `main` for the prompt gate) instead of forking this module. Left
 * unsupplied, every hook uses {@link trace} below, so the shipped behavior is
 * unchanged.
 */

import { appendFileSync } from "node:fs";

/**
 * The sink shape a hook emits through: the event name, its metadata fields, and
 * the level. A host implementation receives the same {@link TraceEvent} names the
 * default emits, so it can remap them onto its own channel's vocabulary.
 *
 * A sink is NOT required to be total — throw freely. Every hook binds the one it
 * was given through {@link bestEffortTrace}, which is what upholds the channel's
 * never-breaks-a-hook posture on host code that cannot promise it.
 * @typedef {(event: string, fields?: Record<string, unknown>, level?: "info"|"debug") => void} TraceFn
 */

/** Trace-channel event names. */
export const TraceEvent = Object.freeze({
  HOOK_RAN: "hook_ran",
  SCAN_INVISIBLE_CHARS_RAN: "scan_invisible_chars_ran",
  SCAN_LOADED_INSTRUCTIONS_RAN: "scan_loaded_instructions_ran",
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

/**
 * `sink` with {@link trace}'s best-effort posture forced onto it: a throw is
 * swallowed, so an announcement can never break the hook making it.
 *
 * This is what makes the sink safely injectable. The announcement call sites were
 * placed under the guarantee that emitting cannot fail, and one of them relies on
 * it outright: scan-invisible-chars announces BEFORE it auto-cleans the
 * contaminated instruction files and arms the PreToolUse gate, with no catch
 * above it, so a throwing sink there would abort the scan — leaving the payload on
 * disk, the gate un-armed, and NO announcement on any channel. The loss the
 * announcement exists to make loud would itself be silent.
 *
 * Swallowing is right here and is not licence to swallow elsewhere in this tree:
 * a dropped announcement is already loud in the host's own detector — that is what
 * a trace channel is — whereas a killed hook is loud nowhere.
 * @param {TraceFn} sink
 * @returns {TraceFn}
 */
export function bestEffortTrace(sink) {
  return (event, fields, level) => {
    try {
      sink(event, fields, level);
    } catch {
      // See above: an announcement must never be the thing that breaks a hook.
    }
  };
}
