/**
 * The one place a hook's own wall-clock cost is measured and reported.
 *
 * These hooks sit on the critical path of every tool call, every prompt and
 * every session start: whatever they spend, the user waits. That cost is also
 * the hardest kind of bug to notice from inside — a hook that got slow looks
 * exactly like an agent that got slow, so it goes unreported for weeks (one
 * SessionStart scan blocked startup for 30 SECONDS before anyone traced it back
 * here). A hook past the budget therefore says so IN BAND, in the model's
 * context, where it cannot be missed and can be relayed to the operator.
 *
 * One threshold, one message, one merge rule, shared by every hook — the
 * measurement is worthless if each hook words it differently or picks its own
 * bar for "slow".
 *
 * What it deliberately does NOT count is ONE-TIME PROVISIONING (see
 * {@link excludeProvisioning}). A dependency-install wait or a cold redactor
 * spawn is wall-clock the user really waits, but it is not a cost this hook
 * pays per call and it is not a bug worth a report — charging it would make the
 * FIRST call of every session cry wolf, which is precisely the alert fatigue
 * this notice exists to avoid.
 *
 * Dependency-free on purpose: everything imports this, including hook-io, so a
 * back-import would close a cycle. The one emitter it needs is passed in.
 */

/**
 * Wall-clock a single hook invocation may spend before it is reported as slow.
 *
 * A second is far above anything these hooks do when healthy (Layer 1 is a few
 * regex passes; the redactor daemon answers in tens of milliseconds once warm)
 * and far below the point where a human is merely impatient — so crossing it
 * means something is actually wrong, not that the machine is busy.
 */
export const SLOW_HOOK_THRESHOLD_MS = 1000;

/** Where a reader is asked to send the timing. */
const ISSUE_URL =
  "https://github.com/AlexanderMattTurner/agent-sanitizer/issues/new";

// Process-wide total of milliseconds spent in one-time provisioning. A running
// total rather than a flag because a single hook run can pay more than one (a
// dependency wait AND a cold daemon spawn), and they may not nest.
let provisioningMs = 0;

/**
 * Run `work`, charging its whole duration to provisioning so no timer running
 * across it counts that time. Charged in a `finally`, so a provisioning step
 * that FAILS is still excluded — the wait happened either way, and a hook that
 * then fails is reported through its fault posture, not as "slow".
 *
 * Wrap only genuinely one-time, per-session setup: waiting out a dependency
 * install, waiting for a cold redactor daemon to bind. Never wrap the hook's
 * actual work — that is exactly what this measurement is for.
 * @template T
 * @param {() => Promise<T>} work
 * @param {() => number} [now]  injectable clock, for tests
 * @returns {Promise<T>}
 */
export async function excludeProvisioning(work, now = Date.now) {
  const started = now();
  try {
    return await work();
  } finally {
    provisioningMs += Math.max(0, now() - started);
  }
}

/**
 * Start measuring; the returned function reports the milliseconds elapsed so
 * far MINUS any provisioning charged in the meantime, and may be called more
 * than once.
 *
 * Only provisioning charged since this timer started is subtracted, so an
 * earlier run's cold start cannot pay down a later run's real cost. A
 * provisioning window that straddles the timer's start would otherwise be able
 * to subtract more than the timer has measured, so the result is floored at 0.
 * @param {() => number} [now]  injectable clock, for tests
 * @returns {() => number}
 */
export function startHookTimer(now = Date.now) {
  const started = now();
  const provisionedBefore = provisioningMs;
  return () =>
    Math.max(0, now() - started - (provisioningMs - provisionedBefore));
}

/**
 * The model-facing line for a hook that overran the budget, or null when it did
 * not. Addressed to the model because the model is the only party that reliably
 * reads this channel — stderr from a non-blocking hook is easy to miss — and it
 * is asked to relay the number, since the operator is the one who can file it.
 * @param {string} hookName
 * @param {number} elapsedMs
 * @param {number} [thresholdMs]
 * @returns {string | null}
 */
export function slowHookNotice(
  hookName,
  elapsedMs,
  thresholdMs = SLOW_HOOK_THRESHOLD_MS,
) {
  if (elapsedMs <= thresholdMs) return null;
  return (
    `agent-sanitizer PERFORMANCE: the ${hookName} hook took ` +
    `${(elapsedMs / 1000).toFixed(1)}s, over its ${(thresholdMs / 1000).toFixed(1)}s budget — ` +
    "this delay is the sanitizer's, not the model's, and every affected call pays it. " +
    `Tell the user, and suggest they report it at ${ISSUE_URL} with the hook name and timing.`
  );
}

/**
 * `verdict` with the slow-hook notice folded into its `additional_context`, or
 * the verdict untouched when the run was within budget. Also writes the notice
 * to stderr, so the timing survives in the transcript even for a hook whose
 * verdict carries no context channel to the model.
 *
 * Appended, never substituted: the context slot is how a hook reports a REDACTED
 * secret or a stripped payload, and a timing note must not displace that.
 * @template {{ additional_context?: string }} V
 * @param {string} hookName
 * @param {number} elapsedMs
 * @param {V} verdict
 * @param {(chunk: string) => void} [writeErr]  injectable stderr sink, for tests
 * @returns {V}
 */
export function withSlowHookNotice(
  hookName,
  elapsedMs,
  verdict,
  writeErr = (chunk) => process.stderr.write(chunk),
) {
  const notice = slowHookNotice(hookName, elapsedMs);
  if (notice === null) return verdict;
  writeErr(notice + "\n");
  return {
    ...verdict,
    additional_context: verdict.additional_context
      ? `${verdict.additional_context} ${notice}`
      : notice,
  };
}

/**
 * Report a slow run for a hook that answers with a bare `hookSpecificOutput`
 * envelope rather than a control-plane verdict — SessionStart, which has no
 * verdict channel at all. A within-budget run emits nothing, so the quiet path
 * stays quiet (and the hook's silent-success contract is unchanged).
 * @param {string} hookName
 * @param {number} elapsedMs
 * @param {string} hookEventName
 * @param {(event: string, fields: Record<string, unknown>) => void} emit  the
 *   stdout envelope writer (hook-io's emitHookResponse); passed in rather than
 *   imported so this module stays dependency-free — see the module doc
 * @param {(chunk: string) => void} [writeErr]  injectable stderr sink, for tests
 * @returns {boolean}  whether a notice was emitted
 */
export function reportSlowHook(
  hookName,
  elapsedMs,
  hookEventName,
  emit,
  writeErr = (chunk) => process.stderr.write(chunk),
) {
  const notice = slowHookNotice(hookName, elapsedMs);
  if (notice === null) return false;
  writeErr(notice + "\n");
  emit(hookEventName, { additionalContext: notice });
  return true;
}
