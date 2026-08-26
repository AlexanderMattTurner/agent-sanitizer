/**
 * The one place a hook's own cost is measured and reported — one threshold, one
 * message, one merge rule, shared by every hook.
 *
 * These hooks sit on the critical path of every tool call, prompt and session
 * start: whatever they spend, the user waits. A slow hook is also the hardest
 * bug to notice from inside — it looks exactly like a slow agent, so it goes
 * unreported for weeks (one SessionStart scan blocked startup for 30 SECONDS
 * before anyone traced it back here). A hook past the budget therefore says so
 * IN BAND, in the model's context, where it can be relayed to the operator.
 *
 * FOUR numbers, because wall-clock alone cannot say whose cost it is: a hook on
 * a contended host waits far longer than it computes (a 1.1 KB payload and a
 * 235 KB one both reported 7.2s on a loaded 2-vCPU box, against 0.3s of work).
 * So the notice prints, beside the clock, the CPU this process burned, the time
 * it spent inside redactor round trips, and the time it spent inside a HOST
 * EXTENSION it called ({@link chargeHostExtension}) — the redactor daemon and a
 * host callback's subprocess or socket peer are separate processes whose CPU this
 * one cannot see (see {@link processCpuMs}), so the call that waits for each is
 * the only measurable stand-in. The notice GATES on none of them: a hook wedged
 * on a dead redactor socket burns no CPU and is exactly the sanitizer's fault.
 *
 * The host-extension window is what turned "blocked on something outside the
 * sanitizer" — a verdict nobody can act on — into a named callee: a composer's
 * best-effort audit POST to an unreachable sink charged every tool call its full
 * 1.0s connect bound, and the notice could name none of it.
 *
 * ONE-TIME PROVISIONING is excluded (see {@link excludeProvisioning}): charging
 * an install to the hook that merely waited it out would make the FIRST call of
 * every session cry wolf, which is the alert fatigue this notice fights.
 *
 * Dependency-free on purpose: everything imports this, including hook-io, so a
 * back-import would close a cycle. The one emitter it needs is passed in.
 */

/**
 * Wall-clock a single hook invocation may spend before it is reported as slow.
 *
 * A second is far above anything these hooks do when healthy (Layer 1 is a few
 * regex passes; the redactor daemon answers in tens of milliseconds once warm)
 * and far below the point where a human is merely impatient. Crossing it means
 * the user waited that long, which is worth saying either way; whether the
 * sanitizer or a busy machine spent it is what the CPU figure answers.
 */
export const SLOW_HOOK_THRESHOLD_MS = 1000;

/**
 * Wall-clock a ONE-TIME provisioning step may spend before it is reported.
 *
 * Two orders of magnitude above {@link SLOW_HOOK_THRESHOLD_MS}, because it
 * measures something categorically different: a dependency install that a
 * session pays once, not a cost every tool call repeats. A cold `uv` install of
 * the redactor engine is seconds and a cold `pip` one can be tens of them, so a
 * budget anywhere near a second would report every first session — the alert
 * fatigue this whole module exists to avoid. Past a minute, something is
 * actually wrong (a serial pip resolve, a wedged mirror, or an idempotence bug
 * re-provisioning every session), which is worth saying out loud.
 */
export const SLOW_PROVISION_THRESHOLD_MS = 60000;

/** Where a reader is asked to send the timing. */
const ISSUE_URL =
  "https://github.com/AlexanderMattTurner/agent-sanitizer/issues/new";

/**
 * Milliseconds as the seconds string every notice below prints.
 *
 * Rounds tenths half-UP from an exact integer count of hundredths, rather than
 * `(ms / 1000).toFixed(1)`: the shell port of this module
 * (plugin/scripts/lib/hook-timing.sh) has to produce the byte-identical string
 * with integer arithmetic, and `toFixed` rounds the underlying double — so 1150
 * would print "1.1" here (1.15 is below its decimal value as a double) and "1.2"
 * there. `ms / 100` lands exactly on a half only when `ms` ends in 50, and every
 * such quotient is dyadic, so this rounding is exact for every input.
 * @param {number} ms
 * @returns {string}
 */
export function formatSeconds(ms) {
  return (Math.round(ms / 100) / 10).toFixed(1);
}

/**
 * Bytes as a human-scaled string (B / KB / MB, one decimal past B) for the
 * slow-hook notice's payload clause. No shell-parity constraint applies here —
 * unlike {@link formatSeconds}, the shell port never has a payload size to
 * print (see plugin/scripts/lib/hook-timing.sh's header).
 * @param {number} bytes
 * @returns {string}
 */
export function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/**
 * Debugging context a caller may already have in hand when a hook overruns its
 * budget, so the notice names WHAT was slow instead of just HOW slow — the gap
 * that made this specific latency report take a manual multi-step
 * investigation to characterize (which tool call, how large a payload) before
 * anyone could act on it.
 * `cpuMs` is the run's own processor time, `redactorMs` the wall-clock it spent
 * inside redactor round trips, and `hostMs` the wall-clock it spent inside host
 * extensions (all from {@link startHookTimer}); absent when the caller has no way
 * to measure them, which is what the shell port of this module reports.
 * @typedef {{
 *   payloadBytes?: number | null,
 *   tool?: string | null,
 *   cpuMs?: number | null,
 *   redactorMs?: number | null,
 *   hostMs?: number | null,
 * }} SlowHookContext
 */

/**
 * The parenthetical clause naming `context`'s payload size and tool, or `""`
 * when neither is known — so a caller with nothing to name gets the same notice
 * text as one that passes no context at all. `cpuMs` is deliberately not here:
 * it needs the sentence {@link slowHookNotice} gives it, not a bare number in a
 * list of what was slow.
 * @param {SlowHookContext | undefined} [context]
 * @returns {string}
 */
function formatContextSuffix(context) {
  if (!context) return "";
  const parts = [];
  if (typeof context.payloadBytes === "number")
    parts.push(`a ${formatBytes(context.payloadBytes)} payload`);
  if (context.tool) parts.push(`tool ${context.tool}`);
  return parts.length > 0 ? ` (${parts.join(", ")})` : "";
}

/**
 * This process's own user+system processor time so far, in milliseconds.
 *
 * `process.cpuUsage()` is RUSAGE_SELF: it counts what this node process
 * computed and excludes both idle waiting and any child process. That is
 * exactly the split the notice needs — a hook blocked on a socket, a lock or a
 * loaded scheduler adds wall-clock here and no CPU.
 * @returns {number}
 */
function processCpuMs() {
  const { user, system } = process.cpuUsage();
  return (user + system) / 1000;
}

// Process-wide totals of wall-clock and CPU spent in one-time provisioning. A
// running total rather than a flag because a single hook run can pay more than
// one (a dependency wait AND a cold daemon spawn), and they may not nest.
let provisioningMs = 0;
let provisioningCpuMs = 0;

// Process-wide total of wall-clock spent inside redactor round trips. Wall-clock
// and not CPU because the daemon is a separate process: its work is invisible to
// processCpuMs, so how long this side waited for an answer is the only
// measurement available.
let redactorRoundTripMs = 0;

// Process-wide total of wall-clock spent inside host extensions. Same reason as
// the redactor total above: a callback's cost lands in a subprocess or a socket
// peer, so this side's wait is the only measurement available.
let hostExtensionMs = 0;

/**
 * Run `work` — one redactor round trip — charging its duration to the redactor
 * share, so a run that spent its second inside a redaction call is told apart
 * from one that spent it anywhere else. Charged in a `finally`, since a round
 * trip that THROWS (a stall that hit its deadline) is the one that spent the
 * most.
 *
 * Unlike {@link excludeProvisioning} this only attributes; the time stays in the
 * hook's wall-clock, because a slow redaction is a per-call cost the user waits
 * for.
 * @template T
 * @param {() => Promise<T>} work
 * @param {() => number} [now]  injectable clock, for tests
 * @returns {Promise<T>}
 */
export async function chargeRedactorRoundTrip(work, now = Date.now) {
  const started = now();
  try {
    return await work();
  } finally {
    redactorRoundTripMs += Math.max(0, now() - started);
  }
}

/**
 * Run `work` — one call into a HOST EXTENSION (a composer's `postText`, `audit`
 * or other injected callback) — charging its duration to the host share, so a run
 * that spent its second inside a callback is told apart from one that spent it
 * anywhere else. Charged in a `finally`, since a callback that THROWS is the one
 * that spent the most.
 *
 * Like {@link chargeRedactorRoundTrip} this only attributes; the time stays in
 * the hook's wall-clock, because the user waits for it either way. It says WHERE
 * the time went and declines to say WHOSE: the wait holds the callback's own work
 * AND whatever descheduling the host imposed on it.
 *
 * `work` may be synchronous — a callback that spawns a subprocess and blocks is
 * charged in full, because the whole call runs inside this bracket.
 * @template T
 * @param {() => Promise<T> | T} work
 * @param {() => number} [now]  injectable clock, for tests
 * @returns {Promise<T>}
 */
export async function chargeHostExtension(work, now = Date.now) {
  const started = now();
  try {
    return await work();
  } finally {
    hostExtensionMs += Math.max(0, now() - started);
  }
}

/**
 * Run `work`, charging its whole duration to provisioning so no timer running
 * across it counts that time. Charged in a `finally`, so a provisioning step
 * that FAILS is still excluded — the wait happened either way, and a hook that
 * then fails is reported through its fault posture, not as "slow".
 *
 * Its CPU is charged too, not just its wall-clock: the lazy dependency import
 * this wraps is real in-process work, so leaving it in would hand the first
 * call of every session a CPU figure it did not spend.
 *
 * Wrap only genuinely one-time, per-session setup: waiting out a dependency
 * install, waiting for a cold redactor daemon to bind. Never wrap the hook's
 * actual work — that is exactly what this measurement is for.
 * @template T
 * @param {() => Promise<T>} work
 * @param {() => number} [now]  injectable clock, for tests
 * @param {() => number} [cpuNow]  injectable CPU clock, for tests
 * @returns {Promise<T>}
 */
export async function excludeProvisioning(
  work,
  now = Date.now,
  cpuNow = processCpuMs,
) {
  const started = now();
  const cpuStarted = cpuNow();
  try {
    return await work();
  } finally {
    provisioningMs += Math.max(0, now() - started);
    provisioningCpuMs += Math.max(0, cpuNow() - cpuStarted);
  }
}

/**
 * Start measuring; each reader on the returned object reports what has elapsed
 * so far MINUS any provisioning charged in the meantime, and may be called more
 * than once.
 *
 * `wallMs` is what the user waited, `cpuMs` is what this process actually
 * computed, `redactorMs` is what it spent inside redactor round trips
 * ({@link chargeRedactorRoundTrip}) and `hostMs` what it spent inside host
 * extensions ({@link chargeHostExtension}). All four are needed to say where a
 * slow run's time went — see the module header for the report that read a contended
 * host as a sanitizer bug.
 *
 * Every reader counts only what was charged since this timer started, so an
 * earlier run's cold start cannot pay down a later run's real cost, and an
 * earlier run's round trip cannot be blamed on this one. A provisioning window
 * that straddles the timer's start would otherwise be able to subtract more than
 * the timer has measured, so the results are floored at 0.
 * @param {() => number} [now]  injectable clock, for tests
 * @param {() => number} [cpuNow]  injectable CPU clock, for tests
 * @returns {{ wallMs: () => number, cpuMs: () => number, redactorMs: () => number, hostMs: () => number }}
 */
export function startHookTimer(now = Date.now, cpuNow = processCpuMs) {
  const started = now();
  const cpuStarted = cpuNow();
  const provisionedBefore = provisioningMs;
  const provisionedCpuBefore = provisioningCpuMs;
  const redactorBefore = redactorRoundTripMs;
  const hostBefore = hostExtensionMs;
  return {
    wallMs: () =>
      Math.max(0, now() - started - (provisioningMs - provisionedBefore)),
    cpuMs: () =>
      Math.max(
        0,
        cpuNow() - cpuStarted - (provisioningCpuMs - provisionedCpuBefore),
      ),
    redactorMs: () => Math.max(0, redactorRoundTripMs - redactorBefore),
    hostMs: () => Math.max(0, hostExtensionMs - hostBefore),
  };
}

/**
 * The attribution sentence for a run whose CPU and redactor-round-trip shares
 * are both known: the three numbers, then which of the four WINDOWS the time went
 * into — this hook computing, the redactor call, a host extension, or none of
 * them.
 *
 * A window, not a culprit. The round trip is wall-clock measured from this side,
 * so it holds the daemon's scan AND whatever descheduling the host imposed on
 * either end; claiming the daemon from it would re-commit, one bucket over, the
 * overreach this whole split exists to retract. Separating those two needs
 * telemetry from inside the daemon, and the wire protocol has no place to carry
 * it — the response is `handle_request`'s object or a bare JSON `null`, which no
 * sibling field can ride on. So the redactor verdict says WHERE and declines to
 * say WHOSE, while the other two windows, which no host load can move time into,
 * are named outright.
 *
 * The host-extension window is named the same way and for the same reason: the
 * callback is the composer's code, so a wait inside it is a cost the COMPOSER
 * owns, and naming it is what lets a reader look at the right repository. A
 * composer's audit POST to an absent sink is the case that motivated it.
 *
 * The CPU, redactor and host shares overlap by the framing this side does
 * mid-round-trip and mid-callback, so they do not sum to the elapsed time; a
 * share that dominates despite the overlap is still the one to act on.
 * @param {number} elapsedMs
 * @param {number} cpuMs
 * @param {number} redactorMs
 * @param {number} hostMs
 * @returns {string}
 */
function attributeWait(elapsedMs, cpuMs, redactorMs, hostMs) {
  const otherMs = Math.max(0, elapsedMs - cpuMs - redactorMs - hostMs);
  const largest = Math.max(cpuMs, redactorMs, hostMs, otherMs);
  const verdict =
    redactorMs === largest
      ? "The largest share was spent inside the redactor round trip — the daemon's scan, the host it shares, or both; this hook was not computing it."
      : hostMs === largest
        ? "The largest share was spent inside a host extension this hook called — a callback the composer injected, and a cost that composer owns; neither the sanitizer nor the redactor was computing it."
        : cpuMs === largest
          ? "The largest share is this hook computing — a per-call cost the sanitizer owns, repeated by every affected call."
          : "The largest share is none of those three: it was blocked on a loaded machine or on something outside the sanitizer that it called without measuring.";
  return (
    `, of which ${formatSeconds(cpuMs)}s was this hook's own CPU, ` +
    `${formatSeconds(redactorMs)}s was inside redactor round trips and ` +
    `${formatSeconds(hostMs)}s was inside host extensions. ${verdict}`
  );
}

/**
 * The model-facing line for a hook that overran the budget, or null when it did
 * not. Addressed to the model because the model is the only party that reliably
 * reads this channel — stderr from a non-blocking hook is easy to miss — and it
 * is asked to relay the numbers, since the operator is the one who can file it.
 *
 * With `context.cpuMs` in hand the line says which share of the wait was the
 * sanitizer computing, and with `context.redactorMs` too it names the window the
 * time went into ({@link attributeWait}), including `context.hostMs`'s host
 * extensions — a caller that measured the first two but has no extensions to
 * charge reports that window as zero, which is a measurement and not a shrug. Without them the line says that it cannot
 * tell, rather than asserting an attribution nothing measured: a wall-clock
 * overrun on a loaded host is the common case, and blaming it on the sanitizer
 * sends the operator hunting a per-call cost that does not exist.
 *
 * A CPU figure alone cannot pick a cause, so with only that the clause names
 * candidates and commits to none. A hook that blocks on a dead socket inside a
 * HOST extension spends no CPU and adds no machine load, so naming either as the
 * cause would be a second wrong guess.
 * @param {string} hookName
 * @param {number} elapsedMs
 * @param {number} [thresholdMs]
 * @param {SlowHookContext} [context]  known CPU time / payload size /
 *   triggering tool, so the notice is self-diagnosing rather than requiring the
 *   next reader to reconstruct what was slow by hand
 * @returns {string | null}
 */
export function slowHookNotice(
  hookName,
  elapsedMs,
  thresholdMs = SLOW_HOOK_THRESHOLD_MS,
  context,
) {
  if (elapsedMs <= thresholdMs) return null;
  const cpuMs = context?.cpuMs;
  const redactorMs = context?.redactorMs;
  const attributed =
    typeof cpuMs === "number" && typeof redactorMs === "number";
  // A caller with the first two windows but no host measurement charged nothing
  // to it, which is a zero and not an unknown — every such caller runs the
  // charger, so an absent number means no callback ran.
  const hostMs = typeof context?.hostMs === "number" ? context.hostMs : 0;
  const attribution = attributed
    ? attributeWait(elapsedMs, cpuMs, redactorMs, hostMs)
    : typeof cpuMs === "number"
      ? `, and used ${formatSeconds(cpuMs)}s of CPU. ` +
        "Only the CPU share is work every affected call repeats; the rest was spent waiting, on a busy machine or on something this hook called."
      : ". Wall-clock alone cannot separate the sanitizer's own work from a busy machine.";
  const timings = attributed
    ? "all four timings"
    : typeof cpuMs === "number"
      ? "both timings"
      : "timing";
  return (
    `agent-sanitizer PERFORMANCE: the ${hookName} hook took ` +
    `${formatSeconds(elapsedMs)}s${formatContextSuffix(context)}, over its ${formatSeconds(thresholdMs)}s budget${attribution} ` +
    `Tell the user, and suggest they report it at ${ISSUE_URL} with the hook name and ${timings}.`
  );
}

/**
 * The line for a ONE-TIME provisioning step that overran
 * {@link SLOW_PROVISION_THRESHOLD_MS}, or null when it did not.
 *
 * Deliberately NOT {@link slowHookNotice} with a bigger threshold: that message
 * splits the wait into a per-call share and machine contention, and neither
 * reading is the one to take away here. What is actionable about a slow install
 * is the installer (uv resolves in a fraction of pip's time) and the fact that a
 * repeat means the idempotence check is broken — so this asks for a report only
 * on the repeat, which is the version of this that is a bug.
 *
 * The one caller is the shell provisioner, whose port of this module
 * (plugin/scripts/lib/hook-timing.sh) must emit this exact string; that port and
 * this definition are pinned to each other by a contract test rather than left
 * as two independently-worded copies.
 * @param {string} stepName
 * @param {number} elapsedMs
 * @param {number} [thresholdMs]
 * @param {string} [advice] step-specific speedup advice — the default fits the
 *   engine install; the hook-binary download passes its own, because telling a
 *   user mid-download that uv would help is advice about the wrong step
 * @returns {string | null}
 */
export function slowProvisionNotice(
  stepName,
  elapsedMs,
  thresholdMs = SLOW_PROVISION_THRESHOLD_MS,
  advice = "Installing uv makes it faster",
) {
  if (elapsedMs <= thresholdMs) return null;
  return (
    `agent-sanitizer PERFORMANCE: one-time setup (${stepName}) took ` +
    `${formatSeconds(elapsedMs)}s, over its ${formatSeconds(thresholdMs)}s budget — ` +
    "this is paid once per install, not per tool call, so the session is not slow from here on. " +
    `${advice}; if it happens on EVERY new session, report it at ${ISSUE_URL}.`
  );
}

/**
 * Write the slow-hook notice to stderr and return it, or return null when the
 * run was within budget (writing nothing, so the quiet path stays quiet).
 *
 * The one place the notice reaches stderr: every reporter below needs the
 * transcript copy, and a hook whose run ENDED IN AN ERROR has nothing but this —
 * its verdict is the fail-closed one its `onError` composed, and diluting that
 * message with a performance aside would bury the fault. A judge that spent
 * thirty seconds and then threw is exactly the case the timing exists to name,
 * so the error path measures and reports; it just reports on the human channel.
 * @param {string} hookName
 * @param {number} elapsedMs
 * @param {(chunk: string) => void} [writeErr]  injectable stderr sink, for tests
 * @param {SlowHookContext} [context]  see {@link slowHookNotice}
 * @returns {string | null}
 */
export function writeSlowHookNotice(
  hookName,
  elapsedMs,
  writeErr = (chunk) => process.stderr.write(chunk),
  context,
) {
  const notice = slowHookNotice(hookName, elapsedMs, undefined, context);
  if (notice === null) return null;
  writeErr(notice + "\n");
  return notice;
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
 * @param {SlowHookContext} [context]  see {@link slowHookNotice}
 * @returns {V}
 */
export function withSlowHookNotice(
  hookName,
  elapsedMs,
  verdict,
  writeErr = (chunk) => process.stderr.write(chunk),
  context,
) {
  const notice = writeSlowHookNotice(hookName, elapsedMs, writeErr, context);
  if (notice === null) return verdict;
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
 * @param {SlowHookContext} [context]  see {@link slowHookNotice}
 * @returns {boolean}  whether a notice was emitted
 */
export function reportSlowHook(
  hookName,
  elapsedMs,
  hookEventName,
  emit,
  writeErr = (chunk) => process.stderr.write(chunk),
  context,
) {
  const notice = writeSlowHookNotice(hookName, elapsedMs, writeErr, context);
  if (notice === null) return false;
  emit(hookEventName, { additionalContext: notice });
  return true;
}
