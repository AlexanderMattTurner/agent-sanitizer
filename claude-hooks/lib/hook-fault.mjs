/**
 * THE failure posture, in one place.
 *
 * Every hook in this package has to answer the same question when its own
 * machinery breaks: does the guarded action proceed with a warning (fail OPEN,
 * the shipped default) or is it withheld (fail CLOSED, what
 * AGENT_SANITIZER_FAIL_OPEN=0 buys)? Before this module each hook answered it by
 * hand — four hand-rolled renderings in three different envelope shapes, one
 * hook (scan-invisible-chars) that never consulted the knob at all, and a
 * dispatcher default arm that hard-exited past it. A posture that is re-derived
 * per hook is a posture nobody can audit: the one hook that forgot is invisible
 * until an operator who pinned the strict posture silently does not get it.
 *
 * So the posture becomes DATA. Each hook registers one policy — what it guards,
 * which event it answers, and how its CLOSED verdict renders — and this module
 * owns everything shared: the single {@link failOpenEnabled} read, the default
 * OPEN rendering, and the shape of the outcome a hook then writes. A hook with
 * no registered policy is a hard error at fault time rather than a silent
 * default, and `test/claude-hooks-posture.test.mjs` enumerates the modules on
 * disk so a hook added without a policy fails there first.
 *
 * WHY REGISTRATION AND NOT A LITERAL TABLE HERE: a closed verdict is
 * hook-specific content (the PostToolUse suppression has to shape-match the tool
 * response it replaces; the PreToolUse ask/deny split reads the host's message
 * table), and every hook already imports this module's peer `hook-io.mjs`. A
 * literal table would have to import the hooks back, which is a cycle. The list
 * of hooks that MUST register is still declared here, as data, so the set is
 * closed in both directions.
 */
import {
  failOpenEnabled,
  failOpenContext,
  safeErrMessage,
} from "./hook-io.mjs";

/**
 * The hook modules that must register a fault policy — every CLI entry point in
 * `claude-hooks/*.mjs`. Declared here rather than discovered so registering an
 * unknown name is an error instead of a typo nobody notices.
 * @type {readonly string[]}
 */
export const FAULT_POLICY_HOOKS = Object.freeze([
  "plugin-hooks",
  "pretooluse-sanitize",
  "sanitize-output",
  "sanitize-user-prompt",
  "scan-invisible-chars",
]);

/**
 * What a hook's fault renders to. `fields`/`envelope` are the stdout response
 * (`fields` is the `hookSpecificOutput` body, wrapped with the policy's event;
 * `envelope` is a hook that answers with a top-level shape instead, like
 * UserPromptSubmit's `{decision:"block"}`); `stderr` and `exitCode` are the
 * process-level halves a hook with no stdout channel uses; `armAlert` asks the
 * caller to persist its cross-hook alert so a LATER gate carries the closed
 * posture the faulting hook could not express itself.
 * @typedef {{
 *   posture: "open" | "closed",
 *   fields: Record<string, unknown> | null,
 *   fallbackFields: Record<string, unknown> | null,
 *   envelope: object | null,
 *   stderr: string | null,
 *   exitCode: number,
 *   armAlert: boolean,
 * }} FaultOutcome
 */

/**
 * What a policy's `open`/`closed` builder returns: any subset of a
 * {@link FaultOutcome}'s renderable slots. Everything omitted takes its default
 * (no output, exit 0, no alert).
 * @typedef {{
 *   fields?: Record<string, unknown>,
 *   fallbackFields?: Record<string, unknown>,
 *   envelope?: object,
 *   stderr?: string,
 *   exitCode?: number,
 *   armAlert?: boolean,
 * }} FaultParts
 */

/**
 * The context a builder is handed: the caller's own inputs (whatever it passed
 * to {@link hookFaultOutcome}) plus the three values every hook derived by hand
 * before — the hook name, the scrubbed error message, and the model-facing
 * open-posture warning.
 * @typedef {Record<string, any> & {
 *   hook: string,
 *   err: unknown,
 *   message: string,
 *   openContext: string,
 * }} FaultContext
 */

/**
 * A hook's declared posture.
 * @typedef {{
 *   event: string | null,
 *   guarded: string,
 *   open?: (ctx: FaultContext) => FaultParts,
 *   closed: (ctx: FaultContext) => FaultParts,
 * }} FaultPolicy
 */

/** @type {Map<string, FaultPolicy>} */
const policies = new Map();

/**
 * Declare a hook's failure posture. Called at module scope by each hook, so
 * importing the hook is what makes its posture reachable.
 * @param {string} hook  a member of {@link FAULT_POLICY_HOOKS}
 * @param {FaultPolicy} policy
 * @returns {void}
 */
export function registerFaultPolicy(hook, policy) {
  if (!FAULT_POLICY_HOOKS.includes(hook))
    throw new Error(
      `unknown hook ${JSON.stringify(hook)}: add it to FAULT_POLICY_HOOKS in ` +
        "claude-hooks/lib/hook-fault.mjs before registering a posture for it",
    );
  policies.set(hook, policy);
}

/**
 * The registered policy for `hook`. Throws rather than defaulting: a hook whose
 * posture nobody declared has no defensible default — guessing OPEN would let
 * the guarded action through on a hook an operator believed was strict, and
 * guessing CLOSED would block a session on a wiring bug.
 * @param {string} hook
 * @returns {FaultPolicy}
 */
export function faultPolicy(hook) {
  const policy = policies.get(hook);
  if (policy === undefined)
    throw new Error(
      `no fault policy registered for hook ${JSON.stringify(hook)}; call ` +
        "registerFaultPolicy at the hook module's scope",
    );
  return policy;
}

/**
 * The default OPEN rendering: no verdict, and a non-empty `additionalContext`
 * recording that the guarded content passed through unsanitized. Non-empty
 * matters — an empty stdout is recorded by Claude Code as a CLEAN run rather
 * than a degraded one, so the posture would give up visibility as well as
 * enforcement.
 * @param {FaultContext} ctx
 * @returns {FaultParts}
 */
function defaultOpen(ctx) {
  return { fields: { additionalContext: ctx.openContext } };
}

/**
 * Resolve `hook`'s response to its own failure under the caller's posture. This
 * is the ONLY place {@link failOpenEnabled} is consulted on a hook fault, so the
 * knob cannot be honored in three hooks and skipped in the fourth.
 * @param {string} hook
 * @param {unknown} err
 * @param {Record<string, any> & {
 *   env?: NodeJS.ProcessEnv | Record<string, string | undefined>,
 * }} [ctx]  hook-specific inputs threaded to the builders (a message table, the
 *   parsed input, a remedy); `env` selects the posture and is not passed on
 * @returns {FaultOutcome}
 */
export function hookFaultOutcome(hook, err, ctx = {}) {
  const policy = faultPolicy(hook);
  const open = failOpenEnabled(ctx.env);
  /** @type {FaultContext} */
  const full = {
    ...ctx,
    hook,
    err,
    message: safeErrMessage(err),
    openContext: failOpenContext(hook, policy.guarded, err),
  };
  const parts = (open ? (policy.open ?? defaultOpen) : policy.closed)(full);
  const fields = parts.fields ?? null;
  // A policy that supplies `fields` but no event has nothing to wrap them in;
  // that is a policy bug, not a runtime condition, so say so rather than
  // silently emitting nothing (which reads as a clean run).
  if (fields !== null && parts.envelope === undefined && policy.event === null)
    throw new Error(
      `fault policy for ${JSON.stringify(hook)} returns hookSpecificOutput ` +
        "fields but declares no event to wrap them in",
    );
  return Object.freeze({
    posture: open ? "open" : "closed",
    fields,
    fallbackFields: parts.fallbackFields ?? null,
    envelope:
      parts.envelope ??
      (fields === null
        ? null
        : { hookSpecificOutput: { hookEventName: policy.event, ...fields } }),
    stderr: parts.stderr ?? null,
    exitCode: parts.exitCode ?? 0,
    armAlert: parts.armAlert ?? false,
  });
}

/**
 * Render an outcome's stdout/stderr halves and return its exit code. The caller
 * decides what to do with the code (a hook that must keep running ignores it),
 * and performs `armAlert` itself — persisting the alert needs the hook's own
 * report text, which this module has no view of.
 * @param {FaultOutcome} outcome
 * @param {(chunk: string) => void} [write]
 * @param {(chunk: string) => void} [writeErr]
 * @returns {number}
 */
export function writeFaultOutcome(
  outcome,
  write = (chunk) => process.stdout.write(chunk),
  writeErr = (chunk) => process.stderr.write(chunk),
) {
  if (outcome.envelope !== null) write(JSON.stringify(outcome.envelope));
  if (outcome.stderr !== null) writeErr(outcome.stderr);
  return outcome.exitCode;
}
