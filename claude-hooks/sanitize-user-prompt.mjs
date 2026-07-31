/**
 * UserPromptSubmit: gate user prompts on payload-capable invisible Unicode
 * and ANSI escapes. A prompt pasted from a tampered web page can carry tag
 * characters or zero-width sequences that the LLM reads but the user cannot
 * see. The PostToolUse sanitizer never runs on user input, so this is the
 * only line of defense.
 *
 * UserPromptSubmit cannot rewrite the prompt — `additionalContext` is added
 * alongside the original, not in place of it — so the only way to neutralize
 * a payload is to block. Thresholds match scan-invisible-chars (SessionStart)
 * for UX consistency.
 *
 * One carve-out: a prompt whose only escape content is SGR color/style codes
 * (ESC [ params m) passes with a note instead of blocking. Pasting colored
 * terminal output (test runs, build logs) is the single most common debugging
 * action, and SGR is display-only by the ECMA-48 grammar — it cannot move the
 * cursor, erase the screen, or carry an OSC payload. Anything beyond SGR
 * (cursor movement, erase, OSC title-set, DCS/APC/PM) still blocks, as do the
 * invisible-char thresholds, which are the actual web-paste payload defense.
 */
import {
  readStdinJson,
  safeErrMessage,
  isMain,
  lazyImport,
  missingPackageError,
  DEFAULT_MISSING_PACKAGE_REMEDY,
} from "./lib/hook-io.mjs";
import { controlPlane, runJudgeCli } from "./lib/control-plane.mjs";
import { trace, TraceEvent } from "./lib/trace.mjs";
// classifyPrompt (the user-prompt verdict) and stripAnsiFully (its ANSI stripper)
// come from the agent-sanitizer package. They are bound by a *caught* dynamic
// import, never a bare top-level `import … from "…"`: a static npm import
// resolves before any try/catch, so a missing node_modules would crash this hook
// at load and let the prompt through UNSANITIZED (fail-open). A failed load
// leaves the bindings undefined, which the judge's typeof guard turns into a
// fail-closed block.
/** @type {typeof import("agent-sanitizer/prompt").classifyPrompt} */
export let classifyPrompt;
/** @type {typeof import("agent-sanitizer").stripAnsiFully} */
let stripAnsiFully;

/**
 * The reasons this gate emits, as a table a host overrides. A host that knows
 * which of ITS files wires the adapter, and what a reader should do about a
 * failure, can say so — the package cannot, since it has no idea where it is
 * installed. Every field is a plain string or a string-returning function, so
 * an override is auditable next to the default it replaces.
 * @type {Readonly<{
 *   unknownEvent: string,
 *   blockContext: string,
 *   sgrNote: string,
 *   hookFailed: (cause: string) => string,
 *   remedy: string,
 * }>}
 */
export const USER_PROMPT_MESSAGES = Object.freeze({
  unknownEvent: "User prompt blocked (fail-closed): unrecognized hook payload.",
  blockContext:
    "User prompt blocked: payload-capable invisible/ANSI characters detected.",
  sgrNote:
    "The prompt contains ANSI SGR color codes (pasted terminal output). They are display-only formatting noise; read through them.",
  hookFailed: (cause) =>
    `sanitize-user-prompt hook failed (fail-closed): ${cause}`,
  // What a reader should run when the package itself is what is missing. It
  // rides in this table rather than a separate argument because it is host text
  // exactly like the reasons above, and one channel means a host cannot supply
  // its wording in one place and forget it in the other.
  remedy: DEFAULT_MISSING_PACKAGE_REMEDY,
});

/* c8 ignore start — module-load boundary: the imports resolve in every real
 * run, and their failure (the package absent) can't be simulated in-process, so
 * neither arm is observable to the in-process tests. The judge's typeof guard
 * converts an undefined stripper into a fail-closed block — that guard IS tested. */
// Stryker disable all
// lazyImport rather than a bare `await import` in a try/catch: it RECORDS the
// loader error, which is the only thing that can tell a missing install apart
// from a present package missing an export. Discarding it leaves
// missingPackageError with nothing to report but a guess.
// The cast asserts the loaded SHAPE, not that it loaded: lazyImport yields {} on
// failure, so either binding can still be undefined here — which is exactly what
// the judge's typeof guard turns into a fail-closed block.
({ classifyPrompt } = /** @type {typeof import("agent-sanitizer/prompt")} */ (
  await lazyImport("agent-sanitizer/prompt")
));
({ stripAnsiFully } = /** @type {typeof import("agent-sanitizer")} */ (
  await lazyImport("agent-sanitizer")
));
// Stryker restore all
/* c8 ignore stop */

/**
 * Judge a normalized prompt-submit event. Agent-agnostic: consumes the
 * control-plane ToolCallEvent and returns a Verdict, so the same prompt gate
 * renders through any agent adapter, not just Claude's. Throws (into the
 * calling hook's catch) when the sanitizer package never loaded — this hook is
 * the only defense on user input, so a prompt it cannot classify must block,
 * never pass through.
 * @param {import("agent-control-plane-core").ToolCallEvent} event
 * @param {((s: string) => string) | null} [strip]  the ANSI stripper (defaults
 *   to the package's stripAnsiFully; injectable so the fail-closed path is testable)
 * @param {Partial<typeof USER_PROMPT_MESSAGES>} [overrides]  reason overrides,
 *   merged over the defaults so a partial table can never leave a field unset
 * @returns {import("agent-control-plane-core").Verdict}
 */
export function judgeSanitizeUserPrompt(
  event,
  strip = stripAnsiFully,
  overrides = USER_PROMPT_MESSAGES,
) {
  // MERGED over the defaults, never substituted for them — a host that overrides
  // one field would otherwise leave the rest undefined. main() threads the same
  // object into its onError, where a missing field throws out of the catch and
  // the gate emits nothing, which the harness reads as a pass: fail OPEN.
  const messages = { ...USER_PROMPT_MESSAGES, ...overrides };
  const { Decision, EventKind } = controlPlane();
  // A payload the adapter cannot classify carries no readable prompt, so an
  // abstain would fail OPEN on harness contract drift; this gate's posture is
  // deny-when-blind. (Renders through the adapter's top-level decision:"block"
  // channel — a non-PRE_TOOL event has no permissionDecision body — which Claude
  // honors on UserPromptSubmit.)
  if (event.event === EventKind.UNKNOWN)
    return { decision: Decision.DENY, reason: messages.unknownEvent };
  if (event.event !== EventKind.PROMPT_SUBMIT)
    return { decision: Decision.ALLOW };
  // The module-load guard: a missing stripper means agent-sanitizer never
  // loaded. Guarding on the stripper alone is sufficient — it is bound AFTER
  // classifyPrompt, so a present stripper proves the classifier loaded too.
  if (typeof strip !== "function")
    throw missingPackageError("agent-sanitizer", undefined, messages.remedy);
  // The contract guarantees a string here: every adapter normalizes the
  // prompt-submit input (Claude's parse coerces a missing/non-string prompt to
  // "" via asString), so a defensive typeof re-check is a dead branch.
  const prompt = /** @type {string} */ (event.input.prompt);
  if (!prompt) return { decision: Decision.ALLOW };
  const verdict = classifyPrompt(prompt, strip);
  if (verdict.action === "pass") return { decision: Decision.ALLOW };
  if (verdict.action === "note")
    return { decision: Decision.ALLOW, additional_context: messages.sgrNote };
  // block: carry the reason AND a context note — UserPromptSubmit can't rewrite
  // the prompt, so the context is the only forward signal about why it dropped.
  return {
    decision: Decision.DENY,
    reason: verdict.reason,
    additional_context: messages.blockContext,
  };
}

/**
 * @param {() => Promise<any> | any} read
 * @param {(chunk: string) => void} write
 * @param {((s: string) => string) | null} [strip]  the ANSI stripper (defaults
 *   to the package's stripAnsiFully; injectable so the fail-closed path is testable)
 * @param {Partial<typeof USER_PROMPT_MESSAGES>} [overrides]  reason overrides,
 *   merged over the defaults so a partial table can never leave a field unset
 * @returns {Promise<void>}
 */
export async function main(
  read,
  write,
  strip = stripAnsiFully,
  overrides = USER_PROMPT_MESSAGES,
) {
  // Merged, not substituted — see judgeSanitizeUserPrompt. onError below is the
  // call site where a missing field would throw out of the catch and fail OPEN.
  const messages = { ...USER_PROMPT_MESSAGES, ...overrides };
  // Delegate the parse → judge → render → write contract to the shared
  // runJudgeCli so this hook doesn't re-implement the control-plane boundary:
  // runJudgeCli reads stdin BEFORE loading the control-plane package, so a
  // load failure fails to this hook's posture (the onError block) instead of
  // leaving stdin unread. The fail-closed onError writes the UserPromptSubmit
  // `decision:"block"` envelope by hand because the adapter that would render it
  // is exactly what may have failed to load.
  await runJudgeCli(
    "sanitize-user-prompt",
    (event) => {
      const verdict = judgeSanitizeUserPrompt(event, strip, messages);
      // Announce engagement on the trace channel like the other stdin hooks —
      // a prompt gate that silently stopped running is otherwise invisible.
      trace(TraceEvent.HOOK_RAN, {
        hook: "sanitize-user-prompt",
        outcome:
          verdict.decision === controlPlane().Decision.DENY
            ? "deny"
            : verdict.additional_context
              ? "note"
              : "allow",
      });
      return verdict;
    },
    {
      readInput: read,
      write,
      onError: (err) =>
        write(
          JSON.stringify({
            decision: "block",
            reason: messages.hookFailed(safeErrMessage(err)),
          }),
        ),
    },
  );
}

/* c8 ignore start — CLI entry runs only in the spawned subprocess; main/render/
 * classifyPrompt are mutation-tested via the in-process tests that call them. */
// Stryker disable all: same subprocess-only boundary as the c8 ignore — the
// direct-run guard can't be observed in-process.
if (isMain(import.meta.url)) {
  void main(readStdinJson, (chunk) => process.stdout.write(chunk));
}
/* c8 ignore stop */
// Stryker restore all
