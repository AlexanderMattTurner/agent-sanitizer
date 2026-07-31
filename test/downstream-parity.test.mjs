/**
 * The seams are only worth shipping if a host can retire its FORK with them, so
 * this composes all three at once — reason table, deny gate, host remedy —
 * against the shapes a real downstream (agent-glovebox) forks these modules to
 * get today, where the unit cases each exercise one seam in isolation.
 *
 * The strings are transcribed from that fork rather than invented, because what
 * they demonstrate is the thing the package cannot do for itself: they cite the
 * host's own paths (`.claude/hooks/…`, `session-setup.sh`). Each assertion
 * compares the emitted verdict against the text this test HANDED IN, never
 * against the downstream's file — so this cannot rot when that wording changes,
 * and it is not a second copy of anything. What it fails on is a refactor that
 * drops a table field, stops threading `session_id`, or lets a gate deny fall
 * through into the rewriting layers — each of which makes the fork unretirable
 * again, and none of which the per-seam cases would show as one broken workflow.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

const { claudeAdapter } = await import("agent-control-plane-core/claude");
const { Decision } = await import("agent-control-plane-core");
const { missingPackageMessage, safeErrMessage } =
  await import("../claude-hooks/lib/hook-io.mjs");
const { judgeSanitizeUserPrompt } =
  await import("../claude-hooks/sanitize-user-prompt.mjs");
const { judgePreToolUseSanitize, failClosedFields } =
  await import("../claude-hooks/pretooluse-sanitize.mjs");

// Verbatim from the downstream fork.
const HOST_REMEDY =
  "re-run .claude/hooks/session-setup.sh (or pnpm install) and retry.";

const HOST_PROMPT_MESSAGES = {
  remedy: HOST_REMEDY,
  unknownEvent:
    "User prompt blocked (fail-closed): unrecognized hook payload — the " +
    "harness's hook-input shape no longer parses as a UserPromptSubmit " +
    "event. Fix the adapter parse (agent-control-plane-core's claude " +
    "adapter, wired by .claude/hooks/sanitize-user-prompt.mjs); " +
    "resubmitting the prompt cannot clear this.",
};

const HOST_PRE_TOOL_USE_MESSAGES = {
  unknownEvent:
    "PreToolUse sanitization blocked (fail-closed): unrecognized hook " +
    "payload — the harness's hook-input shape no longer parses as a " +
    "PreToolUse event. Fix the adapter parse (agent-control-plane-core's " +
    "claude adapter, wired by .claude/hooks/pretooluse-sanitize.mjs); " +
    "retrying the call cannot clear this.",
};

/** @param {Record<string, unknown>} payload */
const parse = (payload) => claudeAdapter.parse(payload);

const unknownEvent = () => parse({ no_such_field: 1 });

describe("a host can retire its fork through the seams", () => {
  it("emits the host's deny-when-blind reason on both gates", async () => {
    assert.equal(
      judgeSanitizeUserPrompt(unknownEvent(), undefined, HOST_PROMPT_MESSAGES)
        .reason,
      HOST_PROMPT_MESSAGES.unknownEvent,
    );
    const verdict = await judgePreToolUseSanitize(unknownEvent(), undefined, {
      messages: HOST_PRE_TOOL_USE_MESSAGES,
    });
    assert.equal(verdict.decision, Decision.DENY);
    assert.equal(verdict.reason, HOST_PRE_TOOL_USE_MESSAGES.unknownEvent);
  });

  it("carries the host's remedy into a fail-closed reason", () => {
    // The fork's whole reason for existing in this module: a reader is told
    // which command to run, and the package cannot know that command.
    const hint = ` ${missingPackageMessage("agent-sanitizer", new Error("Cannot find package"), HOST_REMEDY)}`;
    const fields = failClosedFields(
      true,
      new TypeError("x is not a function"),
      {
        hint,
      },
    );
    assert.equal(fields.permissionDecision, "ask");
    assert.ok(
      /** @type {string} */ (fields.permissionDecisionReason).endsWith(
        HOST_REMEDY,
      ),
    );
    // And it survives the re-scrub the harness applies on the way out.
    assert.ok(
      safeErrMessage(
        /** @type {string} */ (fields.permissionDecisionReason),
      ).endsWith(HOST_REMEDY),
    );
  });

  it("names the host's remedy when the prompt gate's own package is absent", () => {
    // The gate throws rather than returning a verdict, because this hook is the
    // only defense on user input — and the throw's message is what the host's
    // fail-closed envelope relays, so the remedy has to reach it from the table.
    const event = parse({ hook_event_name: "UserPromptSubmit", prompt: "hi" });
    assert.throws(
      () => judgeSanitizeUserPrompt(event, null, HOST_PROMPT_MESSAGES),
      (err) =>
        /** @type {{code?: string}} */ (err).code === "DEP_UNAVAILABLE" &&
        /** @type {Error} */ (err).message.endsWith(HOST_REMEDY),
    );
  });

  it("runs the host's own deny gate, keyed on the session it is given", async () => {
    // Stands in for the fork's PR-skill gate: a once-per-session checkpoint,
    // which needs the session identity and must deny before any rewriting layer.
    const seen = [];
    /** @param {{session_id?: string}} input */
    const hostGate = (input) => {
      seen.push(input.session_id);
      return "Run the /pr-creation skill before opening a PR.";
    };
    const verdict = await judgePreToolUseSanitize(
      parse({
        hook_event_name: "PreToolUse",
        tool_name: "Bash",
        tool_input: { command: "gh pr create --title x" },
        session_id: "sess-abc",
      }),
      undefined,
      { gates: [hostGate], messages: HOST_PRE_TOOL_USE_MESSAGES },
    );
    assert.deepEqual(seen, ["sess-abc"]);
    assert.equal(verdict.decision, Decision.DENY);
    assert.equal(
      verdict.reason,
      "Run the /pr-creation skill before opening a PR.",
    );
    assert.equal(verdict.mutated_input, undefined);
  });
});
