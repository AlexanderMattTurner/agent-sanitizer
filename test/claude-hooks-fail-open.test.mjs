/**
 * AGENT_SANITIZER_FAIL_OPEN, the caller's opt-out from the hooks' fail-closed
 * posture, asserted at the unit level on the three properties that make it safe
 * to ship:
 *
 *   - OFF UNLESS EXACTLY "1". A knob that disarms a sanitizer on "true", "yes"
 *     or a stray "0" is a knob that disarms it by accident.
 *   - SCOPED TO A SANITIZER THAT NEVER RAN. The open posture applies only to the
 *     failures sanitizerUnavailable recognizes (the package did not load). A
 *     layer that THREW has been reached by the payload — an attacker composes
 *     those throws — so they keep their fail-closed verdict in both postures, as
 *     does an unparsable payload.
 *   - INERT WHEN UNSET. Every emission with the knob absent must be
 *     byte-identical to the fail-closed one that shipped before it existed.
 *
 * The subprocess counterparts (the launcher's own branch, and the end-to-end
 * shapes Claude Code receives) live in plugin/test/plugin-bundle.test.mjs.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

const {
  failOpenEnabled,
  failOpenContext,
  sanitizerUnavailable,
  missingPackageError,
  FAIL_OPEN_ENV,
} = await import("../claude-hooks/lib/hook-io.mjs");
const { failClosedFields, hookFailureFields } =
  await import("../claude-hooks/pretooluse-sanitize.mjs");
const { emitFailClosed, emitHookFailure } =
  await import("../claude-hooks/sanitize-output.mjs");
const { main, USER_PROMPT_MESSAGES } =
  await import("../claude-hooks/sanitize-user-prompt.mjs");

const OPEN = { [FAIL_OPEN_ENV]: "1" };
const CLOSED = {};
/** The sanitizer was never installed — the one failure class the knob opens. */
const ABSENT = missingPackageError("agent-sanitizer", new Error("not found"));
/** A layer threw on the payload it was handed — never opened, knob or not. */
const LAYER_THREW = new Error("two output fields collapsed to one name");

/** Collect the fields an emit-style callee writes, instead of touching stdout. */
function collect() {
  /** @type {Record<string, unknown>[]} */
  const emitted = [];
  return { emitted, emit: (fields) => emitted.push(fields) };
}

describe("the fail-open knob itself", () => {
  it("is on for the exact string 1", () => {
    assert.equal(failOpenEnabled({ [FAIL_OPEN_ENV]: "1" }), true);
  });

  it("is off for every other value, including truthy-looking ones", () => {
    for (const value of ["", "0", "true", "TRUE", "yes", "on", " 1", "1 "])
      assert.equal(
        failOpenEnabled({ [FAIL_OPEN_ENV]: value }),
        false,
        `${JSON.stringify(value)} must not disarm the sanitizer`,
      );
    assert.equal(failOpenEnabled({}), false);
  });

  it("names the cause and what went unguarded", () => {
    const context = failOpenContext("sanitize-output", "tool output", ABSENT);
    assert.match(context, /agent-sanitizer is unavailable/);
    assert.match(context, /tool output/);
    assert.match(context, /UNSANITIZED/);
    assert.match(context, new RegExp(`${FAIL_OPEN_ENV}=1`));
  });

  it("carries the remedy on the unloaded-binding branch", () => {
    // The DEP_UNAVAILABLE message above already embeds the remedy. A bare
    // TypeError names neither package nor fix, and this posture emits no
    // permissionDecisionReason to carry one — so the hint must ride here or the
    // operator is told the install broke and nothing about un-breaking it.
    const typeErr = new TypeError("sanitizeText is not a function");
    const context = failOpenContext(
      "pretooluse-sanitize",
      "tool input",
      typeErr,
      () => ["agent-sanitizer"],
      (pkg) => `${pkg} is unavailable: REMEDY-HERE`,
    );
    assert.match(context, /sanitizeText is not a function/);
    assert.match(context, /REMEDY-HERE/);
  });

  it("names no package on a throw that is not an unloaded binding", () => {
    // The recorded-failure set is process-wide and carries no link to THIS
    // error; claiming a package on an unrelated throw sends the reader to a
    // reinstall that fixes nothing.
    const context = failOpenContext(
      "pretooluse-sanitize",
      "tool input",
      LAYER_THREW,
      () => ["agent-sanitizer"],
      (pkg) => `${pkg} is unavailable: REMEDY-HERE`,
    );
    assert.doesNotMatch(context, /REMEDY-HERE/);
  });
});

describe("sanitizerUnavailable", () => {
  it("recognizes the package-never-loaded error", () => {
    assert.equal(sanitizerUnavailable(ABSENT), true);
  });

  it("recognizes an unloaded binding called as a function", () => {
    // What V8 raises when a lazily-imported export stayed undefined. Only while
    // the loader holds a recorded failure — otherwise a TypeError from ordinary
    // buggy code would be misread as a missing install.
    const typeErr = new TypeError("sanitizeText is not a function");
    assert.equal(
      sanitizerUnavailable(typeErr, () => ["agent-sanitizer"]),
      true,
    );
    assert.equal(
      sanitizerUnavailable(typeErr, () => []),
      false,
    );
  });

  it("does NOT recognize a layer that threw on the payload", () => {
    // The distinction the knob's safety rests on: these throws guard content an
    // attacker composed, so they must stay closed under the knob.
    for (const err of [
      LAYER_THREW,
      new RangeError("Maximum call stack size exceeded"),
      new SyntaxError("Unexpected token } in JSON at position 4"),
      new Error("hook stdin exceeds 67108864 bytes; refusing to buffer"),
    ])
      assert.equal(
        sanitizerUnavailable(err, () => ["agent-sanitizer"]),
        false,
      );
  });
});

describe("PreToolUse hookFailureFields", () => {
  it("is byte-identical to the fail-closed fields when the knob is unset", () => {
    for (const parsedOk of [true, false])
      for (const err of [ABSENT, LAYER_THREW])
        assert.deepEqual(
          hookFailureFields(parsedOk, err, { env: CLOSED }),
          failClosedFields(parsedOk, err),
        );
  });

  it("drops the verdict entirely for an absent sanitizer under the knob", () => {
    const fields = hookFailureFields(true, ABSENT, { env: OPEN });
    // A permissionDecision of any value is a verdict; the pass-through is the
    // ABSENCE of one, so assert the key is gone rather than not-"ask".
    assert.equal(fields.permissionDecision, undefined);
    assert.equal(fields.permissionDecisionReason, undefined);
    assert.match(String(fields.additionalContext), /UNSANITIZED/);
  });

  it("still ASKS when a layer threw, even under the knob", () => {
    assert.equal(
      hookFailureFields(true, LAYER_THREW, { env: OPEN }).permissionDecision,
      "ask",
    );
  });

  it("still DENIES unparsable input under the knob", () => {
    assert.equal(
      hookFailureFields(false, ABSENT, { env: OPEN }).permissionDecision,
      "deny",
    );
  });
});

describe("PostToolUse emitHookFailure", () => {
  const RESPONSE = { tool_response: "aws_key=AKIAIOSFODNN7EXAMPLE" };

  it("suppresses exactly as emitFailClosed does when the knob is unset", () => {
    const open = collect();
    emitHookFailure(RESPONSE, ABSENT, open.emit, undefined, CLOSED);
    const closed = collect();
    emitFailClosed(
      RESPONSE,
      `[SANITIZATION FAILED — original output suppressed for safety. Hook error: ${ABSENT.message}]`,
      closed.emit,
    );
    assert.deepEqual(open.emitted, closed.emitted);
  });

  it("leaves the original output in place for an absent sanitizer under the knob", () => {
    const { emitted, emit } = collect();
    emitHookFailure(RESPONSE, ABSENT, emit, undefined, OPEN);
    assert.equal(emitted.length, 1);
    // No updatedToolOutput key at all: the harness shows the original.
    assert.equal(emitted[0].updatedToolOutput, undefined);
    assert.match(String(emitted[0].additionalContext), /UNSANITIZED/);
  });

  it("still suppresses a layer throw under the knob, secret and all", () => {
    // The output hook's layers throw on attacker-composable inputs (colliding
    // field names, runaway nesting, an exhausted redaction budget). Opening
    // there would hand the raw response — secrets included — to the model.
    const { emitted, emit } = collect();
    emitHookFailure(RESPONSE, LAYER_THREW, emit, undefined, OPEN);
    assert.match(String(emitted[0].updatedToolOutput), /SANITIZATION FAILED/);
    assert.ok(!JSON.stringify(emitted[0]).includes("AKIAIOSFODNN7EXAMPLE"));
  });

  it("still suppresses when stdin never parsed, knob or not", () => {
    for (const env of [CLOSED, OPEN]) {
      const { emitted, emit } = collect();
      emitHookFailure(undefined, ABSENT, emit, undefined, env);
      assert.match(String(emitted[0].updatedToolOutput), /SANITIZATION FAILED/);
    }
  });
});

describe("UserPromptSubmit failure posture", () => {
  const PROMPT = { hook_event_name: "UserPromptSubmit", prompt: "hello" };
  /** A stripper that throws the given error — a failure AFTER stdin parsed. */
  const stripThrowing = (err) => () => {
    throw err;
  };

  /** Run main() against an injected reader and return what it wrote. */
  async function run(read, opts) {
    let written = "";
    await main(read, (chunk) => (written += chunk), opts);
    return JSON.parse(written);
  }

  it("blocks the prompt when the knob is unset", async () => {
    const out = await run(async () => PROMPT, {
      strip: stripThrowing(ABSENT),
      env: CLOSED,
    });
    assert.equal(out.decision, "block");
    assert.equal(out.reason, USER_PROMPT_MESSAGES.hookFailed(ABSENT.message));
  });

  it("passes the prompt through for an absent sanitizer under the knob", async () => {
    const out = await run(async () => PROMPT, {
      strip: stripThrowing(ABSENT),
      env: OPEN,
    });
    assert.equal(out.decision, undefined);
    assert.equal(out.hookSpecificOutput.hookEventName, "UserPromptSubmit");
    assert.match(out.hookSpecificOutput.additionalContext, /UNSANITIZED/);
  });

  it("still blocks when the stripper threw on the prompt, knob or not", async () => {
    for (const env of [CLOSED, OPEN]) {
      const out = await run(async () => PROMPT, {
        strip: stripThrowing(LAYER_THREW),
        env,
      });
      assert.equal(out.decision, "block");
    }
  });

  it("still blocks when stdin never parsed, knob or not", async () => {
    for (const env of [CLOSED, OPEN]) {
      const out = await run(
        async () => {
          throw new SyntaxError("Unexpected token");
        },
        { env },
      );
      assert.equal(out.decision, "block");
    }
  });
});
