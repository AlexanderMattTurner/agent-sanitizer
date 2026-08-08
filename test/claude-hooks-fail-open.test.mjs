/**
 * The hooks' failure POSTURE and the AGENT_SANITIZER_FAIL_OPEN knob over it,
 * asserted at the unit level on the three properties that make it shippable:
 *
 *   - OPEN BY DEFAULT. Installed as Claude Code hooks, a hook that could not run
 *     lets the guarded action through with a warning rather than halting the
 *     session on its own breakage — whatever the failure was.
 *   - CLOSED ON REQUEST, EXACTLY. "0" and "false" restore the fail-closed
 *     verdicts, and each emission under them is byte-identical to what the
 *     fail-closed helpers produce on their own.
 *   - THE POSTURE IS ABOUT THE HOOK, NOT THE VERDICT. Nothing here relaxes what
 *     a sanitizer that RAN decided; the subprocess counterparts in
 *     plugin/test/plugin-bundle.test.mjs pin that end to end.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

const { failOpenEnabled, failOpenContext, missingPackageError, FAIL_OPEN_ENV } =
  await import("../claude-hooks/lib/hook-io.mjs");
const {
  failClosedFields,
  hookFailureFields,
  hintedWriteFault,
  REDACTION_HINT,
} = await import("../claude-hooks/pretooluse-sanitize.mjs");
const { DEFAULT_HINT } = await import("../src/rehydrate.mjs");
const { emitFailClosed, emitHookFailure } =
  await import("../claude-hooks/sanitize-output.mjs");
const { main, USER_PROMPT_MESSAGES } =
  await import("../claude-hooks/sanitize-user-prompt.mjs");

/** The shipped posture: nothing set. */
const OPEN = {};
const CLOSED = { [FAIL_OPEN_ENV]: "0" };
/** The sanitizer was never installed — the archetypal environmental failure. */
const ABSENT = missingPackageError("agent-sanitizer", new Error("not found"));
/** A layer threw on the payload it was handed — opens too, by design. */
const LAYER_THREW = new Error("two output fields collapsed to one name");

/** Collect the fields an emit-style callee writes, instead of touching stdout. */
function collect() {
  /** @type {Record<string, unknown>[]} */
  const emitted = [];
  return { emitted, emit: (fields) => emitted.push(fields) };
}

describe("the fail-open posture knob", () => {
  it("is open when nothing is set", () => {
    assert.equal(failOpenEnabled({}), true);
  });

  it("is closed for exactly the two documented opt-out spellings", () => {
    for (const value of ["0", "false"])
      assert.equal(
        failOpenEnabled({ [FAIL_OPEN_ENV]: value }),
        false,
        `${JSON.stringify(value)} must restore the fail-closed posture`,
      );
  });

  it("stays open for every other value, including near-misses", () => {
    // The near-misses are the point: an operator who wanted strictness and
    // wrote one of these is NOT getting it, so the docs name "0" and the
    // launcher matches the same two literals.
    for (const value of ["", "1", "FALSE", "no", "off", "true", " 0", "0 "])
      assert.equal(
        failOpenEnabled({ [FAIL_OPEN_ENV]: value }),
        true,
        `${JSON.stringify(value)} is not an opt-out spelling`,
      );
  });

  it("names the cause, what went unguarded, and the way back to closed", () => {
    const context = failOpenContext("sanitize-output", "tool output", ABSENT);
    assert.match(context, /agent-sanitizer is unavailable/);
    assert.match(context, /tool output/);
    assert.match(context, /UNSANITIZED/);
    assert.match(context, new RegExp(`${FAIL_OPEN_ENV}=0`));
  });

  it("carries the remedy on the unloaded-binding branch", () => {
    // A DEP_UNAVAILABLE message already embeds the remedy. A bare TypeError
    // names neither package nor fix, and this posture emits no
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

describe("PreToolUse hookFailureFields", () => {
  it("drops the verdict entirely by default, whatever the failure", () => {
    for (const parsedOk of [true, false])
      for (const err of [ABSENT, LAYER_THREW]) {
        const fields = hookFailureFields(parsedOk, err, { env: OPEN });
        // A permissionDecision of any value is a verdict; the pass-through is
        // the ABSENCE of one, so assert the key is gone rather than not-"ask".
        assert.equal(fields.permissionDecision, undefined);
        assert.equal(fields.permissionDecisionReason, undefined);
        assert.match(String(fields.additionalContext), /UNSANITIZED/);
      }
  });

  it("is byte-identical to the fail-closed fields under the opt-out", () => {
    for (const parsedOk of [true, false])
      for (const err of [ABSENT, LAYER_THREW])
        assert.deepEqual(
          hookFailureFields(parsedOk, err, { env: CLOSED }),
          failClosedFields(parsedOk, err),
        );
  });

  it("keeps ASK and DENY apart under the opt-out", () => {
    // Non-vacuity for the deepEqual above: it would still pass if both sides
    // collapsed to one verdict.
    assert.equal(
      hookFailureFields(true, ABSENT, { env: CLOSED }).permissionDecision,
      "ask",
    );
    assert.equal(
      hookFailureFields(false, ABSENT, { env: CLOSED }).permissionDecision,
      "deny",
    );
  });
});

describe("PostToolUse emitHookFailure", () => {
  const RESPONSE = { tool_response: "aws_key=AKIAIOSFODNN7EXAMPLE" };

  it("leaves the original output in place by default", () => {
    for (const input of [RESPONSE, undefined])
      for (const err of [ABSENT, LAYER_THREW]) {
        const { emitted, emit } = collect();
        emitHookFailure(input, err, emit, undefined, OPEN);
        assert.equal(emitted.length, 1);
        // No updatedToolOutput key at all: the harness shows the original.
        assert.equal(emitted[0].updatedToolOutput, undefined);
        assert.match(String(emitted[0].additionalContext), /UNSANITIZED/);
      }
  });

  it("suppresses exactly as emitFailClosed does under the opt-out", () => {
    const closedKnob = collect();
    emitHookFailure(RESPONSE, ABSENT, closedKnob.emit, undefined, CLOSED);
    const direct = collect();
    emitFailClosed(
      RESPONSE,
      `[SANITIZATION FAILED — original output suppressed for safety. Hook error: ${ABSENT.message}]`,
      direct.emit,
    );
    assert.deepEqual(closedKnob.emitted, direct.emitted);
  });

  it("withholds the secret under the opt-out, including on a layer throw", () => {
    // The cost the open default accepts, stated as the thing the opt-out buys:
    // the output hook's layers throw on inputs an attacker composes, and only
    // this posture keeps the raw response out of the model's view.
    for (const err of [ABSENT, LAYER_THREW]) {
      const { emitted, emit } = collect();
      emitHookFailure(RESPONSE, err, emit, undefined, CLOSED);
      assert.match(String(emitted[0].updatedToolOutput), /SANITIZATION FAILED/);
      assert.ok(!JSON.stringify(emitted[0]).includes("AKIAIOSFODNN7EXAMPLE"));
    }
  });
});

describe("UserPromptSubmit failure posture", () => {
  const PROMPT = { hook_event_name: "UserPromptSubmit", prompt: "hello" };
  /** A stripper that throws the given error — a failure AFTER stdin parsed. */
  const stripThrowing = (err) => () => {
    throw err;
  };
  /** A reader that throws — the failure BEFORE stdin parsed. */
  const unparsable = async () => {
    throw new SyntaxError("Unexpected token");
  };

  /** Run main() against an injected reader and return what it wrote. */
  async function run(read, opts) {
    let written = "";
    await main(read, (chunk) => (written += chunk), opts);
    return JSON.parse(written);
  }

  it("passes the prompt through by default, whatever the failure", async () => {
    for (const [read, opts] of [
      [async () => PROMPT, { strip: stripThrowing(ABSENT) }],
      [async () => PROMPT, { strip: stripThrowing(LAYER_THREW) }],
      [unparsable, {}],
    ]) {
      const out = await run(read, { ...opts, env: OPEN });
      assert.equal(out.decision, undefined);
      assert.equal(out.hookSpecificOutput.hookEventName, "UserPromptSubmit");
      assert.match(out.hookSpecificOutput.additionalContext, /UNSANITIZED/);
    }
  });

  it("blocks the prompt under the opt-out", async () => {
    const out = await run(async () => PROMPT, {
      strip: stripThrowing(ABSENT),
      env: CLOSED,
    });
    assert.equal(out.decision, "block");
    assert.equal(out.reason, USER_PROMPT_MESSAGES.hookFailed(ABSENT.message));
  });

  it("blocks an unparsable payload under the opt-out", async () => {
    const out = await run(unparsable, { env: CLOSED });
    assert.equal(out.decision, "block");
  });
});

describe("the open posture's placeholder-write carve-out", () => {
  const HINTED_WRITE = {
    tool_name: "Write",
    tool_input: {
      file_path: "/f",
      content: `password=${DEFAULT_HINT}: Secret]\n`,
    },
  };

  it("the hook's restated literal IS the package's DEFAULT_HINT", () => {
    // Exact equality, both directions: a prefix-only behavioral check would
    // keep passing if REDACTION_HINT drifted shorter (over-triggering the
    // carve-out) or the package hint drifted (under-triggering it).
    assert.equal(REDACTION_HINT, DEFAULT_HINT);
  });

  it("recognizes write-shaped inputs carrying the package's hint prefix", () => {
    // DEFAULT_HINT comes from the package; the hook restates the prefix as a
    // literal so the check survives the package failing to load. Driving the
    // package's spelling through the hook's literal pins the two together.
    for (const tool of ["Write", "Edit", "NotebookEdit"])
      assert.equal(
        hintedWriteFault({ tool_name: tool, tool_input: { x: DEFAULT_HINT } }),
        true,
        `${tool} carrying the hint must be held`,
      );
    // The hint can sit arbitrarily deep (MultiEdit nests it in edits[]).
    assert.equal(
      hintedWriteFault({
        tool_name: "MultiEdit",
        tool_input: {
          file_path: "/f",
          edits: [{ old_string: "a", new_string: `${DEFAULT_HINT}]` }],
        },
      }),
      true,
    );
  });

  it("leaves everything else to the open default", () => {
    for (const input of [
      undefined,
      { tool_name: "Bash", tool_input: { command: `echo ${DEFAULT_HINT}]` } },
      { tool_name: "Write", tool_input: { file_path: "/f", content: "plain" } },
      { tool_name: "Write" },
    ])
      assert.equal(hintedWriteFault(input), false);
  });

  it("asks under the OPEN posture instead of passing the write through", () => {
    const fields = hookFailureFields(true, ABSENT, {
      env: OPEN,
      input: HINTED_WRITE,
    });
    assert.equal(fields.permissionDecision, "ask");
    assert.match(String(fields.permissionDecisionReason), /placeholder/);
    assert.match(String(fields.permissionDecisionReason), /fail-open posture/);
    assert.equal(fields.additionalContext, undefined);
  });

  it("keeps the open default for every non-carve-out fault", () => {
    for (const input of [
      undefined,
      { tool_name: "Bash", tool_input: { command: `echo ${DEFAULT_HINT}]` } },
      { tool_name: "Write", tool_input: { file_path: "/f", content: "plain" } },
    ]) {
      const fields = hookFailureFields(true, ABSENT, { env: OPEN, input });
      assert.equal(fields.permissionDecision, undefined);
      assert.match(String(fields.additionalContext), /UNSANITIZED/);
    }
  });

  it("is invisible under the CLOSED posture (already strict)", () => {
    assert.deepEqual(
      hookFailureFields(true, ABSENT, { env: CLOSED, input: HINTED_WRITE }),
      failClosedFields(true, ABSENT),
    );
  });
});
