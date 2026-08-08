/**
 * The shared hook-timing report: one threshold, one message, one merge rule.
 *
 * A hook that gets slow is invisible from the inside — it reads as "the agent is
 * slow" — so the only thing that surfaces it is this in-band notice. These cases
 * pin what the notice says, that it never displaces a hook's real verdict
 * context, and that a healthy run says NOTHING (a performance line on every call
 * would be exactly the alert fatigue the sanitizer's warnings already fight).
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  reportSlowHook,
  slowHookNotice,
  startHookTimer,
  withSlowHookNotice,
  SLOW_HOOK_THRESHOLD_MS,
} from "../claude-hooks/lib/hook-timing.mjs";
import { runJudgeCli } from "../claude-hooks/lib/control-plane.mjs";

/** A clock that advances by exactly the deltas it is given. */
function fakeClock(...deltas) {
  let t = 1_000_000;
  const steps = [0, ...deltas];
  return () => {
    t += /** @type {number} */ (steps.shift() ?? 0);
    return t;
  };
}

describe("startHookTimer", () => {
  it("reports the elapsed milliseconds, and can be read more than once", () => {
    const elapsed = startHookTimer(fakeClock(250, 400));
    assert.equal(elapsed(), 250);
    assert.equal(elapsed(), 650);
  });
});

describe("slowHookNotice", () => {
  it("says nothing at or under the budget", () => {
    assert.equal(slowHookNotice("sanitize-output", 0), null);
    assert.equal(
      slowHookNotice("sanitize-output", SLOW_HOOK_THRESHOLD_MS),
      null,
    );
  });

  it("names the hook, the timing and where to report it", () => {
    const notice = slowHookNotice(
      "scan-invisible-chars",
      SLOW_HOOK_THRESHOLD_MS + 29_000,
    );
    assert.match(notice, /scan-invisible-chars/);
    assert.match(notice, /30\.0s/);
    assert.match(notice, /1\.0s budget/);
    assert.match(notice, /github\.com\/.*\/issues/);
  });

  it("honors an explicit threshold", () => {
    assert.equal(slowHookNotice("x", 50, 100), null);
    assert.match(slowHookNotice("x", 300, 100), /0\.3s/);
  });
});

describe("withSlowHookNotice", () => {
  it("returns the verdict untouched, and writes nothing, under budget", () => {
    const errs = [];
    const verdict = { decision: "allow" };
    const out = withSlowHookNotice("h", 10, verdict, (chunk) =>
      errs.push(chunk),
    );
    assert.equal(out, verdict);
    assert.deepEqual(errs, []);
  });

  it("attaches the notice to a verdict that carries no context", () => {
    const out = withSlowHookNotice(
      "h",
      SLOW_HOOK_THRESHOLD_MS + 500,
      { decision: "allow" },
      () => {},
    );
    assert.equal(out.decision, "allow");
    assert.match(out.additional_context, /PERFORMANCE/);
  });

  it("APPENDS to an existing context instead of replacing it", () => {
    const out = withSlowHookNotice(
      "h",
      SLOW_HOOK_THRESHOLD_MS + 500,
      { decision: "allow", additional_context: "API keys/secrets redacted" },
      () => {},
    );
    assert.match(out.additional_context, /API keys\/secrets redacted/);
    assert.match(out.additional_context, /PERFORMANCE/);
  });

  it("also puts the timing on stderr, once", () => {
    const errs = [];
    withSlowHookNotice(
      "h",
      SLOW_HOOK_THRESHOLD_MS + 500,
      { decision: "allow" },
      (chunk) => errs.push(chunk),
    );
    assert.equal(errs.length, 1);
    assert.match(errs[0], /PERFORMANCE/);
  });
});

describe("reportSlowHook (no-verdict events)", () => {
  it("emits nothing for a run inside the budget", () => {
    const errs = [];
    const emitted = [];
    const reported = reportSlowHook(
      "scan-invisible-chars",
      5,
      "SessionStart",
      (chunk) => errs.push(chunk),
      (event, fields) => emitted.push([event, fields]),
    );
    assert.equal(reported, false);
    assert.deepEqual(errs, []);
    assert.deepEqual(emitted, []);
  });

  it("emits the envelope and the stderr line for a slow run", () => {
    const errs = [];
    const emitted = [];
    const reported = reportSlowHook(
      "scan-invisible-chars",
      SLOW_HOOK_THRESHOLD_MS + 1,
      "SessionStart",
      (chunk) => errs.push(chunk),
      (event, fields) => emitted.push([event, fields]),
    );
    assert.equal(reported, true);
    assert.equal(errs.length, 1);
    assert.equal(emitted.length, 1);
    const [event, fields] = emitted[0];
    assert.equal(event, "SessionStart");
    assert.match(fields.additionalContext, /scan-invisible-chars/);
  });
});

describe("runJudgeCli times every judge hook", () => {
  const event = {
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_input: { command: "echo hi" },
  };

  it("attaches nothing when the judge is quick", async () => {
    const written = [];
    await runJudgeCli("pretooluse-sanitize", () => ({ decision: "allow" }), {
      onError: (err) => assert.fail(String(err)),
      readInput: async () => event,
      write: (chunk) => written.push(chunk),
    });
    assert.equal(
      written.join("").includes("PERFORMANCE"),
      false,
      written.join(""),
    );
  });

  it("attaches the notice when the judge overruns the budget", async () => {
    // A real overrun rather than an injected clock: the wiring under test is
    // that runJudgeCli measures the judge AT ALL, and a stubbed clock would
    // pass even if the call were never timed.
    const written = [];
    const errs = [];
    const realErr = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk) => {
      errs.push(String(chunk));
      return true;
    };
    try {
      await runJudgeCli(
        "pretooluse-sanitize",
        async () => {
          await new Promise((resolve) =>
            setTimeout(resolve, SLOW_HOOK_THRESHOLD_MS + 100),
          );
          return { decision: "allow" };
        },
        {
          onError: (err) => assert.fail(String(err)),
          readInput: async () => event,
          write: (chunk) => written.push(chunk),
        },
      );
    } finally {
      process.stderr.write = realErr;
    }
    const stdout = written.join("");
    assert.match(stdout, /PERFORMANCE/);
    assert.match(stdout, /pretooluse-sanitize/);
    assert.ok(
      errs.some((line) => line.includes("PERFORMANCE")),
      "the timing must also reach stderr",
    );
  });
});
