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
  excludeProvisioning,
  formatBytes,
  reportSlowHook,
  slowHookNotice,
  startHookTimer,
  withSlowHookNotice,
  writeSlowHookNotice,
  SLOW_HOOK_THRESHOLD_MS,
} from "../claude-hooks/lib/hook-timing.mjs";
import { runJudgeCli } from "../claude-hooks/lib/control-plane.mjs";
import { awaitLazyDependency } from "../claude-hooks/lib/hook-io.mjs";
import { redactViaDaemon } from "../claude-hooks/lib/redactor-client.mjs";

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

describe("provisioning is not the hook's cost", () => {
  // The false positive this closes: on a cold container the dependency wait and
  // the first redactor spawn run INSIDE a hook invocation and take seconds. A
  // notice charging those to the hook would fire on the first call of every
  // session, name the wrong culprit, and teach the reader to ignore it.

  it("subtracts a provisioning window that runs inside the timer", async () => {
    let t = 0;
    const clock = () => t;
    const elapsed = startHookTimer(clock);
    t += 50; // real hook work
    await excludeProvisioning(async () => {
      t += 30_000; // a dependency install we merely waited out
    }, clock);
    t += 20; // more real work
    assert.equal(elapsed(), 70);
    assert.equal(slowHookNotice("h", elapsed()), null);
  });

  it("charges provisioning that FAILED, so a failed wait is not reported as slow", async () => {
    let t = 0;
    const clock = () => t;
    const elapsed = startHookTimer(clock);
    await assert.rejects(
      excludeProvisioning(async () => {
        t += 5_000;
        throw new Error("install died");
      }, clock),
      /install died/u,
    );
    assert.equal(elapsed(), 0);
  });

  it("never lets one run's provisioning pay down a later run's real cost", async () => {
    let t = 0;
    const clock = () => t;
    await excludeProvisioning(async () => {
      t += 30_000;
    }, clock);
    // A LATER timer sees none of that credit: its window starts clean.
    const elapsed = startHookTimer(clock);
    t += 2_000;
    assert.equal(elapsed(), 2_000);
    assert.match(slowHookNotice("h", elapsed()), /2\.0s/u);
  });

  it("excuses the cold-start dependency wait (awaitLazyDependency)", async () => {
    let t = 0;
    const clock = () => t;
    const elapsed = startHookTimer(clock);
    let polls = 0;
    const loaded = await awaitLazyDependency({
      // Resolves only after the install "finishes" — three polls of waiting.
      tryImport: async () => (++polls < 4 ? null : { ok: true }),
      markerPresent: () => true,
      setupAlive: () => true,
      now: clock,
      sleep: async () => {
        t += 10_000;
      },
      intervalMs: 10_000,
    });
    assert.deepEqual(loaded, { ok: true });
    assert.equal(elapsed(), 0, "30s of install wait must not be charged");
  });

  it("excuses the cold redactor-daemon spawn", async () => {
    let t = 0;
    const clock = () => t;
    const elapsed = startHookTimer(clock);
    const dead = Object.assign(new Error("no socket"), { code: "ENOENT" });
    let dialled = 0;
    const result = await redactViaDaemon("some text", {
      // First dial fails as if the daemon were absent; the retry succeeds.
      connect: async () => {
        if (++dialled === 1) throw dead;
        return { text: "some text", found: [] };
      },
      spawn: () => {},
      waitForSocket: async () => {
        t += 3_000; // detect-secrets import + plugin prime
        return true;
      },
      now: clock,
    });
    assert.deepEqual(result, { text: "some text", found: [] });
    assert.equal(elapsed(), 0, "the daemon cold start must not be charged");
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

  it("omits the context clause when no context is given", () => {
    const notice = slowHookNotice("h", SLOW_HOOK_THRESHOLD_MS + 500);
    assert.doesNotMatch(notice, /payload/);
    assert.doesNotMatch(notice, /tool /);
  });

  it("omits the context clause when context carries neither field", () => {
    const notice = slowHookNotice(
      "h",
      SLOW_HOOK_THRESHOLD_MS + 500,
      undefined,
      {},
    );
    assert.doesNotMatch(notice, /payload/);
  });

  it("names the payload size and triggering tool when both are known", () => {
    const notice = slowHookNotice(
      "sanitize-output",
      SLOW_HOOK_THRESHOLD_MS + 3_400,
      undefined,
      { payloadBytes: 1_363_149, tool: "TaskOutput" },
    );
    assert.match(notice, /a 1\.3 MB payload/);
    assert.match(notice, /tool TaskOutput/);
  });

  it("names only the field that is known", () => {
    const bytesOnly = slowHookNotice(
      "h",
      SLOW_HOOK_THRESHOLD_MS + 500,
      undefined,
      { payloadBytes: 2048 },
    );
    assert.match(bytesOnly, /a 2\.0 KB payload/);
    assert.doesNotMatch(bytesOnly, /tool /);

    const toolOnly = slowHookNotice(
      "h",
      SLOW_HOOK_THRESHOLD_MS + 500,
      undefined,
      { tool: "Bash" },
    );
    assert.match(toolOnly, /tool Bash/);
    assert.doesNotMatch(toolOnly, /payload/);
  });
});

describe("formatBytes", () => {
  it("tiers bytes, KB and MB", () => {
    assert.equal(formatBytes(512), "512 B");
    assert.equal(formatBytes(2048), "2.0 KB");
    assert.equal(formatBytes(1_363_149), "1.3 MB");
  });
});

describe("writeSlowHookNotice with context", () => {
  it("carries the context into the stderr-written notice", () => {
    const errs = [];
    const notice = writeSlowHookNotice(
      "h",
      SLOW_HOOK_THRESHOLD_MS + 500,
      (chunk) => errs.push(chunk),
      { payloadBytes: 100, tool: "Bash" },
    );
    assert.match(notice, /tool Bash/);
    assert.match(errs[0], /tool Bash/);
  });
});

describe("withSlowHookNotice with context", () => {
  it("folds the context into the verdict's additional_context", () => {
    const out = withSlowHookNotice(
      "h",
      SLOW_HOOK_THRESHOLD_MS + 500,
      { decision: "allow" },
      () => {},
      { payloadBytes: 1_363_149, tool: "TaskOutput" },
    );
    assert.match(out.additional_context, /a 1\.3 MB payload/);
    assert.match(out.additional_context, /tool TaskOutput/);
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
      (event, fields) => emitted.push([event, fields]),
      (chunk) => errs.push(chunk),
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
      (event, fields) => emitted.push([event, fields]),
      (chunk) => errs.push(chunk),
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

  it("reports the timing of a judge that overran AND THEN THREW", async () => {
    // The run most worth naming — slow and broken — used to report nothing at
    // all, because the timer lived inside the try and only the success path
    // read it. Again a real overrun, so the test fails if the catch stops
    // measuring rather than merely stops printing.
    const errs = [];
    let onErrorCalled = false;
    const realErr = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk) => {
      errs.push(String(chunk));
      return true;
    };
    try {
      await runJudgeCli(
        "sanitize-output",
        async () => {
          await new Promise((resolve) =>
            setTimeout(resolve, SLOW_HOOK_THRESHOLD_MS + 100),
          );
          throw new Error("judge exploded");
        },
        {
          onError: () => {
            onErrorCalled = true;
          },
          readInput: async () => event,
          write: () => assert.fail("a throwing judge writes no verdict"),
        },
      );
    } finally {
      process.stderr.write = realErr;
    }
    const stderr = errs.join("");
    assert.match(stderr, /sanitize-output hook error: judge exploded/);
    assert.match(stderr, /PERFORMANCE/);
    assert.match(stderr, /sanitize-output hook took/);
    // The posture still runs: the timing is an addition to the fault report,
    // never a replacement for it.
    assert.ok(onErrorCalled, "onError must still take the failure posture");
  });

  it("names the triggering tool in the notice, but omits payload size for an injected reader", async () => {
    // The tool name comes from adapter.parse(event), independent of which
    // stdin reader ran; the payload-size clause is keyed off readInput being
    // the real readStdinJson, so an injected test seam must not report a
    // stale size left by some earlier real call.
    const written = [];
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
    const stdout = written.join("");
    assert.match(stdout, /tool Bash/);
    assert.doesNotMatch(stdout, /payload/);
  });

  it("says nothing about timing when the INPUT read is what failed", async () => {
    // Nothing was measured — the timer starts only once stdin has arrived — and
    // inventing a number for the wait that preceded it would blame this hook
    // for the harness's handover.
    const errs = [];
    const realErr = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk) => {
      errs.push(String(chunk));
      return true;
    };
    try {
      await runJudgeCli("sanitize-output", () => assert.fail("unreachable"), {
        onError: () => {},
        readInput: async () => {
          await new Promise((resolve) =>
            setTimeout(resolve, SLOW_HOOK_THRESHOLD_MS + 100),
          );
          throw new Error("stdin closed");
        },
        write: () => assert.fail("no verdict"),
      });
    } finally {
      process.stderr.write = realErr;
    }
    assert.match(errs.join(""), /stdin closed/);
    assert.equal(errs.join("").includes("PERFORMANCE"), false);
  });
});
