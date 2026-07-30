/**
 * The host-injection seams on the claude-hooks gates: the reason tables, the
 * PreToolUse host-gate list, the dependency-load diagnostics, and the cold-start
 * poll the hooks wait on while an install is still in flight.
 *
 * These exist because the package cannot know where it is installed. A host that
 * does — that can name the file wiring the adapter, or the command that
 * reinstalls it — must be able to say so in a fail-closed reason without forking
 * the module. So each seam is asserted on two properties:
 *
 *   - INERT BY DEFAULT. A seam left unsupplied must produce byte-identical
 *     output to the same call made with no options bag at all. An extension
 *     point that changes a shipped verdict when nobody uses it is a regression
 *     wearing a feature's clothes.
 *   - LOAD-BEARING WHEN SUPPLIED. The override must reach the emitted reason,
 *     and a host gate's deny must SHORT-CIRCUIT the rewriting layers — a call
 *     reported as both denied and sanitized is two verdicts for one event.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

const { claudeAdapter } = await import("agent-control-plane-core/claude");
const { Decision } = await import("agent-control-plane-core");
const {
  lazyImport,
  lazyImportErrorFor,
  failedLazyPackages,
  missingPackageMessage,
  missingPackageError,
  safeErrMessage,
  DEFAULT_MISSING_PACKAGE_REMEDY,
  hookgateMarkerPath,
  probeSetupAlive,
  awaitLazyDependency,
} = await import("../claude-hooks/lib/hook-io.mjs");
const { judgeSanitizeUserPrompt, USER_PROMPT_MESSAGES } =
  await import("../claude-hooks/sanitize-user-prompt.mjs");
const {
  judgePreToolUseSanitize,
  failClosedFields,
  depLoadHint,
  PRE_TOOL_USE_MESSAGES,
} = await import("../claude-hooks/pretooluse-sanitize.mjs");
const { failClosedContext } =
  await import("../claude-hooks/sanitize-output.mjs");

const HOST_REMEDY = "run ./setup.sh in the project root and retry.";

/** @param {Record<string, unknown>} payload */
const parse = (payload) => claudeAdapter.parse(payload);

const unknownEvent = () => parse({ no_such_field: 1 });

describe("dependency-load diagnostics", () => {
  it("records why a package failed to load and names it as a failed package", async () => {
    const ns = await lazyImport("no-such-package-ffc1a9");
    // lazyImport swallows the failure into {} — that is the fail-closed
    // contract; the recorded error is the only place the cause survives.
    assert.deepEqual(ns, {});
    const err = lazyImportErrorFor("no-such-package-ffc1a9");
    assert.ok(err instanceof Error);
    assert.ok(failedLazyPackages().includes("no-such-package-ffc1a9"));
  });

  it("matches a subpath specifier to its package", async () => {
    await lazyImport("no-such-package-ffc1a9/sub/deep");
    assert.ok(lazyImportErrorFor("no-such-package-ffc1a9") instanceof Error);
    // Reported once under the bare package name, not once per subpath.
    assert.equal(
      failedLazyPackages().filter((p) => p === "no-such-package-ffc1a9").length,
      1,
    );
  });

  it("scopes a scoped package to its two segments", async () => {
    await lazyImport("@scope-ffc1a9/pkg/sub");
    assert.ok(failedLazyPackages().includes("@scope-ffc1a9/pkg"));
    assert.ok(!failedLazyPackages().includes("@scope-ffc1a9"));
  });

  it("never reports a relative or URL specifier as a reinstallable package", async () => {
    await lazyImport("./no-such-relative-ffc1a9.mjs");
    await lazyImport("node:no-such-builtin-ffc1a9");
    const failed = failedLazyPackages();
    assert.ok(!failed.some((p) => p.startsWith(".")));
    assert.ok(!failed.some((p) => p.includes(":")));
  });

  it("ranks a repeat failure as the newest, not by when it first failed", async () => {
    await lazyImport("first-ffc1a9");
    await lazyImport("second-ffc1a9");
    await lazyImport("first-ffc1a9");
    // A fail-closed reason names ONE package; it must be the one that just
    // failed, so a stale first failure cannot outrank the current one.
    assert.equal(failedLazyPackages()[0], "first-ffc1a9");
  });

  it("clears the record once the specifier loads", async () => {
    await lazyImport("agent-sanitizer/invisible");
    assert.equal(lazyImportErrorFor("agent-sanitizer"), undefined);
    assert.ok(!failedLazyPackages().includes("agent-sanitizer"));
  });

  it("keeps the remedy inside the downstream 300-char re-scrub", () => {
    // The reason is re-scrubbed by safeErrMessage before it reaches the user, so
    // an unbounded cause would truncate the remedy off the end — losing the only
    // actionable half of the message. The cap is computed for exactly this.
    const huge = new Error("x".repeat(5000));
    const message = missingPackageMessage("a-package", huge, HOST_REMEDY);
    assert.ok(safeErrMessage(message).endsWith(HOST_REMEDY));
  });

  it("says so when nothing was recorded, rather than inventing a cause", () => {
    const message = missingPackageMessage("a-package", undefined, HOST_REMEDY);
    assert.match(message, /version skew/u);
    assert.ok(message.endsWith(HOST_REMEDY));
  });

  it("defaults the remedy to the package's own wording", () => {
    assert.ok(
      missingPackageMessage("a-package", new Error("boom")).endsWith(
        DEFAULT_MISSING_PACKAGE_REMEDY,
      ),
    );
  });

  it("tags the throwable so a reason-builder does not append a second copy", () => {
    const err = missingPackageError("a-package", new Error("boom"));
    assert.equal(/** @type {{code?: string}} */ (err).code, "DEP_UNAVAILABLE");
    assert.equal(depLoadHint(err), "");
  });

  it("names the failed package and the host remedy on an untagged error", async () => {
    await lazyImport("no-such-package-ffc1a9");
    const hint = depLoadHint(new TypeError("x is not a function"), HOST_REMEDY);
    assert.match(hint, /no-such-package-ffc1a9 is unavailable/u);
    assert.ok(hint.endsWith(HOST_REMEDY));
  });

  it("adds no hint when nothing failed to load", () => {
    assert.equal(
      depLoadHint(new TypeError("unrelated"), HOST_REMEDY, () => []),
      "",
    );
  });
});

describe("user-prompt gate reason table", () => {
  it("is inert by default", () => {
    const event = unknownEvent();
    assert.deepEqual(
      judgeSanitizeUserPrompt(event),
      judgeSanitizeUserPrompt(event, undefined, USER_PROMPT_MESSAGES),
    );
    assert.equal(
      judgeSanitizeUserPrompt(event).reason,
      USER_PROMPT_MESSAGES.unknownEvent,
    );
  });

  it("carries a host's deny-when-blind reason", () => {
    const verdict = judgeSanitizeUserPrompt(unknownEvent(), undefined, {
      ...USER_PROMPT_MESSAGES,
      unknownEvent: "blocked: fix the adapter parse in hooks/prompt.mjs",
    });
    assert.equal(verdict.decision, Decision.DENY);
    assert.equal(
      verdict.reason,
      "blocked: fix the adapter parse in hooks/prompt.mjs",
    );
  });

  it("carries a host's block context on a real payload block", () => {
    // U+E0041 (TAG LATIN A) is payload-capable and invisible: the classifier
    // blocks it, which is the arm that emits blockContext.
    const event = parse({
      hook_event_name: "UserPromptSubmit",
      prompt: `hello${"\u{E0041}".repeat(20)}`,
    });
    const verdict = judgeSanitizeUserPrompt(event, undefined, {
      ...USER_PROMPT_MESSAGES,
      blockContext: "host block note",
    });
    assert.equal(verdict.decision, Decision.DENY);
    assert.equal(verdict.additional_context, "host block note");
  });

  it("reports a missing package as a tagged dependency failure", () => {
    const event = parse({ hook_event_name: "UserPromptSubmit", prompt: "hi" });
    assert.throws(() => judgeSanitizeUserPrompt(event, null), {
      code: "DEP_UNAVAILABLE",
    });
  });
});

describe("PreToolUse host gates", () => {
  /** A tool input the confusable layer WILL rewrite, so a skipped layer shows. */
  const confusableWrite = () =>
    parse({
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      // Cyrillic es/a/er in place of Latin c/a/p.
      tool_input: { command: "сар /tmp/x /tmp/y" },
      session_id: "sess-1",
    });

  it("is inert with no gates supplied", async () => {
    const event = confusableWrite();
    const withBag = await judgePreToolUseSanitize(event, undefined, {});
    const without = await judgePreToolUseSanitize(event);
    assert.deepEqual(withBag, without);
    // Non-vacuous: the layers really did run, so a short-circuit is observable.
    assert.ok(without.mutated_input !== undefined);
  });

  it("denies on a gate reason and skips the rewriting layers", async () => {
    const verdict = await judgePreToolUseSanitize(
      confusableWrite(),
      undefined,
      { gates: [() => "denied: run /pr-creation first"] },
    );
    assert.equal(verdict.decision, Decision.DENY);
    assert.equal(verdict.reason, "denied: run /pr-creation first");
    // The whole point of running gates first: a denied call is not ALSO
    // reported as a sanitized one.
    assert.equal(verdict.mutated_input, undefined);
    assert.equal(verdict.additional_context, undefined);
  });

  it("falls through a gate that abstains, and runs gates in order", async () => {
    const seen = [];
    const verdict = await judgePreToolUseSanitize(
      confusableWrite(),
      undefined,
      {
        gates: [
          (input) => {
            seen.push(input.session_id);
            return null;
          },
          (input) => {
            seen.push(input.tool_name);
            return undefined;
          },
        ],
      },
    );
    assert.deepEqual(seen, ["sess-1", "Bash"]);
    assert.ok(verdict.mutated_input !== undefined);
  });

  it("hands the gate the session identity, which rides in meta not the input", async () => {
    let got;
    await judgePreToolUseSanitize(confusableWrite(), undefined, {
      gates: [
        (input) => {
          got = input;
          return null;
        },
      ],
    });
    // A once-per-session checkpoint cannot tell two sessions apart without it.
    assert.equal(got.session_id, "sess-1");
    assert.equal(got.tool_name, "Bash");
  });

  it("lets a broken gate throw rather than swallowing it", async () => {
    // The throw reaches the CLI's fail-closed catch, which ASKS. Swallowing it
    // would silently downgrade a broken host gate into a pass.
    await assert.rejects(
      judgePreToolUseSanitize(confusableWrite(), undefined, {
        gates: [
          () => {
            throw new Error("gate is broken");
          },
        ],
      }),
      /gate is broken/u,
    );
  });

  it("carries a host's deny-when-blind reason", async () => {
    const verdict = await judgePreToolUseSanitize(unknownEvent(), undefined, {
      messages: { ...PRE_TOOL_USE_MESSAGES, unknownEvent: "host blind deny" },
    });
    assert.equal(verdict.decision, Decision.DENY);
    assert.equal(verdict.reason, "host blind deny");
  });
});

describe("PreToolUse fail-closed fields", () => {
  it("is inert by default", () => {
    const err = new Error("boom");
    assert.deepEqual(
      failClosedFields(true, err),
      failClosedFields(true, err, {}),
    );
  });

  it("asks after a clean parse and denies on unparsable input", () => {
    const err = new Error("boom");
    assert.equal(failClosedFields(true, err).permissionDecision, "ask");
    assert.equal(failClosedFields(false, err).permissionDecision, "deny");
  });

  it("routes both reasons through the host's table and hint", () => {
    const opts = {
      messages: {
        ...PRE_TOOL_USE_MESSAGES,
        failed: (cause) => `HOST-FAILED ${cause}`,
        unparsable: (cause) => `HOST-UNPARSABLE ${cause}`,
      },
      hint: " HOST-HINT",
    };
    assert.equal(
      failClosedFields(true, new Error("boom"), opts).permissionDecisionReason,
      "HOST-FAILED boom HOST-HINT",
    );
    assert.equal(
      failClosedFields(false, new Error("boom"), opts).permissionDecisionReason,
      "HOST-UNPARSABLE boom HOST-HINT",
    );
  });
});

describe("sanitize-output fail-closed context", () => {
  it("says only that the output was suppressed when the deps did load", () => {
    const context = failClosedContext(() => true, HOST_REMEDY);
    assert.match(context, /output was suppressed/u);
    assert.ok(!context.includes(HOST_REMEDY));
  });

  it("names the missing dependency and the host remedy when they did not", () => {
    const context = failClosedContext(() => false, HOST_REMEDY);
    assert.match(context, /agent-sanitizer is unavailable/u);
    assert.ok(context.endsWith(HOST_REMEDY));
  });
});

describe("cold-start marker", () => {
  it("has no path when no project dir is set — nothing installed it", () => {
    assert.equal(hookgateMarkerPath(undefined, "/run/user/1000"), null);
  });

  it("prefers an absolute runtime dir over world-writable /tmp", () => {
    assert.ok(
      hookgateMarkerPath("/w/p", "/run/user/1000").startsWith(
        "/run/user/1000/",
      ),
    );
    assert.ok(hookgateMarkerPath("/w/p", "relative/dir").startsWith("/tmp/"));
    assert.ok(hookgateMarkerPath("/w/p", undefined).startsWith("/tmp/"));
  });

  it("flattens the project dir so the path is one filename", () => {
    const path = hookgateMarkerPath("/work/my proj", undefined);
    assert.equal(path.slice("/tmp/".length).includes("/"), false);
    // Two projects must not collide onto one marker.
    assert.notEqual(path, hookgateMarkerPath("/work/other", undefined));
  });
});

describe("setup-liveness probe", () => {
  it("reads a null path as alive so the caller's own bound governs", () => {
    assert.equal(probeSetupAlive(null), true);
  });

  it("reads an unreadable marker as alive, favouring a brief wait", () => {
    assert.equal(probeSetupAlive("/no/such/marker-ffc1a9"), true);
  });

  it("reads our own live pid as alive", async () => {
    const { writeFileSync, mkdtempSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const marker = join(mkdtempSync(join(tmpdir(), "seam-")), "m");
    writeFileSync(marker, String(process.pid));
    assert.equal(probeSetupAlive(marker), true);
    // A pid that cannot exist reads as dead — that is the arm that stops the
    // wait when setup was killed and left its marker behind.
    writeFileSync(marker, "2147483646");
    assert.equal(probeSetupAlive(marker), false);
    // Garbage contents are a write race, not a death: keep waiting.
    writeFileSync(marker, "not-a-pid");
    assert.equal(probeSetupAlive(marker), true);
  });
});

describe("cold-start wait", () => {
  const never = () => false;
  /** A clock that advances by `step` on every read. */
  const ticking = (step) => {
    let t = 0;
    return () => (t += step);
  };

  it("returns immediately on a warm session, with no sleep at all", async () => {
    let slept = 0;
    const bindings = await awaitLazyDependency({
      tryImport: async () => ({ ok: true }),
      markerPresent: never,
      setupAlive: never,
      sleep: async () => {
        slept += 1;
      },
    });
    assert.deepEqual(bindings, { ok: true });
    assert.equal(slept, 0);
  });

  it("gives up after the grace window when no setup was ever seen", async () => {
    const bindings = await awaitLazyDependency({
      tryImport: async () => null,
      markerPresent: never,
      setupAlive: never,
      now: ticking(2000),
      sleep: async () => {},
      graceMs: 5000,
    });
    // A genuinely-absent dependency must fail closed fast, not after a long
    // block — the wait exists for a live install, not for an absent one.
    assert.equal(bindings, null);
  });

  it("waits out a live install past the grace window, then settles", async () => {
    let attempts = 0;
    let installing = true;
    const bindings = await awaitLazyDependency({
      tryImport: async () => {
        attempts += 1;
        // Setup finishes without ever providing the dep.
        if (attempts === 40) installing = false;
        return null;
      },
      markerPresent: () => installing,
      setupAlive: () => installing,
      now: ticking(500),
      sleep: async () => {},
      graceMs: 5000,
      settleMs: 1000,
      ceilingMs: 900000,
    });
    assert.equal(bindings, null);
    // Past the 5s grace by a wide margin: the marker, not the clock, held it.
    assert.ok(
      attempts > 30,
      `only ${attempts} attempts — the wait was cut off`,
    );
  });

  it("stops at the ceiling when setup is alive but hung", async () => {
    let attempts = 0;
    const bindings = await awaitLazyDependency({
      tryImport: async () => {
        attempts += 1;
        return null;
      },
      markerPresent: () => true,
      setupAlive: () => true,
      now: ticking(100000),
      sleep: async () => {},
      ceilingMs: 900000,
    });
    assert.equal(bindings, null);
    // The ceiling is a backstop, not the normal exit: it must exist, because a
    // hook killed for running over its harness timeout is a fail-OPEN.
    assert.ok(attempts > 1);
  });
});
