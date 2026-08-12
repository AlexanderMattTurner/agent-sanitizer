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
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { rmSync } from "node:fs";

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
  configureMissingPackageRemedy,
  hookgateMarkerPath,
  probeSetupAlive,
  awaitLazyDependency,
} = await import("../claude-hooks/lib/hook-io.mjs");
const { controlPlane } = await import("../claude-hooks/lib/control-plane.mjs");
const { instructionsLoadedFile, recordInstructionsLoaded } =
  await import("../claude-hooks/lib/invisible-alert.mjs");
const {
  configureEnvConfigSource,
  minEnvSecretLen,
  envBoundSecretVars,
  dynamicSecretVars,
} = await import("../claude-hooks/lib/env-config.mjs");
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

  it("spends the whole budget on the remedy when the REMEDY is what is long", () => {
    // The symmetric case to the one above, and the one the host knob opened: a
    // remedy long enough to drive the cause budget negative. safeErrMessage does
    // not clamp a negative cap — `slice(0, -n)` trims from the END — so without
    // the clamp the cause survives nearly whole and pushes the message far past
    // the budget. Clamped, the cause collapses to the truncation marker and the
    // overflow is only what the remedy itself costs.
    const longRemedy = `${"reinstall the dependencies ".repeat(11)}and retry.`;
    assert.ok(longRemedy.length > 260, "remedy must overrun the budget");
    const cause = "a".repeat(400);
    const message = missingPackageMessage(
      "a-package",
      new Error(cause),
      longRemedy,
    );
    assert.ok(message.endsWith(longRemedy));
    assert.ok(
      !message.includes("aaaaaaaaaa"),
      "the cause must not survive when the remedy has spent the budget",
    );
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

  it("names a package only for the error shape an unloaded binding produces", async () => {
    await lazyImport("no-such-package-ffc1a9");
    // The recorded-failure set is process-wide and carries no link to the error
    // being reported, so naming a package from it is only sound for the failure
    // this hint explains: calling an undefined binding, which raises a TypeError.
    // A layer engine reporting its own problem must not be answered with a
    // reinstall that fixes nothing.
    assert.equal(
      depLoadHint(new Error("redactor daemon refused"), HOST_REMEDY),
      "",
    );
    assert.equal(
      depLoadHint(new RangeError("depth exceeded"), HOST_REMEDY),
      "",
    );
    assert.notEqual(depLoadHint(new TypeError("x is not a function")), "");
  });
});

describe("missing-package remedy seam", () => {
  it("is inert by default: unconfigured output is byte-identical after a round trip", () => {
    const before = missingPackageMessage("a-package", new Error("boom"));
    configureMissingPackageRemedy(HOST_REMEDY);
    configureMissingPackageRemedy(null);
    assert.equal(missingPackageMessage("a-package", new Error("boom")), before);
    assert.equal(
      before,
      `a-package is unavailable: boom; ${DEFAULT_MISSING_PACKAGE_REMEDY}`,
    );
  });

  it("reaches controlPlane's missing-package throw end-to-end", () => {
    // The consumer that motivated the seam: controlPlane() throws with no
    // remedy argument, so before the seam it could only ever say pnpm install.
    configureMissingPackageRemedy(HOST_REMEDY);
    try {
      assert.throws(
        () => controlPlane({ claudeAdapter: undefined }),
        (err) => {
          assert.equal(
            /** @type {{code?: string}} */ (err).code,
            "DEP_UNAVAILABLE",
          );
          const message = /** @type {Error} */ (err).message;
          assert.match(message, /agent-control-plane-core is unavailable/u);
          assert.ok(message.endsWith(HOST_REMEDY));
          return true;
        },
      );
    } finally {
      configureMissingPackageRemedy(null);
    }
  });

  it("still lets an explicit per-call remedy win", () => {
    configureMissingPackageRemedy(HOST_REMEDY);
    try {
      const message = missingPackageMessage(
        "a-package",
        new Error("boom"),
        "explicit remedy.",
      );
      assert.ok(message.endsWith("explicit remedy."));
      assert.ok(!message.includes(HOST_REMEDY));
      assert.ok(
        missingPackageError(
          "a-package",
          new Error("boom"),
          "explicit remedy.",
        ).message.endsWith("explicit remedy."),
      );
    } finally {
      configureMissingPackageRemedy(null);
    }
  });

  it("is re-steerable, not latched: the last configure wins", () => {
    configureMissingPackageRemedy("first remedy.");
    configureMissingPackageRemedy(HOST_REMEDY);
    try {
      assert.ok(
        missingPackageMessage("a-package", new Error("boom")).endsWith(
          HOST_REMEDY,
        ),
      );
    } finally {
      configureMissingPackageRemedy(null);
    }
  });

  it("keeps a long configured remedy whole through the 300-char budget", () => {
    // Same clamp the explicit-remedy test above exercises, but through the
    // configured default — the path a host actually takes.
    const longRemedy = `${"run the host installer ".repeat(12)}and retry.`;
    assert.ok(longRemedy.length > 260, "remedy must overrun the budget");
    configureMissingPackageRemedy(longRemedy);
    try {
      const message = missingPackageMessage(
        "a-package",
        new Error("a".repeat(400)),
      );
      assert.ok(message.endsWith(longRemedy));
      assert.ok(
        !message.includes("aaaaaaaaaa"),
        "the cause must not survive when the remedy has spent the budget",
      );
    } finally {
      configureMissingPackageRemedy(null);
    }
  });
});

describe("env-config host source seam", () => {
  // A value long enough for the package floor (16) but short of the host's.
  const env = { MY_API_KEY: "x".repeat(20), PATH: "/usr/bin" };

  it("is inert by default: unconfigured answers are identical after a round trip", () => {
    const floorBefore = minEnvSecretLen();
    const setBefore = envBoundSecretVars(env);
    // Non-vacuous baseline: the shape-inferred path really ran.
    assert.ok(setBefore.includes("MY_API_KEY"));
    configureEnvConfigSource({
      minSecretLen: 99,
      extraVars: ["HOST_SEAM_VAR"],
    });
    configureEnvConfigSource(null);
    assert.equal(minEnvSecretLen(), floorBefore);
    assert.deepEqual(envBoundSecretVars(env), setBefore);
  });

  it("applies a configured floor to the helpers that consult it", () => {
    configureEnvConfigSource({ minSecretLen: 99 });
    try {
      assert.equal(minEnvSecretLen(), 99);
      // 20 chars is below the host floor: no longer secret-shaped enough.
      assert.ok(!dynamicSecretVars(env).includes("MY_API_KEY"));
      assert.ok(!envBoundSecretVars(env).includes("MY_API_KEY"));
      // A value clearing the host floor still qualifies — it is a floor, not a block.
      assert.ok(
        dynamicSecretVars({ MY_API_KEY: "x".repeat(120) }).includes(
          "MY_API_KEY",
        ),
      );
    } finally {
      configureEnvConfigSource(null);
    }
  });

  it("unions configured extraVars into the redaction set, keeping the package floor", () => {
    const floorBefore = minEnvSecretLen();
    configureEnvConfigSource({ extraVars: ["GLOVEBOX_PROVIDER_SEED"] });
    try {
      assert.ok(envBoundSecretVars({}).includes("GLOVEBOX_PROVIDER_SEED"));
      // A partial source keeps the unset field on its package derivation.
      assert.equal(minEnvSecretLen(), floorBefore);
    } finally {
      configureEnvConfigSource(null);
    }
  });

  it("fails closed on a malformed source at USE, not at configure", () => {
    // Configure itself must not throw: it runs at a bundle entry's top level,
    // where a throw kills the hook before its fail-closed catch installs.
    for (const bad of [0, "16"]) {
      configureEnvConfigSource({
        minSecretLen: /** @type {number} */ (bad),
      });
      try {
        assert.throws(() => minEnvSecretLen(), /minSecretLen/u);
        assert.throws(() => dynamicSecretVars(env), /minSecretLen/u);
      } finally {
        configureEnvConfigSource(null);
      }
    }
    for (const bad of ["bad-name", 7]) {
      configureEnvConfigSource({
        extraVars: /** @type {string[]} */ ([bad]),
      });
      try {
        assert.throws(() => envBoundSecretVars({}), /not a variable name/u);
      } finally {
        configureEnvConfigSource(null);
      }
    }
    configureEnvConfigSource({
      extraVars: /** @type {string[]} */ (/** @type {unknown} */ ("X")),
    });
    try {
      assert.throws(() => envBoundSecretVars({}), /must be an array/u);
    } finally {
      configureEnvConfigSource(null);
    }
  });

  it("treats an undefined source as unconfigured, not as a configure-time crash", () => {
    // The shape a host actually produces: configureEnvConfigSource(
    // hostConfig.envSource) with the field absent. A throw here would land at
    // the bundle entry's top level — a fail-OPEN hook — for a host that simply
    // has nothing to configure.
    const packageFloor = minEnvSecretLen();
    configureEnvConfigSource(/** @type {any} */ (undefined));
    try {
      assert.equal(minEnvSecretLen(), packageFloor);
      assert.ok(envBoundSecretVars(env).includes("MY_API_KEY"));
    } finally {
      configureEnvConfigSource(null);
    }
  });

  it("throws at USE on a non-object source, never running silently inert", () => {
    const nonObject = /** @type {any} */ ("X");
    configureEnvConfigSource(nonObject);
    try {
      assert.throws(() => minEnvSecretLen(), /must be an object/u);
      assert.throws(() => envBoundSecretVars({}), /must be an object/u);
    } finally {
      configureEnvConfigSource(null);
    }
  });

  it("throws at USE on a key the seam does not read", () => {
    // A typo'd field name must not leave the helpers on the package derivation
    // while the host believes it configured them — same fail-closed contract as
    // a malformed field value, and same USE-time timing (a configure-time throw
    // lands at the bundle entry's top level, a fail-OPEN hook).
    configureEnvConfigSource(/** @type {any} */ ({ minSecretLength: 32 }));
    try {
      assert.throws(() => minEnvSecretLen(), /unknown key "minSecretLength"/u);
      assert.throws(
        () => envBoundSecretVars({}),
        /unknown key "minSecretLength"/u,
      );
    } finally {
      configureEnvConfigSource(null);
    }
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

  it("fills the unset fields of a PARTIAL reason table", () => {
    // Same fail-open shape as the PreToolUse gate: main() threads this object
    // into its onError. A partial table would also silently drop sgrNote and
    // blockContext from the verdict rather than erroring.
    const verdict = judgeSanitizeUserPrompt(unknownEvent(), undefined, {
      unknownEvent: "host blind deny",
    });
    assert.equal(verdict.reason, "host blind deny");
    const blocked = parse({
      hook_event_name: "UserPromptSubmit",
      prompt: `hello${"\u{E0041}".repeat(20)}`,
    });
    assert.equal(
      judgeSanitizeUserPrompt(blocked, undefined, {
        unknownEvent: "host blind deny",
      }).additional_context,
      USER_PROMPT_MESSAGES.blockContext,
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
    // The remedy travels in the same table as the reasons, so a host that
    // supplies its wording once cannot have it apply to the deny reasons and
    // silently not to the one message that tells a reader what to run.
    assert.throws(
      () =>
        judgeSanitizeUserPrompt(event, null, {
          remedy: "run ./setup.sh first.",
        }),
      (err) =>
        /** @type {Error} */ (err).message.endsWith("run ./setup.sh first."),
    );
  });
});

describe("PreToolUse host gates", () => {
  // The gate also carries a once-per-session notice for a host that never emits
  // InstructionsLoaded, which would land on the FIRST call below and not the
  // second — an asymmetry that has nothing to do with the seam under test. Mark
  // the event as seen so both calls are notice-free; the notice itself is driven
  // in claude-hooks-loaded-instructions.test.mjs. Keyed to the session id the
  // events below carry, which is the key the gate looks the marker up under.
  const SESSION = "sess-1";
  before(() => recordInstructionsLoaded(SESSION));
  after(() => rmSync(instructionsLoadedFile(SESSION), { force: true }));

  /** A tool input the confusable layer WILL rewrite, so a skipped layer shows. */
  const confusableWrite = () =>
    parse({
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      // Cyrillic es/a/er in place of Latin c/a/p.
      tool_input: { command: "сар /tmp/x /tmp/y" },
      session_id: SESSION,
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

  it("fills the unset fields of a PARTIAL reason table", async () => {
    // Every other seam case spreads the whole default table, which is exactly the
    // shape that cannot expose a wholesale substitution. A bare one-field object
    // is what a host actually writes — and the field it did NOT set is consumed
    // inside runJudgeCli's catch, where an undefined reason-builder throws out of
    // the handler and the hook emits nothing at all: a fail-OPEN pass.
    const verdict = await judgePreToolUseSanitize(unknownEvent(), undefined, {
      messages: { unknownEvent: "host blind deny" },
    });
    assert.equal(verdict.reason, "host blind deny");
    const fields = failClosedFields(true, new Error("boom"), {
      messages: { unknownEvent: "host blind deny" },
    });
    assert.equal(
      fields.permissionDecisionReason,
      PRE_TOOL_USE_MESSAGES.failed("boom"),
    );
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
    assert.equal(hookgateMarkerPath("", "/run/user/1000"), null);
  });

  // Both arguments are passed explicitly throughout: omitting one falls back to
  // its process.env default, and a CI runner (which sets XDG_RUNTIME_DIR) then
  // takes a different branch than a developer shell (which usually does not).
  it("prefers an absolute runtime dir over world-writable /tmp", () => {
    assert.ok(
      hookgateMarkerPath("/w/p", "/run/user/1000").startsWith(
        "/run/user/1000/",
      ),
    );
    assert.ok(hookgateMarkerPath("/w/p", "relative/dir").startsWith("/tmp/"));
    assert.ok(hookgateMarkerPath("/w/p", "").startsWith("/tmp/"));
  });

  it("reads both defaults from the environment", () => {
    const saved = { ...process.env };
    try {
      process.env.CLAUDE_PROJECT_DIR = "/env/project";
      process.env.XDG_RUNTIME_DIR = "/run/user/4242";
      // Compared against the explicit-argument call rather than a literal path,
      // so this pins where the defaults come FROM without restating the stem.
      assert.equal(
        hookgateMarkerPath(),
        hookgateMarkerPath("/env/project", "/run/user/4242"),
      );
      delete process.env.CLAUDE_PROJECT_DIR;
      assert.equal(hookgateMarkerPath(), null);
    } finally {
      process.env = saved;
    }
  });

  it("flattens the project dir so the path is one filename", () => {
    const path = hookgateMarkerPath("/work/my proj", "");
    assert.equal(path.slice("/tmp/".length).includes("/"), false);
  });

  it("keeps dirs that flatten alike on separate markers", () => {
    // The flattening is lossy, so it cannot be the identity: these three differ
    // only in characters it replaces. Sharing a marker would make each project's
    // hook wait on the others' installs, silently, in both directions.
    const paths = ["/work/a-b", "/work/a_b", "/work/a b"].map((dir) =>
      hookgateMarkerPath(dir, ""),
    );
    assert.equal(new Set(paths).size, 3);
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
