/**
 * ONE failure posture, enumerated over every hook.
 *
 * Each hook used to answer its own breakage by hand — four renderings in three
 * envelope shapes, one hook that never read AGENT_SANITIZER_FAIL_OPEN at all
 * (an operator who pinned the strict posture silently got an advisory on the one
 * hook guarding session-start ingress), and a dispatcher arm that hard-exited
 * past the question. Hand-rolled postures fail by omission, and omission is
 * exactly what a per-hook test suite does not notice.
 *
 * So this file enumerates the hook modules ON DISK rather than a list typed
 * here: a hook added without a declared posture fails the first assertion, and
 * every hook that has one is driven through a REAL forced fault under both
 * postures, with the emission compared against the table's own entry. Nothing
 * greps a source file; every case runs the hook's actual error path.
 */
import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { withCapturedStdout } from "./helpers/capture-stdout.mjs";

const hooksDir = fileURLToPath(new URL("../claude-hooks", import.meta.url));

// Set before the hooks import: scan-invisible-chars walks CLAUDE_PROJECT_DIR
// and rewrites the instruction files it finds, so pointing it at this repo
// would let the test edit the tree. invisible-alert.mjs resolves both the
// project dir and the alert path at module load.
const projectDir = mkdtempSync(join(tmpdir(), "sanitizer-posture-proj-"));
process.env.CLAUDE_PROJECT_DIR = projectDir;
// An instruction file the scan cannot read: a DIRECTORY where a file is
// expected. The finder lists it, the read fails EISDIR. That is a COVERAGE GAP,
// not a hook fault — the hook worked and is telling you what it could not check.
mkdirSync(join(projectDir, "CLAUDE.md"));
// A second, perfectly readable target, so "did the rest of the project still get
// scanned?" is observable rather than assumed.
writeFileSync(join(projectDir, "AGENTS.md"), "ordinary, clean prose\n");

const { FAIL_OPEN_ENV, missingPackageError } =
  await import("../claude-hooks/lib/hook-io.mjs");
const {
  FAULT_POLICY_HOOKS,
  faultPolicy,
  hookFaultOutcome,
  registerFaultPolicy,
} = await import("../claude-hooks/lib/hook-fault.mjs");
const { SECRETS_ENABLED_ENV } =
  await import("../claude-hooks/lib/env-config.mjs");
// Imported for their REGISTRATIONS: a policy is reachable only once its hook
// module has loaded, which is what makes "declared where the hook lives" true.
const preToolUse = await import("../claude-hooks/pretooluse-sanitize.mjs");
const sanitizeOutput = await import("../claude-hooks/sanitize-output.mjs");
const userPrompt = await import("../claude-hooks/sanitize-user-prompt.mjs");
const scanInvisible = await import("../claude-hooks/scan-invisible-chars.mjs");
await import("../claude-hooks/scan-loaded-instructions.mjs");
await import("../claude-hooks/plugin-hooks.mjs");
const { alertDir } = scanInvisible;
const { invisibleCharAlert } =
  await import("../claude-hooks/lib/invisible-alert.mjs");

// Litter is not free: the SessionStart scanner globs **/CLAUDE.md under its
// project dir, and other suites point that at $TMPDIR — so an unreadable
// fixture left behind here becomes an unscannable instruction file for THEM,
// arming their gate and breaking assertions nowhere near this file.
after(() => {
  rmSync(projectDir, { recursive: true, force: true });
  rmSync(alertDir(), { recursive: true, force: true });
});

/** The two postures, as the environments a hook actually reads. */
const POSTURES = [
  ["open (nothing set)", {}],
  ["closed (opt-out pinned)", { [FAIL_OPEN_ENV]: "0" }],
];

/** The archetypal environmental failure: the sanitizer was never installed. */
const FAULT = missingPackageError("agent-sanitizer", new Error("not found"));

/** Every CLI hook module on disk, by the name it registers under. */
function cliHookModules() {
  return readdirSync(hooksDir, { withFileTypes: true })
    .filter((e) => e.isFile() && e.name.endsWith(".mjs"))
    .map((e) => e.name.replace(/\.mjs$/u, ""))
    .sort();
}

describe("every hook's failure posture comes from one table", () => {
  it("declares a policy for every CLI hook module on disk (non-vacuous)", () => {
    const modules = cliHookModules();
    assert.ok(modules.length > 0, "no .mjs modules found under claude-hooks/");
    // Both directions: a hook added without a spec shows up on the left, a
    // retired name left in the table shows up on the right.
    assert.deepEqual(modules, [...FAULT_POLICY_HOOKS].sort());
    for (const hook of modules)
      assert.ok(
        faultPolicy(hook).closed,
        `${hook} registered no closed verdict`,
      );
  });

  it("reads the knob in exactly one place, and both arms differ per hook", () => {
    for (const hook of FAULT_POLICY_HOOKS) {
      const [open, closed] = POSTURES.map(
        ([, env]) => hookFaultOutcome(hook, FAULT, { env }).posture,
      );
      assert.equal(open, "open", `${hook} is not open by default`);
      assert.equal(closed, "closed", `${hook} ignores the opt-out`);
    }
  });
});

describe("no hook fault withholds output unless the operator opted out", () => {
  // The knob is the only thing that can close a hook, Layer 4 included: a
  // redactor fault must never turn into every tool output being suppressed.
  const SECRETS_ON = { [SECRETS_ENABLED_ENV]: "1" };
  const input = { tool_response: "hello" };
  /** @param {Record<string, string>} env */
  const emittedUnder = (env) => {
    const emitted = [];
    sanitizeOutput.emitHookFailure(
      input,
      FAULT,
      (fields) => emitted.push(fields),
      undefined,
      env,
    );
    return emitted;
  };

  it("leaves every hook open by default, with or without Layer 4", () => {
    for (const env of [{}, SECRETS_ON]) {
      const postures = Object.fromEntries(
        FAULT_POLICY_HOOKS.map((hook) => [
          hook,
          hookFaultOutcome(hook, FAULT, { env }).posture,
        ]),
      );
      assert.deepEqual(
        postures,
        Object.fromEntries(FAULT_POLICY_HOOKS.map((hook) => [hook, "open"])),
        JSON.stringify(env),
      );
    }
  });

  it("leaves the output in the model's view when Layer 4 is on", () => {
    const [fields] = emittedUnder(SECRETS_ON);
    assert.equal(fields.updatedToolOutput, undefined);
    assert.match(String(fields.additionalContext), /UNSANITIZED/u);
  });

  it("suppresses only under the explicit opt-out, Layer 4 or not", () => {
    const closed = emittedUnder({ [FAIL_OPEN_ENV]: "0" });
    assert.match(closed[0].updatedToolOutput, /SANITIZATION FAILED/u);
    assert.deepEqual(
      emittedUnder({ ...SECRETS_ON, [FAIL_OPEN_ENV]: "0" }),
      closed,
    );
  });

  it("refuses a policy with no closed arm", () => {
    const complete = faultPolicy("sanitize-output");
    assert.throws(
      () =>
        registerFaultPolicy("sanitize-output", {
          ...complete,
          closed: undefined,
        }),
      /declares no `closed` arm/u,
    );
    // The refused registration left the real one in place.
    assert.equal(faultPolicy("sanitize-output"), complete);
  });
});

describe("PreToolUse emits exactly its table entry", () => {
  for (const [label, env] of POSTURES)
    it(`under ${label}`, () => {
      const expected = hookFaultOutcome("pretooluse-sanitize", FAULT, {
        parsedOk: true,
        env,
      }).fields;
      assert.deepEqual(
        preToolUse.hookFailureFields(true, FAULT, { env }),
        expected,
      );
    });
});

describe("PostToolUse emits exactly its table entry", () => {
  for (const [label, env] of POSTURES)
    it(`under ${label}`, () => {
      const input = { tool_response: "the raw output" };
      const emitted = [];
      sanitizeOutput.emitHookFailure(
        input,
        FAULT,
        (fields) => emitted.push(fields),
        undefined,
        env,
      );
      const expected = hookFaultOutcome("sanitize-output", FAULT, {
        input,
        env,
      }).fields;
      assert.deepEqual(emitted, [expected]);
    });
});

describe("UserPromptSubmit emits exactly its table entry", () => {
  for (const [label, env] of POSTURES)
    it(`under ${label}`, async () => {
      const written = [];
      await userPrompt.main(
        () => {
          throw FAULT;
        },
        (chunk) => written.push(chunk),
        { env },
      );
      const expected = hookFaultOutcome("sanitize-user-prompt", FAULT, {
        messages: userPrompt.USER_PROMPT_MESSAGES,
        env,
      }).envelope;
      assert.equal(written.length, 1);
      assert.deepEqual(JSON.parse(written[0]), expected);
    });
});

/**
 * Run the SessionStart scan with `env` pinned and stdout/stderr captured.
 * @param {Record<string, string>} env
 * @param {{ scan?: () => any }} [opts]
 */
async function runScanUnder(env, opts = {}) {
  rmSync(alertDir(), { recursive: true, force: true });
  const stderr = [];
  const realWrite = process.stderr.write;
  const realExitCode = process.exitCode;
  const previous = process.env[FAIL_OPEN_ENV];
  Object.assign(process.env, env);
  if (env[FAIL_OPEN_ENV] === undefined) delete process.env[FAIL_OPEN_ENV];
  process.stderr.write = (chunk) => {
    stderr.push(String(chunk));
    return true;
  };
  const announced = [];
  let stdout;
  let exitCode;
  try {
    // The hook's stdout envelope must not reach the real stream: under
    // `--test-reporter=tap` that stream carries this suite's own result.
    ({ stdout } = await withCapturedStdout(() =>
      scanInvisible.cliMain({
        trace: (event, fields) => announced.push({ event, ...fields }),
        ...opts,
      }),
    ));
    exitCode = process.exitCode;
  } finally {
    process.stderr.write = realWrite;
    process.exitCode = realExitCode;
    if (previous === undefined) delete process.env[FAIL_OPEN_ENV];
    else process.env[FAIL_OPEN_ENV] = previous;
  }
  return {
    stderr,
    stdout,
    exitCode,
    announced,
    alertArmed: invisibleCharAlert() !== null,
  };
}

describe("SessionStart emits exactly its table entry on a hook FAULT", () => {
  // The fault is a scanner that throws something that is NOT an errno — i.e. a
  // bug, the only condition left that reaches this hook's posture. An
  // unreadable FILE is deliberately not one (see the coverage describe below).
  const BUG = new TypeError("stripInvisible is not a function");

  for (const [label, env] of POSTURES)
    it(`under ${label}`, async () => {
      const { stderr, announced, alertArmed } = await runScanUnder(env, {
        scan: () => {
          throw BUG;
        },
      });
      const expected = hookFaultOutcome("scan-invisible-chars", BUG, { env });
      assert.deepEqual(stderr, [expected.stderr]);
      assert.deepEqual(
        announced.map((a) => a.outcome),
        ["skipped"],
      );
      // The alert is the only enforcement a SessionStart hook can reach: it
      // makes the PreToolUse gate ask once on the next tool call. Under the
      // open posture there must be none — an advisory that also armed the gate
      // would be the closed posture wearing an open label.
      assert.equal(
        alertArmed,
        expected.armAlert,
        `alert presence disagrees with the table under ${label}`,
      );
    });
});

describe("an unreadable instruction file is a COVERAGE GAP, not a hook fault", () => {
  // The hook worked and is reporting what it could not check, so it announces
  // `partial` rather than `skipped` and keeps scanning the rest of the project.
  // Whether the gap may stop the session is still the operator's posture: the
  // open default warns the user and the model at SessionStart and arms nothing,
  // and only the opt-out arms the tool-call gate.
  /** @param {Record<string, string>} env */
  async function gapUnder(env) {
    const run = await runScanUnder(env);
    assert.deepEqual(
      run.announced.map((a) => a.outcome),
      ["partial"],
    );
    assert.equal(run.announced[0].skipped, 1);
    // The errno text is scrubbed on its way to the operator's terminal and to
    // the alert: it embeds a path globbed out of a possibly-hostile repo.
    assert.match(run.stderr.join(""), /INSTRUCTION FILES NOT SCANNED/u);
    assert.match(run.stderr.join(""), /CLAUDE\.md: EISDIR/u);
    return run;
  }

  it("warns at SessionStart and arms no gate under the open default", async () => {
    const { alertArmed, exitCode, stdout } = await gapUnder({});
    assert.equal(
      alertArmed,
      false,
      "the open default armed the tool-call gate",
    );
    assert.ok(
      !exitCode,
      `exit ${exitCode}: the launcher would call it a crash`,
    );
    const envelope = JSON.parse(stdout);
    const context = envelope.hookSpecificOutput.additionalContext;
    assert.equal(envelope.hookSpecificOutput.hookEventName, "SessionStart");
    assert.match(context, /CLAUDE\.md: EISDIR/u);
    assert.match(context, /failing open/u);
    assert.equal(envelope.systemMessage, context);
  });

  it("arms the gate under the opt-out", async () => {
    const { alertArmed, stdout } = await gapUnder({ [FAIL_OPEN_ENV]: "0" });
    assert.ok(alertArmed, "the gate was not armed for an unscanned file");
    assert.equal(stdout, "");
    assert.match(invisibleCharAlert() ?? "", /CLAUDE\.md: EISDIR/u);
  });

  it("keeps scanning the rest of the project", () => {
    // The regression the old ENOENT-only catch caused: one unreadable target
    // discarded every other file's result.
    const { targets, scanned, skipped } = scanInvisible.scanProject(projectDir);
    assert.equal(skipped.length, 1);
    assert.equal(scanned, targets.length - 1);
    assert.ok(scanned > 0, "no other target was left to prove the point");
  });
});

describe("the plugin dispatcher's unknown-mode arm comes from the table", () => {
  // Broken hooks.json wiring is a FAULT like any other: exit 1 (non-blocking)
  // under the open default, exit 2 (blocking) only under the opt-out.
  for (const [label, env, blockingExit] of [
    [...POSTURES[0], 1],
    [...POSTURES[1], 2],
  ])
    it(`under ${label}`, () => {
      const res = spawnSync(
        process.execPath,
        [join(hooksDir, "plugin-hooks.mjs"), "--hook=no-such-hook"],
        { input: "{}", encoding: "utf8", env: { ...process.env, ...env } },
      );
      const expected = hookFaultOutcome(
        "plugin-hooks",
        new Error('unknown hook mode "no-such-hook"'),
        { env },
      );
      assert.equal(res.stderr, expected.stderr);
      assert.equal(res.status, expected.exitCode);
      assert.equal(res.status, blockingExit);
      assert.equal(res.stdout, "");
      assert.match(res.stderr, /no-such-hook.*reinstall or update the plugin/u);
    });
});
