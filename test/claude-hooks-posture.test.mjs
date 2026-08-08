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
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const hooksDir = fileURLToPath(new URL("../claude-hooks", import.meta.url));

// Set before the hooks import: scan-invisible-chars walks CLAUDE_PROJECT_DIR
// and rewrites the instruction files it finds, so pointing it at this repo
// would let the test edit the tree. invisible-alert.mjs resolves both the
// project dir and the alert path at module load.
const projectDir = mkdtempSync(join(tmpdir(), "sanitizer-posture-proj-"));
process.env.CLAUDE_PROJECT_DIR = projectDir;
// The SessionStart hook's forced fault: a DIRECTORY where an instruction file is
// expected. The finder lists it, the read fails EISDIR — not the ENOENT glob
// race — so it is a genuine fault of the hook rather than a benign skip.
mkdirSync(join(projectDir, "CLAUDE.md"));

const { FAIL_OPEN_ENV, missingPackageError } =
  await import("../claude-hooks/lib/hook-io.mjs");
const { FAULT_POLICY_HOOKS, faultPolicy, hookFaultOutcome } =
  await import("../claude-hooks/lib/hook-fault.mjs");
// Imported for their REGISTRATIONS: a policy is reachable only once its hook
// module has loaded, which is what makes "declared where the hook lives" true.
const preToolUse = await import("../claude-hooks/pretooluse-sanitize.mjs");
const sanitizeOutput = await import("../claude-hooks/sanitize-output.mjs");
const userPrompt = await import("../claude-hooks/sanitize-user-prompt.mjs");
const scanInvisible = await import("../claude-hooks/scan-invisible-chars.mjs");
await import("../claude-hooks/plugin-hooks.mjs");
const { ALERT_FILE } = scanInvisible;

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

describe("SessionStart emits exactly its table entry", () => {
  for (const [label, env] of POSTURES)
    it(`under ${label}`, async () => {
      // Same read the hook performs, so the expected message is the real
      // errno text rather than this test's guess at it.
      let fault;
      try {
        readFileSync(join(projectDir, "CLAUDE.md"), "utf-8");
      } catch (err) {
        fault = err;
      }
      assert.ok(fault, "the forced fault did not fire");

      rmSync(ALERT_FILE, { force: true });
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
      try {
        await scanInvisible.cliMain({ trace: () => {} });
      } finally {
        process.stderr.write = realWrite;
        process.exitCode = realExitCode;
        if (previous === undefined) delete process.env[FAIL_OPEN_ENV];
        else process.env[FAIL_OPEN_ENV] = previous;
      }

      const expected = hookFaultOutcome("scan-invisible-chars", fault, { env });
      assert.deepEqual(stderr, [expected.stderr]);
      // The alert is the only enforcement a SessionStart hook can reach: it
      // makes the PreToolUse gate ask once on the next tool call. Under the
      // open posture there must be none — an advisory that also armed the gate
      // would be the closed posture wearing an open label.
      assert.equal(
        existsSync(ALERT_FILE),
        expected.armAlert,
        `alert presence disagrees with the table under ${label}`,
      );
    });

  it("faults on an unreadable target rather than reporting it clean", () => {
    // Independent of the posture: an EISDIR target is not the ENOENT glob race,
    // so it must reach the fault path at all.
    assert.throws(() => scanInvisible.scanProject(projectDir), {
      code: "EISDIR",
    });
  });
});

describe("the plugin dispatcher's unknown-mode arm comes from the table", () => {
  for (const [label, env] of POSTURES)
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
      // Declared, not incidental: static wiring corruption means no hook runs
      // at all for the life of the install, so this arm blocks in BOTH
      // postures — on the record, next to the four that degrade.
      assert.equal(res.status, 2);
    });
});
