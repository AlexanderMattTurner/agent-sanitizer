/**
 * The shell port of the hook timer says EXACTLY what the node one says.
 *
 * Two SessionStart entry points never reach node — the launcher's preflight
 * (which runs before the hook it launches and is gone the moment it `exec`s)
 * and the python provisioner — so `plugin/scripts/lib/hook-timing.sh` reports
 * their overruns. A second implementation of a message is a second thing to
 * reword, and a reader who saw two different sentences for the same condition
 * would reasonably conclude one of them came from somewhere else.
 *
 * So these cases RUN both implementations over the same inputs and compare the
 * bytes. They are not a grep for a shared string: the shell builds its seconds
 * with integer arithmetic and its own printf, and the rounding sweep below is
 * precisely where a "close enough" port would diverge (`toFixed` rounds the
 * double, so 1150 prints 1.1 while a naive half-up integer rule prints 1.2).
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import path from "node:path";

import {
  formatSeconds,
  slowHookNotice,
  slowProvisionNotice,
  SLOW_HOOK_THRESHOLD_MS,
  SLOW_PROVISION_THRESHOLD_MS,
} from "../claude-hooks/lib/hook-timing.mjs";

const repoRoot = execFileSync("git", ["rev-parse", "--show-toplevel"], {
  encoding: "utf8",
}).trim();
const LIB = path.join(repoRoot, "plugin", "scripts", "lib", "hook-timing.sh");

/**
 * Run one shell function from the lib and return its stdout verbatim. The
 * environment is scrubbed of the test-only threshold overrides, so what is
 * compared is the shipped DEFAULT.
 * @param {string[]} argv  function name followed by its arguments
 * @returns {string}
 */
function sh(argv) {
  const quoted = argv.map((arg) => `'${arg.replaceAll("'", "'\\''")}'`);
  return execFileSync(
    "bash",
    ["-c", `set -uo pipefail; . "$0"; ${quoted.join(" ")}`, LIB],
    {
      encoding: "utf8",
      env: {
        ...process.env,
        _AGENT_SANITIZER_SLOW_HOOK_MS: "",
        _AGENT_SANITIZER_SLOW_PROVISION_MS: "",
      },
    },
  );
}

describe("hook timing: the shell port matches the node module", () => {
  // Every hundredths residue, both sides of each tenth, plus the exact halves
  // where a double and an integer rule are most likely to disagree.
  const MS = [
    0, 1, 49, 50, 51, 99, 100, 949, 950, 999, 1000, 1001, 1049, 1050, 1051,
    1149, 1150, 1151, 1249, 1250, 1251, 1749, 1750, 1949, 1950, 2500, 30000,
    59999, 60000, 60001, 90000, 123456,
  ];

  for (const ms of MS)
    it(`formats ${ms}ms identically`, () =>
      assert.equal(
        sh(["hook_timing_format_seconds", String(ms)]),
        formatSeconds(ms),
      ));

  for (const ms of MS)
    it(`emits the same hook notice for ${ms}ms`, () =>
      assert.equal(
        sh(["slow_hook_notice", "sanitize-output", String(ms)]),
        slowHookNotice("sanitize-output", ms) ?? "",
      ));

  for (const ms of MS)
    it(`emits the same provisioning notice for ${ms}ms`, () =>
      assert.equal(
        sh(["slow_provision_notice", "engine install", String(ms)]),
        slowProvisionNotice("engine install", ms) ?? "",
      ));

  it("agrees on both thresholds, and on which side of them is quiet", () => {
    // Non-vacuity: the sweeps above would all pass if BOTH sides printed
    // nothing forever. Pin that the over-budget cases actually say something,
    // and that the boundary itself is silent (a run exactly at budget is not
    // over it).
    assert.notEqual(sh(["slow_hook_notice", "h", "1001"]), "");
    assert.equal(sh(["slow_hook_notice", "h", "1000"]), "");
    assert.equal(
      sh(["slow_hook_notice", "h", String(SLOW_HOOK_THRESHOLD_MS)]),
      "",
    );
    assert.notEqual(
      sh(["slow_hook_notice", "h", String(SLOW_HOOK_THRESHOLD_MS + 1)]),
      "",
    );
    assert.equal(
      sh(["slow_provision_notice", "p", String(SLOW_PROVISION_THRESHOLD_MS)]),
      "",
    );
    assert.notEqual(
      sh([
        "slow_provision_notice",
        "p",
        String(SLOW_PROVISION_THRESHOLD_MS + 1),
      ]),
      "",
    );
  });

  it("ports the no-CPU wording, which is the only one it can measure", () => {
    // The shell has no per-process CPU reading to give, so what it must match
    // is the node line for a caller that knows none. Pinning the CPU form as
    // DIFFERENT is what fails here if the node default ever starts carrying a
    // number the shell cannot produce.
    const shell = sh(["slow_hook_notice", "safe-launch PreToolUse", "7200"]);
    assert.equal(shell, slowHookNotice("safe-launch PreToolUse", 7200));
    assert.notEqual(
      shell,
      slowHookNotice("safe-launch PreToolUse", 7200, undefined, {
        cpuMs: 300,
      }),
    );
  });

  it("honors an explicit threshold argument, as the node signature does", () => {
    assert.equal(
      sh(["slow_hook_notice", "h", "500", "100"]),
      slowHookNotice("h", 500, 100),
    );
  });

  it("carries a caller's step-specific advice through both ports", () => {
    // The hook-binary provisioner passes download advice where the engine
    // install's "Installing uv makes it faster" would be advice about the wrong
    // step. An empty threshold argument selects the default on both sides.
    const advice = "The binary is ~100 MB, so this mostly measures the network";
    const shell = sh([
      "slow_provision_notice",
      "hook binary download",
      "90000",
      "",
      advice,
    ]);
    assert.equal(
      shell,
      slowProvisionNotice("hook binary download", 90000, undefined, advice),
    );
    assert.match(shell, new RegExp(advice.replaceAll(".", "\\.")));
    assert.doesNotMatch(shell, /Installing uv/);
    // ...and omitting it still yields the engine-install default on both sides.
    assert.equal(
      sh(["slow_provision_notice", "engine install", "90000"]),
      slowProvisionNotice("engine install", 90000),
    );
    assert.match(
      sh(["slow_provision_notice", "engine install", "90000"]),
      /Installing uv makes it faster/,
    );
  });

  it("keeps the provisioning message DIFFERENT from the hook one", () => {
    // They are two ports of two messages, not one message twice: a provisioning
    // wait is not paid per call, and saying it is would send the reader looking
    // for a per-call cost that does not exist.
    const hook = sh(["slow_hook_notice", "x", "90000"]);
    const provision = sh(["slow_provision_notice", "x", "90000"]);
    assert.notEqual(hook, provision);
    assert.match(hook, /Wall-clock alone cannot separate/);
    assert.match(provision, /paid once per install/);
  });

  it("measures elapsed time forward, and never negative", () => {
    const now = Number(sh(["hook_timing_now_ms"]));
    assert.ok(Number.isInteger(now) && now > 1_600_000_000_000, String(now));
    // A start in the future (a clock that stepped backwards mid-hook) floors at
    // zero rather than reporting a negative duration.
    assert.equal(sh(["hook_timing_elapsed_ms", String(now + 5_000)]), "0");
    assert.ok(
      Number(sh(["hook_timing_elapsed_ms", String(now - 5_000)])) >= 5_000,
    );
  });
});
