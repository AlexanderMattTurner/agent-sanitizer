import { spawnSync } from "node:child_process";

/**
 * The `skip` option for a test that needs a toolchain a developer machine may
 * lack (python3, uv, a pinned Unicode runtime).
 *
 * PROBLEM CLASS — a skip that turns a broken cross-check green in CI. A test
 * that skips itself when its precondition is missing is right on a laptop and
 * wrong in CI, which is set up to satisfy every one: there a missing one means
 * the setup or the probe broke, and a skip reports that as a pass. So the skip
 * is honoured only outside CI, and CI throws with the reason instead.
 *
 * Use as `it(name, { skip: skipUnless(probe, reason) }, fn)`, with the probe
 * run OUTSIDE the test body, so a failure of the real work is never read as a
 * missing toolchain.
 * @param {boolean} available  what the probe found
 * @param {string} reason  why the test cannot run without it
 * @returns {false | string}  `false` to run, or the skip reason
 */
export function skipUnless(available, reason) {
  if (available) return false;
  if (process.env.CI)
    throw new Error(
      `${reason} — CI is expected to satisfy this, so a skip here would hide a broken cross-check`,
    );
  return reason;
}

/**
 * Whether `python3` runs at all. A probe only: it says nothing about the
 * module a test then loads, whose failure must stay a failure.
 * @returns {boolean}
 */
export function python3Available() {
  return spawnSync("python3", ["-c", "pass"], { stdio: "ignore" }).status === 0;
}
