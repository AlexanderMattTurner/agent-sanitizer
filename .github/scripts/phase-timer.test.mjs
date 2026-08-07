// Behavioral tests for the phase timer: the real library is sourced by a real
// bash script and every assertion reads an observable — the script's exit
// status, its stderr, and the markdown it appended to $GITHUB_STEP_SUMMARY.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const LIB = join(
  dirname(fileURLToPath(import.meta.url)),
  "lib/phase-timer.bash",
);

// Run BODY with the timer sourced, under the same strict mode the real callers
// use. Returns the exit status, stderr, and the step summary it wrote.
function runTimer(body, { withSummary = true } = {}) {
  const root = mkdtempSync(join(tmpdir(), "phase-timer-"));
  const summary = join(root, "summary.md");
  writeFileSync(summary, "");
  const script = join(root, "run.sh");
  writeFileSync(script, `set -euo pipefail\nsource ${LIB}\n${body}\n`);
  const env = { ...process.env };
  if (withSummary) env.GITHUB_STEP_SUMMARY = summary;
  else delete env.GITHUB_STEP_SUMMARY;
  const res = spawnSync("bash", [script], { encoding: "utf8", env });
  return {
    status: res.status,
    stdout: res.stdout,
    stderr: res.stderr,
    summary: readFileSync(summary, "utf8"),
  };
}

test("every phase and the end-to-end total reach the step summary", () => {
  const res = runTimer(`
    timer_start
    timed_phase "alpha" true
    timed_phase "beta" true
    timer_report "Setup"
  `);
  assert.equal(res.status, 0, res.stderr);
  assert.match(res.summary, /### Setup timing/);
  assert.match(res.summary, /\| alpha \| \d+ \|/);
  assert.match(res.summary, /\| beta \| \d+ \|/);
  // The whole point of the job: a single end-to-end number, not just pieces.
  assert.match(res.summary, /\| \*\*End-to-end\*\* \| \*\*\d+\*\* \|/);
});

test("the total spans the whole run, not just the sum of the phases", () => {
  const res = runTimer(`
    timer_start
    sleep 1
    timed_phase "instant" true
    sleep 1
    timer_report "Setup"
  `);
  assert.equal(res.status, 0, res.stderr);
  const total = Number(
    /\*\*End-to-end\*\* \| \*\*(\d+)\*\*/.exec(res.summary)[1],
  );
  assert.ok(
    total >= 2,
    `untimed gaps must count toward the total, got ${total}`,
  );
});

test("a phase's measured duration is its real wall clock", () => {
  const res = runTimer(`
    timer_start
    timed_phase "slow" sleep 2
    timer_report "Setup"
  `);
  assert.equal(res.status, 0, res.stderr);
  const seconds = Number(/\| slow \| (\d+) \|/.exec(res.summary)[1]);
  assert.ok(seconds >= 2, `expected >= 2s for a 2s phase, got ${seconds}`);
});

test("a failing phase propagates its status and is still reported", () => {
  const res = runTimer(`
    timer_start
    trap 'timer_report "Setup"' EXIT
    timed_phase "boom" bash -c 'exit 3'
    echo "must not reach here"
  `);
  assert.equal(res.status, 3);
  assert.doesNotMatch(res.stdout, /must not reach here/);
  // The partial report is the diagnostic for a setup that died mid-run.
  assert.match(res.summary, /\| boom \| \d+ \|/);
});

test("timed_phase wraps its command in a collapsible log group", () => {
  const res = runTimer(`
    timer_start
    timed_phase "grouped" true
    timer_report "Setup"
  `);
  assert.match(res.stdout, /::group::grouped/);
  assert.match(res.stdout, /::endgroup::/);
});

test("timing is advisory: a slow phase never fails the run", () => {
  const res = runTimer(`
    timer_start
    timed_phase "slow" sleep 2
    timer_report "Setup"
  `);
  assert.equal(res.status, 0, res.stderr);
});

test("timed_phase before timer_start is a loud error, not a bogus duration", () => {
  const res = runTimer(`timed_phase "orphan" true`);
  assert.equal(res.status, 2);
  assert.match(res.stderr, /call timer_start first/);
  assert.equal(res.summary, "");
});

test("a zero-phase report still publishes the total", () => {
  const res = runTimer(`
    timer_start
    timer_report "Setup"
  `);
  assert.equal(res.status, 0, res.stderr);
  assert.match(res.summary, /\| \*\*End-to-end\*\* \| \*\*\d+\*\* \|/);
});

test("outside Actions the report goes to stderr and writes no summary", () => {
  const res = runTimer(
    `
    timer_start
    timed_phase "alpha" true
    timer_report "Setup"
  `,
    { withSummary: false },
  );
  assert.equal(res.status, 0, res.stderr);
  assert.match(res.stderr, /Setup timing \(total \d+s\)/);
  assert.match(res.stderr, /alpha\s+\d+s/);
  assert.equal(res.summary, "");
});

test("an EXIT-trap report before timer_start stays silent instead of faking 0s", () => {
  const res = runTimer(`
    trap 'timer_report "Setup"' EXIT
    exit 4
  `);
  assert.equal(res.status, 4);
  assert.equal(res.summary, "");
  assert.doesNotMatch(res.stderr, /Setup timing/);
});
