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

// Every duration the timer prints, in the natural unit for its magnitude.
const DURATION = String.raw`\d+ms|\d+\.\d+s|\d+m\d{2}s|\d+h\d{2}m\d{2}s`;

// Parse one of those back to milliseconds, so a test can assert on the real
// elapsed time without hard-coding which unit the timer picked.
function toMs(text) {
  const sub = /^(\d+)ms$/.exec(text);
  if (sub) return Number(sub[1]);
  const sec = /^(\d+)\.(\d)s$/.exec(text);
  if (sec) return Number(sec[1]) * 1000 + Number(sec[2]) * 100;
  const min = /^(\d+)m(\d{2})s$/.exec(text);
  if (min) return (Number(min[1]) * 60 + Number(min[2])) * 1000;
  const hour = /^(\d+)h(\d{2})m(\d{2})s$/.exec(text);
  if (hour)
    return (
      (Number(hour[1]) * 3600 + Number(hour[2]) * 60 + Number(hour[3])) * 1000
    );
  throw new Error(`unrecognized duration: ${text}`);
}

// The rendered duration for one table row, e.g. row(summary, "alpha").
function row(summary, label) {
  const match = new RegExp(`\\| ${label} \\| (${DURATION}) \\|`).exec(summary);
  assert.ok(match, `no table row for ${label} in:\n${summary}`);
  return match[1];
}

function endToEnd(summary) {
  const match = new RegExp(
    `\\| \\*\\*End-to-end\\*\\* \\| \\*\\*(${DURATION})\\*\\* \\|`,
  ).exec(summary);
  assert.ok(match, `no end-to-end row in:\n${summary}`);
  return match[1];
}

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
  row(res.summary, "alpha");
  row(res.summary, "beta");
  // The whole point of the job: a single end-to-end number, not just pieces.
  endToEnd(res.summary);
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
  const total = toMs(endToEnd(res.summary));
  assert.ok(
    total >= 2000,
    `untimed gaps must count toward the total, got ${total}ms`,
  );
});

test("a phase's measured duration is its real wall clock", () => {
  const res = runTimer(`
    timer_start
    timed_phase "slow" sleep 2
    timer_report "Setup"
  `);
  assert.equal(res.status, 0, res.stderr);
  const elapsed = toMs(row(res.summary, "slow"));
  assert.ok(
    elapsed >= 2000,
    `expected >= 2000ms for a 2s phase, got ${elapsed}`,
  );
});

test("a sub-second phase reads in milliseconds, not a rounded-off zero", () => {
  const res = runTimer(`
    timer_start
    timed_phase "quick" sleep 0.25
    timer_report "Setup"
  `);
  assert.equal(res.status, 0, res.stderr);
  const rendered = row(res.summary, "quick");
  assert.match(rendered, /^\d+ms$/, `expected milliseconds, got ${rendered}`);
  assert.ok(toMs(rendered) >= 250, `expected >= 250ms, got ${rendered}`);
});

test("a multi-minute phase reads as minutes and seconds", () => {
  // Drive the formatter directly: the alternative is a test that sleeps for two
  // minutes. The phase is real; only its recorded elapsed value is overwritten.
  const res = runTimer(`
    timer_start
    timed_phase "long" true
    _TIMER_ELAPSED_MS[0]=125400
    timer_report "Setup"
  `);
  assert.equal(res.status, 0, res.stderr);
  assert.equal(row(res.summary, "long"), "2m05s");
});

test("the waterfall places each phase at its real offset from the start", () => {
  const res = runTimer(`
    timer_start
    sleep 1
    timed_phase "delayed" sleep 1
    timer_report "Setup"
  `);
  assert.equal(res.status, 0, res.stderr);
  assert.match(res.summary, /```mermaid\ngantt/);
  assert.match(res.summary, /dateFormat x/);
  const bar = /delayed \([^)]+\) :(\d+), (\d+)$/m.exec(res.summary);
  assert.ok(bar, `no gantt bar for the phase in:\n${res.summary}`);
  const [start, end] = [Number(bar[1]), Number(bar[2])];
  // The bar starts after the untimed second, not at zero — that gap is the
  // whole reason for a waterfall rather than a stack of bars from the origin.
  assert.ok(start >= 1000, `expected a >= 1000ms offset, got ${start}`);
  assert.ok(
    end - start >= 1000,
    `expected a >= 1000ms bar, got ${end - start}`,
  );
});

test("the waterfall carries the total as its own bar spanning the run", () => {
  const res = runTimer(`
    timer_start
    timed_phase "alpha" sleep 1
    timer_report "Setup"
  `);
  assert.equal(res.status, 0, res.stderr);
  const bar = /end-to-end \([^)]+\) :crit, 0, (\d+)$/m.exec(res.summary);
  assert.ok(bar, `no total bar in:\n${res.summary}`);
  assert.ok(Number(bar[1]) >= 1000, `total bar too short: ${bar[1]}ms`);
});

test("a colon in a phase label cannot break the gantt syntax", () => {
  const res = runTimer(`
    timer_start
    timed_phase "pnpm: install" true
    timer_report "Setup"
  `);
  assert.equal(res.status, 0, res.stderr);
  const line = /^ {4}pnpm.*:\d+, \d+$/m.exec(res.summary);
  assert.ok(line, `no gantt bar for the colon label in:\n${res.summary}`);
  // Exactly one colon survives: the one separating the title from the metadata.
  assert.equal(line[0].split(":").length - 1, 1, line[0]);
  // The table is not gantt, so it keeps the label verbatim.
  assert.match(res.summary, /\| pnpm: install \|/);
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
  row(res.summary, "boom");
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

test("a zero-phase report publishes the total and no empty diagram", () => {
  const res = runTimer(`
    timer_start
    timer_report "Setup"
  `);
  assert.equal(res.status, 0, res.stderr);
  endToEnd(res.summary);
  assert.doesNotMatch(res.summary, /mermaid/);
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
  assert.match(
    res.stderr,
    new RegExp(`Setup timing \\(end-to-end (${DURATION})\\)`),
  );
  assert.match(res.stderr, new RegExp(`alpha\\s+(${DURATION})`));
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

// The JSON record is what the over-time trend is built from: durations stay in
// integer milliseconds, and formatting is left to whoever displays them.
function runTimerJson(body) {
  const root = mkdtempSync(join(tmpdir(), "phase-timer-json-"));
  const out = join(root, "timing.json");
  const script = join(root, "run.sh");
  writeFileSync(script, `set -euo pipefail\nsource ${LIB}\n${body}\n`);
  const res = spawnSync("bash", [script], {
    encoding: "utf8",
    env: { ...process.env, TIMER_JSON_OUT: out },
  });
  assert.equal(res.status, 0, res.stderr);
  return JSON.parse(readFileSync(out, "utf8"));
}

test("TIMER_JSON_OUT records raw milliseconds for every phase and the total", () => {
  const record = runTimerJson(`
    timer_start
    timed_phase "alpha" sleep 0.3
    timed_phase "beta" true
    timer_report "Session setup"
  `);
  assert.equal(record.title, "Session setup");
  assert.deepEqual(
    record.phases.map((p) => p.label),
    ["alpha", "beta"],
  );
  assert.ok(
    record.phases[0].ms >= 300,
    `alpha too short: ${record.phases[0].ms}`,
  );
  assert.ok(record.phases[1].offset_ms >= 300, "beta must start after alpha");
  assert.ok(record.total_ms >= 300, `total too short: ${record.total_ms}`);
});

test("a label with quotes or backslashes still yields parseable JSON", () => {
  const record = runTimerJson(`
    timer_start
    timed_phase 'say "hi" C:\\path' true
    timer_report "Setup"
  `);
  assert.equal(record.phases[0].label, 'say "hi" C:\\path');
});
