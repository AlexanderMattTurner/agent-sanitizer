// Behavioral tests for the over-time trend chart: the renderer is driven with
// real history files and every assertion reads the markdown a reviewer sees.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { pickUnit, renderChart, render } from "./render-timing-trend.mjs";

const SCRIPT = join(
  dirname(fileURLToPath(import.meta.url)),
  "render-timing-trend.mjs",
);

const entry = (commit, totalMs, phases = {}) => ({
  commit,
  total_ms: totalMs,
  phases: Object.entries(phases).map(([label, ms]) => ({ label, ms })),
});

function historyFile(entries) {
  const root = mkdtempSync(join(tmpdir(), "timing-trend-"));
  const file = join(root, "history.jsonl");
  writeFileSync(file, entries.map((e) => JSON.stringify(e)).join("\n") + "\n");
  return { file, root };
}

test("the chart plots one point per commit, labelled by short sha", () => {
  const md = renderChart(
    [entry("aaaaaaaaaaaa", 90_000), entry("bbbbbbbbbbbb", 100_000)],
    "total",
    "Session setup",
  );
  assert.match(md, /xychart-beta/);
  assert.match(md, /x-axis \["aaaaaaa", "bbbbbbb"\]/);
  assert.match(md, /line \[1\.5, 1\.7\]/);
});

test("the axis unit follows the magnitude of the data", () => {
  assert.equal(pickUnit(999).label, "Milliseconds");
  assert.equal(pickUnit(1000).label, "Seconds");
  assert.equal(pickUnit(59_999).label, "Seconds");
  assert.equal(pickUnit(60_000).label, "Minutes");
  // Sub-second history reads in ms, not as a row of 0.0s.
  const md = renderChart([entry("a1", 120), entry("b2", 340)], "total", "T");
  assert.match(md, /y-axis "Milliseconds"/);
  assert.match(md, /line \[120, 340\]/);
});

test("the y-axis starts at zero so runner noise is not a cliff", () => {
  const md = renderChart(
    [entry("a1", 90_000), entry("b2", 92_000)],
    "total",
    "T",
  );
  assert.match(md, /y-axis "Minutes" 0 --> 2/);
});

test("a named phase is charted from its own series", () => {
  const history = [
    entry("a1", 30_000, { cold: 20_000, warm: 9_000 }),
    entry("b2", 33_000, { cold: 24_000, warm: 8_000 }),
  ];
  const md = renderChart(history, "cold", "Session setup");
  assert.match(md, /title "Session setup — cold"/);
  assert.match(md, /line \[20, 24\]/);
});

test("a run predating the phase is dropped, never plotted as zero", () => {
  const history = [
    entry("a1", 30_000),
    entry("b2", 33_000, { cold: 24_000 }),
    entry("c3", 31_000, { cold: 22_000 }),
  ];
  const md = renderChart(history, "cold", "T");
  assert.match(md, /x-axis \["b2", "c3"\]/);
  assert.doesNotMatch(md, /\ba1\b/);
  assert.match(md, /line \[24, 22\]/);
});

test("a single recorded run says so instead of drawing a one-point line", () => {
  const md = renderChart([entry("a1", 30_000)], "total", "Session setup");
  assert.doesNotMatch(md, /xychart/);
  assert.match(md, /1 recorded run so far — a trend needs at least two\./);
});

test("a quote in a series name cannot break the diagram", () => {
  const md = renderChart(
    [
      entry("a1", 2000, { 'we"ird': 1000 }),
      entry("b2", 2000, { 'we"ird': 1000 }),
    ],
    'we"ird',
    "T",
  );
  const title = /^ {4}title (.*)$/m.exec(md)[1];
  assert.equal(title.split('"').length - 1, 2, title);
});

test("a windowed history says how much it is not showing", () => {
  const entries = Array.from({ length: 5 }, (_, i) =>
    entry(`sha${i}`, 30_000 + i),
  );
  const { file } = historyFile(entries);
  const md = render({ history: file, series: ["total"], limit: 3, title: "T" });
  assert.match(md, /Showing the most recent 3 of 5 recorded runs/);
  assert.match(md, /x-axis \["sha2", "sha3", "sha4"\]/);
});

test("a full history carries no truncation note", () => {
  const { file } = historyFile([entry("a1", 1000), entry("b2", 1000)]);
  const md = render({
    history: file,
    series: ["total"],
    limit: 30,
    title: "T",
  });
  assert.doesNotMatch(md, /Showing the most recent/);
});

test("each series gets its own chart, since xychart has no legend", () => {
  const { file } = historyFile([
    entry("a1", 30_000, { cold: 20_000 }),
    entry("b2", 31_000, { cold: 21_000 }),
  ]);
  const md = render({
    history: file,
    series: ["total", "cold"],
    limit: 30,
    title: "Session setup",
  });
  assert.equal(md.match(/xychart-beta/g).length, 2);
  assert.match(md, /title "Session setup — end-to-end"/);
  assert.match(md, /title "Session setup — cold"/);
});

test("as a CLI it appends the markdown to the step summary", () => {
  const { file, root } = historyFile([
    entry("a1", 30_000),
    entry("b2", 31_000),
  ]);
  const summary = join(root, "summary.md");
  writeFileSync(summary, "");
  const res = spawnSync(
    process.execPath,
    [SCRIPT, "--history", file, "--title", "Session setup"],
    { encoding: "utf8", env: { ...process.env, GITHUB_STEP_SUMMARY: summary } },
  );
  assert.equal(res.status, 0, res.stderr);
  assert.match(readFileSync(summary, "utf8"), /xychart-beta/);
  assert.match(res.stdout, /### Session setup over time/);
});

test("a bad --limit is a loud failure, not a silent default", () => {
  const { file } = historyFile([entry("a1", 1000)]);
  const res = spawnSync(
    process.execPath,
    [SCRIPT, "--history", file, "--limit", "1"],
    { encoding: "utf8" },
  );
  assert.notEqual(res.status, 0);
  assert.match(res.stderr, /--limit must be an integer >= 2/);
});

test("a missing --series value is rejected rather than swallowing the next flag", () => {
  const { file } = historyFile([entry("a1", 1000)]);
  const res = spawnSync(
    process.execPath,
    [SCRIPT, "--history", file, "--series"],
    {
      encoding: "utf8",
    },
  );
  assert.notEqual(res.status, 0);
  assert.match(res.stderr, /--series needs a value/);
});
