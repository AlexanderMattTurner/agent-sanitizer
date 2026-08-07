#!/usr/bin/env node
// Render how a timed run's durations move over commits, as a Mermaid line
// chart per series, and append it to the step summary.
//
// The per-run waterfall answers "where did this run's time go"; only a series
// across commits answers "is setup getting slower", which is the question that
// actually decides whether anyone acts. History lives as one JSON object per
// line (see append-timing-history.sh), oldest first.
//
// Usage:
//   node render-timing-trend.mjs --history <file.jsonl> \
//     [--series total] [--series "session-setup (cold cache)"] \
//     [--limit 30] [--title "Session setup"]
//
// Mermaid's xychart has no legend, so each series gets its own titled chart
// rather than several unlabelled lines sharing one axis.

import { readFileSync, appendFileSync } from "node:fs";

const DEFAULT_LIMIT = 30;

// Same rule the shell-side formatter follows: show a quantity in the unit that
// makes it read naturally. Picked once per chart from the largest point, so
// every point on an axis shares one unit.
export function pickUnit(maxMs) {
  if (maxMs < 1000) return { label: "Milliseconds", perMs: 1 };
  if (maxMs < 60_000) return { label: "Seconds", perMs: 1000 };
  return { label: "Minutes", perMs: 60_000 };
}

// One decimal is the most precision a chart axis can honestly carry; an integer
// count of the next unit down would defeat the point of choosing a unit.
function scale(ms, unit) {
  return Number((ms / unit.perMs).toFixed(1));
}

export function parseHistory(text) {
  return text
    .split("\n")
    .filter((line) => line.trim() !== "")
    .map((line) => JSON.parse(line));
}

// A series is either the run total or one named phase. A run that predates the
// phase (renamed, added later) simply has no point — the caller reports the
// gap rather than plotting a zero, which would read as "it got fast".
function seriesValue(entry, series) {
  if (series === "total") return entry.total_ms;
  const phase = (entry.phases ?? []).find((p) => p.label === series);
  return phase?.ms;
}

// Mermaid strings are double-quoted with no escape syntax, so a quote in a
// title cannot be escaped — replace it rather than emit a broken diagram.
function mermaidString(text) {
  return `"${String(text).replace(/["\n]/g, "'")}"`;
}

export function renderChart(entries, series, title) {
  const points = entries
    .map((e) => ({ commit: e.commit, ms: seriesValue(e, series) }))
    .filter((p) => Number.isFinite(p.ms));
  const heading = `${title} — ${series === "total" ? "end-to-end" : series}`;
  if (points.length < 2) {
    return `_${heading}: ${points.length} recorded run${
      points.length === 1 ? "" : "s"
    } so far — a trend needs at least two._\n\n`;
  }
  const unit = pickUnit(Math.max(...points.map((p) => p.ms)));
  const values = points.map((p) => scale(p.ms, unit));
  // Anchor at zero: a chart auto-scaled to the spread turns runner noise into
  // a dramatic slope, which is how advisory numbers become alarms.
  const max = Math.max(...values);
  return [
    "```mermaid",
    "xychart-beta",
    `    title ${mermaidString(heading)}`,
    `    x-axis [${points
      .map((p) => mermaidString(String(p.commit ?? "").slice(0, 7)))
      .join(", ")}]`,
    `    y-axis ${mermaidString(unit.label)} 0 --> ${Math.ceil(max * 1.1)}`,
    `    line [${values.join(", ")}]`,
    "```",
    "",
    "",
  ].join("\n");
}

function parseArgs(argv) {
  const opts = { series: [], limit: DEFAULT_LIMIT, title: "Timing" };
  for (let i = 0; i < argv.length; i++) {
    const need = (flag) => {
      if (i + 1 >= argv.length) throw new Error(`${flag} needs a value`);
      return argv[++i];
    };
    if (argv[i] === "--history") opts.history = need("--history");
    else if (argv[i] === "--series") opts.series.push(need("--series"));
    else if (argv[i] === "--limit") opts.limit = Number(need("--limit"));
    else if (argv[i] === "--title") opts.title = need("--title");
    else throw new Error(`unknown argument: ${argv[i]}`);
  }
  if (!opts.history) throw new Error("--history is required");
  if (opts.series.length === 0) opts.series = ["total"];
  if (!Number.isInteger(opts.limit) || opts.limit < 2)
    throw new Error(`--limit must be an integer >= 2, got ${opts.limit}`);
  return opts;
}

export function render(opts) {
  const all = parseHistory(readFileSync(opts.history, "utf8"));
  const entries = all.slice(-opts.limit);
  const dropped = all.length - entries.length;
  const charts = opts.series
    .map((s) => renderChart(entries, s, opts.title))
    .join("");
  // Never let a window silently masquerade as the whole history.
  const note =
    dropped > 0
      ? `_Showing the most recent ${entries.length} of ${all.length} recorded runs._\n\n`
      : "";
  return `### ${opts.title} over time\n\n${charts}${note}`;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const markdown = render(parseArgs(process.argv.slice(2)));
  process.stdout.write(markdown);
  if (process.env.GITHUB_STEP_SUMMARY)
    appendFileSync(process.env.GITHUB_STEP_SUMMARY, markdown);
}
