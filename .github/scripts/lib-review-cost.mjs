<<<<<<< local
// Shared reader for a Claude run's execution log, plus the PR-review cost
// footnote built from it — used by the reviewer (post-pr-review.mjs, which posts
// the cost line). One source for parsing the log, reading a run's cost and its
// error flag, formatting dollars, and rendering the "how many PRs fit in a Max
// 20x weekly allowance" line, so the consumers can never drift.
||||||| base
// Shared cost accounting for the PR-review footnote — used by both the reviewer
// (post-pr-review.mjs, which posts the original cost line) and the Haiku
// thread-resolver (compute-haiku-cost-footer.mjs, which tallies each follow-up
// run onto that same footnote). One source for reading a Claude run's cost,
// formatting dollars, and rendering the "how many PRs fit in a Max 20x weekly
// allowance" line, so the two producers can never drift.
=======
// Shared cost accounting for the PR-review footnote — used by post-pr-review.mjs,
// which posts the cost line. One source for reading a Claude run's cost,
// formatting dollars, and rendering the "how many PRs fit in a Max 20x weekly
// allowance" line.
>>>>>>> template
import { readFileSync } from "node:fs";

// The Claude action's execution log as a flat event list — an array of streamed
// events, or a single object. `[]` when the log is missing/unparsable.
function readRunEvents(executionFile) {
  const file =
    executionFile ||
    process.env.EXECUTION_FILE ||
    (process.env.RUNNER_TEMP
      ? `${process.env.RUNNER_TEMP}/claude-execution-output.json`
      : "");
  if (!file) return [];
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(file, "utf8"));
  } catch {
    return [];
  }
  return Array.isArray(parsed) ? parsed : [parsed];
}

// True when the run reported `is_error` — the session failed (a dead credential,
// an unavailable model, a hard API error) rather than completing with nothing to
// say. The action EXITS 0 either way and its own `result` event still reads
// `subtype: "success"`, so this flag is the only signal separating "reviewed and
// found nothing" from "never reviewed at all"; a caller that does not check it
// reports green for a review that never happened.
export function runErrored(executionFile) {
  return readRunEvents(executionFile).some(
    (ev) => ev && typeof ev === "object" && ev.is_error === true,
  );
}

// Pull `total_cost_usd` (and the model that ran) out of the execution log — its
// terminal `type: "result"` event carries the API-equivalent cost. Returns {}
// when the log is missing/unparsable so callers simply omit the cost; a missing
// cost must never break posting.
export function readRunCost(executionFile) {
  const events = readRunEvents(executionFile);
  let cost;
  let model;
  for (const ev of events) {
    if (ev && typeof ev === "object") {
      if (typeof ev.total_cost_usd === "number") cost = ev.total_cost_usd;
      if (model === undefined && typeof ev.model === "string") model = ev.model;
    }
  }
  return { cost, model };
}

<<<<<<< local
// Sub-cent costs keep four decimals; everything else two.
||||||| base
// Sub-cent costs keep four decimals (a Haiku run is a fraction of a cent);
// everything else two.
=======
// Sub-cent costs keep four decimals;
// everything else two.
>>>>>>> template
export function formatDollars(cost) {
  return cost < 0.01 ? cost.toFixed(4) : cost.toFixed(2);
}

// The assumed Max 20x weekly API-equivalent budget (override with
// MAX20X_WEEKLY_USD); 0 when unset/invalid so callers can drop budget-relative text.
export function weeklyBudget() {
  const w = Number.parseFloat(process.env.MAX20X_WEEKLY_USD || "2000");
  return Number.isFinite(w) && w > 0 ? w : 0;
}

// The final footnote line: at this per-PR cost, roughly how many PRs fit in a
// Max 20x weekly allowance. Returns "" when it can't be estimated (no cost, no
// budget) so the caller omits the line rather than printing a bogus number.
export function plansLine(totalCost, weekly = weeklyBudget()) {
  if (!Number.isFinite(totalCost) || totalCost <= 0 || !weekly) return "";
  const prs = Math.floor(weekly / totalCost);
  return `<sub>📉 ~${prs.toLocaleString("en-US")} PRs/week at this rate on a Max 20× plan.</sub>`;
}
