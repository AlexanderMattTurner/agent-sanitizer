// Answer one question on a schedule: is the default branch red RIGHT NOW?
//
// `ci-failure-notify` is edge-triggered — it fires once, on the `workflow_run`
// completion event that flipped a workflow to `failure`. One missed edge (the
// ntfy topic unset, a dropped delivery, a maintainer who saw the push at 2am and
// went back to sleep) and `main` stays red with no further signal until the next
// push happens to re-run that workflow. That is not hypothetical: #169 landed on
// `main` with nine red tests and sat there for ~30 hours.
//
// This turns that edge into a LEVEL. It asks the Actions API for the newest
// completed push/schedule run of every workflow on the default branch and exits
// non-zero if any of them concluded `failure`. Run on a schedule, it re-reports
// for as long as the branch is red, so the alert cannot be slept through — and
// it goes quiet by itself the moment the branch recovers.
//
// It is deliberately NOT a required check and takes no fixing action: its whole
// output is "these workflows are red on this branch, go look".
import { fileURLToPath } from "node:url";

// This workflow's own path. Excluded from the sweep because including it would
// latch: the first red run becomes the newest run, which the next run reads as
// evidence that the branch is red, forever — long after the real failure was
// fixed. `main-health.test.mjs` asserts this file exists, so a rename that
// misses this constant fails the guard instead of silently disabling it.
export const SELF_WORKFLOW_PATH = ".github/workflows/main-health.yaml";

// Only these two event types say anything about the branch's own health. A
// `pull_request` run tests a merge commit that does not exist on the branch, and
// a `workflow_run` listener's conclusion describes the listener, not the code.
const BRANCH_EVENTS = new Set(["push", "schedule"]);

// `failure` only — matching ci-failure-notify's predicate exactly, so the two
// signals can never disagree about what counts as red. `cancelled` is excluded
// on purpose: a run superseded by a newer push is cancelled routinely here, and
// treating that as a failure would make this alert fire on ordinary activity.
// The precision matters more than the recall — an alert that cries wolf on every
// force-push is an alert nobody reads.
const RED = "failure";

/**
 * Every active workflow defined in `.github/workflows/`, paged to completion.
 *
 * Workflows GitHub synthesizes (`dynamic/dependabot/...`, CodeQL's default
 * setup) are dropped: they carry no file in the tree, so nothing in this repo
 * can fix or silence them, and a red one would pin this check on forever.
 */
async function activeWorkflows(request) {
  const collected = [];
  for (let page = 1; ; page += 1) {
    const body = await request(`/actions/workflows?per_page=100&page=${page}`);
    const batch = body.workflows ?? [];
    collected.push(...batch);
    if (batch.length === 0 || collected.length >= body.total_count) {
      if (collected.length < body.total_count)
        throw new Error(
          `workflow listing stopped at ${collected.length} of ${body.total_count}`,
        );
      return collected.filter(
        (wf) =>
          wf.state === "active" &&
          wf.path.startsWith(".github/workflows/") &&
          wf.path !== SELF_WORKFLOW_PATH,
      );
    }
  }
}

/**
 * The workflows whose newest completed push/schedule run on `branch` is red.
 *
 * `request(path)` takes a repo-relative API path and resolves to parsed JSON;
 * injecting it keeps this function drivable from a test without a network or a
 * token. Returns `[]` when the branch is healthy.
 */
export async function redWorkflows({ request, branch }) {
  const red = [];
  for (const wf of await activeWorkflows(request)) {
    // Newest-first; take the first branch-event run and judge only that one. An
    // older red run under a newer green one is a failure that has already been
    // fixed, and reporting it would make the check un-clearable.
    const { workflow_runs: runs = [] } = await request(
      `/actions/workflows/${wf.id}/runs` +
        `?branch=${encodeURIComponent(branch)}&status=completed&per_page=20`,
    );
    const latest = runs.find((run) => BRANCH_EVENTS.has(run.event));
    if (latest?.conclusion !== RED) continue;
    red.push({
      workflow: wf.name,
      event: latest.event,
      sha: latest.head_sha,
      url: latest.html_url,
    });
  }
  return red;
}

/** Human-readable verdict for the job log and the ntfy click-through. */
export function report(branch, red) {
  if (red.length === 0) return `${branch} is green: no red workflow runs.`;
  const lines = red.map(
    (r) => `  - ${r.workflow} (${r.event}, ${r.sha.slice(0, 8)}) ${r.url}`,
  );
  return [
    `${branch} is RED — ${red.length} workflow(s) whose newest run failed:`,
    ...lines,
  ].join("\n");
}

async function main() {
  const repo = process.env.GITHUB_REPOSITORY;
  const branch = process.env.DEFAULT_BRANCH;
  const token = process.env.GH_TOKEN;
  // Fail loud rather than sweeping zero workflows and declaring victory: a
  // health check that reports green because it was misconfigured is worse than
  // no health check at all.
  if (!repo) throw new Error("GITHUB_REPOSITORY is required");
  if (!branch) throw new Error("DEFAULT_BRANCH is required");
  if (!token) throw new Error("GH_TOKEN is required");

  const base = process.env.GITHUB_API_URL ?? "https://api.github.com";
  const request = async (path) => {
    const res = await fetch(`${base}/repos/${repo}${path}`, {
      headers: {
        accept: "application/vnd.github+json",
        authorization: `Bearer ${token}`,
        "x-github-api-version": "2022-11-28",
      },
    });
    if (!res.ok)
      throw new Error(`GET ${path} failed: ${res.status} ${res.statusText}`);
    return res.json();
  };

  const red = await redWorkflows({ request, branch });
  process.stdout.write(`${report(branch, red)}\n`);
  if (red.length > 0) process.exitCode = 1;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await main();
