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
// completed push/schedule run of each workflow on the default branch and exits
// non-zero if any of them concluded `failure`. Run on a schedule, it re-reports
// for as long as the branch is red, so the alert cannot be slept through — and
// it goes quiet by itself the moment the branch recovers.
//
// SCOPE AND PREDICATE BOTH COME FROM ci-failure-notify. The predicate is
// `failure` because that is its `if:`; the set of workflows is read out of its
// own `workflows:` list at runtime rather than re-derived from the tree. Those
// are not the same set, and the difference is the whole point: `Nightly unseeded
// fuzz`, `Mutation tests` and `Pack smoke test` are deliberately absent from it.
// A red nightly fuzz means "go look" and is already routed to a deduped issue by
// nightly-fuzz-issue.js precisely because nobody should be paged for it — and
// this sweep re-reports for as long as the branch stays red, so paging on it
// would turn one counterexample into a recurring push until the next nightly
// clears it. Widening the paging set is a decision to make by editing that
// list, never a side effect of a second scope drifting past it.
//
// It is deliberately NOT a required check and takes no fixing action: its whole
// output is "these workflows are red on this branch, go look".
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// This workflow's own path. Excluded from the sweep because including it would
// latch: the first red run becomes the newest run, which the next run reads as
// evidence that the branch is red, forever — long after the real failure was
// fixed. `main-health.test.mjs` asserts this file exists, so a rename that
// misses this constant fails the guard instead of silently disabling it.
export const SELF_WORKFLOW_PATH = ".github/workflows/main-health.yaml";

// The SSOT for which workflows are worth paging a human about — genuinely one
// source, read at runtime rather than restated here, so the two alerts cannot
// drift. This used to credit a ci-truth-serum pre-commit hook
// (check-failure-notifier-coverage) with keeping the roster honest against the
// tree; no such hook exists. What actually holds the roster to the tree is
// test/failure-notify-roster.test.mjs, whose partition assertion requires every
// push-to-main/`schedule:` workflow to be rostered or exempt in its own yaml —
// so intersecting against it inherits THAT maintenance, not a phantom hook's.
export const NOTIFIER_WORKFLOW_PATH =
  ".github/workflows/ci-failure-notify.yaml";

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
 * The workflow NAMES listed under ci-failure-notify's `on.workflow_run.workflows`.
 *
 * Hand-rolled rather than pulled through a YAML parser because this script runs
 * from a bare `node` with no dependency install — but it is deliberately narrow:
 * it anchors on a line that is exactly `workflows:`, then takes only block
 * sequence items indented deeper than it, and throws if that yields nothing.
 * A parse that quietly returned `[]` would make the sweep report every branch
 * green forever, so the empty case is the one that must be loud.
 */
export function pagedWorkflowNames(yaml) {
  const lines = yaml.split("\n");
  const start = lines.findIndex((line) =>
    /^\s*workflows:\s*(#.*)?$/.test(line),
  );
  if (start === -1)
    throw new Error(`${NOTIFIER_WORKFLOW_PATH}: no \`workflows:\` block`);
  const keyIndent = lines[start].match(/^\s*/)[0].length;

  const names = [];
  for (const line of lines.slice(start + 1)) {
    if (/^\s*$/.test(line)) continue;
    const item = line.match(/^(\s*)-\s+(.*?)\s*$/);
    // Anything that is not a deeper-indented list item ends the block: the next
    // top-level key, or a sibling key of `workflows:` itself.
    if (!item || item[1].length <= keyIndent) break;
    names.push(item[2].replace(/^["']|["']$/g, ""));
  }
  if (names.length === 0)
    throw new Error(`${NOTIFIER_WORKFLOW_PATH}: \`workflows:\` block is empty`);
  return new Set(names);
}

/**
 * The active workflows this sweep is allowed to page on, paged to completion.
 *
 * `pagedNames` is the scope gate (see the header): a workflow absent from
 * ci-failure-notify's list is not a paging surface, so it is not one here.
 * Workflows GitHub synthesizes (`dynamic/dependabot/...`, CodeQL's default
 * setup) are dropped on top of that: they carry no file in the tree, so nothing
 * in this repo can fix or silence them, and a red one would pin this check on
 * forever even if a name happened to match.
 */
async function sweptWorkflows(request, pagedNames) {
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
          wf.path !== SELF_WORKFLOW_PATH &&
          pagedNames.has(wf.name),
      );
    }
  }
}

/**
 * The workflows whose newest completed push/schedule run on `branch` is red.
 *
 * `request(path)` takes a repo-relative API path and resolves to parsed JSON,
 * and `pagedNames` is the name set from `pagedWorkflowNames()`; injecting both
 * keeps this function drivable from a test without a network or a token.
 * Returns `[]` when the branch is healthy.
 */
export async function redWorkflows({ request, branch, pagedNames }) {
  const red = [];
  for (const wf of await sweptWorkflows(request, pagedNames)) {
    // Newest-first; take the first branch-event run and judge only that one. An
    // older red run under a newer green one is a failure that has already been
    // fixed, and reporting it would make the check un-clearable.
    //
    // `per_page=100` rather than a tighter window: `find` skipping past
    // pull_request/workflow_run runs means a short window could contain no
    // branch run at all and read as green — the same silent under-report the
    // listing above throws on, in the one script whose job is not to declare
    // victory by accident. 100 is the same single request.
    const { workflow_runs: runs = [] } = await request(
      `/actions/workflows/${wf.id}/runs` +
        `?branch=${encodeURIComponent(branch)}&status=completed&per_page=100`,
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

  // Resolved against this file, not the process cwd, so the sweep does not
  // depend on which directory the workflow happened to invoke it from.
  const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
  const pagedNames = pagedWorkflowNames(
    readFileSync(join(repoRoot, NOTIFIER_WORKFLOW_PATH), "utf8"),
  );

  const red = await redWorkflows({ request, branch, pagedNames });
  process.stdout.write(`${report(branch, red)}\n`);
  if (red.length > 0) process.exitCode = 1;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await main();
