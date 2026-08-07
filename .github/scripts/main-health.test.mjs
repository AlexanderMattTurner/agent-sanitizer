import { strict as assert } from "node:assert";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { redWorkflows, report, SELF_WORKFLOW_PATH } from "./main-health.mjs";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

/**
 * Build a `request` stub over a fixture of workflows and their runs.
 *
 * `workflows` are listing entries; `runsById` maps workflow id -> the runs the
 * API would return, newest first. Records every path requested so a test can
 * assert what was NOT fetched.
 */
function stubRequest(workflows, runsById, { pageSize = 100 } = {}) {
  const seen = [];
  const request = async (path) => {
    seen.push(path);
    const listing = path.match(
      /^\/actions\/workflows\?per_page=\d+&page=(\d+)$/,
    );
    if (listing) {
      const page = Number(listing[1]);
      return {
        total_count: workflows.length,
        workflows: workflows.slice((page - 1) * pageSize, page * pageSize),
      };
    }
    const runs = path.match(/^\/actions\/workflows\/(\d+)\/runs\?/);
    assert.ok(runs, `unexpected request path: ${path}`);
    return { workflow_runs: runsById[runs[1]] ?? [] };
  };
  return { request, seen };
}

const wf = (id, name, extra = {}) => ({
  id,
  name,
  state: "active",
  path: `.github/workflows/${name.toLowerCase().replaceAll(" ", "-")}.yaml`,
  ...extra,
});

const run = (conclusion, extra = {}) => ({
  event: "push",
  conclusion,
  head_sha: "0123456789abcdef0123456789abcdef01234567",
  html_url: "https://github.com/o/r/actions/runs/1",
  ...extra,
});

test("reports a workflow whose newest push run failed", async () => {
  const { request } = stubRequest([wf(1, "Node tests")], {
    1: [run("failure")],
  });
  const red = await redWorkflows({ request, branch: "main" });
  assert.deepEqual(
    red.map((r) => r.workflow),
    ["Node tests"],
  );
  assert.equal(red[0].event, "push");
  assert.equal(red[0].sha, "0123456789abcdef0123456789abcdef01234567");
});

test("reports a failed scheduled run too — a nightly is branch health", async () => {
  const { request } = stubRequest([wf(1, "Nightly unseeded fuzz")], {
    1: [run("failure", { event: "schedule" })],
  });
  const red = await redWorkflows({ request, branch: "main" });
  assert.equal(red.length, 1);
  assert.equal(red[0].event, "schedule");
});

test("an older red run under a newer green one is already fixed, not red", async () => {
  const { request } = stubRequest([wf(1, "Node tests")], {
    1: [run("success"), run("failure")],
  });
  assert.deepEqual(await redWorkflows({ request, branch: "main" }), []);
});

test("cancelled is not failure — a superseded run must not raise the alarm", async () => {
  const { request } = stubRequest([wf(1, "Node tests")], {
    1: [run("cancelled"), run("success")],
  });
  assert.deepEqual(await redWorkflows({ request, branch: "main" }), []);
});

test("skips pull_request and workflow_run conclusions, judging the next branch run", async () => {
  const { request } = stubRequest([wf(1, "Node tests")], {
    1: [
      run("failure", { event: "pull_request" }),
      run("failure", { event: "workflow_run" }),
      run("success"),
    ],
  });
  assert.deepEqual(await redWorkflows({ request, branch: "main" }), []);
});

test("a workflow with no branch run at all is not red", async () => {
  const { request } = stubRequest([wf(1, "CI failure notify")], {
    1: [run("failure", { event: "workflow_run" })],
  });
  assert.deepEqual(await redWorkflows({ request, branch: "main" }), []);
});

test("excludes itself — otherwise its own first red run latches the check on forever", async () => {
  const self = wf(1, "Main branch health", { path: SELF_WORKFLOW_PATH });
  const { request, seen } = stubRequest([self], { 1: [run("failure")] });
  assert.deepEqual(await redWorkflows({ request, branch: "main" }), []);
  assert.ok(
    !seen.some((p) => p.includes("/runs")),
    "self workflow must not even be queried",
  );
});

test("the self-exclusion names a workflow that exists", () => {
  // Non-vacuity: without this, renaming the workflow file turns the exclusion
  // above into a no-op that excludes nothing and silently re-latches.
  assert.ok(
    existsSync(join(REPO_ROOT, SELF_WORKFLOW_PATH)),
    `${SELF_WORKFLOW_PATH} does not exist — update SELF_WORKFLOW_PATH`,
  );
});

test("the self-exclusion is load-bearing: the same run IS red under any other path", async () => {
  // Proves the previous test's exclusion is doing the work, not the fixture.
  const notSelf = wf(1, "Main branch health", {
    path: ".github/workflows/some-other-name.yaml",
  });
  const { request } = stubRequest([notSelf], { 1: [run("failure")] });
  assert.equal((await redWorkflows({ request, branch: "main" })).length, 1);
});

test("skips inactive workflows and GitHub's synthesized ones", async () => {
  const { request } = stubRequest(
    [
      wf(1, "Disabled thing", { state: "disabled_manually" }),
      wf(2, "Dependency Graph", { path: "dynamic/dependabot/update-graph" }),
      wf(3, "Node tests"),
    ],
    { 1: [run("failure")], 2: [run("failure")], 3: [run("failure")] },
  );
  const red = await redWorkflows({ request, branch: "main" });
  assert.deepEqual(
    red.map((r) => r.workflow),
    ["Node tests"],
  );
});

test("pages the workflow listing to completion", async () => {
  const many = Array.from({ length: 7 }, (_, i) => wf(i + 1, `W${i + 1}`));
  const { request } = stubRequest(
    many,
    { 7: [run("failure")] },
    { pageSize: 3 },
  );
  const red = await redWorkflows({ request, branch: "main" });
  assert.deepEqual(
    red.map((r) => r.workflow),
    ["W7"],
    "the workflow on the last page must still be swept",
  );
});

test("throws rather than under-reporting when the listing is short", async () => {
  const request = async (path) =>
    path.startsWith("/actions/workflows?")
      ? { total_count: 5, workflows: [] }
      : { workflow_runs: [] };
  await assert.rejects(
    () => redWorkflows({ request, branch: "main" }),
    /stopped at 0 of 5/,
  );
});

test("the branch is passed through to the API, not hardcoded", async () => {
  const { request, seen } = stubRequest([wf(1, "Node tests")], { 1: [] });
  await redWorkflows({ request, branch: "release/2.x" });
  assert.ok(
    seen.some((p) => p.includes("branch=release%2F2.x")),
    `branch never reached the API: ${seen.join(" ")}`,
  );
});

test("report() names every red workflow and stays quiet when green", () => {
  assert.match(report("main", []), /main is green/);
  const body = report("main", [
    {
      workflow: "Node tests",
      event: "push",
      sha: "0123456789abcdef",
      url: "https://example.invalid/1",
    },
    {
      workflow: "Lint",
      event: "push",
      sha: "fedcba9876543210",
      url: "https://example.invalid/2",
    },
  ]);
  assert.match(body, /main is RED — 2 workflow\(s\)/);
  assert.match(
    body,
    /Node tests \(push, 01234567\) https:\/\/example.invalid\/1/,
  );
  assert.match(body, /Lint \(push, fedcba98\) https:\/\/example.invalid\/2/);
});
