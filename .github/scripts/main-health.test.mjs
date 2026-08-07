import { strict as assert } from "node:assert";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  NOTIFIER_WORKFLOW_PATH,
  pagedWorkflowNames,
  redWorkflows,
  report,
  SELF_WORKFLOW_PATH,
} from "./main-health.mjs";

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

/**
 * Sweep a fixture. `pagedNames` defaults to every name the fixture defines, so
 * the scope gate never silently masks a test about the run predicate; tests that
 * are ABOUT the scope gate pass their own.
 */
async function sweep(workflows, runsById, opts = {}) {
  const { request, seen } = stubRequest(workflows, runsById, opts);
  const pagedNames =
    opts.pagedNames ?? new Set(workflows.map((each) => each.name));
  const red = await redWorkflows({
    request,
    branch: opts.branch ?? "main",
    pagedNames,
  });
  return { red, seen };
}

test("reports a workflow whose newest push run failed", async () => {
  const { red } = await sweep([wf(1, "Node tests")], { 1: [run("failure")] });
  assert.deepEqual(
    red.map((r) => r.workflow),
    ["Node tests"],
  );
  assert.equal(red[0].event, "push");
  assert.equal(red[0].sha, "0123456789abcdef0123456789abcdef01234567");
});

test("reports a failed scheduled run too — a nightly is branch health", async () => {
  const { red } = await sweep([wf(1, "Release canary")], {
    1: [run("failure", { event: "schedule" })],
  });
  assert.equal(red.length, 1);
  assert.equal(red[0].event, "schedule");
});

test("an older red run under a newer green one is already fixed, not red", async () => {
  const { red } = await sweep([wf(1, "Node tests")], {
    1: [run("success"), run("failure")],
  });
  assert.deepEqual(red, []);
});

test("cancelled is not failure — a superseded run must not raise the alarm", async () => {
  const { red } = await sweep([wf(1, "Node tests")], {
    1: [run("cancelled"), run("success")],
  });
  assert.deepEqual(red, []);
});

test("skips pull_request and workflow_run conclusions, judging the next branch run", async () => {
  const { red } = await sweep([wf(1, "Node tests")], {
    1: [
      run("failure", { event: "pull_request" }),
      run("failure", { event: "workflow_run" }),
      run("success"),
    ],
  });
  assert.deepEqual(red, []);
});

test("a workflow with no branch run at all is not red", async () => {
  const { red } = await sweep([wf(1, "CI failure notify")], {
    1: [run("failure", { event: "workflow_run" })],
  });
  assert.deepEqual(red, []);
});

test("asks for a 100-run window, so `find` has room to skip non-branch runs", async () => {
  const { seen } = await sweep([wf(1, "Node tests")], { 1: [] });
  assert.ok(
    seen.some((p) => p.includes("per_page=100") && p.includes("/runs")),
    `run window was not 100: ${seen.join(" ")}`,
  );
});

test("excludes itself — otherwise its own first red run latches the check on forever", async () => {
  const self = wf(1, "Main branch health", { path: SELF_WORKFLOW_PATH });
  const { red, seen } = await sweep([self], { 1: [run("failure")] });
  assert.deepEqual(red, []);
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
  const { red } = await sweep([notSelf], { 1: [run("failure")] });
  assert.equal(red.length, 1);
});

test("skips inactive workflows and GitHub's synthesized ones", async () => {
  const { red } = await sweep(
    [
      wf(1, "Disabled thing", { state: "disabled_manually" }),
      wf(2, "Dependency Graph", { path: "dynamic/dependabot/update-graph" }),
      wf(3, "Node tests"),
    ],
    { 1: [run("failure")], 2: [run("failure")], 3: [run("failure")] },
  );
  assert.deepEqual(
    red.map((r) => r.workflow),
    ["Node tests"],
  );
});

test("pages the workflow listing to completion", async () => {
  const many = Array.from({ length: 7 }, (_, i) => wf(i + 1, `W${i + 1}`));
  const { red } = await sweep(many, { 7: [run("failure")] }, { pageSize: 3 });
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
    () => redWorkflows({ request, branch: "main", pagedNames: new Set() }),
    /stopped at 0 of 5/,
  );
});

test("the branch is passed through to the API, not hardcoded", async () => {
  const { seen } = await sweep(
    [wf(1, "Node tests")],
    { 1: [] },
    {
      branch: "release/2.x",
    },
  );
  assert.ok(
    seen.some((p) => p.includes("branch=release%2F2.x")),
    `branch never reached the API: ${seen.join(" ")}`,
  );
});

// --- scope gate: the sweep pages on exactly what ci-failure-notify pages on ---

test("a red workflow absent from the notifier list is not paged on", async () => {
  const { red, seen } = await sweep(
    [wf(1, "Nightly unseeded fuzz"), wf(2, "Node tests")],
    { 1: [run("failure", { event: "schedule" })], 2: [run("failure")] },
    { pagedNames: new Set(["Node tests"]) },
  );
  assert.deepEqual(
    red.map((r) => r.workflow),
    ["Node tests"],
    "an unlisted workflow must not reach the paging channel",
  );
  assert.ok(
    !seen.some((p) => p.startsWith("/actions/workflows/1/runs")),
    "an unlisted workflow must not even be queried",
  );
});

test("the scope gate is load-bearing: the same fixture IS red once listed", async () => {
  const { red } = await sweep(
    [wf(1, "Nightly unseeded fuzz")],
    { 1: [run("failure", { event: "schedule" })] },
    { pagedNames: new Set(["Nightly unseeded fuzz"]) },
  );
  assert.equal(red.length, 1);
});

test("parses the real ci-failure-notify list", () => {
  const names = pagedWorkflowNames(
    readFileSync(join(REPO_ROOT, NOTIFIER_WORKFLOW_PATH), "utf8"),
  );
  // Non-vacuity: a parser that silently returned a near-empty set would make
  // the sweep report every branch green forever.
  assert.ok(
    names.size >= 10,
    `parsed only ${names.size} names from ${NOTIFIER_WORKFLOW_PATH}`,
  );
  for (const expected of ["Node tests", "Lint", "Main branch health"])
    assert.ok(names.has(expected), `${expected} missing from the parsed list`);
  // The block ends where the block ends: `concurrency`/`permissions` are sibling
  // keys, not workflow names.
  for (const stray of ["concurrency", "permissions", "jobs"])
    assert.ok(!names.has(stray), `parser ran past the block and took ${stray}`);
});

test("the parser stops at the end of the block and unquotes items", () => {
  const names = pagedWorkflowNames(
    [
      "on:",
      "  workflow_run:",
      "    types: [completed]",
      "    workflows:",
      "      - Node tests",
      '      - "Quoted name"',
      "      - PR meta (privileged)",
      "",
      "concurrency:",
      "  group: x",
      "      - not a workflow",
    ].join("\n"),
  );
  assert.deepEqual(
    [...names],
    ["Node tests", "Quoted name", "PR meta (privileged)"],
  );
});

test("the parser throws rather than returning an empty scope", () => {
  assert.throws(
    () => pagedWorkflowNames("on:\n  push:\n    branches: [main]\n"),
    /no `workflows:` block/,
  );
  assert.throws(
    () => pagedWorkflowNames("    workflows:\nconcurrency:\n  group: x\n"),
    /`workflows:` block is empty/,
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
