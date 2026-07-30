// Behavior tests for post-pr-review.mjs: run the real script over a temp
// PR_INPUT_DIR (diff.txt + review.json) and assert on the reviews-API payload it
// emits — anchor validation, suggested-edit rendering, the summary spill path,
// and the SKIP paths. Drives the script as a subprocess (its real entry point),
// never re-implements its logic.
import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  mkdtempSync,
  writeFileSync,
  readFileSync,
  existsSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCRIPT = join(__dirname, "post-pr-review.mjs");

// The severity model's SSOT, read rather than restated: the marker and
// synthetic-anchor tests below iterate `gating` member-by-member, so a severity
// added to (or dropped from) the config is covered without editing this file —
// and review-findings-gate.sh builds its predicate from the same list.
const SEVERITIES = JSON.parse(
  readFileSync(
    new URL("../../config/review-severities.json", import.meta.url),
    "utf8",
  ),
);

// A unified diff for src/foo.js whose one hunk yields these commentable lines:
//   RIGHT (new file): 1, 2, 3, 4, 5      LEFT (old file): 1, 2, 3, 4
// Line 5 is RIGHT-only (a context line whose old-side number, 4, differs), which
// lets a test prove a suggestion forces the RIGHT side.
const DIFF = `diff --git a/src/foo.js b/src/foo.js
index 1111111..2222222 100644
--- a/src/foo.js
+++ b/src/foo.js
@@ -1,4 +1,5 @@
 const a = 1;
-const b = 2;
+const b = 3;
+const c = 4;
 const d = 5;
 const e = 6;
`;

const dirs = [];
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop(), { recursive: true, force: true });
});

// Run the poster over a temp dir seeded with `review` (object) and a diff
// (default DIFF). Returns { status, payload, summary } where payload/summary are
// null when no payload file was written.
function run(review, { diff = DIFF, headSha, executionFile, maxWeekly } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "prr-"));
  dirs.push(dir);
  writeFileSync(join(dir, "diff.txt"), diff);
  writeFileSync(
    join(dir, "review.json"),
    typeof review === "string" ? review : JSON.stringify(review),
  );
  // Neutralize the cost footer by default so body assertions are deterministic:
  // clear both the explicit EXECUTION_FILE and the RUNNER_TEMP fallback path
  // (CI runners set RUNNER_TEMP, which would otherwise be probed). Footer tests
  // opt back in via the executionFile option.
  const env = { ...process.env, PR_INPUT_DIR: dir, EXECUTION_FILE: "" };
  delete env.RUNNER_TEMP;
  if (headSha !== undefined) env.HEAD_SHA = headSha;
  if (executionFile !== undefined) env.EXECUTION_FILE = executionFile;
  if (maxWeekly !== undefined) env.MAX20X_WEEKLY_USD = maxWeekly;
  const status = execFileSync("node", [SCRIPT], {
    env,
    encoding: "utf8",
  }).trim();
  const payloadPath = join(dir, "review-payload.json");
  const summaryPath = join(dir, "review-summary.txt");
  return {
    status,
    payload: existsSync(payloadPath)
      ? JSON.parse(readFileSync(payloadPath, "utf8"))
      : null,
    summary: existsSync(summaryPath) ? readFileSync(summaryPath, "utf8") : null,
  };
}

describe("post-pr-review: anchored inline comments", () => {
  it("renders a single-line finding with a suggestion block", () => {
    const { status, payload } = run({
      summary: "needs changes",
      findings: [
        {
          path: "src/foo.js",
          line: 2,
          side: "RIGHT",
          severity: "warning",
          title: "bug",
          body: "wrong value",
          suggestion: "const b = 4;",
        },
      ],
    });
    assert.equal(status, "PAYLOAD");
    assert.equal(payload.event, "COMMENT");
    assert.equal(payload.comments.length, 1);
    const c = payload.comments[0];
    assert.equal(c.path, "src/foo.js");
    assert.equal(c.line, 2);
    assert.equal(c.side, "RIGHT");
    assert.equal(c.start_line, undefined);
    // Exact body INCLUDING the hidden severity marker, which trails the
    // suggestion fence — the gate matches it as a whole line, and the fence must
    // still close before it.
    assert.equal(
      c.body,
      "🟡 bug — wrong value\n\n```suggestion\nconst b = 4;\n```\n\n<!-- severity: warning -->",
    );
  });

  it("carries start_line/start_side for a multi-line suggestion", () => {
    const { payload } = run({
      summary: "s",
      findings: [
        {
          path: "src/foo.js",
          line: 3,
          start_line: 2,
          side: "RIGHT",
          severity: "nit",
          title: "t",
          body: "b",
          suggestion: "const b = 3;\nconst c = 5;",
        },
      ],
    });
    const c = payload.comments[0];
    assert.equal(c.line, 3);
    assert.equal(c.start_line, 2);
    assert.equal(c.start_side, "RIGHT");
    assert.match(c.body, /```suggestion\nconst b = 3;\nconst c = 5;\n```/);
  });

  it("comments on a removed line via the LEFT side", () => {
    const { payload } = run({
      summary: "s",
      findings: [
        {
          path: "src/foo.js",
          line: 2,
          side: "LEFT",
          severity: "nit",
          title: "t",
          body: "b",
        },
      ],
    });
    assert.equal(payload.comments.length, 1);
    assert.equal(payload.comments[0].side, "LEFT");
    assert.doesNotMatch(payload.comments[0].body, /suggestion/);
  });

  it("forces RIGHT when a finding carries a suggestion", () => {
    // side LEFT + line 5: 5 is RIGHT-only, so this only anchors if forced RIGHT.
    const { payload } = run({
      summary: "s",
      findings: [
        {
          path: "src/foo.js",
          line: 5,
          side: "LEFT",
          severity: "warning",
          title: "t",
          body: "b",
          suggestion: "const e = 7;",
        },
      ],
    });
    assert.equal(payload.comments.length, 1);
    assert.equal(payload.comments[0].side, "RIGHT");
    assert.match(payload.comments[0].body, /```suggestion/);
  });

  it("uses a longer fence when the suggestion contains backticks", () => {
    const { payload } = run({
      summary: "s",
      findings: [
        {
          path: "src/foo.js",
          line: 4,
          side: "RIGHT",
          severity: "nit",
          title: "t",
          body: "b",
          suggestion: "a ``` b",
        },
      ],
    });
    assert.match(payload.comments[0].body, /````suggestion\na ``` b\n````/);
  });
});

describe("post-pr-review: severity icons", () => {
  for (const [severity, expected] of [
    ["blocking", "🔴"],
    ["warning", "🟡"],
    ["nit", "🔵"],
    ["bogus", "•"],
  ]) {
    it(`maps ${severity} to ${expected}`, () => {
      const { payload } = run({
        summary: "s",
        findings: [
          {
            path: "src/foo.js",
            line: 1,
            side: "RIGHT",
            severity,
            title: "t",
            body: "b",
          },
        ],
      });
      // First line only: the hidden severity marker the gate reads is appended
      // to every anchored body and is asserted in its own block below.
      assert.equal(
        payload.comments[0].body.split("\n")[0],
        `${expected} t — b`,
      );
    });
  }
});

describe("post-pr-review: summary + spill", () => {
  it("spills an un-anchorable NIT into Additional notes, not comments", () => {
    // Only a non-gating severity spills: a gating one is anchored synthetically
    // so it opens a thread the status gate can see (asserted in its own block).
    const { payload } = run({
      summary: "verdict line",
      findings: [
        {
          path: "src/foo.js",
          line: 999,
          side: "RIGHT",
          severity: "nit",
          title: "t",
          body: "b",
        },
      ],
    });
    assert.equal(payload.comments.length, 0);
    assert.match(payload.body, /^verdict line/);
    assert.match(payload.body, /#### Additional notes/);
    assert.match(payload.body, /`src\/foo\.js:999`: t — b/);
  });

  it("posts a summary-only review when there are no findings", () => {
    const { status, payload } = run({ summary: "looks good", findings: [] });
    assert.equal(status, "PAYLOAD");
    assert.deepEqual(payload.comments, []);
    assert.equal(payload.body, "looks good");
  });

  it("falls back to a placeholder body when comments exist but summary is empty", () => {
    const { payload } = run({
      summary: "",
      findings: [
        {
          path: "src/foo.js",
          line: 1,
          side: "RIGHT",
          severity: "nit",
          title: "t",
          body: "b",
        },
      ],
    });
    assert.equal(payload.comments.length, 1);
    assert.equal(payload.body, "Automated review.");
  });
});

describe("post-pr-review: the review event carries no merge consequence", () => {
  // Every review posts as a COMMENT — what holds the merge is the
  // review-findings status gate, which reads the threads, not the review event.
  // A verdict that used to mint APPROVE/REQUEST_CHANGES must no longer do so:
  // an APPROVE here would satisfy a review-required ruleset on the strength of
  // the model's prose, and a REQUEST_CHANGES would strand the PR with no
  // approval minter left to clear it.
  for (const verdict of [
    "looks_good",
    "LOOKS_GOOD",
    "needs_changes",
    " Blocking ",
    "bogus",
    "",
    undefined,
  ]) {
    it(`posts COMMENT for verdict ${JSON.stringify(verdict)}`, () => {
      const review = { summary: "s", findings: [] };
      if (verdict !== undefined) review.verdict = verdict;
      const { payload } = run(review);
      assert.equal(payload.event, "COMMENT");
    });
  }

  it("carries the inline findings on the comment review", () => {
    const { payload } = run({
      summary: "minor only",
      verdict: "looks_good",
      findings: [
        {
          path: "src/foo.js",
          line: 2,
          side: "RIGHT",
          severity: "nit",
          title: "t",
          body: "b",
        },
      ],
    });
    assert.equal(payload.event, "COMMENT");
    assert.equal(payload.comments.length, 1);
  });

  it("skips entirely when the reviewer produced no findings and no summary", () => {
    // The gate does not count a skipped run as a review, so this leaves the PR
    // RED rather than passing it unreviewed — the fail-closed direction.
    const { status } = run({ summary: "", verdict: "blocking", findings: [] });
    assert.equal(status, "SKIP");
  });
});

describe("post-pr-review: the severity marker the gate reads", () => {
  const anchored = (severity) => ({
    summary: "s",
    findings: [
      {
        path: "src/foo.js",
        line: 2,
        side: "RIGHT",
        severity,
        title: "t",
        body: "b",
      },
    ],
  });

  // Iterated from the SSOT so a severity added to config/review-severities.json
  // is covered without editing this test — and so a gating severity that stopped
  // being stamped cannot pass here.
  for (const severity of SEVERITIES.gating) {
    it(`stamps a whole-line marker for the gating severity ${severity}`, () => {
      const { payload } = run(anchored(severity));
      assert.equal(payload.comments.length, 1);
      // Whole-LINE match is what the gate's jq predicate does, so assert the
      // marker is its own line rather than merely a substring.
      assert.ok(
        payload.comments[0].body
          .split("\n")
          .includes(`<!-- severity: ${severity} -->`),
        `no whole-line marker for ${severity}: ${payload.comments[0].body}`,
      );
    });
  }

  it("stamps the marker for a non-gating severity too (the gate filters, not the writer)", () => {
    const { payload } = run(anchored("nit"));
    assert.ok(
      payload.comments[0].body.split("\n").includes("<!-- severity: nit -->"),
    );
  });

  it("stamps no marker for a severity outside the model", () => {
    const { payload } = run(anchored("catastrophic"));
    assert.doesNotMatch(payload.comments[0].body, /<!-- severity:/u);
  });

  it("puts the marker after the suggestion fence, never inside it", () => {
    const { payload } = run({
      summary: "s",
      findings: [
        {
          path: "src/foo.js",
          line: 2,
          side: "RIGHT",
          severity: "blocking",
          title: "t",
          body: "b",
          suggestion: "const x = 1;",
        },
      ],
    });
    const body = payload.comments[0].body;
    assert.ok(body.includes("```suggestion"));
    assert.ok(
      body.indexOf("<!-- severity: blocking -->") > body.lastIndexOf("```"),
      `marker landed inside the fence: ${body}`,
    );
  });
});

describe("post-pr-review: an unanchorable gating finding still opens a thread", () => {
  // The status gate can only see THREADS. A gating finding that spilled into the
  // review body would hold nothing, which is the one way this reviewer could
  // silently lose its grip on a merge.
  const unanchorable = (severity) => ({
    summary: "s",
    findings: [
      {
        path: "src/foo.js",
        line: 9999,
        side: "RIGHT",
        severity,
        title: "t",
        body: "b",
      },
    ],
  });

  for (const severity of SEVERITIES.gating) {
    it(`anchors a ${severity} finding synthetically instead of spilling`, () => {
      const { payload } = run(unanchorable(severity));
      assert.equal(payload.comments.length, 1);
      assert.match(payload.comments[0].body, /PR-wide finding at/u);
      assert.ok(
        payload.comments[0].body
          .split("\n")
          .includes(`<!-- severity: ${severity} -->`),
      );
      // Its original coordinates stay legible to the author.
      assert.match(payload.comments[0].body, /src\/foo\.js:9999/u);
      assert.doesNotMatch(payload.body, /Additional notes/u);
    });
  }

  it("still spills a nit, which gates nothing either way", () => {
    const { payload } = run(unanchorable("nit"));
    assert.deepEqual(payload.comments, []);
    assert.match(payload.body, /Additional notes/u);
  });

  it("normalizes the severity, so a cased gating value cannot spill", () => {
    const { payload } = run(unanchorable(" Blocking "));
    assert.equal(payload.comments.length, 1);
    assert.match(payload.comments[0].body, /PR-wide finding at/u);
  });

  it("carries no suggestion onto a synthetic anchor", () => {
    // The synthetic line is not the line the finding is about, so an applied
    // suggestion there would edit unrelated code.
    const { payload } = run({
      summary: "s",
      findings: [
        {
          path: "src/foo.js",
          line: 9999,
          side: "RIGHT",
          severity: "blocking",
          title: "t",
          body: "b",
          suggestion: "const x = 1;",
        },
      ],
    });
    assert.equal(payload.comments.length, 1);
    assert.doesNotMatch(payload.comments[0].body, /```suggestion/u);
  });
});

describe("post-pr-review: commit pinning", () => {
  it("pins commit_id from HEAD_SHA", () => {
    const { payload } = run(
      { summary: "s", findings: [] },
      { headSha: "abc123" },
    );
    assert.equal(payload.commit_id, "abc123");
  });

  it("omits commit_id when HEAD_SHA is unset", () => {
    const { payload } = run({ summary: "s", findings: [] });
    assert.equal("commit_id" in payload, false);
  });
});

describe("post-pr-review: SKIP paths", () => {
  it("skips when there are no findings and no summary", () => {
    const { status, payload } = run({ summary: "", findings: [] });
    assert.equal(status, "SKIP");
    assert.equal(payload, null);
  });

  it("skips (does not throw) on invalid review.json", () => {
    const { status, payload } = run("{ not valid json");
    assert.equal(status, "SKIP");
    assert.equal(payload, null);
  });

  it("drops a finding with no title/body", () => {
    const { status, payload } = run({
      summary: "",
      findings: [
        { path: "src/foo.js", line: 1, side: "RIGHT", severity: "nit" },
      ],
    });
    assert.equal(status, "SKIP");
    assert.equal(payload, null);
  });
});

describe("post-pr-review: cost footer", () => {
  // Write an execution log shaped like the Claude action's output (an array of
  // streamed events; the terminal `result` event carries total_cost_usd) and
  // return its path, tracked for cleanup.
  function writeExecLog(events) {
    const dir = mkdtempSync(join(tmpdir(), "prr-exec-"));
    dirs.push(dir);
    const path = join(dir, "claude-execution-output.json");
    writeFileSync(path, JSON.stringify(events));
    return path;
  }

  it("appends a compact cost + PRs/week footer from the execution log", () => {
    const executionFile = writeExecLog([
      { type: "system", subtype: "init", model: "claude-sonnet-5" },
      { type: "result", subtype: "success", total_cost_usd: 0.16 },
    ]);
    const { payload, summary } = run(
      { summary: "looks good", findings: [] },
      { executionFile, maxWeekly: "2000" },
    );
    assert.match(payload.body, /^looks good\n\n---\n/);
    assert.match(
      payload.body,
      /📊 Review cost: \*\*\$0\.16\*\* \(claude-sonnet-5\)\./,
    );
    // 2000 / 0.16 = 12,500 PRs/week.
    assert.match(
      payload.body,
      /📉 ~12,500 PRs\/week at this rate on a Max 20× plan\./,
    );
    // The hidden marker lets the resolver read this cost back.
    assert.match(payload.body, /<!-- review-cost usd=0\.16 -->/);
    // The fallback summary file carries the identical footered body.
    assert.equal(summary, payload.body);
  });

  it("computes PRs/week from cost and the weekly budget", () => {
    const executionFile = writeExecLog([
      { type: "result", total_cost_usd: 10 },
    ]);
    const { payload } = run(
      { summary: "s", findings: [] },
      { executionFile, maxWeekly: "1000" },
    );
    assert.match(payload.body, /📊 Review cost: \*\*\$10\.00\*\*\./);
    // floor(1000 / 10) = 100 PRs/week.
    assert.match(payload.body, /~100 PRs\/week at this rate/);
  });

  it("surfaces a runaway cost as ~0 PRs/week", () => {
    // A cost above the weekly budget: floor(1000 / 2469) = 0.
    const executionFile = writeExecLog([
      { type: "result", total_cost_usd: 2469 },
    ]);
    const { payload } = run(
      { summary: "s", findings: [] },
      { executionFile, maxWeekly: "1000" },
    );
    assert.match(payload.body, /~0 PRs\/week at this rate/);
  });

  it("renders sub-cent costs with four decimals", () => {
    const executionFile = writeExecLog([
      { type: "result", total_cost_usd: 0.0009 },
    ]);
    const { payload } = run(
      { summary: "s", findings: [] },
      { executionFile, maxWeekly: "2000" },
    );
    assert.match(payload.body, /📊 Review cost: \*\*\$0\.0009\*\*/);
  });

  it("uses the footer as the body when there is no summary but a comment exists", () => {
    const executionFile = writeExecLog([{ type: "result", total_cost_usd: 1 }]);
    const { payload } = run(
      {
        summary: "",
        findings: [
          {
            path: "src/foo.js",
            line: 2,
            side: "RIGHT",
            severity: "warning",
            title: "t",
            body: "b",
          },
        ],
      },
      { executionFile },
    );
    assert.equal(payload.comments.length, 1);
    // Not the "Automated review." placeholder — the footer stands in as the body.
    assert.match(payload.body, /📊 Review cost:/);
    assert.doesNotMatch(payload.body, /Automated review\./);
  });

  it("omits the footer when the execution log is missing", () => {
    const { payload } = run(
      { summary: "looks good", findings: [] },
      { executionFile: "/nonexistent/claude-execution-output.json" },
    );
    assert.equal(payload.body, "looks good");
  });

  it("omits the footer when the execution log has no cost", () => {
    const executionFile = writeExecLog([
      { type: "system", subtype: "init", model: "claude-sonnet-5" },
    ]);
    const { payload } = run(
      { summary: "looks good", findings: [] },
      { executionFile },
    );
    assert.equal(payload.body, "looks good");
  });

  it("does not throw on a malformed execution log", () => {
    const dir = mkdtempSync(join(tmpdir(), "prr-exec-"));
    dirs.push(dir);
    const executionFile = join(dir, "claude-execution-output.json");
    writeFileSync(executionFile, "{ not json");
    const { status, payload } = run(
      { summary: "looks good", findings: [] },
      { executionFile },
    );
    assert.equal(status, "PAYLOAD");
    assert.equal(payload.body, "looks good");
  });
});

describe("post-pr-review: output sanitization", () => {
  it("strips invisible + ANSI payloads the model echoed into a comment body", () => {
    const { payload } = run({
      summary: "needs changes",
      findings: [
        {
          path: "src/foo.js",
          line: 2,
          side: "RIGHT",
          severity: "warning",
          title: "bug\u200Bhere",
          body: "fix \x1b[31mthis\x1b[0m now",
        },
      ],
    });
    assert.equal(payload.comments.length, 1);
    assert.ok(!payload.comments[0].body.includes("\u200B"));
    assert.ok(!payload.comments[0].body.includes("\x1b"));
    assert.match(payload.comments[0].body, /bughere/);
    assert.match(payload.comments[0].body, /fix this now/);
  });

  it("strips invisible + ANSI payloads from the summary/spill body", () => {
    const { payload } = run({
      summary: "all\u200B good \x1b[1mhere\x1b[0m",
      findings: [],
    });
    assert.ok(!payload.body.includes("\u200B"));
    assert.ok(!payload.body.includes("\x1b"));
    assert.equal(payload.body, "all good here");
  });
});

// The failure this exists to stop: claude-code-action EXITS 0 when the agent's
// session dies (a dead credential, an unentitled model, a hard API error), and
// its own terminal event still reads `subtype: "success"`. Only `is_error`
// separates "reviewed and found nothing" from "never reviewed". Without the
// check, that run reports SKIP and the PR shows a green reviewer that looked at
// nothing — observed live on agent-sanitizer#194, where both OAuth credentials
// failed in 472ms at $0 and the job stayed green.
describe("post-pr-review: an errored agent run is not a clean review", () => {
  function executionLog(events) {
    const dir = mkdtempSync(join(tmpdir(), "prr-exec-"));
    dirs.push(dir);
    const file = join(dir, "claude-execution-output.json");
    writeFileSync(file, JSON.stringify(events));
    return file;
  }

  it("reports ERRORED when the run set is_error, whatever the review says", () => {
    const { status, payload } = run(
      { findings: [], summary: "looks good to me" },
      {
        executionFile: executionLog([
          { type: "system", subtype: "init", model: "claude-opus-4-8" },
          {
            type: "result",
            subtype: "success",
            is_error: true,
            num_turns: 1,
            total_cost_usd: 0,
          },
        ]),
      },
    );
    assert.equal(status, "ERRORED");
    assert.equal(payload, null, "an errored run must post nothing");
  });

  it("still posts a real review when the run did not error", () => {
    const { status } = run(
      {
        findings: [
          {
            path: "src/foo.js",
            line: 4,
            side: "RIGHT",
            severity: "warning",
            body: "a real finding",
          },
        ],
        summary: "s",
      },
      {
        executionFile: executionLog([
          {
            type: "result",
            subtype: "success",
            is_error: false,
            total_cost_usd: 1.2,
          },
        ]),
      },
    );
    assert.equal(status, "PAYLOAD");
  });

  it("leaves the no-log case alone (SKIP, not a failure)", () => {
    const { status } = run({ findings: [], summary: "" });
    assert.equal(status, "SKIP");
  });
});
