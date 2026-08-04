// Behavior tests for post-pr-review.mjs: run the real script over a temp
// PR_INPUT_DIR (diff.txt + review.json) and assert on the reviews-API payload it
// emits — anchor validation, suggested-edit rendering, the summary spill path,
// the SKIP paths, and the fail-loud path (a crashed reviewer that wrote no
// review.json exits non-zero). Drives the script as a subprocess (its real entry
// point), never re-implements its logic.
import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
  copyFileSync,
  symlinkSync,
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
    // A warning-severity finding holds the merge even with no verdict (see the
    // finding-severity gate suite below); this test's focus is the suggestion
    // block, but the event reflects that escalation.
    assert.equal(payload.event, "REQUEST_CHANGES");
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

describe("post-pr-review: diff-view anchor remap", () => {
  // In DIFF the physical lines of diff.txt are: 1-5 headers/hunk, then content:
  //   6 ` const a = 1;` (ctx, new 1)   7 `-const b = 2;` (old 2)
  //   8 `+const b = 3;` (new 2)        9 `+const c = 4;` (new 3)
  //   10 ` const d = 5;` (new 4)       11 ` const e = 6;` (new 5)
  // Views 6-11 never collide with the commentable new-file lines 1-5, so a
  // finding carrying a view number is unambiguously un-anchorable pre-remap.

  it("remaps a diff-file line number to the real new-file line", () => {
    const { payload } = run({
      summary: "s",
      findings: [
        {
          path: "src/foo.js",
          line: 8,
          side: "RIGHT",
          severity: "blocking",
          title: "t",
          body: "b",
        },
      ],
    });
    assert.equal(payload.comments.length, 1);
    assert.equal(payload.comments[0].line, 2);
    assert.equal(payload.comments[0].side, "RIGHT");
    assert.doesNotMatch(payload.body, /Additional notes/);
  });

  it("keeps a suggestion riding a remapped added-line anchor", () => {
    const { payload } = run({
      summary: "s",
      findings: [
        {
          path: "src/foo.js",
          line: 9,
          side: "RIGHT",
          severity: "warning",
          title: "t",
          body: "b",
          suggestion: "const c = 5;",
        },
      ],
    });
    assert.equal(payload.comments.length, 1);
    assert.equal(payload.comments[0].line, 3);
    assert.match(payload.comments[0].body, /```suggestion\nconst c = 5;\n```/);
  });

  it("remaps a removed-line diff-view number to the LEFT side", () => {
    const { payload } = run({
      summary: "s",
      findings: [
        {
          path: "src/foo.js",
          line: 7,
          side: "RIGHT",
          severity: "nit",
          title: "t",
          body: "b",
        },
      ],
    });
    assert.equal(payload.comments.length, 1);
    assert.equal(payload.comments[0].line, 2);
    assert.equal(payload.comments[0].side, "LEFT");
  });

  it("spills a suggestion pointed at a removed diff-view line (RIGHT-only)", () => {
    const { payload } = run({
      summary: "s",
      findings: [
        {
          path: "src/foo.js",
          line: 7,
          side: "RIGHT",
          severity: "warning",
          title: "t",
          body: "b",
          suggestion: "const b = 9;",
        },
      ],
    });
    assert.equal(payload.comments.length, 0);
    assert.match(payload.body, /`src\/foo\.js:7`: t — b/);
  });

  it("remaps start_line through the same coordinate space", () => {
    const { payload } = run({
      summary: "s",
      findings: [
        {
          path: "src/foo.js",
          line: 9,
          start_line: 8,
          side: "RIGHT",
          severity: "warning",
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
  });

  it("drops an unremappable start_line but still posts the remapped line", () => {
    // start_line 7 is a removed line: it can only remap LEFT, so it cannot open
    // a RIGHT-side range — the comment posts single-line at the remapped anchor.
    const { payload } = run({
      summary: "s",
      findings: [
        {
          path: "src/foo.js",
          line: 9,
          start_line: 7,
          side: "RIGHT",
          severity: "warning",
          title: "t",
          body: "b",
        },
      ],
    });
    const c = payload.comments[0];
    assert.equal(c.line, 3);
    assert.equal(c.start_line, undefined);
  });

  it("does not remap across paths: a view line in another file's hunk spills", () => {
    // Two-file diff: view line 14 is bar.js content (new-file line 2). Claimed
    // under foo.js it must spill, not anchor to the wrong file's coordinates;
    // claimed under bar.js it remaps.
    const twoFileDiff = `diff --git a/src/foo.js b/src/foo.js
index 1111111..2222222 100644
--- a/src/foo.js
+++ b/src/foo.js
@@ -1,1 +1,2 @@
 const a = 1;
+const b = 3;
diff --git a/src/bar.js b/src/bar.js
index 3333333..4444444 100644
--- a/src/bar.js
+++ b/src/bar.js
@@ -1,1 +1,2 @@
 const x = 1;
+const y = 2;
`;
    const mismatch = run(
      {
        summary: "s",
        findings: [
          {
            path: "src/foo.js",
            line: 14,
            side: "RIGHT",
            severity: "warning",
            title: "t",
            body: "b",
          },
        ],
      },
      { diff: twoFileDiff },
    );
    assert.equal(mismatch.payload.comments.length, 0);
    assert.match(mismatch.payload.body, /`src\/foo\.js:14`: t — b/);

    const match = run(
      {
        summary: "s",
        findings: [
          {
            path: "src/bar.js",
            line: 14,
            side: "RIGHT",
            severity: "warning",
            title: "t",
            body: "b",
          },
        ],
      },
      { diff: twoFileDiff },
    );
    assert.equal(match.payload.comments.length, 1);
    assert.equal(match.payload.comments[0].path, "src/bar.js");
    assert.equal(match.payload.comments[0].line, 2);
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

  it("escalates a looks_good verdict to REQUEST_CHANGES when a nit is filed", () => {
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
    assert.equal(payload.event, "REQUEST_CHANGES");
    assert.equal(payload.comments.length, 1);
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

describe("post-pr-review: any real finding holds the merge", () => {
  const warnFinding = {
    path: "src/foo.js",
    line: 2,
    side: "RIGHT",
    severity: "warning",
    title: "lax shape",
    body: "a tighter design is available",
  };

  it("escalates a looks_good verdict to REQUEST_CHANGES on a warning finding", () => {
    const { payload } = run({
      summary: "minor design concern",
      verdict: "looks_good",
      findings: [warnFinding],
    });
    assert.equal(payload.event, "REQUEST_CHANGES");
    assert.equal(payload.comments.length, 1);
  });

  it("escalates a looks_good verdict to REQUEST_CHANGES on a blocking-severity finding", () => {
    // A 🔴 finding stamped looks_good (model inconsistency) must still hold: a
    // warning gates, so the strictly-more-severe blocking severity must too.
    const { payload } = run({
      summary: "should not have approved",
      verdict: "looks_good",
      findings: [{ ...warnFinding, severity: "blocking" }],
    });
    assert.equal(payload.event, "REQUEST_CHANGES");
  });

  it("escalates a verdict-less COMMENT to REQUEST_CHANGES on a warning finding", () => {
    const review = {
      summary: "no verdict, one warning",
      findings: [warnFinding],
    };
    const { payload } = run(review);
    assert.equal(payload.event, "REQUEST_CHANGES");
  });

  it("holds even when the warning finding spills to the summary (un-anchorable)", () => {
    const { payload } = run({
      summary: "design note",
      verdict: "looks_good",
      findings: [{ ...warnFinding, line: 999 }],
    });
    assert.equal(payload.event, "REQUEST_CHANGES");
    assert.equal(payload.comments.length, 0);
    assert.match(payload.body, /#### Additional notes/);
  });

  it("gates on a cased/padded severity ( Warning )", () => {
    const { payload } = run({
      summary: "s",
      verdict: "looks_good",
      findings: [{ ...warnFinding, severity: " Warning " }],
    });
    assert.equal(payload.event, "REQUEST_CHANGES");
  });

  it("gates on a nit too — looks_good escalates to REQUEST_CHANGES", () => {
    const { payload } = run({
      summary: "cosmetic only",
      verdict: "looks_good",
      findings: [{ ...warnFinding, severity: "nit" }],
    });
    assert.equal(payload.event, "REQUEST_CHANGES");
    assert.equal(payload.comments.length, 1);
  });

  it("does NOT gate on a detail-less finding (nothing to resolve)", () => {
    // A finding with no title/body is dropped, so it can't hold the merge with no
    // comment or note for the author to resolve — the verdict's event stands.
    const { payload } = run({
      summary: "ok",
      verdict: "looks_good",
      findings: [
        { path: "src/foo.js", line: 2, side: "RIGHT", severity: "warning" },
      ],
    });
    assert.equal(payload.event, "APPROVE");
    assert.deepEqual(payload.comments, []);
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

describe("post-pr-review: fail loud on a crashed reviewer", () => {
  // Run the poster expecting a NON-ZERO exit; returns { code, stderr }. A missing
  // or unparsable review.json means the reviewer crashed before writing its
  // verdict — that must go red, not skip green. `writeReview: false` omits
  // review.json entirely (the crash that produced #2366's silent green).
  // The fail-loud path is gated on the run having actually reached the model:
  // a positive total_cost_usd means the reviewer RAN and then crashed (red),
  // whereas zero/absent cost means it never reached the model (unconfigured /
  // credential failure) and skips green. Every fail case therefore writes a
  // cost>0 execution log so it exercises the "ran and crashed" branch.
  function ranExecLog() {
    const dir = mkdtempSync(join(tmpdir(), "prr-exec-"));
    dirs.push(dir);
    const path = join(dir, "claude-execution-output.json");
    writeFileSync(
      path,
      JSON.stringify([{ type: "result", total_cost_usd: 0.1 }]),
    );
    return path;
  }

  function runPoster(review, { writeReview = true, executionFile = "" } = {}) {
    const dir = mkdtempSync(join(tmpdir(), "prr-"));
    dirs.push(dir);
    writeFileSync(join(dir, "diff.txt"), DIFF);
    if (writeReview)
      writeFileSync(
        join(dir, "review.json"),
        typeof review === "string" ? review : JSON.stringify(review),
      );
    const env = {
      ...process.env,
      PR_INPUT_DIR: dir,
      EXECUTION_FILE: executionFile,
    };
    delete env.RUNNER_TEMP;
    // spawnSync captures stdout AND stderr regardless of exit code, so the
    // skip-path warning (emitted on a zero exit) is observable too.
    const res = spawnSync("node", [SCRIPT], { env, encoding: "utf8" });
    if (res.error) throw res.error;
    return {
      code: res.status,
      stdout: res.stdout ?? "",
      stderr: res.stderr ?? "",
      payload: existsSync(join(dir, "review-payload.json")),
    };
  }

  it("exits non-zero when the reviewer RAN (cost>0) but wrote no review.json", () => {
    const { code, stderr, payload } = runPoster(null, {
      writeReview: false,
      executionFile: ranExecLog(),
    });
    assert.equal(code, 1);
    assert.match(stderr, /::error::/);
    assert.match(stderr, /crashed/);
    assert.equal(payload, false);
  });

  it("exits non-zero on an unparsable review.json when the reviewer ran", () => {
    const { code, stderr, payload } = runPoster("{ not valid json", {
      executionFile: ranExecLog(),
    });
    assert.equal(code, 1);
    assert.match(stderr, /::error::/);
    assert.equal(payload, false);
  });

  it("SKIPS (green) when review.json is missing and run cost is zero/absent — the reviewer never reached the model (unconfigured / credential failure)", () => {
    const { code, stdout, stderr, payload } = runPoster(null, {
      writeReview: false,
      executionFile: "", // no execution log → readRunCost() returns {}
    });
    assert.equal(code, 0);
    assert.match(stdout, /SKIP/);
    assert.match(stderr, /never reached the model/);
    assert.match(stderr, /CLAUDE_CODE_OAUTH_TOKEN/);
    assert.equal(payload, false);
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

// The severity model lives in config/review-severities.json. These tests stage a
// COPY of the script beside a config of their own, because the script resolves
// that file relative to its own location — the property that keeps an untrusted
// PR head from supplying the config that decides which of its findings hold the
// merge. Editing the real config in place would race every other test.
describe("post-pr-review: the severity config is the single source of truth", () => {
  const SCRIPTS = __dirname;

  // Stage <root>/.github/scripts/{post-pr-review,lib-review-cost}.mjs beside
  // <root>/config/review-severities.json, with node_modules symlinked so the
  // sanitizer import still resolves. Returns the staged script's path.
  function stage(configText) {
    const root = mkdtempSync(join(tmpdir(), "prr-ssot-"));
    dirs.push(root);
    const scripts = join(root, ".github", "scripts");
    mkdirSync(scripts, { recursive: true });
    mkdirSync(join(root, "config"), { recursive: true });
    for (const f of ["post-pr-review.mjs", "lib-review-cost.mjs"])
      copyFileSync(join(SCRIPTS, f), join(scripts, f));
    symlinkSync(join(SCRIPTS, "node_modules"), join(scripts, "node_modules"));
    if (configText !== null)
      writeFileSync(join(root, "config", "review-severities.json"), configText);
    return join(scripts, "post-pr-review.mjs");
  }

  // Same contract as run() above, against a staged script + config.
  function runStaged(configText, review) {
    const script = stage(configText);
    const dir = mkdtempSync(join(tmpdir(), "prr-in-"));
    dirs.push(dir);
    writeFileSync(join(dir, "diff.txt"), DIFF);
    writeFileSync(join(dir, "review.json"), JSON.stringify(review));
    const env = { ...process.env, PR_INPUT_DIR: dir, EXECUTION_FILE: "" };
    delete env.RUNNER_TEMP;
    const res = spawnSync("node", [script], { env, encoding: "utf8" });
    const payloadPath = join(dir, "review-payload.json");
    return {
      code: res.status,
      stderr: res.stderr,
      payload: existsSync(payloadPath)
        ? JSON.parse(readFileSync(payloadPath, "utf8"))
        : null,
    };
  }

  const NIT = {
    verdict: "looks_good",
    summary: "one small thing",
    findings: [
      {
        path: "src/foo.js",
        line: 2,
        side: "RIGHT",
        severity: "nit",
        title: "naming",
        body: "prefer b2",
      },
    ],
  };
  const config = (over) =>
    JSON.stringify({
      gating: ["blocking", "warning", "nit"],
      icons: { blocking: "🔴", warning: "🟡", nit: "🔵" },
      ...over,
    });

  it("drops a severity from `gating` and the review stops holding the merge", () => {
    // THE falsifier for the whole wiring: identical input, one edited config
    // value, and the posted review event changes. If both runs agreed, the
    // config would be documentation nobody reads.
    const held = runStaged(config({}), NIT);
    assert.equal(held.payload.event, "REQUEST_CHANGES");
    const released = runStaged(
      config({ gating: ["blocking", "warning"] }),
      NIT,
    );
    assert.equal(released.payload.event, "APPROVE");
    assert.equal(
      released.payload.comments.length,
      1,
      "the finding still posts",
    );
  });

  it("an edited icon reaches the posted comment body", () => {
    const { payload } = runStaged(
      config({ icons: { blocking: "🔴", warning: "🟡", nit: "🧢" } }),
      NIT,
    );
    assert.match(payload.comments[0].body, /^🧢 /);
  });

  it("renders the icon for a severity the model cased differently", () => {
    // The gate lowercases before testing membership, so a cased severity holds
    // the merge; the glyph must follow it rather than falling back to "•".
    const { payload } = runStaged(config({}), {
      ...NIT,
      findings: [{ ...NIT.findings[0], severity: " Nit " }],
    });
    assert.equal(payload.event, "REQUEST_CHANGES");
    assert.match(payload.comments[0].body, /^🔵 /);
  });

  it("an absent config keeps the shipped model rather than failing", () => {
    // `config/` is not in template-sync's SYNC_PATHS, so every repo that syncs
    // this script gets it WITHOUT the config file. Treating that as fatal would
    // red every review in every downstream repo, on a file that cannot arrive.
    const { code, payload } = runStaged(null, NIT);
    assert.equal(code, 0);
    assert.equal(payload.event, "REQUEST_CHANGES", "nit gates by default");
    assert.match(payload.comments[0].body, /^🔵 /);
  });

  for (const [why, text] of [
    ["the config is not JSON", "{ not json"],
    // An empty gating set approves every review and retires the hold with no
    // other symptom — the one failure a default would make invisible.
    ["`gating` is empty", config({ gating: [] })],
    ["`gating` is absent", '{"icons":{"nit":"🔵"}}'],
    ["`icons` is absent", '{"gating":["nit"]}'],
    ["the config is a bare JSON null", "null"],
    ["`icons` is an array", '{"gating":["0"],"icons":["🔵"]}'],
    ["a gating severity has no icon", config({ icons: { blocking: "🔴" } })],
    ["an icon is not a string", config({ icons: { nit: 7 } })],
  ]) {
    it(`fails closed when ${why}`, () => {
      const { code, payload, stderr } = runStaged(text, NIT);
      assert.notEqual(code, 0, stderr);
      assert.equal(
        payload,
        null,
        "nothing may post on an unknown severity model",
      );
      assert.match(stderr, /review-severities\.json/);
    });
  }
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
