/**
 * A gate whose verdict is a pure function of PR review state can only be as
 * fresh as the last thing that recomputed it, and in this repo the events that
 * would recompute it do not fire.
 *
 * `review-gate.yaml` and `review-findings-gate.yaml` both key on
 * `pull_request_review`. GitHub does not emit that event for a review posted,
 * dismissed or edited with GITHUB_TOKEN — the recursion guard — so every review
 * this repo's own automation files is invisible to them. Their other leg is a
 * push, which has already happened by the time the review lands. The verdict
 * then survives as whatever it last computed, wrong in both directions: pending
 * on a PR that has been reviewed (observed on #290, and auto-merge waits on it
 * forever), or green on one whose only review was dismissed, which is fail-open
 * on a required merge gate.
 *
 * So the invariant, checked here: EVERY job that mutates review state also
 * re-derives EVERY review-keyed gate, in the same job. Both sides are derived
 * from the tree rather than listed — a new gate on that trigger, or a new job
 * that posts a review, is caught the day it is written rather than the day a PR
 * hangs. `reconcile-review-gate.sh`'s cron bounds the damage to one sweep
 * interval; this bounds it to zero for anything a reviewer can see in a diff.
 *
 * An exemption is a `# review-gate-exempt: <reason>` marker in the exempt
 * workflow's own file, so the excuse travels with the thing it excuses and
 * deleting the workflow deletes the excuse.
 *
 * LIMIT, stated rather than implied: the call graph is TEXTUAL, so a script that
 * still names a gate reads as re-deriving it even if the call is now dead code.
 * What this catches is the realistic regression — a new review-writing job, or a
 * reverted block — and all three of those red it. What it cannot catch is a
 * live-but-unreachable call, which is a job for review and for lint.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import { parse } from "yaml";

const repoRoot = execFileSync("git", ["rev-parse", "--show-toplevel"], {
  encoding: "utf8",
}).trim();

const tracked = (glob) =>
  execFileSync("git", ["ls-files", "--", glob], {
    cwd: repoRoot,
    encoding: "utf8",
  })
    .split("\n")
    .filter(Boolean);

const read = (relative) => readFileSync(join(repoRoot, relative), "utf8");

const workflowPaths = [
  ...tracked(".github/workflows/*.yaml"),
  ...tracked(".github/workflows/*.yml"),
];
const scriptPaths = tracked(".github/scripts/*.sh");

/**
 * Two shapes, one marker. Bare — `# review-gate-exempt: <reason>` — on a
 * workflow that keys on `pull_request_review` but is no gate. Qualified —
 * `# review-gate-exempt(<context>): <reason>` — on a workflow whose jobs change
 * review state and deliberately do NOT re-derive that one gate.
 */
const EXEMPT_MARKER = /#\s*review-gate-exempt:\s*(?<reason>\S.*)/;
const SCOPED_EXEMPT =
  /#\s*review-gate-exempt\((?<context>[^)]+)\):\s*(?<reason>\S.*)/g;

const scopedExemptions = (source) =>
  new Set([...source.matchAll(SCOPED_EXEMPT)].map((m) => m.groups.context));

/** Every `run:` body in a workflow, keyed by the job that owns it. */
function jobsWithRunBodies(source) {
  const doc = parse(source);
  return Object.entries(doc?.jobs ?? {}).map(([id, job]) => ({
    id,
    runs: (job?.steps ?? [])
      .map((step) => step?.run)
      .filter((run) => typeof run === "string"),
  }));
}

/**
 * The scripts a shell command invokes, as repo-relative `.github/scripts` paths.
 * Matched on the FULL path, never the bare basename: `reconcile-review-gate.sh`
 * ends with `review-gate.sh`, so a basename test reports a job as running a gate
 * it never runs — the guard would then pass by mis-reading its own evidence.
 */
const scriptsIn = (command) =>
  scriptPaths.filter((path) => command.includes(path));

/** How one script names another, on a boundary so a suffix cannot collide. */
const invocationOf = (path) =>
  new RegExp(`(?:^|[\\s"'/])${path.slice(".github/scripts/".length)}\\b`, "m");

/**
 * A script MUTATES review state when it CREATES or DISMISSES a review — the two
 * acts that move the gates' predicates. Matched on the write verb, so the reads
 * every gate script performs against the same `/reviews` endpoint do not count
 * themselves in, and an edit of a review's BODY does not either (it changes no
 * predicate). Derived from what the scripts call, so a writer added later joins
 * this set without anyone remembering to list it.
 */
const MUTATES_REVIEW =
  /gh pr review|(?:-X|--method) POST[^\n]*\/reviews\b|(?:-X|--method) PUT[^\n]*\/dismissals\b/;

/**
 * Which scripts each script can reach, as a call graph over `.github/scripts`.
 * BOTH questions this file asks are reachability questions — "does this job end
 * up writing a review?" and "does it end up re-deriving the gate?" — and the
 * hops are real: the cron job runs `sweep-reviewer-holds.sh`, which delegates to
 * `approve-if-reviewer-hold-clear.sh`, which is where both the write and the
 * re-derivation live. A depth-1 answer to either one is wrong.
 */
const callGraph = new Map(
  scriptPaths.map((path) => [
    path,
    scriptPaths.filter(
      (other) => other !== path && invocationOf(other).test(read(path)),
    ),
  ]),
);

const reachableFrom = (roots) => {
  const seen = new Set(roots);
  const stack = [...roots];
  while (stack.length > 0)
    for (const next of callGraph.get(stack.pop()) ?? []) {
      if (seen.has(next)) continue;
      seen.add(next);
      stack.push(next);
    }
  return seen;
};

const writesReviewDirectly = new Set(
  scriptPaths.filter((path) => MUTATES_REVIEW.test(read(path))),
);

const reviewMutatingScripts = scriptPaths.filter((path) =>
  [...reachableFrom([path])].some((reached) =>
    writesReviewDirectly.has(reached),
  ),
);

/**
 * A workflow is a review-keyed GATE when it triggers on `pull_request_review`
 * and is not exempt. Two things can then re-derive its verdict, and a job needs
 * EITHER: run the gate's own script, or write the gate's context directly — the
 * skipped class does the latter on purpose, because the gate's real predicate
 * says red for a PR nothing reviewed and the skip decision is what licenses it.
 * The context string is read out of the script that owns it rather than restated
 * here, so a rename moves both sides at once.
 */
const CONTEXT_CONSTANT = /^(?:CHECK_NAME|GATE_CONTEXT)="(?<context>[^"]+)"/m;

const reviewKeyedGates = workflowPaths.flatMap((path) => {
  const source = read(path);
  const doc = parse(source);
  if (!("pull_request_review" in (doc?.on ?? {}))) return [];
  if (EXEMPT_MARKER.test(source)) return [];
  const scripts = [
    ...new Set(
      jobsWithRunBodies(source).flatMap((job) => job.runs.flatMap(scriptsIn)),
    ),
  ];
  const contexts = scripts
    .map((script) => CONTEXT_CONSTANT.exec(read(script))?.groups.context)
    .filter(Boolean);
  return [{ path, scripts, contexts }];
});

describe("review-keyed gates are re-derived wherever review state changes", () => {
  // Non-vacuity: the whole file passes trivially if either side comes up empty,
  // which is exactly what a refactor that renames a trigger or a script would do.
  it("finds both a gate and a review-mutating script to check", () => {
    assert.ok(
      reviewKeyedGates.length > 0,
      "no workflow triggers on pull_request_review — the derivation is broken, not the repo",
    );
    assert.ok(
      reviewMutatingScripts.length > 0,
      "no .github/scripts file posts or dismisses a review — the derivation is broken",
    );
    for (const gate of reviewKeyedGates)
      assert.ok(
        gate.contexts.length > 0,
        `${gate.path} keys on pull_request_review but no script it runs declares a CHECK_NAME/GATE_CONTEXT, so no job can be shown to compensate for it`,
      );
  });

  it("every job that mutates review state re-derives every gate", () => {
    const gaps = [];
    for (const path of workflowPaths) {
      const source = read(path);
      const exempt = scopedExemptions(source);
      for (const job of jobsWithRunBodies(source)) {
        const body = job.runs.join("\n");
        const ran = job.runs.flatMap(scriptsIn);
        // A step can write a review INLINE — this tree already posts a check run
        // that way — and such a job reaches no script at all, so testing only
        // `ran` would let the very regression this file promises to catch pass.
        if (
          !MUTATES_REVIEW.test(body) &&
          !ran.some((script) => reviewMutatingScripts.includes(script))
        )
          continue;
        for (const gate of reviewKeyedGates) {
          if (gate.contexts.some((context) => exempt.has(context))) continue;
          // Re-derivation is transitive too: a step that runs the reconciler
          // runs the gate script, one call deeper.
          const reached = reachableFrom(ran);
          const rederived =
            gate.scripts.some((script) => reached.has(script)) ||
            gate.contexts.some((context) => body.includes(context));
          if (!rederived)
            gaps.push(
              `${path}:${job.id} changes review state but re-derives neither ${gate.scripts.join("/")} nor its context ${JSON.stringify(gate.contexts)}`,
            );
        }
      }
    }
    assert.deepEqual(
      gaps,
      [],
      "a review posted with GITHUB_TOKEN fires no pull_request_review event, so each of these leaves a required gate holding a stale verdict",
    );
  });

  it("every exemption states a reason", () => {
    for (const path of workflowPaths) {
      const source = read(path);
      const match = EXEMPT_MARKER.exec(source);
      if (!match) continue;
      assert.ok(
        "pull_request_review" in (parse(source)?.on ?? {}),
        `${path} is marked review-gate-exempt but does not key on pull_request_review — delete the stale marker`,
      );
      assert.ok(
        match.groups.reason.trim().length > 10,
        `${path}'s review-gate-exempt marker needs a reason, not a token`,
      );
    }
  });
});
