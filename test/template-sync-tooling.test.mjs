/**
 * The `sync` job of `template-sync.yaml` runs its scripts from a staged copy,
 * never from the working tree — asserted over the job the workflow declares.
 *
 * `SYNC_PATHS` covers `.github/scripts`, so `template-sync.sh` writes conflict
 * markers into the sync job's own tooling, and the resolve step then checks out
 * the `template-sync` branch. A later `bash .github/scripts/x.sh` therefore
 * reads a marker-bearing copy of the very script it is running: run
 * 33209471506 died on `template-sync-resolve.sh: line 38: syntax error near
 * unexpected token '<<<'`. The fix stages the default branch's `.github/` to
 * `${RUNNER_TEMP}` and points every `run:` at `$SYNC_TOOLS`.
 *
 * Whole-directory staging removed the per-SCRIPT decision, not the per-STEP
 * one: each step still opts in by hand. A step added later that writes `bash
 * .github/scripts/x.sh` re-enters the identical bug, reads as correct in
 * review, and passes YAML parsing, zizmor and `bash -n`. It fails only in a
 * live sync run that hits conflicts — the rarest path, and the one that already
 * cost a red weekly run.
 *
 * The job's steps are ITERATED, not listed: a fixed list of the seven paths
 * that exist today goes stale the moment a step is added, which is the exact
 * failure this file exists to catch. `preflight` is deliberately out of scope —
 * it is a separate job on a sparse checkout that nothing has written to yet.
 *
 * Two carve-outs, both derived rather than named. The step that BUILDS the
 * staged tree reads the working tree by construction, and it runs before
 * anything has written to it; it is found by the step id the `SYNC_TOOLS`
 * expression points at, so renaming the step does not silently widen the
 * exemption. And a script may run from any staged tree, not only this one —
 * the job already clones the resolver to `${RUNNER_TEMP}/resolver` and exports
 * `RESOLVER_DIR` — so the requirement is that a script path starts from a
 * variable, plus a check that `$SYNC_TOOLS` is still the mechanism in use.
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

const WORKFLOW = ".github/workflows/template-sync.yaml";

const workflow = parse(readFileSync(join(repoRoot, WORKFLOW), "utf8"));
const syncJob = workflow?.jobs?.sync;

/** The name a step reports itself by, for an assertion message. */
const label = (step, index) => step.name ?? step.id ?? `step #${index + 1}`;

/**
 * The id of the step that stages the tooling, read out of the expression the
 * other steps point at (`${{ steps.<id>.outputs.… }}`) rather than hardcoded.
 */
const stagingStepId = JSON.stringify(syncJob ?? null).match(
  /steps\.([A-Za-z0-9_-]+)\.outputs\.[A-Za-z0-9_-]+\s*\}\}/,
)?.[1];

/**
 * The expression a step must bind `SYNC_TOOLS` to.
 *
 * Presence of the key is not the invariant: `SYNC_TOOLS: .github/scripts` with
 * `run: bash "$SYNC_TOOLS/x.sh"` clears every other assertion in this file and
 * still runs the marker-bearing copy — the bug run 33209471506 hit.
 */
const STAGED_SCRIPTS = `\${{ steps.${stagingStepId}.outputs.scripts }}`;

/** Every step of the `sync` job that runs a shell block, with its index. */
const runSteps = (syncJob?.steps ?? [])
  .map((step, index) => ({ step, index }))
  .filter(({ step }) => typeof step.run === "string")
  .filter(({ step }) => step.id !== stagingStepId);

/**
 * Every token ending in `.sh` inside a `run:` block, quotes stripped.
 *
 * A script path is one shell word, so a whitespace split recovers it; the
 * surrounding quotes are the only decoration this workflow puts on one. That is
 * enough to read WHICH tree a path names, which is the whole question here —
 * it is not a shell parser and makes no claim about what the block executes.
 */
const scriptTokens = (run) =>
  run
    .split(/\s+/)
    .filter((word) => /\.sh(["']?)$/.test(word))
    .map((word) => word.replace(/^["']|["']$/g, ""));

describe("template-sync.yaml: the sync job runs staged tooling", () => {
  it("declares a sync job with steps that run shell", () => {
    assert.ok(syncJob, `${WORKFLOW}: no \`sync\` job`);
    // Non-vacuity: every assertion below iterates this set, so an empty one
    // would pass them all while checking nothing.
    assert.ok(
      runSteps.length > 0,
      `${WORKFLOW}: the \`sync\` job declares no \`run:\` steps`,
    );
  });

  it("names no script in the working tree", () => {
    for (const { step, index } of runSteps)
      assert.ok(
        !step.run.includes(".github/scripts"),
        `${WORKFLOW}: ${label(step, index)} names .github/scripts — the sync ` +
          `writes conflict markers there, so run it from "$SYNC_TOOLS/…" instead`,
      );
  });

  it("roots every script path in a staged-tree variable", () => {
    const seen = [];
    for (const { step, index } of runSteps)
      for (const token of scriptTokens(step.run)) {
        seen.push(token);
        assert.ok(
          /^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?\//.test(token),
          `${WORKFLOW}: ${label(step, index)} runs ${token}, a path this job's ` +
            `own sync can rewrite — run it from a staged tree ("$SYNC_TOOLS/…")`,
        );
      }
    // Non-vacuity: the loop above is silent on a job that runs no script at
    // all, which is also what a renamed staging scheme would look like. The
    // second assertion keeps `$SYNC_TOOLS` the mechanism rather than one
    // variable among many — the first would pass on a job that staged nothing.
    assert.ok(
      seen.length > 0,
      `${WORKFLOW}: the \`sync\` job invokes no \`.sh\` script — this file no ` +
        `longer checks what it was written for`,
    );
    assert.ok(
      seen.some((token) => /^\$\{?SYNC_TOOLS\}?\//.test(token)),
      `${WORKFLOW}: no script runs from "$SYNC_TOOLS/" any more — the staged ` +
        `tree this file is about is no longer in use`,
    );
  });

  it("sets SYNC_TOOLS to the staged copy in every step that reads it", () => {
    for (const { step, index } of runSteps) {
      if (!step.run.includes("SYNC_TOOLS")) continue;
      assert.equal(
        (step.env ?? {}).SYNC_TOOLS ?? (syncJob.env ?? {}).SYNC_TOOLS,
        STAGED_SCRIPTS,
        `${WORKFLOW}: ${label(step, index)} reads $SYNC_TOOLS but does not set ` +
          `it to the staged copy — add \`SYNC_TOOLS: ${STAGED_SCRIPTS}\` to the ` +
          `step's env, or to the job's`,
      );
    }
  });
});
