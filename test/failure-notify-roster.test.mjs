/**
 * Every workflow that can fail unseen is either on the notifier's roster or
 * exempt IN ITS OWN FILE — a partition, checked here.
 *
 * A push-to-main or scheduled run emits no PR webhook: nothing turns red on
 * anyone's screen. `ci-failure-notify.yaml` converts such a failure into a phone
 * push, and `workflow_run` has no wildcard, so its `workflows:` list has to name
 * each one. That list claimed to be kept honest by "a ci-truth-serum hook
 * (check-failure-notifier-coverage)". No such hook exists: the pinned rev
 * provides 18 `check-*` ids and not one of them references this file. The gap
 * that fiction covered was live — `Mutation tests` and `Pack smoke test` both
 * run on push-to-main and were on no roster, so they could fail on `main`
 * indefinitely and page nobody.
 *
 * The exemptions live as a `# failure-notify-exempt: <reason>` marker in the
 * exempt workflow's own yaml rather than as prose in a third file (they were
 * justified only in a comment in `.github/scripts/main-health.mjs`). A reason
 * that travels with the thing it excuses is one a reader of that thing can find,
 * and deleting the workflow deletes the excuse with it.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";

import {
  NOTIFIER_WORKFLOW_PATH,
  pagedWorkflowNames,
} from "../.github/scripts/main-health.mjs";

const repoRoot = execFileSync("git", ["rev-parse", "--show-toplevel"], {
  encoding: "utf8",
}).trim();

const read = (relative) => readFileSync(join(repoRoot, relative), "utf8");

const workflowFiles = execFileSync(
  "git",
  ["ls-files", "--", ".github/workflows/*.yaml", ".github/workflows/*.yml"],
  { cwd: repoRoot, encoding: "utf8" },
)
  .split("\n")
  .filter(Boolean);

/** The lines of the top-level `on:` block, comments and blanks dropped. */
function onBlock(yaml, path) {
  const lines = yaml.split("\n");
  // `on: # zizmor: ignore[…]` is a real form in this tree, so a trailing
  // comment is allowed — but nothing else on the line is.
  const start = lines.findIndex((line) => /^on:\s*(#.*)?$/.test(line));
  // Fail loud: a workflow this parser cannot read must not silently count as
  // "has no triggers", which would excuse it from the partition entirely.
  if (start === -1) throw new Error(`${path}: no top-level \`on:\` block`);
  const block = [];
  for (const line of lines.slice(start + 1)) {
    if (/^\s*(#.*)?$/.test(line)) continue;
    if (/^\S/.test(line)) break;
    block.push(line);
  }
  if (block.length === 0) throw new Error(`${path}: empty \`on:\` block`);
  return block;
}

/** The branch names a `push:` trigger is restricted to, or null for "any". */
function pushBranches(block) {
  const pushAt = block.findIndex((line) => /^ {2}push:\s*(#.*)?$/.test(line));
  if (pushAt === -1) return undefined;
  const branches = [];
  let inBranches = false;
  for (const line of block.slice(pushAt + 1)) {
    if (/^ {2}\S/.test(line)) break; // next trigger key
    const key = line.match(/^ {4}([a-z_]+):\s*(.*?)\s*$/);
    if (key) {
      inBranches = key[1] === "branches";
      // Inline form: `branches: [main]` / `branches: ["main", "next"]`.
      if (inBranches && key[2] !== "")
        return key[2]
          .replace(/^\[|\]$/g, "")
          .split(",")
          .map((name) => name.trim().replace(/^["']|["']$/g, ""));
      continue;
    }
    const item = line.match(/^ {6}-\s*(.*?)\s*$/);
    if (inBranches && item) branches.push(item[1].replace(/^["']|["']$/g, ""));
  }
  // A `push:` with no `branches:` fires on every branch, main included.
  return branches.length > 0 ? branches : null;
}

/** Whether a workflow can fail with nobody watching: push-to-main or schedule. */
function firesUnwatched(yaml, path) {
  const block = onBlock(yaml, path);
  if (block.some((line) => /^ {2}schedule:\s*(#.*)?$/.test(line))) return true;
  const branches = pushBranches(block);
  if (branches === undefined) return false;
  return branches === null || branches.includes("main");
}

const EXEMPT_MARKER = /^#\s*failure-notify-exempt:\s*(\S.*)$/m;

const workflows = workflowFiles.map((path) => {
  const yaml = read(path);
  const name = yaml.match(/^name:\s*(.*?)\s*$/m)?.[1];
  if (!name) throw new Error(`${path}: no top-level \`name:\``);
  return {
    path,
    name,
    unwatched: firesUnwatched(yaml, path),
    exemption: yaml.match(EXEMPT_MARKER)?.[1],
  };
});

const unwatched = workflows.filter((wf) => wf.unwatched);
const roster = pagedWorkflowNames(read(NOTIFIER_WORKFLOW_PATH));

describe("post-merge failure-notification roster", () => {
  it("recognises the triggers it is supposed to, and only those", () => {
    // Non-vacuity: a parser that answered `false` everywhere would make the
    // partition below hold over an empty set.
    assert.ok(
      unwatched.length >= 20,
      `only ${unwatched.length} unwatched workflows detected`,
    );
    const byName = new Map(workflows.map((wf) => [wf.name, wf.unwatched]));
    for (const [name, expected] of [
      ["Node tests", true], // push: branches: ["main"]
      ["Main branch health", true], // schedule only
      ["Auto-resolve merge conflicts", true], // push: branches: [main]
      ["Nightly unseeded fuzz", true], // schedule only, and exempt below
      ["PR meta", false], // pull_request only
      ["Claude PR review", false], // pull_request_target only
      ["Decide (reusable)", false], // workflow_call only
      ["CI failure notify", false], // workflow_run only — it IS the listener
    ]) {
      assert.ok(byName.has(name), `no workflow named ${name}`);
      assert.equal(byName.get(name), expected, `${name} classified wrongly`);
    }
  });

  it("reads a push restricted away from main as watched", () => {
    // Fixed inputs, because no workflow in the tree currently pushes to a
    // non-main branch — without these the `includes("main")` arm would never be
    // exercised against a negative and could be a constant `true`.
    const on = (body) => `name: probe\n\non:\n${body}\njobs: {}\n`;
    assert.equal(
      firesUnwatched(on("  push:\n    branches: [main]\n"), "p"),
      true,
    );
    assert.equal(
      firesUnwatched(on("  push:\n    branches: [next]\n"), "p"),
      false,
    );
    assert.equal(
      firesUnwatched(
        on("  push:\n    branches:\n      - next\n      - main\n"),
        "p",
      ),
      true,
    );
    assert.equal(firesUnwatched(on("  push:\n"), "p"), true);
    assert.equal(firesUnwatched(on("  pull_request:\n"), "p"), false);
    // `paths:` under push must not be mistaken for `branches:`.
    assert.equal(
      firesUnwatched(on("  push:\n    paths:\n      - src/**\n"), "p"),
      true,
    );
    assert.throws(
      () => firesUnwatched("name: probe\njobs: {}\n", "p"),
      /no top-level/,
    );
  });

  it("partitions every unwatched workflow into roster or a declared exemption", () => {
    const unrostered = unwatched
      .filter((wf) => !roster.has(wf.name) && wf.exemption === undefined)
      .map((wf) => `${wf.path} (${wf.name})`);
    assert.deepEqual(
      unrostered,
      [],
      "these run on push-to-main or a schedule and route to NOBODY: add the " +
        "workflow's `name:` to `workflows:` in .github/workflows/ci-failure-notify.yaml, " +
        "or put a `# failure-notify-exempt: <reason>` comment in the workflow itself",
    );

    const both = unwatched
      .filter((wf) => roster.has(wf.name) && wf.exemption !== undefined)
      .map((wf) => wf.path);
    assert.deepEqual(both, [], "workflows are both rostered and exempt");

    // The roster's other direction: a name matching no unwatched workflow is a
    // dead entry, and `workflow_run` binds by name, so it can never fire.
    const names = new Set(unwatched.map((wf) => wf.name));
    assert.deepEqual(
      [...roster].filter((name) => !names.has(name)),
      [],
      "ci-failure-notify.yaml lists workflows that no longer run on push-to-main or a schedule",
    );
  });

  it("keeps every exemption declared in its own file, with a real reason", () => {
    const exempt = workflows.filter((wf) => wf.exemption !== undefined);
    // Non-vacuity for the marker regex: it has to actually match something, or
    // the partition above degenerates into "the roster covers everything".
    assert.deepEqual(
      exempt.map((wf) => wf.path),
      [".github/workflows/fuzz-nightly.yaml"],
      "the exempt set changed — every entry needs its reasoning reviewed",
    );
    for (const wf of exempt)
      assert.ok(
        wf.exemption.length > 30,
        `${wf.path}: failure-notify-exempt needs a real reason, got "${wf.exemption}"`,
      );
    // An exemption on a workflow that cannot fail unwatched excuses nothing.
    for (const wf of exempt)
      assert.ok(wf.unwatched, `${wf.path} is exempt from a rule it never met`);
  });

  it("routes the two workflows the missing hook left unrouted", () => {
    // Pinned by name: these are the concrete holes the fictional
    // check-failure-notifier-coverage was credited with preventing, and a revert
    // that drops them again must fail here rather than only in the partition.
    for (const name of ["Mutation tests", "Pack smoke test"])
      assert.ok(roster.has(name), `${name} is unrouted again`);
  });
});
