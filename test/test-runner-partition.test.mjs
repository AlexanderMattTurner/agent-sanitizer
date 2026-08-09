/**
 * Every committed test suite is CLAIMED by a runner that actually executes it.
 *
 * `node --test`'s default discovery skips dot-directories. That is not a
 * hypothetical: planting three always-failing suites — one under `test/`, one
 * under `.claude/hooks/`, one under `.hooks/` — and running the default
 * discovery finds exactly the first, and the run goes green with two failing
 * suites in the tree. `.pre-commit-config.yaml` had even grown an
 * `exclude: \.test\.mjs$` on its `^\.claude/hooks/.*\.mjs$` lints: the config
 * anticipated suites in a directory no runner reached.
 *
 * The repo answers that for `.github/scripts` (a discovery script), for
 * `plugin/test` and for the credential-ladder suite (explicit workflow steps),
 * and now for the dot-hook directories (a pre-commit hook). What nothing did was
 * check the SET: a suite that lands somewhere none of them look is a file full
 * of assertions that never run, and it looks exactly like a passing one.
 *
 * So this enumerates the runners, derives what each claims FROM ITS OWN
 * CONFIGURATION (the workflow's `node --test` arguments, the discovery script's
 * git pathspec, the pre-commit hook's `files:` regex) rather than from a copy
 * of it here, and asserts the union covers every tracked `*.test.mjs`. Claims
 * may overlap — `plugin/test/*.test.mjs` is both discovered by `pnpm test` and
 * named explicitly in the workflow, deliberately — so the assertion is coverage,
 * not disjointness.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  globSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";

// The shipped tree, not the instrumented copy Stryker runs this beside. Resolved
// from the helper's own location rather than `git rev-parse --show-toplevel`:
// that call appeared to work only because the sandbox sits inside the checkout,
// so git walked up out of it silently. `git ls-files` below still asks git, but
// for a different question — which paths are TRACKED — anchored to this root.
import { repoRoot as REPO_ROOT } from "../.hooks/lib/repo-root.mjs";

const read = (relative) => readFileSync(join(REPO_ROOT, relative), "utf8");

/** Tracked paths matching a git pathspec, repo-relative. */
const tracked = (...pathspecs) =>
  execFileSync("git", ["ls-files", "--", ...pathspecs], {
    cwd: REPO_ROOT,
    encoding: "utf8",
  })
    .split("\n")
    .filter(Boolean);

const SUITES = tracked("*.test.mjs");

const WORKFLOWS = tracked(
  ".github/workflows/*.yaml",
  ".github/workflows/*.yml",
);

/**
 * Whether `path` would be found by `node --test` with no file arguments.
 *
 * The rule is Node's, not ours, and `runnerDiscoveryRule` below re-derives it
 * from a real `node --test` run over a scratch tree — a hardcoded predicate
 * that Node later changed would silently claim files nothing runs.
 */
const discoveredByDefault = (path) =>
  path.endsWith(".test.mjs") &&
  !path.split("/").some((segment) => segment.startsWith("."));

/**
 * The file arguments of every `run: node --test …` step in the workflows.
 *
 * Anchored on `run:` so the prose ABOUT `node --test` in node-tests.yaml's
 * comments (which is where the dot-directory blind spot is explained) is not
 * mistaken for an invocation.
 */
function workflowTestGlobs() {
  const globs = [];
  for (const workflow of WORKFLOWS)
    for (const line of read(workflow).split("\n")) {
      const run = line.match(/^\s*run:\s*node --test\s+(.*?)\s*$/);
      if (run) globs.push(...run[1].split(/\s+/));
    }
  return globs;
}

/** The git pathspec the .github/scripts discovery script enumerates. */
function discoveryPathspec() {
  const script = read(".github/scripts/run-script-tests.sh");
  const match = script.match(/git ls-files -- '([^']+)'/);
  // Fail loud: a rewritten invocation this parser no longer recognises must not
  // read as "the script claims nothing", which would blame the suites instead.
  if (!match)
    throw new Error(
      "run-script-tests.sh: no `git ls-files -- '<pathspec>'` invocation found",
    );
  return match[1];
}

/**
 * One local pre-commit hook's body, as a `key: value` map.
 *
 * Hand-rolled rather than parsed with a YAML library because the repo has no
 * YAML dependency (see `pagedWorkflowNames` in .github/scripts/main-health.mjs
 * for the same trade-off), and deliberately narrow: it takes the lines of one
 * block-sequence item and throws when the id is absent rather than returning an
 * empty map that would read as "the hook claims nothing".
 */
function precommitHook(id) {
  const lines = read(".pre-commit-config.yaml").split("\n");
  const start = lines.findIndex((line) =>
    new RegExp(`^\\s*- id: ${id}\\s*$`).test(line),
  );
  if (start === -1)
    throw new Error(`.pre-commit-config.yaml: no hook with id ${id}`);
  const indent = lines[start].match(/^\s*/)[0].length;
  const body = {};
  for (const line of lines.slice(start + 1)) {
    if (/^\s*$/.test(line)) continue;
    const entry = line.match(/^(\s*)([a-z_]+):\s*(.*?)\s*$/);
    if (!entry || entry[1].length <= indent) break;
    body[entry[2]] = entry[3];
  }
  return body;
}

const DOT_HOOK = precommitHook("dot-directory-test-suites");
const DOT_HOOK_FILES = new RegExp(DOT_HOOK.files);

/** A `claims` predicate over a fixed, eagerly-resolved path list. */
const memberOf = (paths) => {
  const set = new Set(paths);
  return (path) => set.has(path);
};

/**
 * Every runner that executes committed suites, and what each one claims.
 * `claims` is a repo-relative predicate; `where` is what a contributor must edit
 * to widen it.
 */
const RUNNERS = [
  {
    name: "pnpm test (node --test default discovery)",
    where: "package.json scripts.test -> scripts/coverage.mjs",
    claims: discoveredByDefault,
  },
  {
    // Resolved once: `claims` is called for every suite, and re-shelling out to
    // git per call turns a set membership test into a hundred subprocesses.
    name: ".github/scripts/run-script-tests.sh",
    where: "its git ls-files pathspec",
    claims: memberOf(tracked(discoveryPathspec())),
  },
  {
    name: "explicit `node --test` workflow steps",
    where: ".github/workflows/*.yaml",
    claims: memberOf(
      workflowTestGlobs().flatMap((pattern) =>
        globSync(pattern, { cwd: REPO_ROOT }),
      ),
    ),
  },
  {
    name: "pre-commit hook dot-directory-test-suites",
    where: ".pre-commit-config.yaml",
    claims: (path) => DOT_HOOK_FILES.test(path),
  },
];

/** The runners claiming `path`. */
const claimants = (path) =>
  RUNNERS.filter((runner) => runner.claims(path)).map((runner) => runner.name);

describe("test-runner discovery partition", () => {
  it("has a non-empty suite set with a suite in every runner's territory", () => {
    // Non-vacuity for everything below: an empty SUITES (a broken ls-files, a
    // pathspec typo) would make the coverage assertion pass over nothing.
    assert.ok(SUITES.length > 50, `only ${SUITES.length} suites tracked`);
    for (const known of [
      "test/guard-pairs.test.mjs",
      "test/test-runner-partition.test.mjs",
      ".github/scripts/main-health.test.mjs",
      ".github/scripts/auto-resolve/lib.test.mjs",
      ".github/scripts/lib/anthropic-ladder.test.mjs",
      "plugin/test/plugin-bundle.test.mjs",
      "scripts/version-bump.test.mjs",
    ])
      assert.ok(SUITES.includes(known), `${known} is not a tracked suite`);
  });

  it("claims every tracked *.test.mjs with at least one runner", () => {
    const orphans = SUITES.filter((path) => claimants(path).length === 0);
    assert.deepEqual(
      orphans,
      [],
      "these suites run in NO job — `node --test`'s default discovery skips " +
        "dot-directories, so a suite there is silently never executed. Register " +
        "each with a runner: " +
        RUNNERS.map((r) => `${r.name} (${r.where})`).join("; "),
    );
  });

  it("gives every runner something to run", () => {
    // A runner whose claim set went empty — a glob that stopped matching, a
    // pathspec that no longer resolves — is the exact failure run-script-tests.sh
    // exists to fail loud on, and it would leave the assertion above passing
    // because some OTHER runner happens to cover the same files.
    for (const runner of RUNNERS.filter(
      (r) => r.name !== "pre-commit hook dot-directory-test-suites",
    )) {
      const claimed = SUITES.filter(runner.claims);
      assert.ok(claimed.length > 0, `${runner.name} claims no suite`);
    }
    // The dot-directory hook legitimately claims nothing TODAY (no suite lives
    // there yet), so its predicate is proven against fixed inputs instead — the
    // regex has to work on the day the first such suite lands.
    for (const wanted of [
      ".claude/hooks/drop-superseded-ci-events.test.mjs",
      ".hooks/run-guard-pairs.test.mjs",
    ])
      assert.ok(DOT_HOOK_FILES.test(wanted), `${wanted} would not be run`);
    for (const unwanted of [
      ".claude/hooks/drop-superseded-ci-events.mjs",
      "test/guard-pairs.test.mjs",
      ".github/scripts/main-health.test.mjs",
    ])
      assert.ok(!DOT_HOOK_FILES.test(unwanted), `${unwanted} matched the hook`);
  });

  it("checks each derived runner is actually invoked by something", () => {
    // A claim read from the runner's OWN configuration stays true after nothing
    // invokes that runner any more: delete the workflow step and
    // run-script-tests.sh, its pathspec and therefore its claim are all still
    // there, so its suites run in no job while the partition above stays green.
    // That is the one-direction gate this file exists to close, one level up.
    assert.match(
      WORKFLOWS.map(read).join("\n"),
      /run-script-tests\.sh/u,
      "no workflow invokes run-script-tests.sh, so its claim runs nothing",
    );
    // `discoveredByDefault` stands in for `pnpm test` reaching `node --test`;
    // repointing that script would retire the largest claim silently.
    assert.match(
      JSON.parse(read("package.json")).scripts.test,
      /^node scripts\/coverage\.mjs$/u,
      "`pnpm test` no longer reaches `node --test`, so default discovery claims nothing",
    );
  });

  it("runs the dot-directory suites rather than merely linting them", () => {
    // `entry: node --test` with pre-commit's default pass_filenames means the
    // matched paths ARE the arguments. Turning that off would hand `node --test`
    // no files, which falls back to default discovery — the very blind spot this
    // hook exists to cover, reported as a pass.
    assert.equal(DOT_HOOK.entry, "node --test");
    assert.equal(DOT_HOOK.pass_filenames, undefined);
    assert.equal(DOT_HOOK.language, "system");
  });

  it("derives the default-discovery rule from a real `node --test` run", () => {
    // The one claim with no configuration to read: Node's own discovery. Driven
    // over a scratch tree so `discoveredByDefault` is checked against the runner
    // rather than against a memory of its documentation.
    const scratch = mkdtempSync(join(tmpdir(), "runner-discovery-"));
    try {
      const planted = [
        "visible/a.test.mjs",
        "nested/deep/b.test.mjs",
        ".dothooks/c.test.mjs",
        "outer/.inner/d.test.mjs",
        "visible/not-a-suite.mjs",
      ];
      for (const path of planted) {
        mkdirSync(join(scratch, dirname(path)), { recursive: true });
        // Each names itself, so the reporter output identifies exactly which
        // files the runner reached.
        writeFileSync(
          join(scratch, path),
          `import { test } from "node:test";\ntest(${JSON.stringify(path)}, () => {});\n`,
        );
      }
      // NODE_TEST_CONTEXT is inherited from THIS run and would switch the child
      // to the v8-serialized child-process protocol, whose output carries none
      // of these names — the discovery set would read as empty and the equality
      // below would hold vacuously against an empty expectation.
      const env = { ...process.env };
      delete env.NODE_TEST_CONTEXT;
      const stdout = execFileSync(
        process.execPath,
        ["--test", "--test-reporter=tap"],
        { cwd: scratch, encoding: "utf8", env },
      );
      const found = planted.filter((path) => stdout.includes(path));
      assert.deepEqual(
        found.sort(),
        planted.filter(discoveredByDefault).sort(),
        "node --test's default discovery no longer matches discoveredByDefault",
      );
      // Non-vacuity: the equality above would also hold if BOTH sides were
      // empty, which is what a runner that found nothing looks like.
      assert.ok(found.length > 0, "node --test discovered nothing at all");
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  });
});
