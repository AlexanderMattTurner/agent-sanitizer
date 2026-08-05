// Behavioral tests for the nightly-fuzz issue reporter. The unit under test is
// the body the maintainer actually reads: every assertion is about what the
// issue says, not about how the script is written.
//
// Regression #211: a nightly run failed with 9 ordinary red tests and the issue
// it opened claimed fast-check "hit a failing input" while quoting the run's
// last 80 lines — which, after 2000+ tests, is the TAP summary and the coverage
// table. It named no failing test and carried no seed, so it was unactionable.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import mod from "./nightly-fuzz-issue.js";

const { report } = mod;
const RUN_URL = "https://github.com/o/r/actions/runs/1";

/** A failing TAP test with its YAML diagnostic, as `node --test` emits it. */
const notOk = (n, name, error, indent = "") =>
  [
    `${indent}not ok ${n} - ${name}`,
    `${indent}  ---`,
    `${indent}  duration_ms: 1.5`,
    `${indent}  failureType: 'testCodeFailure'`,
    `${indent}  error: |-`,
    ...error.split("\n").map((line) => `${indent}    ${line}`),
    `${indent}  code: 'ERR_ASSERTION'`,
    `${indent}  ...`,
  ].join("\n");

const passing = (n, name) =>
  [`ok ${n} - ${name}`, "  ---", "  duration_ms: 0.3", "  ..."].join("\n");

// What every real `pnpm test` run ends with, and what the old reporter quoted.
const TRAILER = [
  "1..338",
  "# tests 2163",
  "# suites 263",
  "# pass 2154",
  "# fail 9",
  "# duration_ms 67211.3",
  "---------------------------|---------|----------|---------|---------",
  "File                       | % Stmts | % Branch | % Funcs | % Lines ",
  "---------------------------|---------|----------|---------|---------",
  "All files                  |     100 |      100 |     100 |     100 ",
  " confusables.mjs           |     100 |      100 |     100 |     100 ",
  " invisible.mjs             |     100 |      100 |     100 |     100 ",
  " view-map.mjs              |     100 |      100 |     100 |     100 ",
  "---------------------------|---------|----------|---------|---------",
  "[ELIFECYCLE] Test failed. See above for more details.",
].join("\n");

/** A run whose failures sit far above a long passing tail — the #211 shape. */
const buriedFailureLog = (failures) =>
  [
    ...failures,
    ...Array.from({ length: 200 }, (_, i) => passing(i + 100, `a later test`)),
    TRAILER,
  ].join("\n");

const FASTCHECK_ERROR = [
  "Property failed after 3 tests",
  '{ seed: -1147234157, path: "2:0:1", endOnFailure: true }',
  'Counterexample: ["\\u200b"]',
  "Shrunk 4 time(s)",
  "Got AssertionError: expected the zero-width space to be stripped",
].join("\n");

test("quotes the failing test, not the coverage-table tail (#211)", () => {
  const { body } = report(
    buriedFailureLog([
      notOk(
        60,
        "the deduplicated duplicate release scripts stay gone",
        ".github/scripts/version-bump.test.mjs must not exist\n\ntrue !== false",
      ),
    ]),
    RUN_URL,
  );
  assert.match(body, /not ok 60 - the deduplicated duplicate release scripts/);
  assert.match(body, /version-bump\.test\.mjs must not exist/);
  // The old body was exactly this and nothing else.
  assert.doesNotMatch(body, /% Stmts/);
  assert.doesNotMatch(body, /All files/);
});

test("does not claim a counterexample when fast-check printed none", () => {
  const log = buriedFailureLog([
    notOk(60, "a plain red test", "true !== false"),
  ]);
  const { title, body } = report(log, RUN_URL);
  assert.match(title, /no counterexample/);
  assert.match(body, /no fast-check counterexample/);
  assert.match(body, /already red on `main`/);
  assert.doesNotMatch(body, /hit a failing input/);
  assert.doesNotMatch(body, /seed fast-check prints below/);
});

test("reports a real counterexample as one, carrying the seed", () => {
  const log = buriedFailureLog([
    notOk(41, "invisible (property): strips every Cf run", FASTCHECK_ERROR),
  ]);
  const { title, body } = report(log, RUN_URL);
  assert.equal(title, "Nightly fuzz found a failing input");
  assert.match(body, /hit a failing input/);
  assert.match(body, /seed: -1147234157/);
  assert.match(body, /Counterexample/);
});

test("a `not ok` alone is not a counterexample — both fast-check markers are required", () => {
  // "Property failed after" with no seed line, and a seed-shaped line with no
  // property header: neither may promote an ordinary failure to a fuzz find.
  for (const error of [
    "Property failed after 3 tests",
    '{ seed: -1, path: "0", endOnFailure: true }',
  ]) {
    const { title } = report(
      buriedFailureLog([notOk(1, "half a marker", error)]),
      RUN_URL,
    );
    assert.match(title, /no counterexample/, `promoted on: ${error}`);
  }
});

test("caps the quoted failures and says how many it dropped", () => {
  const failures = Array.from({ length: 9 }, (_, i) =>
    notOk(i + 1, `failure number ${i + 1}`, "true !== false"),
  );
  const { body } = report(buriedFailureLog(failures), RUN_URL);
  assert.match(body, /not ok 1 - failure number 1/);
  assert.match(
    body,
    /_4 further failing test\(s\) omitted; see the run log\._/,
  );
  assert.doesNotMatch(body, /not ok 9 - failure number 9/);
});

test("an outsized failure does not starve the ones after it", () => {
  // Real shape: version-bump's "hardened npm-view logic" failure dumps the whole
  // release script into its diagnostic. Skipping past it must still quote the
  // small failures that follow, and still count it as omitted.
  const { body } = report(
    buriedFailureLog([
      notOk(1, "a small failure", "true !== false"),
      notOk(2, "a failure that dumps a script", "x\n".repeat(5000)),
      notOk(3, "another small failure", "true !== false"),
    ]),
    RUN_URL,
  );
  assert.match(body, /not ok 1 - a small failure/);
  assert.match(body, /not ok 3 - another small failure/);
  assert.doesNotMatch(body, /not ok 2 - a failure that dumps a script/);
  assert.match(body, /_1 further failing test\(s\) omitted/);
});

test("quotes one truncated failure rather than nothing", () => {
  const { body } = report(
    notOk(1, "a very loud failure", "x".repeat(20000)),
    RUN_URL,
  );
  assert.match(body, /not ok 1 - a very loud failure/);
  assert.match(body, /… \(truncated\)/);
  assert.ok(body.length < 12000, `body was ${body.length} chars`);
});

test("captures an indented subtest failure with its diagnostic", () => {
  const log = [
    "# Subtest: invisible",
    notOk(2, "strips a Cf run", "expected '' to equal 'a'", "    "),
    "    1..2",
    "not ok 12 - invisible",
    "  ---",
    "  error: '1 subtest failed'",
    "  ...",
    TRAILER,
  ].join("\n");
  const { body } = report(log, RUN_URL);
  assert.match(body, /not ok 2 - strips a Cf run/);
  assert.match(body, /expected '' to equal 'a'/);
  // The block must stop at the dedented `1..2`, not swallow the rest of the run.
  assert.doesNotMatch(body, /% Stmts/);
});

test("fences output that itself contains a code fence", () => {
  // markdownlint's rule fixtures are markdown, so a failing diff can carry ```.
  const { body } = report(
    buriedFailureLog([
      notOk(1, "a markdown fixture failed", "expected:\n```\n| a | b |\n```"),
    ]),
    RUN_URL,
  );
  const fences = body.match(/^`{3,}$/gm) ?? [];
  assert.equal(fences.length, 2, `unbalanced fences: ${fences}`);
  assert.ok(fences[0].length > 3, "the fence must outrun the quoted one");
  assert.equal(fences[0], fences[1]);
  assert.match(body, /\| a \| b \|/);
});

test("falls back to the tail, labelled, when the run emitted no TAP", () => {
  const { body } = report(
    "pnpm: command not found\nfatal: the runner died\n",
    RUN_URL,
  );
  assert.match(body, /No TAP `not ok` line was found/);
  assert.match(body, /fatal: the runner died/);
});

test("says so when nothing at all was captured", () => {
  const { body } = report("", RUN_URL);
  assert.match(body, /\(no test output was captured\)/);
});

test("always links the run", () => {
  assert.match(report("", RUN_URL).body, /- Run: https:\/\/github\.com\/o\/r/);
});

// --- End to end: the real entry point against a stubbed Octokit -------------

/** Run the module's default export in a temp cwd holding `fuzz-output.log`. */
function runReporter(log, openIssues) {
  const dir = mkdtempSync(join(tmpdir(), "nightly-fuzz-"));
  writeFileSync(join(dir, "fuzz-output.log"), log);
  const calls = { created: [], commented: [], notices: [] };
  const github = {
    rest: {
      issues: {
        listForRepo: async () => ({ data: openIssues }),
        create: async (args) => {
          calls.created.push(args);
          return { data: { number: 999 } };
        },
        createComment: async (args) => {
          calls.commented.push(args);
          return { data: {} };
        },
      },
    },
  };
  const context = {
    repo: { owner: "o", repo: "r" },
    serverUrl: "https://github.com",
    runId: 42,
  };
  const cwd = process.cwd();
  process.chdir(dir);
  return mod({
    github,
    context,
    core: { notice: (m) => calls.notices.push(m) },
  })
    .then(() => calls)
    .finally(() => {
      process.chdir(cwd);
      rmSync(dir, { recursive: true, force: true });
    });
}

test("opens a labelled issue naming the failing test when none is open", async () => {
  const calls = await runReporter(
    buriedFailureLog([notOk(60, "the release scripts stay gone", "boom")]),
    [],
  );
  assert.equal(calls.commented.length, 0);
  assert.equal(calls.created.length, 1);
  const [issue] = calls.created;
  assert.deepEqual(issue.labels, ["nightly-fuzz"]);
  assert.match(issue.body, /not ok 60 - the release scripts stay gone/);
  assert.match(issue.title, /no counterexample/);
  assert.match(calls.notices[0], /Opened nightly fuzz issue #999/);
});

test("appends to the open rollup issue instead of opening a duplicate", async () => {
  const calls = await runReporter(
    buriedFailureLog([notOk(7, "another red test", "boom")]),
    [{ number: 211 }],
  );
  assert.equal(calls.created.length, 0);
  assert.equal(calls.commented.length, 1);
  assert.equal(calls.commented[0].issue_number, 211);
  assert.match(calls.commented[0].body, /not ok 7 - another red test/);
  assert.match(calls.notices[0], /Appended .* to existing issue #211/);
});

test("still reports when the log file is missing entirely", async () => {
  const dir = mkdtempSync(join(tmpdir(), "nightly-fuzz-nolog-"));
  const created = [];
  const cwd = process.cwd();
  process.chdir(dir);
  try {
    await mod({
      github: {
        rest: {
          issues: {
            listForRepo: async () => ({ data: [] }),
            create: async (args) => {
              created.push(args);
              return { data: { number: 1 } };
            },
          },
        },
      },
      context: {
        repo: { owner: "o", repo: "r" },
        serverUrl: "https://github.com",
        runId: 1,
      },
      core: { notice: () => {} },
    });
  } finally {
    process.chdir(cwd);
    rmSync(dir, { recursive: true, force: true });
  }
  assert.equal(created.length, 1);
  assert.match(created[0].body, /\(no test output was captured\)/);
});

// The fixture builders must not be the thing under test: prove they produce the
// shape the reporter is meant to survive.
test("fixture sanity: the buried-failure log really does end in the coverage table", () => {
  const log = buriedFailureLog([notOk(1, "x", "y")]);
  const tail = log.split("\n").slice(-80).join("\n");
  assert.doesNotMatch(tail, /not ok/);
  assert.match(tail, /% Stmts/);
});
