/**
 * `pnpm lint` covers the automation layer, not just the library.
 *
 * `eslint.config.mjs` used to ignore `.github/**`, `.hooks/**` and `.claude/**`
 * wholesale on the grounds that "the template's automation scripts carry their
 * own conventions". The effect was that `pnpm lint` linted ZERO of the ~50 JS
 * files there — four hook modules that run inside a Claude session, three
 * CommonJS scripts that run in CI holding a token, and every suite under
 * `.github/scripts`. Un-ignoring them surfaced five real errors on the first
 * run (four dead initialisers and a `throw` that dropped its cause).
 *
 * An `ignores` entry is one line, so the cheapest way to make a lint failure go
 * away is to re-add it — and nothing would notice. This asks ESLint itself
 * whether it would lint each file, so the assertion is about the resolved live
 * config rather than about the text of it.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { describe, it } from "node:test";
import { ESLint } from "eslint";

const REPO_ROOT = execFileSync("git", ["rev-parse", "--show-toplevel"], {
  encoding: "utf8",
}).trim();

const tracked = (...pathspecs) =>
  execFileSync("git", ["ls-files", "--", ...pathspecs], {
    cwd: REPO_ROOT,
    encoding: "utf8",
  })
    .split("\n")
    .filter(Boolean);

const eslint = new ESLint({ cwd: REPO_ROOT });

/** The tracked JS files under the automation directories. */
const AUTOMATION = tracked(
  ".github/**.mjs",
  ".github/**.js",
  ".github/**.cjs",
  ".hooks/**.mjs",
  ".claude/hooks/**.mjs",
);

describe("lint scope", () => {
  it("lints every tracked JS file under .github, .hooks and .claude/hooks", async () => {
    // Non-vacuity: an empty pathspec result would make the loop assert nothing.
    assert.ok(
      AUTOMATION.length > 40,
      `only ${AUTOMATION.length} files matched`,
    );
    for (const known of [
      ".github/scripts/main-health.mjs",
      ".github/scripts/nightly-fuzz-issue.js",
      ".hooks/run-guard-pairs.mjs",
      ".claude/hooks/drop-superseded-ci-events.mjs",
    ])
      assert.ok(AUTOMATION.includes(known), `${known} is not tracked`);

    const ignored = [];
    for (const file of AUTOMATION)
      if (await eslint.isPathIgnored(file)) ignored.push(file);
    assert.deepEqual(
      ignored,
      [],
      "eslint.config.mjs ignores these — `pnpm lint` reports them clean without reading them",
    );
  });

  it("still applies a real rule set to an automation file", async () => {
    // isPathIgnored() only proves the file is in scope; a `files:` block that
    // stopped matching would leave it linted by nothing but the parser, which
    // reads as green just as convincingly. Lint a snippet AS one of those paths
    // and require the recommended rules to fire.
    const [result] = await eslint.lintText(
      "const unused = 1;\nbadGlobal();\n",
      {
        filePath: `${REPO_ROOT}/.github/scripts/lint-scope-probe.mjs`,
      },
    );
    const ruleIds = result.messages.map((m) => m.ruleId).sort();
    assert.deepEqual(ruleIds, ["no-undef", "no-unused-vars"]);
  });

  it("does not lint the gitignored worktree copies of the repo", async () => {
    // The paired negative: `.claude/worktrees/` is a second checkout of this
    // same tree, so linting it would double every finding at paths that do not
    // exist on the branch.
    assert.equal(
      await eslint.isPathIgnored(".claude/worktrees/agent-x/src/index.mjs"),
      true,
    );
  });
});
