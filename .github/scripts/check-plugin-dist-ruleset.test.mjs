// check-plugin-dist-ruleset.sh against a stand-in `gh` that answers the two
// REST reads with fixture text, so each verdict is pinned without a network
// call: red when nothing restricts updates to the install branch, green when
// an `update` rule does, and green where there is no install branch at all
// (the downstream repos template-sync delivers the workflow to).
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT = join(
  dirname(fileURLToPath(import.meta.url)),
  "check-plugin-dist-ruleset.sh",
);

const scratched = [];
process.on("exit", () => {
  for (const dir of scratched) rmSync(dir, { recursive: true, force: true });
});
const scratchDir = () => {
  const dir = mkdtempSync(join(tmpdir(), "plugin-dist-ruleset-"));
  scratched.push(dir);
  return dir;
};

// Prints the already-filtered (`--jq`) answer the script asks for: the
// rulesets listing, or the space-joined rule types active on the branch.
const FAKE_GH = `#!/usr/bin/env bash
case "$2" in
*/rulesets*) printf '%s\\n' "\${FAKE_RULESETS:-}" ;;
*/rules/branches/*) printf '%s\\n' "\${FAKE_RULES:-}" ;;
*) echo "unexpected gh call: $*" >&2; exit 2 ;;
esac
`;

const marketplace = (source) =>
  JSON.stringify({ plugins: [{ name: "fixture", source }] });

const GIT_SUBDIR = {
  source: "git-subdir",
  url: "https://example.invalid/fixture.git",
  path: "plugin",
  ref: "plugin-dist",
};

/** Run the check in a repo holding `marketplaceText` (none when null). */
const check = (marketplaceText, rules) => {
  const repo = scratchDir();
  if (marketplaceText !== null) {
    mkdirSync(join(repo, ".claude-plugin"));
    writeFileSync(
      join(repo, ".claude-plugin", "marketplace.json"),
      marketplaceText,
    );
  }
  const bin = scratchDir();
  writeFileSync(join(bin, "gh"), FAKE_GH);
  chmodSync(join(bin, "gh"), 0o755);
  const run = spawnSync("bash", [SCRIPT], {
    cwd: repo,
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${bin}:${process.env.PATH}`,
      GITHUB_REPOSITORY: "owner/repo",
      FAKE_RULESETS: "1 Main protection (Repository, active)",
      FAKE_RULES: rules,
    },
  });
  return { status: run.status, stderr: run.stderr };
};

test("an install branch no rule restricts updates to fails, naming the branch", () => {
  for (const rules of ["", "deletion non_fast_forward"]) {
    const { status, stderr } = check(marketplace(GIT_SUBDIR), rules);
    assert.equal(status, 1, stderr);
    assert.match(
      stderr,
      /No active ruleset restricts updates to refs\/heads\/plugin-dist/,
    );
  }
});

test("an update rule on the install branch passes", () => {
  const { status, stderr } = check(
    marketplace(GIT_SUBDIR),
    "creation deletion non_fast_forward update",
  );
  assert.equal(status, 0, stderr);
  assert.match(stderr, /Active rules on refs\/heads\/plugin-dist: .*update/);
});

test("a repo with no install branch passes without asking GitHub", () => {
  for (const text of [null, marketplace("./plugin")]) {
    const { status, stderr } = check(text, "");
    assert.equal(status, 0, stderr);
    assert.match(stderr, /no install branch to protect/);
    assert.doesNotMatch(stderr, /Rulesets on/);
  }
});
