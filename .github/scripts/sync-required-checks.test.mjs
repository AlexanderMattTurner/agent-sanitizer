// sync-required-checks.sh against a stand-in `gh` (which applies the script's
// own `--jq` filter to fixture pages, one value per page as gh does) and a
// stand-in `uv` (which records the apply tool's argv). That pins which ruleset
// the apply step writes, without a network call or a ruleset mutation.
// ci-truth-serum's own discovery cannot pick between two repo-owned branch
// rulesets, so the script must name the one carrying the default branch's
// required checks.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT = join(
  dirname(fileURLToPath(import.meta.url)),
  "sync-required-checks.sh",
);
const REPO_ROOT = join(dirname(SCRIPT), "..", "..");

const scratched = [];
process.on("exit", () => {
  for (const dir of scratched) rmSync(dir, { recursive: true, force: true });
});

// Answers only the one read the script should make, so a call against any
// other path fails the run instead of passing on a guess.
const FAKE_GH = `#!/usr/bin/env bash
[[ "$1 $2 $3 $4" == "api --paginate repos/o/r/rules/branches/main --jq" ]] || {
  echo "unexpected gh call: $*" >&2; exit 2; }
[[ -z "\${FAKE_GH_EXIT:-}" ]] || exit "$FAKE_GH_EXIT"
printf '%s' "$FAKE_RULES" | jq -r "$5"
`;
const FAKE_UV = `#!/usr/bin/env bash
printf '%s\\n' "$@" >"$UV_ARGV"
`;

const rule = (type, id, source) => ({
  type,
  ruleset_id: id,
  ruleset_source_type: source,
});
const page = (...rules) => JSON.stringify(rules);

/** Run the script with `pages` (concatenated JSON arrays) and extra env. */
const run = (pages, env = {}) => {
  const bin = mkdtempSync(join(tmpdir(), "sync-required-checks-"));
  scratched.push(bin);
  for (const [name, body] of [
    ["gh", FAKE_GH],
    ["uv", FAKE_UV],
  ]) {
    writeFileSync(join(bin, name), body);
    chmodSync(join(bin, name), 0o755);
  }
  const argvFile = join(bin, "argv");
  const result = spawnSync("bash", [SCRIPT], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${bin}:${process.env.PATH}`,
      REPO: "o/r",
      DEFAULT_BRANCH: "main",
      FAKE_RULES: pages,
      UV_ARGV: argvFile,
      ...env,
    },
  });
  const argv =
    result.status === 0
      ? readFileSync(argvFile, "utf8").split("\n").filter(Boolean)
      : null;
  return { ...result, argv };
};

const MAIN_PROTECTION = [
  rule("deletion", 17962702, "Repository"),
  rule("required_status_checks", 17962702, "Repository"),
];
const ORG_DEFAULT = rule("deletion", 18360957, "Organization");

/** The apply tool's argv after the `uv run` options, for ruleset `id`. */
const applied = (id, check) => [
  "python",
  "-m",
  "ci_truth_serum.sync_required_checks",
  "--repo",
  "o/r",
  "--ruleset-id",
  String(id),
  ...(check ? ["--check"] : []),
];
const toolArgv = (argv) => argv.slice(argv.indexOf("python"));

for (const [name, pages] of [
  ["one page", page(...MAIN_PROTECTION, ORG_DEFAULT)],
  ["split across pages", page(ORG_DEFAULT) + page(...MAIN_PROTECTION)],
  [
    "a second repo-owned ruleset with no required checks",
    page(...MAIN_PROTECTION, rule("non_fast_forward", 99, "Repository")),
  ],
])
  for (const check of [true, false])
    test(`names the ruleset requiring checks on main (${name}, check=${check})`, () => {
      const { status, stderr, argv } = run(pages, {
        CHECK_ONLY: check ? "true" : "",
      });
      assert.equal(status, 0, stderr);
      assert.deepEqual(toolArgv(argv), applied(17962702, check));
    });

for (const [name, pages, found] of [
  [
    "two repo-owned rulesets require checks",
    page(
      rule("required_status_checks", 1, "Repository"),
      rule("required_status_checks", 2, "Repository"),
    ),
    "found: 1\n2",
  ],
  ["only an org ruleset applies", page(ORG_DEFAULT), "found: none"],
  ["no ruleset applies", page(), "found: none"],
])
  test(`refuses to guess when ${name}`, () => {
    const { status, stderr } = run(pages);
    assert.equal(status, 1);
    assert.ok(
      stderr.includes(
        `Expected exactly one repo-owned ruleset requiring status checks on main of o/r; ${found}`,
      ),
      stderr,
    );
  });

test("fails with gh's own status when the read fails", () => {
  const { status, stderr } = run(page(...MAIN_PROTECTION), {
    FAKE_GH_EXIT: "4",
  });
  assert.equal(status, 4, stderr);
});

test("requires DEFAULT_BRANCH", () => {
  const { status, stderr } = run(page(...MAIN_PROTECTION), {
    DEFAULT_BRANCH: "",
  });
  assert.equal(status, 1);
  assert.match(stderr, /DEFAULT_BRANCH required/);
});
