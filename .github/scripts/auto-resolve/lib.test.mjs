import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const LIB = join(HERE, "lib.sh");

// The protected set is the one definition BOTH the prepare log and the land
// step's pushed-resolution warning read, so it is tested where it lives rather
// than through either caller.
function protectedMatches(paths, env = {}) {
  const out = execFileSync(
    "bash",
    ["-c", `source "${LIB}"; protected_matches "$@"`, "_", ...paths],
    { encoding: "utf8", env: { ...process.env, ...env } },
  );
  return out.split("\n").filter(Boolean);
}

test("the default protected set covers this template's Claude config and CI machinery, member by member", () => {
  const members = [
    ".claude/hooks/probe.txt",
    ".claude/skills/probe.txt",
    ".claude/settings.json",
    ".github/workflows/ci.yaml",
    ".github/scripts/probe.sh",
    ".github/actions/probe/action.yaml",
  ];
  for (const path of members) {
    assert.deepEqual(protectedMatches([path]), [path], `${path} is protected`);
  }
});

test("ordinary source and top-level files are NOT protected", () => {
  for (const path of ["setup.sh", "src/index.js", "infra/main.tf", "README.md"])
    assert.deepEqual(protectedMatches([path]), [], `${path} is not protected`);
});

test("protected_matches returns the protected SUBSET of a mixed list, in order", () => {
  assert.deepEqual(
    protectedMatches([
      "src/index.js",
      ".github/workflows/ci.yaml",
      "docs/a.md",
      ".claude/settings.json",
    ]),
    [".github/workflows/ci.yaml", ".claude/settings.json"],
  );
});

test("AUTO_RESOLVE_PROTECTED_RE widens the set for a repo with more sensitive trees", () => {
  const env = {
    AUTO_RESOLVE_PROTECTED_RE: "^(\\.claude/|\\.github/|infra/)",
  };
  assert.deepEqual(protectedMatches(["infra/main.tf"], env), ["infra/main.tf"]);
  assert.deepEqual(protectedMatches(["src/index.js"], env), []);
});

test("protected_matches on an empty list is empty, not an error", () => {
  assert.deepEqual(protectedMatches([]), []);
});

// The OAuth rung list is the fact three callers used to re-type; it is tested
// where it now lives, member by member, so a dropped rung reds here rather than
// only on the adopter who provisioned exactly that one.
const LADDER = join(HERE, "..", "lib", "claude-oauth-ladder.bash");
function ladder(env) {
  return execFileSync(
    "bash",
    ["-c", `source "${LADDER}"; claude_oauth_ladder`],
    {
      encoding: "utf8",
      env: { PATH: process.env.PATH ?? "", ...env },
    },
  )
    .split("\n")
    .filter(Boolean);
}

test("every rung the workflow passes is walked, member by member", () => {
  const rungs = [
    "CLAUDE_CODE_OAUTH_TOKEN_FALLBACK",
    "CLAUDE_CODE_OAUTH_TOKEN_FALLBACK_2",
    "CLAUDE_CODE_OAUTH_TOKEN_FALLBACK_3",
    "CLAUDE_CODE_OAUTH_TOKEN_FALLBACK_4",
    "CLAUDE_CODE_OAUTH_TOKEN_FALLBACK_5",
    "CLAUDE_CODE_OAUTH_TOKEN_FALLBACK_6",
    "CLAUDE_CODE_OAUTH_TOKEN",
  ];
  for (const rung of rungs)
    assert.deepEqual(ladder({ [rung]: `tok-${rung}` }), [`tok-${rung}`], rung);
  const all = Object.fromEntries(rungs.map((r) => [r, `tok-${r}`]));
  assert.deepEqual(
    ladder(all),
    rungs.map((r) => `tok-${r}`),
  ); // and in order
});

test("an unset middle rung is stepped over, not treated as the end of the ladder", () => {
  assert.deepEqual(
    ladder({
      CLAUDE_CODE_OAUTH_TOKEN_FALLBACK: "a",
      CLAUDE_CODE_OAUTH_TOKEN_FALLBACK_2: "",
      CLAUDE_CODE_OAUTH_TOKEN_FALLBACK_3: "b",
    }),
    ["a", "b"],
  );
});

test("the operator's own token is walked LAST, after every dedicated rung", () => {
  assert.deepEqual(
    ladder({
      CLAUDE_CODE_OAUTH_TOKEN: "personal",
      CLAUDE_CODE_OAUTH_TOKEN_FALLBACK: "ci-a",
      CLAUDE_CODE_OAUTH_TOKEN_FALLBACK_6: "ci-b",
    }),
    ["ci-a", "ci-b", "personal"],
  );
});

test("a setup with only the operator's own token still reaches it", () => {
  assert.deepEqual(ladder({ CLAUDE_CODE_OAUTH_TOKEN: "personal" }), [
    "personal",
  ]);
});

test("a credential configured twice is only paid for once", () => {
  assert.deepEqual(
    ladder({
      CLAUDE_CODE_OAUTH_TOKEN: "same",
      CLAUDE_CODE_OAUTH_TOKEN_FALLBACK_3: "same",
      CLAUDE_CODE_OAUTH_TOKEN_FALLBACK_4: "other",
    }),
    ["same", "other"],
  );
});

test("no credential configured is an empty ladder, not an error", () => {
  assert.deepEqual(ladder({}), []);
});

// The resolver entrypoint's own admission check. It used to demand rung 1 by
// name, so a repo that had rotated CLAUDE_CODE_OAUTH_TOKEN out and provisioned
// only the fallbacks failed EVERY conflict resolution before reaching the
// model — reported downstream as "no execution log", which names the wrong
// cause. These run the real script in a sandbox whose install and fan-out are
// stubbed, so what is under test is the admission decision alone.
const RESOLVE_ENTRYPOINT = join(HERE, "..", "claude-conflict-resolve.sh");

function runResolver(env) {
  const sandbox = mkdtempSync(join(tmpdir(), "conflict-resolve-"));
  mkdirSync(join(sandbox, "lib"));
  mkdirSync(join(sandbox, "auto-resolve"));
  copyFileSync(RESOLVE_ENTRYPOINT, join(sandbox, "claude-conflict-resolve.sh"));
  copyFileSync(LADDER, join(sandbox, "lib", "claude-oauth-ladder.bash"));
  // Stubs: the CLI install is a network op, and the fan-out is the paid model
  // call. Both record that they ran so a test can assert the script got past
  // the guard rather than merely exiting 0.
  writeFileSync(
    join(sandbox, "install-claude-cli.sh"),
    `#!/usr/bin/env bash\ntouch "${join(sandbox, "installed")}"\n`,
  );
  writeFileSync(
    join(sandbox, "auto-resolve", "fanout.sh"),
    `#!/usr/bin/env bash
mkdir -p "$FANOUT_DIR"
printf '%s' "$CLAUDE_CODE_OAUTH_TOKEN" >>"${join(sandbox, "rungs-tried")}"
printf '{"is_error":false}' >"$FANOUT_DIR/execution.json"
`,
  );
  const res = spawnSync("bash", [join(sandbox, "claude-conflict-resolve.sh")], {
    encoding: "utf8",
    cwd: sandbox,
    env: {
      PATH: process.env.PATH ?? "",
      FANOUT_DIR: join(sandbox, "fanout"),
      ...env,
    },
  });
  return {
    status: res.status,
    stderr: res.stderr,
    installed: existsSync(join(sandbox, "installed")),
    rungsTried: existsSync(join(sandbox, "rungs-tried"))
      ? readFileSync(join(sandbox, "rungs-tried"), "utf8")
      : "",
  };
}

test("the resolver runs on a fallback rung when rung 1 is unset", () => {
  const res = runResolver({ CLAUDE_CODE_OAUTH_TOKEN_FALLBACK_3: "fb3" });
  assert.equal(res.status, 0, res.stderr);
  assert.ok(res.installed, "the CLI install must be reached");
  assert.equal(res.rungsTried, "fb3", "the fallback rung must be handed down");
});

test("the resolver refuses only when the WHOLE ladder is empty, and says which vars to set", () => {
  const res = runResolver({});
  assert.equal(res.status, 1);
  assert.match(res.stderr, /no Claude credential configured/);
  assert.match(res.stderr, /CLAUDE_CODE_OAUTH_TOKEN_FALLBACK_6/);
  assert.equal(
    res.installed,
    false,
    "the refusal must land before the CLI install is paid for",
  );
});
