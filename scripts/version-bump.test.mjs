import { strict as assert } from "node:assert";
import { execFileSync, spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const LIVE_SCRIPT = join(REPO_ROOT, ".github", "scripts", "version-bump.sh");
const AUTO_VERSION_YAML = join(
  REPO_ROOT,
  ".github",
  "workflows",
  "auto-version.yaml",
);

// --- Drift / single-source-of-truth contract ------------------------------
// The release path is a two-copy hazard: a `scripts/` and a `.github/scripts/`
// version-bump.sh once coexisted and silently diverged (one kept a
// `npm view ... || echo "0.0.0"` fallback that rebases the version to 0.0.1 on a
// transient registry outage). These assertions fail loudly if the duplicate
// reappears or the workflow stops pointing at the hardened live copy.

test("the deduplicated duplicate release scripts stay gone", () => {
  assert.equal(
    existsSync(join(REPO_ROOT, "scripts", "version-bump.sh")),
    false,
    "scripts/version-bump.sh must not exist; .github/scripts is the single source of truth",
  );
  assert.equal(
    existsSync(join(REPO_ROOT, "scripts", "promote-changelog.mjs")),
    false,
    "scripts/promote-changelog.mjs must not exist; .github/scripts is the single source of truth",
  );
  // The template ships its own version-bump.test.mjs alongside the script; a
  // template-sync drops it into .github/scripts/ where it re-tests the TEMPLATE's
  // release design (plain-string `npm view`, GITHUB_TOKEN-only push) against this
  // repo's hardened live script and fails 5/6. This file is the single test copy;
  // the template duplicate must not reappear.
  assert.equal(
    existsSync(join(REPO_ROOT, ".github", "scripts", "version-bump.test.mjs")),
    false,
    ".github/scripts/version-bump.test.mjs must not exist; scripts/version-bump.test.mjs is the single test copy",
  );
});

test("auto-version.yaml invokes exactly the live hardened release script", () => {
  const yaml = readFileSync(AUTO_VERSION_YAML, "utf8");
  const invocations = [...yaml.matchAll(/bash\s+(\S*version-bump\.sh)/g)].map(
    (m) => m[1],
  );
  assert.deepEqual(
    invocations,
    [".github/scripts/version-bump.sh"],
    "the workflow must run one, and only the .github/scripts, version-bump.sh",
  );
  assert.ok(existsSync(LIVE_SCRIPT), "the invoked script must exist on disk");
});

test("the release checkout pushes with the org ruleset-bypass token or GITHUB_TOKEN, never a cross-account PAT", () => {
  // The release-docs commit and vX.Y.Z tag are pushed with the credentials the
  // checkout persists. github-actions[bot] (GITHUB_TOKEN) cannot push past this
  // repo's branch-protection ruleset, so the checkout rides the in-org
  // TEMPLATE_SYNC_TOKEN_ORG (authorized to bypass the ruleset on THIS repo) and
  // falls back to GITHUB_TOKEN where that org secret is absent. What it must
  // NEVER be is a cross-account PAT (TEMPLATE_SYNC_TOKEN, minted for a different
  // owner): that is rejected 403 by this repo's remote, stranding every release —
  // npm publishes but the tag never lands, so the next run re-reads the climbing
  // npm version and bumps again.
  const yaml = readFileSync(AUTO_VERSION_YAML, "utf8");
  const tokenLines = yaml
    .split("\n")
    .filter((l) => /^\s*token:/.test(l))
    .map((l) => l.trim());
  assert.deepEqual(
    tokenLines,
    ["token: ${{ secrets.TEMPLATE_SYNC_TOKEN_ORG || secrets.GITHUB_TOKEN }}"],
    "the checkout must pin the in-org ruleset-bypass token with a GITHUB_TOKEN fallback, never a cross-account PAT",
  );
});

test("the live release script carries the hardened npm-view logic", () => {
  const src = readFileSync(LIVE_SCRIPT, "utf8");
  // Positive markers: enumerate the idioms that make this the hardened copy, so
  // the guard fails if any is refactored away (it must not pass vacuously).
  const requiredMarkers = [
    /grep -q "E404"/, // distinguishes unpublished from a network outage
    /Refusing to guess a version/, // fails loud on a non-E404 npm error
    /npm view "\$PACKAGE_NAME" versions --json/, // reads the full version list, not the lagging `latest` tag
    /npm view "\$PACKAGE_NAME@\$candidate" deprecated/, // probes each candidate to skip retired versions
    /max_version/, // reconciles npm vs the highest git tag
    /BASE_VERSION=\$\(max_version/,
    /emit_output "released=true"/, // couples the PyPI publish
    /emit_output "version=\$NEW_VERSION"/,
  ];
  for (const marker of requiredMarkers) {
    assert.match(src, marker);
  }
  // Negative marker: the vacuous fallback that rebases to 0.0.0 on any error.
  assert.doesNotMatch(
    src,
    /npm view[^\n]*\|\|\s*echo\s*"0\.0\.0"/,
    "the `npm view ... || echo 0.0.0` fallback must never return",
  );
});

// --- Behavioral: npm-view error handling ----------------------------------
// Run the REAL script in a throwaway git repo with `npm` stubbed on PATH. Both
// scenarios exit before any publish/push, so nothing leaves the sandbox.

/** Build a throwaway git repo tagged v0.0.0 at HEAD, plus a stubbed `npm`. */
function makeSandbox(npmStubBody) {
  const dir = mkdtempSync(join(tmpdir(), "vbump-"));
  writeFileSync(
    join(dir, "package.json"),
    JSON.stringify({ name: "sandbox-pkg", version: "0.0.0" }) + "\n",
  );
  const binDir = join(dir, "stub-bin");
  mkdirSync(binDir);
  const npmStub = join(binDir, "npm");
  writeFileSync(npmStub, `#!/usr/bin/env bash\n${npmStubBody}\n`);
  chmodSync(npmStub, 0o755);

  const git = (...args) =>
    execFileSync("git", args, { cwd: dir, stdio: "ignore" });
  git("init", "-q");
  git("config", "user.email", "t@t.test");
  git("config", "user.name", "t");
  git("commit", "-q", "--allow-empty", "-m", "chore: seed");
  git("tag", "v0.0.0");
  return { dir, binDir };
}

/** Run the live script in `dir`; return {status, stderr, stdout}. */
function runScript(dir, binDir) {
  const env = { ...process.env, PATH: `${binDir}:${process.env.PATH}` };
  delete env.ANTHROPIC_API_KEY;
  delete env.GITHUB_OUTPUT;
  const res = spawnSync("bash", [LIVE_SCRIPT], {
    cwd: dir,
    env,
    encoding: "utf8",
  });
  assert.equal(res.error, undefined, "failed to spawn the release script");
  return { status: res.status, stderr: res.stderr, stdout: res.stdout };
}

test("a network-error npm view aborts rather than rebasing to 0.0.0", () => {
  // Non-E404 failure: the registry is unreachable.
  const { dir, binDir } = makeSandbox(
    'echo "npm error code ETIMEDOUT" >&2\necho "npm error network request to https://registry.npmjs.org failed" >&2\nexit 1',
  );
  try {
    const { status, stderr } = runScript(dir, binDir);
    assert.notEqual(status, 0, "must exit non-zero on an unexpected npm error");
    assert.match(stderr, /failed unexpectedly \(not E404\)/);
    assert.doesNotMatch(
      stderr,
      /Highest live npm version: 0\.0\.0/,
      "must not silently treat a network outage as an unpublished package",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an E404 npm view treats the package as unpublished (0.0.0)", () => {
  const { dir, binDir } = makeSandbox(
    'echo "npm error code E404" >&2\necho "npm error 404 Not Found - GET https://registry.npmjs.org/sandbox-pkg" >&2\nexit 1',
  );
  try {
    const { status, stderr } = runScript(dir, binDir);
    // HEAD is already tagged v0.0.0, so the script logs the resolved version and
    // exits 0 at the already-released guard — proving E404 -> 0.0.0, no abort.
    assert.equal(status, 0, "E404 must not abort the release run");
    assert.match(stderr, /Highest live npm version: 0\.0\.0/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("bumps from the highest live version, not the lagging latest dist-tag", () => {
  // The registry's `latest` tag can lag the highest published version. The base
  // must be the max LIVE version (1.37.0 -> 1.38.0), never `latest` (1.6.4 ->
  // 1.7.0, already taken -> skip-forever), and a deprecated higher major (6.0.0)
  // must be excluded. Every `@version` existence probe answers "exists" so the
  // run stops at the already-exists guard before any publish/push.
  // `npm view pkg versions --json` -> the full array (latest lags at 1.6.4).
  // `npm view pkg@<v> deprecated` -> the retired-major note for 6.0.0, empty
  // (live) otherwise. `npm view pkg@<v> version` (existence probe) -> exists.
  const stub = `if [[ "$2" == *@* ]]; then
  if [[ "$3" == "deprecated" ]]; then
    [[ "$2" == *@6.0.0 ]] && echo "automated major-bump bug"
    exit 0
  fi
  exit 0
else
  echo '["1.6.4","1.7.0","1.37.0","6.0.0"]'
fi`;
  const { dir, binDir } = makeSandbox(stub);
  try {
    const git = (...args) =>
      execFileSync("git", args, { cwd: dir, stdio: "ignore" });
    git("commit", "-q", "--allow-empty", "-m", "feat: add a real feature");
    const { status, stderr } = runScript(dir, binDir);
    assert.equal(status, 0, stderr);
    assert.match(stderr, /Highest live npm version: 1\.37\.0/);
    assert.match(stderr, /New version: 1\.38\.0/);
    assert.doesNotMatch(stderr, /New version: 1\.7\.0/); // not the lagging-tag bump
    assert.doesNotMatch(stderr, /New version: 6\./); // deprecated major excluded
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// --- Re-running a completed release must not republish it ------------------
// Real incident: run #148 was re-run against the merge SHA it had already
// released as 2.0.1, computed 2.0.2, and published a byte-identical duplicate
// that now sits at `latest` with no tag and no CHANGELOG entry. The release tag
// lands on the release-docs commit — a CHILD of the published SHA — so from the
// published SHA `git describe` reports the PREVIOUS release and the run re-cuts
// the same commit range under a fresh version. Only `git tag --contains HEAD`
// sees a tag written after HEAD.

test("a re-run against an already-released SHA skips instead of republishing", () => {
  // npm reports 1.1.0 live (what the first run published), so an unguarded run
  // would bump to 1.1.1 and republish the same commits. Every `@version` probe
  // answers "exists" so nothing can publish even if the guard regressed.
  const { dir, binDir } = makeSandbox(`if [[ "$2" == *@* ]]; then
  exit 0
else
  echo '["1.1.0"]'
fi`);
  try {
    const git = (...args) =>
      execFileSync("git", args, { cwd: dir, stdio: "ignore" });
    // The exact released topology: published SHA -> release-docs commit -> tag.
    git("commit", "-q", "--allow-empty", "-m", "feat: the released feature");
    const publishedSha = execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: dir,
      encoding: "utf8",
    }).trim();
    git("commit", "-q", "--allow-empty", "-m", "docs: release 1.1.0 [skip ci]");
    git("tag", "v1.1.0");
    // Re-run: the workflow checks out the SHA the run was dispatched for.
    git("checkout", "-q", publishedSha);

    // The premise of the bug — from the published SHA the tag is invisible to
    // `describe`, so the guard cannot be passing for the wrong reason.
    assert.equal(
      execFileSync(
        "git",
        ["describe", "--tags", "--match", "v*", "--abbrev=0"],
        {
          cwd: dir,
          encoding: "utf8",
        },
      ).trim(),
      "v0.0.0",
      "precondition: the released tag must be invisible to `git describe` here",
    );

    const { status, stderr } = runScript(dir, binDir);
    assert.equal(status, 0, stderr);
    assert.match(stderr, /HEAD is already released as v1\.1\.0\. Skipping\./);
    assert.doesNotMatch(
      stderr,
      /New version:/,
      "the re-run must exit before computing a version",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// --- Automated major bumps are disabled ------------------------------------
// A breaking-change marker (`type!:` subject or `BREAKING CHANGE:` footer) must
// be CAPPED at a minor bump, never a major one: a stray `!` in a routine commit
// must not leap the whole version line (the real cause of the 1.x -> 5.x drift).
// The npm stub reports the package at 5.0.0 and answers the `pkg@<version>`
// existence probe with success, so each run stops at the "already exists" guard
// BEFORE any publish/push — nothing leaves the sandbox.
const NPM_AT_5_STUB = `if [[ "$2" == *@* ]]; then
  # deprecated probe -> empty (live); version-existence probe -> exists (exit 0)
  exit 0
else
  echo '["5.0.0"]'
fi`;

for (const { name, subject, body } of [
  {
    name: "a `type!:` subject",
    subject: "feat(api)!: drop the legacy field",
    body: "",
  },
  {
    name: "a `BREAKING CHANGE:` footer",
    subject: "refactor(core): rework the seam",
    body: "\n\nBREAKING CHANGE: the filterInjection seam signature changed",
  },
]) {
  test(`${name} is capped at a minor bump, never a major one`, () => {
    const { dir, binDir } = makeSandbox(NPM_AT_5_STUB);
    try {
      const git = (...args) =>
        execFileSync("git", args, { cwd: dir, stdio: "ignore" });
      // A breaking-change commit past the v0.0.0 tag — the exact input that used
      // to decide a major bump (5.x -> 6.0).
      git("commit", "-q", "--allow-empty", "-m", subject + body);
      const { status, stderr } = runScript(dir, binDir);
      assert.equal(status, 0, stderr);
      assert.match(stderr, /Conventional Commits bump level: minor/);
      assert.match(stderr, /New version: 5\.1\.0/);
      assert.doesNotMatch(stderr, /bump level: major/);
      assert.doesNotMatch(stderr, /New version: 6\./);
      assert.match(stderr, /automated MAJOR bumps are disabled/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
}

// --- Release-docs push races a concurrent branch advance -------------------
// The auto-version concurrency group serializes this workflow, but the default
// branch can still move mid-run via an ordinary PR merge from another actor. The
// run then holds a stale tip and its `git push HEAD:main` is rejected
// non-fast-forward. A plain retry can never win (the remote never rewinds); the
// script must fetch the new tip, rebase the release-docs commit onto it, and
// retry. This exercises the REAL script against a real bare remote that advances
// out from under it, and proves the release lands without clobbering the racing
// commit.

test("release-docs push rebases onto a branch that advanced mid-run", () => {
  const dir = mkdtempSync(join(tmpdir(), "vbump-race-"));
  const remote = join(dir, "remote.git");
  const work = join(dir, "work");
  const other = join(dir, "other");

  // npm stub: base is 1.0.0 (live), the target 1.1.0 is not yet published (so
  // the run proceeds to publish), every deprecation probe reports "live".
  const npmStub = `if [[ "$2" == *@* ]]; then
  if [[ "$3" == "version" ]]; then exit 1; fi
  exit 0
else
  echo '["1.0.0"]'
fi`;
  const changelog = "# Changelog\n\n## Unreleased\n\n### Added\n\n- A thing.\n";

  const gitW = (...args) =>
    execFileSync("git", args, { cwd: work, stdio: "ignore" });
  const gitO = (...args) =>
    execFileSync("git", args, { cwd: other, stdio: "ignore" });

  try {
    execFileSync("git", ["init", "-q", "--bare", "-b", "main", remote]);

    mkdirSync(work);
    gitW("init", "-q", "-b", "main");
    gitW("config", "user.email", "t@t.test");
    gitW("config", "user.name", "t");
    writeFileSync(
      join(work, "package.json"),
      JSON.stringify({ name: "sandbox-pkg", version: "1.0.0" }) + "\n",
    );
    writeFileSync(join(work, "CHANGELOG.md"), changelog);
    const binDir = join(work, "stub-bin");
    mkdirSync(binDir);
    writeFileSync(join(binDir, "npm"), `#!/usr/bin/env bash\n${npmStub}\n`);
    chmodSync(join(binDir, "npm"), 0o755);
    // pnpm publish must succeed without leaving the sandbox.
    writeFileSync(
      join(binDir, "pnpm"),
      "#!/usr/bin/env bash\necho 'stub publish ok'\nexit 0\n",
    );
    chmodSync(join(binDir, "pnpm"), 0o755);
    gitW("add", "-A");
    gitW("commit", "-q", "-m", "chore: seed");
    gitW("tag", "v1.0.0");
    gitW("remote", "add", "origin", remote);
    gitW("push", "-q", "origin", "main");
    gitW("push", "-q", "origin", "v1.0.0");
    // A release-worthy commit the run will publish.
    gitW("commit", "-q", "--allow-empty", "-m", "feat: add a thing");

    // Simulate a concurrent PR merge advancing origin/main out from under the
    // run: a second clone pushes a commit that does NOT touch CHANGELOG.md.
    execFileSync("git", ["clone", "-q", remote, other], { stdio: "ignore" });
    gitO("config", "user.email", "o@o.test");
    gitO("config", "user.name", "o");
    writeFileSync(join(other, "OTHER.txt"), "concurrent work\n");
    gitO("add", "-A");
    gitO("commit", "-q", "-m", "chore: concurrent merge");
    gitO("push", "-q", "origin", "main");

    const env = { ...process.env, PATH: `${binDir}:${process.env.PATH}` };
    delete env.ANTHROPIC_API_KEY;
    delete env.GITHUB_OUTPUT;
    // In CI these name the PR's merge ref (e.g. 167/merge), and the script reads
    // GITHUB_REF_NAME as the branch to push the release-docs commit to. Left set,
    // the run would target that ref instead of the sandbox repo's `main`, so the
    // rebase-on-reject path never fires and the test fails only under Actions.
    delete env.GITHUB_REF_NAME;
    delete env.GITHUB_REF;
    const res = spawnSync("bash", [LIVE_SCRIPT], {
      cwd: work,
      env,
      encoding: "utf8",
    });
    assert.equal(res.error, undefined, "failed to spawn the release script");
    assert.equal(res.status, 0, res.stderr);

    // Proves we went through the rebase-on-reject path, not a lucky
    // fast-forward — guards the test against passing vacuously.
    assert.match(res.stderr, /rejected \(attempt \d+\/\d+\); rebasing/);

    // The release-docs commit and tag reached the remote, stacked ON TOP of the
    // racing commit (a force-push would have erased it).
    const remoteSubjects = execFileSync(
      "git",
      ["-C", remote, "log", "main", "--pretty=%s"],
      { encoding: "utf8" },
    );
    assert.match(remoteSubjects, /docs: release 1\.1\.0/);
    assert.match(
      remoteSubjects,
      /chore: concurrent merge/,
      "the concurrent commit must survive — the push must rebase, never force",
    );
    const remoteTags = execFileSync("git", ["-C", remote, "tag"], {
      encoding: "utf8",
    });
    assert.match(remoteTags, /^v1\.1\.0$/m, "the release tag must be pushed");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
