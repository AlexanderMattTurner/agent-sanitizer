// commit-refreshed-manifest.sh drives real git against a real bare remote —
// nothing here is stubbed, because the whole script IS its git handling. The
// bun compile that produces the manifest is the half deliberately left out of
// the script (auto-version.yaml runs the generator in the step above it), so
// the four-target, ~400 MB download never has to happen for these cases.
//
// Each case is a way the default branch can end up NOT carrying a manifest that
// describes its bundle — the state the SessionStart provisioner refuses to
// install a binary in.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT = join(
  dirname(fileURLToPath(import.meta.url)),
  "commit-refreshed-manifest.sh",
);
const MANIFEST = "plugin/dist/hooks/hook-binaries.sha256";

const scratched = [];
process.on("exit", () => {
  for (const dir of scratched) rmSync(dir, { recursive: true, force: true });
});
const scratchDir = (prefix) => {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  scratched.push(dir);
  return dir;
};

const git = (cwd, ...args) => {
  const run = spawnSync("git", args, { cwd, encoding: "utf8" });
  assert.equal(run.status, 0, `git ${args.join(" ")}: ${run.stderr}`);
  return run.stdout.trim();
};

const writeManifest = (repo, contents) => {
  mkdirSync(join(repo, dirname(MANIFEST)), { recursive: true });
  writeFileSync(join(repo, MANIFEST), contents);
};

/**
 * A clone of a bare remote whose `main` already carries a manifest, standing in
 * for the auto-version checkout.
 * @returns {{repo: string, remote: string}}
 */
const scratchCheckout = () => {
  const remote = scratchDir("refresh-manifest-remote-");
  git(remote, "init", "--bare", "--initial-branch=main", ".");
  const repo = scratchDir("refresh-manifest-repo-");
  git(repo, "init", "--initial-branch=main", ".");
  git(repo, "config", "user.name", "seed");
  git(repo, "config", "user.email", "seed@example.invalid");
  writeManifest(repo, "old\n");
  git(repo, "add", "-A");
  git(repo, "commit", "-m", "seed");
  git(repo, "remote", "add", "origin", remote);
  git(repo, "push", "origin", "main");
  return { repo, remote };
};

/** Run the script in `repo`, with a fast retry so a rejected push is quick. */
const refresh = (repo, env = {}) =>
  spawnSync("bash", [SCRIPT], {
    cwd: repo,
    encoding: "utf8",
    env: {
      ...process.env,
      GITHUB_REF_NAME: "main",
      RETRY_MAX: "1",
      RETRY_BASE_DELAY: "0",
      ...env,
    },
  });

test("pushes a changed manifest to the branch and commits nothing else", () => {
  const { repo, remote } = scratchCheckout();
  writeManifest(repo, "fresh\n");
  // A second dirty file stands in for package.json, which version-bump.sh
  // leaves modified in the working tree; committing it here would publish a
  // version bump nobody asked for.
  writeFileSync(join(repo, "package.json"), "{}\n");

  const run = refresh(repo);
  assert.equal(run.status, 0, run.stderr);

  assert.equal(git(remote, "show", "main:" + MANIFEST), "fresh");
  assert.match(
    git(remote, "log", "-1", "--format=%s", "main"),
    /^chore\(plugin\):/,
  );
  assert.deepEqual(
    git(remote, "show", "--name-only", "--format=", "main").split("\n"),
    [MANIFEST],
  );
});

test("does nothing when the manifest already describes this tree", () => {
  const { repo, remote } = scratchCheckout();
  const before = git(remote, "rev-parse", "main");

  const run = refresh(repo);
  assert.equal(run.status, 0, run.stderr);

  assert.equal(git(remote, "rev-parse", "main"), before);
  assert.match(run.stderr, /already describes this tree/);
});

test("refuses a detached HEAD that GITHUB_REF_NAME does not name", () => {
  const { repo, remote } = scratchCheckout();
  git(repo, "checkout", "--detach", "HEAD");
  writeManifest(repo, "fresh\n");
  const before = git(remote, "rev-parse", "main");

  const run = refresh(repo, { GITHUB_REF_NAME: "" });
  assert.equal(run.status, 1);
  assert.match(run.stderr, /detached HEAD/);
  assert.equal(git(remote, "rev-parse", "main"), before);
});

// The self-healing case: a racing merge moved the branch, so this run's
// manifest describes neither tree and must NOT be forced on. Going red here is
// what stops auto-version.yaml from tagging a release the provisioner rejects.
test("fails loudly when the branch moved under it", () => {
  const { repo, remote } = scratchCheckout();
  const racer = scratchDir("refresh-manifest-racer-");
  git(racer, "clone", remote, ".");
  git(racer, "config", "user.name", "racer");
  git(racer, "config", "user.email", "racer@example.invalid");
  writeFileSync(join(racer, "raced.txt"), "merged while we compiled\n");
  git(racer, "add", "-A");
  git(racer, "commit", "-m", "feat: race");
  git(racer, "push", "origin", "main");
  const raced = git(remote, "rev-parse", "main");

  writeManifest(repo, "fresh\n");
  const run = refresh(repo);

  assert.equal(run.status, 1);
  assert.match(run.stderr, /failed to push the refreshed/);
  assert.equal(git(remote, "rev-parse", "main"), raced);
  assert.equal(git(remote, "show", "main:" + MANIFEST), "old");
});
