// commit-refreshed-manifest.sh drives real git against a real bare remote —
// the tip sync, the change detection, the commit and the push all run for real.
// Only the generator is stood in for, and only because the real one
// (`build-hook-binaries.mjs`) compiles four bun targets at ~100 MB each on a
// cold cross-target cache: that is the licensed "cannot run in a test" case, and
// it is why the script takes the generator as argv instead of calling it by name.
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

/** A clone of `remote` that can land commits on main behind the run's back. */
const racer = (remote) => {
  const dir = scratchDir("refresh-manifest-racer-");
  git(dir, "clone", remote, ".");
  git(dir, "config", "user.name", "racer");
  git(dir, "config", "user.email", "racer@example.invalid");
  return dir;
};
const land = (dir, file, contents) => {
  writeFileSync(join(dir, file), contents);
  git(dir, "add", "-A");
  git(dir, "commit", "-m", `feat: ${file}`);
  git(dir, "push", "origin", "main");
};

/** Shell that writes `contents` into the manifest, as the real generator would. */
const generatorWriting = (contents) =>
  `mkdir -p ${dirname(MANIFEST)} && printf '%s\\n' '${contents}' >${MANIFEST}`;

/**
 * Run the script in `repo` with a stand-in generator.
 * @param {string} repo
 * @param {string} [generator] shell run as the generator; defaults to one that
 *   writes a manifest differing from the seed.
 */
const refresh = (repo, generator = generatorWriting("fresh"), env = {}) =>
  spawnSync("bash", [SCRIPT, "bash", "-c", generator], {
    cwd: repo,
    encoding: "utf8",
    // A fast retry so the rejected-push case does not sit in backoff.
    env: {
      ...process.env,
      GITHUB_REF_NAME: "main",
      RETRY_MAX: "1",
      RETRY_BASE_DELAY: "0",
      ...env,
    },
  });

test("pushes a changed manifest and commits only that file", () => {
  const { repo, remote } = scratchCheckout();

  // The generator also drops a stray file: only the manifest may be committed,
  // so an unrelated artifact of the build never rides along onto main.
  const run = refresh(
    repo,
    `${generatorWriting("fresh")} && echo scratch >build.log`,
  );
  assert.equal(run.status, 0, run.stderr);

  assert.equal(git(remote, "show", `main:${MANIFEST}`), "fresh");
  assert.match(
    git(remote, "log", "-1", "--format=%s", "main"),
    /^chore\(plugin\):/,
  );
  assert.deepEqual(
    git(remote, "show", "--name-only", "--format=", "main").split("\n"),
    [MANIFEST],
  );
});

test("does nothing when the generator leaves the manifest alone", () => {
  const { repo, remote } = scratchCheckout();
  const before = git(remote, "rev-parse", "main");

  const run = refresh(repo, generatorWriting("old"));
  assert.equal(run.status, 0, run.stderr);

  assert.equal(git(remote, "rev-parse", "main"), before);
  assert.match(run.stderr, /already describes the tip/);
});

test("refuses a detached HEAD that GITHUB_REF_NAME does not name", () => {
  const { repo, remote } = scratchCheckout();
  git(repo, "checkout", "--detach", "HEAD");
  const before = git(remote, "rev-parse", "main");

  const run = refresh(repo, generatorWriting("fresh"), { GITHUB_REF_NAME: "" });
  assert.equal(run.status, 1);
  assert.match(run.stderr, /detached HEAD/);
  assert.equal(git(remote, "rev-parse", "main"), before);
});

test("refuses to run with no generator to run", () => {
  const { repo, remote } = scratchCheckout();
  const before = git(remote, "rev-parse", "main");

  const run = spawnSync("bash", [SCRIPT], {
    cwd: repo,
    encoding: "utf8",
    env: { ...process.env, GITHUB_REF_NAME: "main" },
  });
  assert.equal(run.status, 1);
  assert.match(run.stderr, /usage:/);
  assert.equal(git(remote, "rev-parse", "main"), before);
});

// The concurrency group queues auto-version runs, so by the time one starts, the
// branch can already carry a later merge than the SHA that triggered it.
// Compiling from that stale checkout would describe a bundle no longer on the
// branch AND be rejected non-fast-forward — one stale checkout, both failures.
test("regenerates against the branch tip, not the checked-out SHA", () => {
  const { repo, remote } = scratchCheckout();
  land(racer(remote), "merged-first.txt", "landed before this run started\n");
  const raced = git(remote, "rev-parse", "main");

  const run = refresh(repo);
  assert.equal(run.status, 0, run.stderr);

  assert.equal(git(remote, "show", `main:${MANIFEST}`), "fresh");
  assert.equal(git(remote, "rev-parse", "main~1"), raced);
});

// A merge that lands DURING the compile is the residual case: this run's
// manifest describes neither tree, so going red — which aborts the release —
// beats forcing it on. The next push to main re-runs this from the new tip.
test("fails loudly when the branch moves during the generator run", () => {
  const { repo, remote } = scratchCheckout();
  const during = racer(remote);
  const run = refresh(
    repo,
    `${generatorWriting("fresh")} && git -C ${during} commit --allow-empty -m 'feat: race' -q && git -C ${during} push -q origin main`,
  );

  assert.equal(run.status, 1);
  assert.match(run.stderr, /failed to push the refreshed/);
  assert.equal(git(remote, "show", `main:${MANIFEST}`), "old");
});
