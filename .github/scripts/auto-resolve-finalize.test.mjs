import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  mkdtempSync,
  writeFileSync,
  readFileSync,
  mkdirSync,
  chmodSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPT = join(HERE, "auto-resolve-finalize.sh");
const scratch = () => mkdtempSync(join(tmpdir(), "auto-resolve-fin-"));
const git = (cwd, ...args) =>
  execFileSync("git", ["-C", cwd, ...args], { encoding: "utf8" });

// A work clone mid-merge: `main` and `feature` both edit `file` (default a.md),
// and b.md exists cleanly on both. Merging main into feature conflicts on
// `file` only. `extras` maps path → content committed cleanly on both sides —
// a lockfile fixture needs the sibling manifest its tool requires, or
// lockfile_tool correctly declines to claim it. Returns { work, origin }.
function midMerge(bContent = "b base\n", file = "a.md", extras = {}) {
  const root = scratch();
  const origin = join(root, "origin.git");
  const work = join(root, "work");
  git(root, "init", "--bare", "-q", origin);
  git(root, "clone", "-q", origin, work);
  git(work, "config", "user.email", "t@t");
  git(work, "config", "user.name", "t");
  git(work, "config", "commit.gpgsign", "false");
  mkdirSync(dirname(join(work, file)), { recursive: true });
  writeFileSync(join(work, file), "base\n");
  writeFileSync(join(work, "b.md"), bContent);
  for (const [p, content] of Object.entries(extras)) {
    mkdirSync(dirname(join(work, p)), { recursive: true });
    writeFileSync(join(work, p), content);
  }
  git(work, "add", "-A");
  git(work, "commit", "-q", "-m", "base");
  git(work, "branch", "-M", "main");
  git(work, "push", "-q", "origin", "main");
  git(work, "checkout", "-q", "-b", "feature");
  writeFileSync(join(work, file), "feature side\n");
  git(work, "commit", "-q", "-am", "feature");
  git(work, "push", "-q", "origin", "feature");
  git(work, "checkout", "-q", "main");
  writeFileSync(join(work, file), "main side\n");
  git(work, "commit", "-q", "-am", "main change");
  git(work, "checkout", "-q", "feature");
  try {
    git(work, "merge", "--no-edit", "main");
    throw new Error("expected a conflict");
  } catch (err) {
    if (String(err.message).includes("expected a conflict")) throw err;
  }
  return { work, origin };
}

// Run finalize.sh in `work` with a fake `gh` on PATH that records every
// invocation, so a test can assert on the comment(s)/labels the script posts.
// `env` overrides/extends the script's environment (e.g. PROTECTED_PATHS, or
// TEMPLATE_SYNC_TOKEN_ORG: "" to exercise the fail-closed path). `shims` maps
// extra executable name → bash body, installed on PATH ahead of the real tool
// (e.g. a fake `pnpm` standing in for lockfile regeneration). Returns the error
// (null on success), whether a merge is still in progress (MERGE_HEAD present),
// and the recorded gh argv lines.
function runFinalize(work, conflictList, env = {}, shims = {}) {
  // The shim lives OUTSIDE the work clone: finalize.sh refuses any untracked
  // file inside the tree, so parking .fakebin/.gh-calls there would trip it.
  const root = dirname(work);
  const ghLog = join(root, ".gh-calls");
  writeFileSync(ghLog, "");
  const ghBin = join(root, ".fakebin");
  mkdirSync(ghBin, { recursive: true });
  const ghPath = join(ghBin, "gh");
  writeFileSync(
    ghPath,
    `#!/usr/bin/env bash\nprintf '%s\\n' "$*" >> "${ghLog}"\nexit 0\n`,
  );
  chmodSync(ghPath, 0o755);
  for (const [name, body] of Object.entries(shims)) {
    const p = join(ghBin, name);
    writeFileSync(p, `#!/usr/bin/env bash\n${body}\n`);
    chmodSync(p, 0o755);
  }
  let error = null;
  try {
    execFileSync("bash", [SCRIPT], {
      cwd: work,
      encoding: "utf8",
      env: {
        ...process.env,
        HEAD_REF: "feature",
        BASE_REF: "main",
        PR: "1",
        GITHUB_TOKEN: "x",
        // Push token present by default so the happy path pushes to the local
        // file:// origin (the extraheader auth is a no-op for file transport).
        // A test overrides it to "" to exercise the fail-closed branch.
        TEMPLATE_SYNC_TOKEN_ORG: "x",
        CONFLICT_LIST: conflictList,
        ...env,
        PATH: `${ghBin}:${process.env.PATH ?? ""}`,
      },
    });
  } catch (err) {
    error = err;
  }
  let merging = true;
  try {
    git(work, "rev-parse", "--verify", "-q", "MERGE_HEAD");
  } catch {
    merging = false;
  }
  const ghCalls = readFileSync(ghLog, "utf8").split("\n").filter(Boolean);
  return { error, merging, ghCalls };
}

test("finalize commits + pushes when the resolution stays within the conflicted set", () => {
  const { work, origin } = midMerge();
  writeFileSync(join(work, "a.md"), "resolved: feature + main\n"); // "LLM" resolved a.md
  const before = git(work, "rev-parse", "origin/feature").trim();
  const { error, merging } = runFinalize(work, "a.md");
  assert.equal(error, null); // committed and pushed cleanly
  assert.equal(merging, false);
  const after = git(origin, "rev-parse", "feature").trim();
  assert.notEqual(after, before); // origin advanced by the merge commit
});

test("finalize REFUSES a stray edit to a file outside the conflicted set", () => {
  const { work, origin } = midMerge();
  writeFileSync(join(work, "a.md"), "resolved\n"); // the allowed conflict
  writeFileSync(join(work, "b.md"), "the LLM strayed here\n"); // NOT in CONFLICT_LIST
  const before = git(origin, "rev-parse", "feature").trim();
  const { error, merging } = runFinalize(work, "a.md");
  assert.notEqual(error, null); // finalize failed (exit != 0)
  assert.equal(merging, false); // merge aborted
  assert.equal(git(origin, "rev-parse", "feature").trim(), before); // nothing pushed
});

test("finalize REFUSES a new untracked file the resolver created", () => {
  const { work, origin } = midMerge();
  writeFileSync(join(work, "a.md"), "resolved\n");
  writeFileSync(join(work, "sneaky.md"), "new file the LLM added\n");
  const before = git(origin, "rev-parse", "feature").trim();
  const { error } = runFinalize(work, "a.md");
  assert.notEqual(error, null);
  assert.equal(git(origin, "rev-parse", "feature").trim(), before);
});

test("finalize REFUSES when a conflict marker is left behind", () => {
  const { work, origin } = midMerge();
  writeFileSync(
    join(work, "a.md"),
    "top\n<<<<<<< HEAD\nx\n=======\ny\n>>>>>>> main\n",
  );
  const before = git(origin, "rev-parse", "feature").trim();
  const { error, merging } = runFinalize(work, "a.md");
  assert.notEqual(error, null);
  assert.equal(merging, false);
  assert.equal(git(origin, "rev-parse", "feature").trim(), before);
});

test("finalize IGNORES a benign ======= line in a clean, non-conflicted file", () => {
  // A committed Markdown setext-H1 underline (`=======`) in a file that did NOT
  // conflict must not trip the leftover-marker scan: the scan is scoped to the
  // resolved set, so an unrelated doc line can't abort every resolution. Red
  // against a whole-tree `git grep -- .`, green against the scoped scan.
  const { work, origin } = midMerge("Title\n=======\n\nbody\n");
  writeFileSync(join(work, "a.md"), "resolved: feature + main\n");
  const before = git(origin, "rev-parse", "feature").trim();
  const { error, merging } = runFinalize(work, "a.md");
  assert.equal(error, null); // succeeds despite b.md's ======= line
  assert.equal(merging, false);
  assert.notEqual(git(origin, "rev-parse", "feature").trim(), before); // pushed
});

test("leftover markers WITH permission denials report the true cause (blocked, not too hard)", () => {
  const { work, origin } = midMerge();
  writeFileSync(
    join(work, "a.md"),
    "top\n<<<<<<< HEAD\nx\n=======\ny\n>>>>>>> main\n",
  );
  const before = git(origin, "rev-parse", "feature").trim();
  const { error, merging, ghCalls } = runFinalize(work, "a.md", {
    LLM_PERMISSION_DENIALS: "5",
  });
  assert.notEqual(error, null); // still fails — nothing was resolved
  assert.equal(merging, false); // merge aborted
  assert.equal(git(origin, "rev-parse", "feature").trim(), before); // nothing pushed
  const comments = ghCalls.filter((c) => c.startsWith("pr comment"));
  assert.equal(comments.length, 1);
  assert.ok(comments[0].includes("denied permission 5 time"));
  assert.ok(!comments[0].includes("left conflict markers behind")); // NOT the "too hard" message
});

test("a successful finalize posts exactly one comment, with no protected-path warning by default", () => {
  const { work } = midMerge();
  writeFileSync(join(work, "a.md"), "resolved: feature + main\n");
  const { error, ghCalls } = runFinalize(work, "a.md");
  assert.equal(error, null);
  const comments = ghCalls.filter((c) => c.startsWith("pr comment"));
  assert.equal(comments.length, 1);
  assert.ok(comments[0].includes("Auto-resolved the merge conflict"));
  assert.ok(!comments[0].includes("protected path"));
});

test("a successful finalize with PROTECTED_PATHS folds the warning into the success comment", () => {
  const { work } = midMerge();
  writeFileSync(join(work, "a.md"), "resolved: feature + main\n");
  const { error, ghCalls } = runFinalize(work, "a.md", {
    PROTECTED_PATHS: ".github/workflows/ci.yaml",
  });
  assert.equal(error, null);
  const comments = ghCalls.filter((c) => c.startsWith("pr comment"));
  assert.equal(comments.length, 1);
  assert.ok(comments[0].includes("Auto-resolved the merge conflict"));
  assert.ok(comments[0].includes("protected path"));
  assert.ok(comments[0].includes(".github/workflows/ci.yaml"));
});

// A `pnpm` shim that refuses to behave like a tool run on a bad seed, so every
// property finalize's regen stage depends on is load-bearing in the test:
// deleting the `git checkout`, flipping it back to `--ours`, dropping a flag,
// or dropping the credential scrubbing each turns this green run red.
// `argvLog` lives OUTSIDE the work tree — an untracked file inside it would be
// a different failure.
const pnpmShim = (argvLog, lock = "pnpm-lock.yaml") => `
printf '%s\\n' "$*" >> "${argvLog}"
grep -q '<<<<<<<' "${lock}" && { echo "seeded with conflict markers" >&2; exit 3; }
grep -q 'main side' "${lock}" || { echo "not seeded from the base side" >&2; exit 4; }
[ -z "\${TEMPLATE_SYNC_TOKEN_ORG:-}\${GITHUB_TOKEN:-}\${GH_TOKEN:-}" ] || { echo "push credentials visible to the tool" >&2; exit 5; }
printf 'lockfileVersion: regenerated\\n' > "${lock}"
`;

test("finalize regenerates a deferred lockfile from the BASE side, scrubbed, and pushes", () => {
  const { work, origin } = midMerge("b base\n", "pnpm-lock.yaml", {
    "package.json": "{}\n",
  });
  const argvLog = join(dirname(work), ".pnpm-argv");
  writeFileSync(argvLog, "");
  const before = git(origin, "rev-parse", "feature").trim();
  const { error, merging, ghCalls } = runFinalize(
    work,
    "",
    { DEFERRED_LOCK: "pnpm-lock.yaml" },
    { pnpm: pnpmShim(argvLog) },
  );
  assert.equal(error, null);
  assert.equal(merging, false);
  assert.notEqual(git(origin, "rev-parse", "feature").trim(), before); // pushed
  assert.equal(
    git(origin, "show", "feature:pnpm-lock.yaml"),
    "lockfileVersion: regenerated\n", // the TOOL's output, not either side's
  );
  // The flags are load-bearing: --lockfile-only keeps it off node_modules,
  // --no-frozen-lockfile defeats pnpm's CI default (which would refuse the
  // update), and --ignore-scripts keeps PR-authored lifecycle code from running
  // in a job that holds a write token.
  assert.equal(
    readFileSync(argvLog, "utf8").trim(),
    "install --lockfile-only --no-frozen-lockfile --ignore-scripts",
  );
  const comments = ghCalls.filter((c) => c.startsWith("pr comment"));
  assert.equal(comments.length, 1);
  assert.ok(comments[0].includes("Auto-resolved the merge conflict"));
});

test("a deferred lockfile in a SUBDIRECTORY is regenerated in its own directory", () => {
  // The only case that exercises regen_lockfile's `cd "$(dirname …)"`: the shim
  // writes to a RELATIVE path, so it lands in the wrong place unless finalize
  // ran the tool from sub/.
  const { work, origin } = midMerge("b base\n", "sub/pnpm-lock.yaml", {
    "sub/package.json": "{}\n",
  });
  const argvLog = join(dirname(work), ".pnpm-argv-sub");
  writeFileSync(argvLog, "");
  const { error } = runFinalize(
    work,
    "",
    { DEFERRED_LOCK: "sub/pnpm-lock.yaml" },
    { pnpm: pnpmShim(argvLog) },
  );
  assert.equal(error, null);
  assert.equal(
    git(origin, "show", "feature:sub/pnpm-lock.yaml"),
    "lockfileVersion: regenerated\n",
  );
});

test("a failing lockfile regeneration aborts loud and pushes nothing", () => {
  const { work, origin } = midMerge("b base\n", "pnpm-lock.yaml", {
    "package.json": "{}\n",
  });
  const before = git(origin, "rev-parse", "feature").trim();
  const { error, merging, ghCalls } = runFinalize(
    work,
    "",
    { DEFERRED_LOCK: "pnpm-lock.yaml" },
    { pnpm: "exit 1" },
  );
  assert.notEqual(error, null); // failed rather than guessing a lockfile
  assert.equal(merging, false); // merge aborted for a human
  assert.equal(git(origin, "rev-parse", "feature").trim(), before); // no push
  const comments = ghCalls.filter((c) => c.startsWith("pr comment"));
  assert.equal(comments.length, 1);
  assert.ok(comments[0].includes("could not finish"));
  assert.ok(comments[0].includes("pnpm-lock.yaml"));
});

test("finalize FAILS CLOSED (labels auto-resolve-blocked, no push) when no push token is set", () => {
  const { work, origin } = midMerge();
  writeFileSync(join(work, "a.md"), "resolved: feature + main\n");
  const before = git(origin, "rev-parse", "feature").trim();
  const { error, ghCalls } = runFinalize(work, "a.md", {
    TEMPLATE_SYNC_TOKEN_ORG: "", // absent → no token can reliably push
  });
  assert.notEqual(error, null); // fails loud rather than pushing with a weak token
  assert.equal(git(origin, "rev-parse", "feature").trim(), before); // nothing pushed
  // Labeled auto-resolve-blocked so discover skips it until a human intervenes.
  assert.ok(ghCalls.some((c) => c.includes("auto-resolve-blocked")));
  const comments = ghCalls.filter((c) => c.startsWith("pr comment"));
  assert.equal(comments.length, 1);
  assert.ok(comments[0].includes("TEMPLATE_SYNC_TOKEN_ORG"));
});
