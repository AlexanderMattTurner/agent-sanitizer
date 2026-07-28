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
const SCRIPT = join(HERE, "auto-resolve-prepare.sh");
const scratch = () => mkdtempSync(join(tmpdir(), "auto-resolve-"));

const git = (cwd, ...args) =>
  execFileSync("git", ["-C", cwd, ...args], { encoding: "utf8" });

// Build an origin repo whose `main` and `feature` branches both edit every path
// in `files` (a string or array), so merging main into feature conflicts on
// exactly those paths. `baseExtras` maps extra path → content committed on the
// base only (e.g. a .gitattributes marking a path unmergeable). Returns a
// `work` clone checked out on feature (with `origin` pointing at the bare repo).
function fixtureConflictingOn(files, baseExtras = {}) {
  files = Array.isArray(files) ? files : [files];
  const root = scratch();
  const origin = join(root, "origin.git");
  const work = join(root, "work");
  git(root, "init", "--bare", "-q", origin);
  git(root, "clone", "-q", origin, work);
  git(work, "config", "user.email", "t@t");
  git(work, "config", "user.name", "t");

  for (const [p, content] of Object.entries(baseExtras)) {
    mkdirSync(dirname(join(work, p)), { recursive: true });
    writeFileSync(join(work, p), content);
  }
  for (const file of files) {
    mkdirSync(dirname(join(work, file)), { recursive: true });
    writeFileSync(join(work, file), "base\n");
  }
  git(work, "add", "-A");
  git(work, "commit", "-q", "-m", "base");
  git(work, "branch", "-M", "main");
  git(work, "push", "-q", "origin", "main");

  git(work, "checkout", "-q", "-b", "feature");
  for (const file of files) writeFileSync(join(work, file), "feature side\n");
  git(work, "commit", "-q", "-am", "feature");
  git(work, "push", "-q", "origin", "feature");

  git(work, "checkout", "-q", "main");
  for (const file of files) writeFileSync(join(work, file), "main side\n");
  git(work, "commit", "-q", "-am", "main change");
  git(work, "push", "-q", "origin", "main");

  git(work, "checkout", "-q", "feature");
  return work;
}

// Run prepare.sh in `work` with a fake `gh` on PATH that records every
// invocation, so a test can assert prepare never talks to GitHub (flagging a
// protected path is finalize's job, via the `protected_paths` output). Returns
// the parsed $GITHUB_OUTPUT, whether a merge is still in progress (MERGE_HEAD
// present), and the recorded gh argv lines.
function runPrepare(work, { path, shims = {} } = {}) {
  const outFile = join(work, ".gh-output");
  writeFileSync(outFile, "");
  const ghLog = join(work, ".gh-calls");
  writeFileSync(ghLog, "");
  const ghBin = join(work, ".fakebin");
  mkdirSync(ghBin, { recursive: true });
  const ghPath = join(ghBin, "gh");
  writeFileSync(
    ghPath,
    `#!/usr/bin/env bash\nprintf '%s\\n' "$*" >> "${ghLog}"\nexit 0\n`,
  );
  chmodSync(ghPath, 0o755);
  // Stub the lockfile tools rather than relying on the host's toolchain:
  // prepare only probes them with `command -v`, so a stub is enough, and it
  // keeps classification tests hermetic on a runner where (say) uv is absent.
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
        BASE_REF: "main",
        HEAD_REF: "feature",
        GITHUB_TOKEN: "x",
        GITHUB_OUTPUT: outFile,
        PATH: `${ghBin}:${path ?? process.env.PATH ?? ""}`,
      },
    });
  } catch (err) {
    error = err;
  }
  const outputs = Object.fromEntries(
    readFileSync(outFile, "utf8")
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        const i = line.indexOf("=");
        return [line.slice(0, i), line.slice(i + 1)];
      }),
  );
  let merging = true;
  try {
    git(work, "rev-parse", "--verify", "-q", "MERGE_HEAD");
  } catch {
    merging = false;
  }
  const ghCalls = readFileSync(ghLog, "utf8").split("\n").filter(Boolean);
  const commented = ghCalls.some((c) => c.startsWith("pr comment"));
  return { outputs, merging, error, ghCalls, commented };
}

test("a conflict in a SAFE path is handed to the LLM with an empty protected set", () => {
  const work = fixtureConflictingOn("docs/thing.md");
  const { outputs, merging, commented } = runPrepare(work);
  assert.equal(outputs.needs_llm, "true");
  assert.equal(outputs.needs_commit, "true");
  assert.equal(outputs.conflict_list, "docs/thing.md");
  assert.equal(outputs.protected_paths, "");
  assert.equal(merging, true); // merge left mid-flight for Claude + finalize
  assert.equal(commented, false);
});

test("a conflict in a PROTECTED path is handed to the LLM AND reported via protected_paths", () => {
  const work = fixtureConflictingOn(".github/workflows/ci.yaml");
  const { outputs, merging, ghCalls } = runPrepare(work);
  assert.equal(outputs.needs_llm, "true"); // resolved, not escalated away
  assert.equal(outputs.needs_commit, "true");
  assert.equal(outputs.conflict_list, ".github/workflows/ci.yaml");
  assert.equal(outputs.protected_paths, ".github/workflows/ci.yaml"); // finalize flags it
  assert.equal(merging, true); // merge KEPT for Claude + finalize, not aborted
  // Prepare never talks to GitHub — a run that resolves nothing says nothing,
  // so the flag rides finalize's pushed-resolution comment instead.
  assert.deepEqual(ghCalls, []);
});

test("each protected prefix is reported and handed to the LLM, member by member", () => {
  // The generic template protects exactly two areas: the repo's Claude config
  // (.claude/) and all of its CI machinery (.github/). Build a probe file under
  // each protected prefix, plus a NON-protected control that must resolve with an
  // empty protected set.
  const protectedPrefixes = [
    ".claude/hooks/",
    ".claude/skills/",
    ".github/workflows/",
    ".github/scripts/",
    ".github/actions/",
  ];
  const cases = [
    ...protectedPrefixes.map((p) => ({
      path: `${p}probe.txt`,
      protected: true,
    })),
    // Control: a top-level script is NOT protected under the generic regex.
    { path: "setup.sh", protected: false },
    { path: "src/index.js", protected: false },
  ];
  for (const { path, protected: isProtected } of cases) {
    const work = fixtureConflictingOn(path);
    const { outputs, merging, commented } = runPrepare(work);
    assert.equal(outputs.needs_commit, "true", `${path} must still resolve`);
    assert.equal(outputs.needs_llm, "true", `${path} must go to the LLM`);
    assert.equal(merging, true, `${path} merge must be kept`);
    assert.equal(
      outputs.protected_paths,
      isProtected ? path : "",
      `${path} protected_paths mismatch`,
    );
    assert.equal(commented, false, `${path} must not comment from prepare`);
  }
});

// Every lockfile in lib.sh's `lockfile_tool` table, with the manifest its tool
// requires beside it. All three tools are present in this repo's toolchain, so
// `command -v` holds wherever this suite runs. Kept in lockstep with the case
// table: a lockfile added there without a case here classifies untested.
const LOCKFILES = [
  {
    lock: "pnpm-lock.yaml",
    tool: "pnpm",
    manifest: "package.json",
    manifestBody: "{}\n",
  },
  {
    lock: "package-lock.json",
    tool: "npm",
    manifest: "package.json",
    manifestBody: "{}\n",
  },
  {
    lock: "uv.lock",
    tool: "uv",
    manifest: "pyproject.toml",
    manifestBody: "[project]\nname = 'x'\n",
  },
];

for (const { lock, tool, manifest, manifestBody } of LOCKFILES) {
  test(`a conflicted ${lock} is deferred to owning-tool regeneration, never the LLM`, () => {
    const work = fixtureConflictingOn(lock, { [manifest]: manifestBody });
    const { outputs, merging, commented } = runPrepare(work, {
      shims: { [tool]: "exit 0" },
    });
    assert.equal(outputs.needs_llm, "false");
    assert.equal(outputs.needs_commit, "true");
    assert.equal(outputs.conflict_list, "");
    assert.equal(outputs.deferred_lock, lock);
    assert.equal(outputs.unresolvable, undefined);
    assert.equal(merging, true); // merge kept mid-flight for finalize's regen
    assert.equal(commented, false);
  });
}

test("a lockfile in a SUBDIRECTORY is claimed via its own sibling manifest", () => {
  const work = fixtureConflictingOn("sub/pnpm-lock.yaml", {
    "sub/package.json": "{}\n",
  });
  const { outputs } = runPrepare(work, { shims: { pnpm: "exit 0" } });
  assert.equal(outputs.deferred_lock, "sub/pnpm-lock.yaml");
  assert.equal(outputs.conflict_list, "");
});

test("a lockfile-NAMED file with no sibling manifest is NOT claimed — it goes to the LLM", () => {
  // Precision over recall: a committed fixture named package-lock.json is not a
  // lockfile. Claiming it would be SILENT corruption — `npm install
  // --package-lock-only` in a manifest-less directory succeeds and writes an
  // empty-dependency lockfile over the fixture while the run stays green.
  const work = fixtureConflictingOn("test/fixtures/package-lock.json");
  const { outputs, merging } = runPrepare(work, { shims: { npm: "exit 0" } });
  assert.equal(outputs.deferred_lock, "");
  assert.equal(outputs.conflict_list, "test/fixtures/package-lock.json");
  assert.equal(outputs.unresolvable, undefined);
  assert.equal(merging, true);
});

test("a lockfile whose owning tool is ABSENT from PATH is unresolvable, not sent to the LLM", () => {
  // The `command -v` gate's other branch: with no tool to rerun, an edit-based
  // "resolution" can never be verified, so it must hand off to a human rather
  // than fall through to the LLM.
  const work = fixtureConflictingOn("pnpm-lock.yaml", {
    "package.json": "{}\n",
  });
  // No pnpm shim, and every real pnpm stripped from PATH.
  const pnpmDirs = new Set(
    execFileSync("bash", ["-c", "command -v pnpm || true"], {
      encoding: "utf8",
    })
      .split("\n")
      .filter(Boolean)
      .map((p) => dirname(p)),
  );
  const path = (process.env.PATH ?? "")
    .split(":")
    .filter((d) => d && !pnpmDirs.has(d))
    .join(":");
  const { outputs, commented } = runPrepare(work, { path });
  assert.equal(outputs.needs_llm, "false");
  assert.equal(outputs.needs_commit, "false");
  assert.equal(outputs.unresolvable, "pnpm-lock.yaml");
  assert.equal(outputs.conflict_list, undefined);
  assert.equal(commented, false);
});

test("a manifest+lockfile conflict splits: manifest to the LLM, lockfile to regen", () => {
  const work = fixtureConflictingOn(["package.json", "pnpm-lock.yaml"]);
  const { outputs, merging } = runPrepare(work);
  assert.equal(outputs.needs_llm, "true");
  assert.equal(outputs.needs_commit, "true");
  assert.equal(outputs.conflict_list, "package.json");
  assert.equal(outputs.deferred_lock, "pnpm-lock.yaml");
  assert.equal(outputs.unresolvable, undefined);
  assert.equal(merging, true);
});

test("a `-merge`-attributed conflict with no owning tool is handed off as unresolvable", () => {
  const work = fixtureConflictingOn("assets/logo.bin", {
    ".gitattributes": "*.bin -merge\n",
  });
  const { outputs, commented } = runPrepare(work);
  assert.equal(outputs.needs_llm, "false");
  assert.equal(outputs.needs_commit, "false");
  assert.equal(outputs.unresolvable, "assets/logo.bin");
  // Prepare never talks to GitHub — the handoff comment is the HANDOFF step's.
  assert.equal(commented, false);
});

test("a clean merge (no conflict) is a no-op", () => {
  // feature edits a different file than main → no conflict.
  const root = scratch();
  const origin = join(root, "origin.git");
  const work = join(root, "work");
  git(root, "init", "--bare", "-q", origin);
  git(root, "clone", "-q", origin, work);
  git(work, "config", "user.email", "t@t");
  git(work, "config", "user.name", "t");
  writeFileSync(join(work, "a.txt"), "a\n");
  writeFileSync(join(work, "b.txt"), "b\n");
  git(work, "add", "-A");
  git(work, "commit", "-q", "-m", "base");
  git(work, "branch", "-M", "main");
  git(work, "push", "-q", "origin", "main");
  git(work, "checkout", "-q", "-b", "feature");
  writeFileSync(join(work, "a.txt"), "a changed on feature\n");
  git(work, "commit", "-q", "-am", "feature");
  git(work, "checkout", "-q", "main");
  writeFileSync(join(work, "b.txt"), "b changed on main\n");
  git(work, "commit", "-q", "-am", "main");
  git(work, "push", "-q", "origin", "main");
  git(work, "checkout", "-q", "feature");

  const { outputs, merging } = runPrepare(work);
  assert.equal(outputs.needs_commit, "false");
  assert.equal(outputs.needs_llm, "false");
  assert.equal(merging, false); // clean merge auto-committed, no conflict
});
