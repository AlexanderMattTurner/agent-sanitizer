// Shared fixtures for the auto-resolve BUNDLE and LAND tests. Not a test file
// itself: importing a `*.test.mjs` module would re-run its whole suite inside
// whichever suite imported it.
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
import { cleanGitEnv } from "../../../test/helpers/git-env.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPT = join(HERE, "bundle.sh");
const scratch = () => mkdtempSync(join(tmpdir(), "auto-resolve-bundle-"));
const git = (cwd, ...args) =>
  execFileSync("git", ["-C", cwd, ...args], {
    encoding: "utf8",
    env: cleanGitEnv,
  });

// A work clone mid-merge: `main` and `feature` both edit a.md, and b.md exists
// cleanly on both. Merging main into feature conflicts on a.md only. Both
// branches are pushed, so the merge's two parents are reachable from origin —
// which is what the land step requires.
function midMerge({
  bContent = "b base\n",
  extraConflict = null,
  seed = null,
} = {}) {
  const root = scratch();
  const origin = join(root, "origin.git");
  const work = join(root, "work");
  git(root, "init", "--bare", "-q", origin);
  git(root, "clone", "-q", origin, work);
  git(work, "config", "user.email", "t@t");
  git(work, "config", "user.name", "t");
  git(work, "config", "commit.gpgsign", "false");
  writeFileSync(join(work, "a.md"), "base\n");
  writeFileSync(join(work, "b.md"), bContent);
  // Files both branches share unchanged (a repo's committed tooling), so they
  // are present mid-merge without being part of the conflict.
  if (seed) seed(work);
  if (extraConflict) {
    mkdirSync(dirname(join(work, extraConflict)), { recursive: true });
    writeFileSync(join(work, extraConflict), "base\n");
  }
  git(work, "add", "-A");
  git(work, "commit", "-q", "-m", "base");
  git(work, "branch", "-M", "main");
  git(work, "push", "-q", "origin", "main");
  git(work, "checkout", "-q", "-b", "feature");
  writeFileSync(join(work, "a.md"), "feature side\n");
  if (extraConflict) writeFileSync(join(work, extraConflict), "feature side\n");
  git(work, "commit", "-q", "-am", "feature");
  git(work, "push", "-q", "origin", "feature");
  git(work, "checkout", "-q", "main");
  writeFileSync(join(work, "a.md"), "main side\n");
  if (extraConflict) writeFileSync(join(work, extraConflict), "main side\n");
  git(work, "commit", "-q", "-am", "main change");
  git(work, "push", "-q", "origin", "main");
  git(work, "checkout", "-q", "feature");
  try {
    git(work, "merge", "--no-edit", "main");
    throw new Error("expected a conflict");
  } catch (err) {
    if (String(err.message).includes("expected a conflict")) throw err;
  }
  return { work, origin, root };
}

// A modify/delete fixture: feature deletes a.md, main edits it. Git leaves NO
// conflict markers — the working tree simply holds main's version.
function midMergeModifyDelete() {
  const root = scratch();
  const origin = join(root, "origin.git");
  const work = join(root, "work");
  git(root, "init", "--bare", "-q", origin);
  git(root, "clone", "-q", origin, work);
  git(work, "config", "user.email", "t@t");
  git(work, "config", "user.name", "t");
  git(work, "config", "commit.gpgsign", "false");
  writeFileSync(join(work, "a.md"), "base\n");
  writeFileSync(join(work, "b.md"), "b\n");
  git(work, "add", "-A");
  git(work, "commit", "-q", "-m", "base");
  git(work, "branch", "-M", "main");
  git(work, "push", "-q", "origin", "main");
  git(work, "checkout", "-q", "-b", "feature");
  git(work, "rm", "-q", "a.md");
  git(work, "commit", "-q", "-m", "feature deletes a.md");
  git(work, "push", "-q", "origin", "feature");
  git(work, "checkout", "-q", "main");
  writeFileSync(join(work, "a.md"), "main side\n");
  git(work, "commit", "-q", "-am", "main edits a.md");
  git(work, "push", "-q", "origin", "main");
  git(work, "checkout", "-q", "feature");
  try {
    git(work, "merge", "--no-edit", "main");
    throw new Error("expected a conflict");
  } catch (err) {
    if (String(err.message).includes("expected a conflict")) throw err;
  }
  return { work, origin, root };
}

// A mid-merge tree that also declares regen rules: `gen.txt` is generator-owned
// and conflicts alongside its source `a.md`, which is exactly the case
// prepare.sh defers to bundle.sh's post-LLM regeneration. The generator is
// committed (bundle.sh refuses untracked files) and derives its output from the
// resolved source, so a test can tell a real regeneration from git's "ours".
//
// `generatorBody` is the committed generator's script body; the default writes
// gen.txt from a.md. Pass a failing body to exercise the refusal path.
function midMergeGenerated({ generatorBody = null } = {}) {
  const body =
    generatorBody ??
    `import { readFileSync, writeFileSync } from "node:fs";
writeFileSync("gen.txt", "generated from: " + readFileSync("a.md", "utf8"));
`;
  return midMerge({
    extraConflict: "gen.txt",
    seed: (w) => {
      mkdirSync(join(w, ".github", "scripts"), { recursive: true });
      mkdirSync(join(w, "config"), { recursive: true });
      writeFileSync(
        join(w, ".github", "scripts", "resolve-generated.mjs"),
        readFileSync(join(HERE, "..", "resolve-generated.mjs"), "utf8"),
      );
      writeFileSync(
        join(w, "config", "auto-resolve-regen-rules.json"),
        JSON.stringify({
          rules: [
            { generator: "gen.mjs", sources: ["a.md"], owns: ["gen.txt"] },
          ],
        }),
      );
      writeFileSync(join(w, "gen.mjs"), body);
    },
  });
}

// Runs bundle.sh in `work` with a fake `gh` on PATH that records every
// invocation, so a test can assert on the comment(s)/labels it posts. The
// self-review is left unconfigured (no OAuth token in the environment), so
// these tests exercise the verify-and-bundle path only.
function runBundle(work, conflictList, env = {}) {
  // The shims live OUTSIDE the work clone: bundle.sh refuses any untracked file
  // inside the tree, so parking .fakebin/.gh-calls there would trip it.
  const root = dirname(work);
  const ghLog = join(root, ".gh-calls");
  writeFileSync(ghLog, "");
  const binDir = join(root, ".fakebin");
  mkdirSync(binDir, { recursive: true });
  const ghPath = join(binDir, "gh");
  writeFileSync(
    ghPath,
    `#!/usr/bin/env bash\nprintf '%s\\n' "$*" >> "${ghLog}"\nexit 0\n`,
  );
  chmodSync(ghPath, 0o755);
  const bundleDir = join(root, "bundle-out");
  let error = null;
  let stdout = "";
  try {
    stdout = execFileSync("bash", [SCRIPT], {
      cwd: work,
      encoding: "utf8",
      env: {
        ...cleanGitEnv,
        HEAD_REF: "feature",
        BASE_REF: "main",
        PR: "1",
        BUNDLE_DIR: bundleDir,
        CONFLICT_LIST: conflictList,
        CLAUDE_CODE_OAUTH_TOKEN: "",
        CLAUDE_CODE_OAUTH_TOKEN_FALLBACK: "",
        CLAUDE_CODE_OAUTH_TOKEN_FALLBACK_2: "",
        CLAUDE_CODE_OAUTH_TOKEN_FALLBACK_3: "",
        CLAUDE_CODE_OAUTH_TOKEN_FALLBACK_4: "",
        CLAUDE_CODE_OAUTH_TOKEN_FALLBACK_5: "",
        CLAUDE_CODE_OAUTH_TOKEN_FALLBACK_6: "",
        ...env,
        PATH: `${binDir}:${cleanGitEnv.PATH ?? ""}`,
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
  return {
    error,
    merging,
    ghCalls,
    stdout,
    bundleDir,
    bundle: join(bundleDir, "merge.bundle"),
  };
}

export { midMerge, midMergeModifyDelete, midMergeGenerated, runBundle };
