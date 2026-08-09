// install-sanitizer.sh, local-checkout path.
//
// Regression: npm packs a `file:` dependency by running that package's own
// `prepare`/`prepack`, and does so even under --ignore-scripts (npm 10.9). This
// repo's `prepare` is `pnpm build:types`, and the three claude-* review
// workflows install neither pnpm nor the typescript devDependency — so the
// install step died with `pnpm: not found` and took every review job with it
// before it read a single diff. The fixture's lifecycle scripts below exit
// non-zero, so this test fails exactly the way CI did if the staging that
// strips them is removed.
import { strict as assert } from "node:assert";
import { execFileSync, spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const SCRIPT = join(
  dirname(fileURLToPath(import.meta.url)),
  "install-sanitizer.sh",
);

/**
 * A miniature of this repo as the script sees it: named `agent-sanitizer` (so
 * the local-checkout branch is taken), dependency-free (so the install needs no
 * registry), carrying a `files` allowlist and lifecycle scripts that fail.
 */
function makeCheckout() {
  const dir = mkdtempSync(join(tmpdir(), "install-sanitizer-"));
  const manifest = {
    name: "agent-sanitizer",
    version: "0.0.0",
    type: "module",
    main: "src/index.mjs",
    scripts: {
      prepare: "exit 17",
      prepack: "exit 17",
    },
    files: ["src/*.mjs"],
  };
  writeFileSync(
    join(dir, "package.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
  );
  mkdirSync(join(dir, "src"));
  writeFileSync(
    join(dir, "src", "index.mjs"),
    "export const sanitize = () => {};\n",
  );
  // Outside `files`: proves the install still ships the PUBLISHED tree rather
  // than the whole checkout, which is what staging-then-packing preserves.
  writeFileSync(join(dir, "unpublished.txt"), "not in files\n");
  mkdirSync(join(dir, ".github", "scripts"), { recursive: true });

  // `git archive HEAD` stages the committed tree, so the fixture needs a commit.
  const git = (...args) =>
    execFileSync("git", ["-C", dir, ...args], { encoding: "utf8" });
  git("init", "--quiet");
  git("config", "user.email", "test@example.com");
  git("config", "user.name", "test");
  git("add", "--all");
  git("-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "fixture");
  return dir;
}

test("installs the local checkout without running its lifecycle scripts", () => {
  const dir = makeCheckout();
  const res = spawnSync("bash", [SCRIPT], { cwd: dir, encoding: "utf8" });
  const installed = join(
    dir,
    ".github",
    "scripts",
    "node_modules",
    "agent-sanitizer",
  );
  const ok = res.status === 0;
  const hasEntry = existsSync(join(installed, "src", "index.mjs"));
  const hasUnpublished = existsSync(join(installed, "unpublished.txt"));
  rmSync(dir, { recursive: true, force: true });

  assert.equal(ok, true, `install failed:\n${res.stdout}\n${res.stderr}`);
  assert.equal(
    hasEntry,
    true,
    "the local checkout's entry point was not installed",
  );
  assert.equal(
    hasUnpublished,
    false,
    "installed a file outside `files` — the install no longer mirrors the published package",
  );
});
