// Tests for `.github/scripts/set-plugin-version.mjs` — the release step that
// stamps the published version into the Claude Code plugin manifest — plus the
// standing invariant that the COMMITTED manifest version is a real release, not
// the 0.1.0 placeholder it was frozen at while npm climbed to 2.x.

import { strict as assert } from "node:assert";
import { execFileSync, spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

const REPO_ROOT = execFileSync("git", ["rev-parse", "--show-toplevel"], {
  encoding: "utf8",
}).trim();
const SCRIPT = join(REPO_ROOT, ".github", "scripts", "set-plugin-version.mjs");
const MANIFEST_REL = join("plugin", ".claude-plugin", "plugin.json");
const LIVE_MANIFEST = join(REPO_ROOT, MANIFEST_REL);
const CHANGELOG = join(REPO_ROOT, "CHANGELOG.md");
const VERSION_BUMP = join(REPO_ROOT, ".github", "scripts", "version-bump.sh");

/** Compare two X.Y.Z strings numerically. */
function compareSemver(a, b) {
  const [aMaj, aMin, aPatch] = a.split(".").map(Number);
  const [bMaj, bMin, bPatch] = b.split(".").map(Number);
  return aMaj - bMaj || aMin - bMin || aPatch - bPatch;
}

/** Write a manifest into a throwaway dir and run the script there. */
function runInSandbox(manifestContents, env = {}) {
  const dir = mkdtempSync(join(tmpdir(), "plugin-version-"));
  mkdirSync(join(dir, "plugin", ".claude-plugin"), { recursive: true });
  const manifestPath = join(dir, MANIFEST_REL);
  if (manifestContents !== null) writeFileSync(manifestPath, manifestContents);
  const res = spawnSync("node", [SCRIPT], {
    cwd: dir,
    env: { ...process.env, ...env },
    encoding: "utf8",
  });
  assert.equal(res.error, undefined, "failed to spawn set-plugin-version.mjs");
  const after =
    manifestContents === null ? null : readFileSync(manifestPath, "utf8");
  rmSync(dir, { recursive: true, force: true });
  return { ...res, after };
}

const PRETTY_MANIFEST = `{
  "name": "agent-sanitizer",
  "version": "0.1.0",
  "keywords": ["security", "sanitization"]
}
`;

test("stamps the released version into the manifest", () => {
  const { status, after, stdout } = runInSandbox(PRETTY_MANIFEST, {
    NEW_VERSION: "3.4.5",
  });
  assert.equal(status, 0);
  assert.equal(JSON.parse(after).version, "3.4.5");
  assert.match(stdout, /version to 3\.4\.5/);
});

test("preserves the manifest's existing formatting", () => {
  // Re-serializing the parsed object would reflow the one-line keywords array
  // and fail format:check on the default branch, where the release commit lands.
  const { after } = runInSandbox(PRETTY_MANIFEST, { NEW_VERSION: "3.4.5" });
  assert.equal(after, PRETTY_MANIFEST.replace('"0.1.0"', '"3.4.5"'));
});

test("is idempotent when the manifest already names the version", () => {
  const already = PRETTY_MANIFEST.replace('"0.1.0"', '"3.4.5"');
  const { status, after } = runInSandbox(already, { NEW_VERSION: "3.4.5" });
  assert.equal(status, 0);
  assert.equal(after, already);
});

for (const { name, manifest, env } of [
  {
    name: "a missing NEW_VERSION",
    manifest: PRETTY_MANIFEST,
    env: { NEW_VERSION: "" },
  },
  {
    name: "a non-semver NEW_VERSION",
    manifest: PRETTY_MANIFEST,
    env: { NEW_VERSION: "v3.4.5-rc.1" },
  },
  {
    name: "a manifest with no version field",
    manifest: '{\n  "name": "agent-sanitizer"\n}\n',
    env: { NEW_VERSION: "3.4.5" },
  },
  {
    name: "a manifest with a non-string version",
    manifest: '{\n  "version": 3\n}\n',
    env: { NEW_VERSION: "3.4.5" },
  },
  {
    name: "a manifest that is not valid JSON",
    manifest: "{ not json\n",
    env: { NEW_VERSION: "3.4.5" },
  },
  {
    name: "an absent manifest",
    manifest: null,
    env: { NEW_VERSION: "3.4.5" },
  },
]) {
  test(`fails loudly on ${name}`, () => {
    const { status, stderr, after } = runInSandbox(manifest, env);
    assert.notEqual(status, 0, "must exit non-zero");
    assert.match(stderr, /::error::plugin manifest version:/);
    if (manifest !== null)
      assert.equal(after, manifest, "a failed run must not rewrite the file");
  });
}

// The rewrite is a non-global regex, so it targets the FIRST `"version":` in
// the file. A nested one ahead of the top-level field is exactly what the
// reparse checks exist for — and each ordering trips a different guard, so both
// are pinned here. Without them the guards could be deleted undetected, and the
// script would be no safer than the cheaper `set-pyproject-version.sh` awk shape.
for (const { name, topLevelVersion, expected } of [
  {
    name: "leaves the top-level version stale",
    topLevelVersion: "0.1.0",
    expected: /rewrite did not set the top-level "version"/,
  },
  {
    name: "leaves the top-level version already correct",
    topLevelVersion: "3.4.5",
    expected: /changed other fields/,
  },
]) {
  test(`refuses a rewrite that ${name} because a nested "version" came first`, () => {
    const nested = `{
  "dependencies": { "some-plugin": { "version": "9.9.9" } },
  "version": "${topLevelVersion}"
}
`;
    const { status, stderr, after } = runInSandbox(nested, {
      NEW_VERSION: "3.4.5",
    });
    assert.notEqual(status, 0, "must exit non-zero");
    // Pin WHICH guard fires: each ordering exercises a different one, so a
    // looser assertion would let one guard's deletion hide behind the other.
    assert.match(stderr, expected);
    assert.equal(after, nested, "a failed run must not rewrite the file");
  });
}

// --- Standing invariants on the committed manifest ------------------------

test("the committed plugin manifest advertises a real released version", () => {
  const { version } = JSON.parse(readFileSync(LIVE_MANIFEST, "utf8"));
  assert.match(
    version,
    /^[0-9]+\.[0-9]+\.[0-9]+$/,
    "the plugin version must be strict X.Y.Z semver",
  );

  // The newest dated CHANGELOG section is the last version this repo released;
  // the release commit stamps both files, so the manifest must never sit BELOW
  // it (that is exactly the 0.1.0-vs-npm-2.14.1 drift this guards). Being ahead
  // is tolerated: a release whose changelog body came back empty publishes and
  // stamps the manifest without promoting an Unreleased section.
  const dated = readFileSync(CHANGELOG, "utf8").match(
    /^## \[([0-9]+\.[0-9]+\.[0-9]+)\]/m,
  );
  assert.ok(dated, "CHANGELOG.md must contain a dated release section");
  assert.ok(
    compareSemver(version, dated[1]) >= 0,
    `plugin.json version ${version} is behind the latest released version ${dated[1]}`,
  );
});

test("the release script stamps and commits the plugin manifest", () => {
  // Positive markers, so this cannot pass vacuously if the stamping step is
  // refactored away: the script must run the helper AND stage the manifest in
  // the release-docs commit.
  const src = readFileSync(VERSION_BUMP, "utf8");
  assert.match(src, /PLUGIN_MANIFEST="plugin\/\.claude-plugin\/plugin\.json"/);
  assert.match(src, /node "\$SCRIPT_DIR\/set-plugin-version\.mjs"/);
  assert.match(src, /for release_doc in CHANGELOG\.md "\$PLUGIN_MANIFEST"/);
  assert.match(src, /git add -- "\$\{RELEASE_DOCS_PATHS\[@\]\}"/);
});
