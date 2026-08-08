import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const HELPER = join(
  dirname(fileURLToPath(import.meta.url)),
  "rotate-release-age-exemption.mjs",
);

// A faithful miniature of pnpm-workspace.yaml: comments that must survive the
// rotation, and a version-exact own-package exemption. The comment naming the
// old version proves the edit anchors on the LIST-ITEM line, not on a bare
// substring of the version.
const WORKSPACE = `# window rationale comment
minimumReleaseAge: 4320

# exempt our own package (agent-sanitizer@1.2.3 as prose must NOT be touched)
minimumReleaseAgeExclude:
  - agent-sanitizer@1.2.3
`;

/** Run the real helper against `content` in a scratch file; return the result. */
function run(content, pin) {
  const dir = mkdtempSync(join(tmpdir(), "rotate-exemption-"));
  const file = join(dir, "pnpm-workspace.yaml");
  writeFileSync(file, content);
  const res = spawnSync("node", [HELPER, file, pin], { encoding: "utf8" });
  assert.equal(res.error, undefined, "failed to spawn the helper");
  const text = readFileSync(file, "utf8");
  rmSync(dir, { recursive: true, force: true });
  return { status: res.status, stdout: res.stdout, stderr: res.stderr, text };
}

test("rotates the single list entry and leaves comments untouched", () => {
  const { status, text } = run(WORKSPACE, "9.9.9");
  assert.equal(status, 0);
  assert.equal(
    text,
    WORKSPACE.replace("  - agent-sanitizer@1.2.3", "  - agent-sanitizer@9.9.9"),
  );
  // The prose mention of the old version must survive verbatim.
  assert.match(text, /agent-sanitizer@1\.2\.3 as prose/u);
});

test("no-op when the entry already names the pin", () => {
  const { status, stdout, text } = run(WORKSPACE, "1.2.3");
  assert.equal(status, 0);
  assert.equal(text, WORKSPACE);
  assert.match(stdout, /already names agent-sanitizer@1\.2\.3/u);
});

test("fails loud when no entry exists — even if the version appears in prose", () => {
  const noEntry = WORKSPACE.replace("  - agent-sanitizer@1.2.3\n", "");
  const { status, stderr, text } = run(noEntry, "9.9.9");
  assert.equal(status, 1);
  assert.match(stderr, /expected exactly one .* found 0/u);
  assert.equal(text, noEntry, "a failed rotation must not write");
});

test("fails loud when more than one entry exists", () => {
  const twoEntries = `${WORKSPACE}  - agent-sanitizer@2.0.0\n`;
  const { status, stderr, text } = run(twoEntries, "9.9.9");
  assert.equal(status, 1);
  assert.match(stderr, /expected exactly one .* found 2/u);
  assert.equal(text, twoEntries, "a failed rotation must not write");
});

test("production default reads the real workspace file and the real pin", () => {
  // Run helper with no argv from the repo root: against the committed tree the
  // entry must already match the committed pin, so this is a no-op exercising
  // the enginePin() default path end-to-end. It doubles as the SSOT contract:
  // if a pin bump ever lands without the rotation, this fails on that PR.
  const root = spawnSync("git", ["rev-parse", "--show-toplevel"], {
    encoding: "utf8",
  }).stdout.trim();
  const before = readFileSync(join(root, "pnpm-workspace.yaml"), "utf8");
  const res = spawnSync("node", [HELPER], { cwd: root, encoding: "utf8" });
  assert.equal(res.status, 0, res.stderr);
  assert.match(res.stdout, /already names agent-sanitizer@/u);
  assert.equal(readFileSync(join(root, "pnpm-workspace.yaml"), "utf8"), before);
});
