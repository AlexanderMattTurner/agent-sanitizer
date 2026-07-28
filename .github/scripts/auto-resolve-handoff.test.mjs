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
const SCRIPT = join(HERE, "auto-resolve-handoff.sh");

// Run handoff.sh with a fake `gh` that records every invocation. Returns the
// error (handoff must ALWAYS exit non-zero — it exists to fail the run loud)
// and the recorded gh argv lines.
function runHandoff(unresolvable) {
  const root = mkdtempSync(join(tmpdir(), "auto-resolve-handoff-"));
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
  let error = null;
  try {
    execFileSync("bash", [SCRIPT], {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        PR: "7",
        BASE_REF: "main",
        UNRESOLVABLE: unresolvable,
        PATH: `${ghBin}:${process.env.PATH ?? ""}`,
      },
    });
  } catch (err) {
    error = err;
  }
  // The comment body is multi-line, so per-line splitting would scatter it:
  // expose the raw log for content assertions alongside the split lines.
  const ghRaw = readFileSync(ghLog, "utf8");
  const ghCalls = ghRaw.split("\n").filter(Boolean);
  return { error, ghCalls, ghRaw };
}

test("handoff labels the PR auto-resolve-blocked, comments once, and fails the run", () => {
  const { error, ghCalls, ghRaw } = runHandoff("assets/logo.bin");
  assert.notEqual(error, null); // the run must fail loud
  // Labeled so discover skips this PR until a human removes the label — a base
  // push cannot change an unmergeable conflict, so retrying only re-spends.
  assert.ok(
    ghCalls.some(
      (c) => c.startsWith("pr edit 7") && c.includes("auto-resolve-blocked"),
    ),
  );
  const comments = ghCalls.filter((c) => c.startsWith("pr comment"));
  assert.equal(comments.length, 1);
  assert.ok(ghRaw.includes("assets/logo.bin"));
  assert.ok(ghRaw.includes("remove the label to re-enable"));
});

test("handoff bullets every unresolvable path", () => {
  const { error, ghRaw } = runHandoff("a.bin b.bin");
  assert.notEqual(error, null);
  assert.ok(ghRaw.includes("- `a.bin`"));
  assert.ok(ghRaw.includes("- `b.bin`"));
});
