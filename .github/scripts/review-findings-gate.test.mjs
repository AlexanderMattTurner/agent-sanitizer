/**
 * The gate's unreported-verdict arm.
 *
 * review-findings-gate.sh posts the REQUIRED "Review findings resolved" check
 * run only when its evaluation reaches the POST at the end. A run that dies
 * first leaves the head with no check run under that context at all, which
 * GitHub renders as "Expected — Waiting for status to be reported" and which
 * blocks the merge on a check nothing will ever send: resolving a thread fires
 * no workflow event, so the gate is not re-derived until the next push or a
 * `recheck-review-gate` label. GATE_UNREPORTED is the caller's `always()` arm
 * for that case, and these cases pin that it reports RED on the head rather
 * than staying silent, and that it refuses to report against no sha at all.
 */
import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const GATE = join(REPO_ROOT, ".github/scripts/review-findings-gate.sh");

/** A `gh` on PATH that records its argv and exits 0, so nothing reaches GitHub. */
function stubGh() {
  const dir = mkdtempSync(join(tmpdir(), "review-findings-gate-"));
  const log = join(dir, "argv.log");
  writeFileSync(
    join(dir, "gh"),
    `#!/usr/bin/env bash\nprintf '%s\\n' "$@" >>${JSON.stringify(log)}\n`,
    { mode: 0o755 },
  );
  return { dir, log };
}

const runGate = ({ dir, env }) =>
  execFileSync("bash", [GATE], {
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${dir}:${process.env.PATH}`,
      GH_TOKEN: "stub-token",
      GH_REPO: "o/r",
      PR: "348",
      ...env,
    },
  });

test("reports the required check RED on the head when the evaluation never ran", () => {
  const { dir, log } = stubGh();
  runGate({
    dir,
    env: { GATE_UNREPORTED: "1", REPORT_SHA: "dec0ded" },
  });
  const argv = readFileSync(log, "utf8");
  // The context name, the sha and the conclusion are the three things that
  // decide whether the merge box stops waiting; an assertion on the call alone
  // would pass for a green verdict posted to the wrong sha.
  assert.match(argv, /^repos\/o\/r\/check-runs$/mu);
  assert.match(argv, /^name=Review findings resolved$/mu);
  assert.match(argv, /^head_sha=dec0ded$/mu);
  assert.match(argv, /^conclusion=failure$/mu);
  assert.match(argv, /^status=completed$/mu);
  // Fail CLOSED: a run that derived nothing must never claim the gate passed.
  assert.doesNotMatch(argv, /^conclusion=success$/mu);
});

test("refuses to report when there is no head sha to report against", () => {
  const { dir, log } = stubGh();
  assert.throws(
    () => runGate({ dir, env: { GATE_UNREPORTED: "1" } }),
    /REPORT_SHA/u,
  );
  // Non-vacuity for the case above: the guard is what stops a check run being
  // POSTed with an empty head_sha, so nothing may have reached `gh` here.
  assert.throws(() => readFileSync(log, "utf8"), /ENOENT/u);
});
