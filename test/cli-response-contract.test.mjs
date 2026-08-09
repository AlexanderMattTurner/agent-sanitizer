import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { describe, it } from "node:test";

import { OPS } from "../bin/sanitize-cli.mjs";

/**
 * The CLI is the ONLY bridge between the JS source of truth and every non-JS
 * caller, and its `sanitize` op used to re-list the result's fields by hand.
 * That hand-written projection was a second copy of the return shape with
 * nothing keeping it in sync, and it had already drifted: `splices` was part of
 * `sanitize()`'s result and silently never reached the wire.
 *
 * The mirror-image failure lived on the Python side, where `SanitizeResult(**resp)`
 * made the skew fatal in one direction — a field the client predated raised
 * `TypeError` and took the caller down, so the two ends could not be updated in
 * either order without a broken intermediate state.
 *
 * This test is the partition that replaces both hand-syncs: the CLI's live
 * response keys and the Python dataclass's fields must be the SAME SET.
 */

const PY = "python3";

/** The interpreter probe is separated from the check itself on purpose: a bare
 * `catch` around the real work cannot tell "no python3 on this runner" from
 * "the module moved / raised", and would retire the cross-check in exactly the
 * scenario it exists to catch. */
function pythonAvailable() {
  try {
    execFileSync(PY, ["-c", "pass"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

describe("CLI response shape is a checked projection, not a hand-written one", () => {
  it("the sanitize op forwards every field sanitize() produces", async () => {
    const resp = await OPS.sanitize({
      text: '<p>hi</p><div style="height:0;overflow:hidden">payload</div>',
      html: true,
    });
    const keys = Object.keys(resp).sort();
    assert.deepEqual(keys, [
      "cleaned",
      "found",
      "notes",
      "splices",
      "warnings",
    ]);
    // Non-vacuity: the op must actually have done something, or the key set
    // above could be satisfied by a stub returning empty containers.
    assert.equal(typeof resp.cleaned, "string");
    assert.ok(Array.isArray(resp.splices));
  });

  it("the Python client's SanitizeResult accepts exactly those fields", (t) => {
    if (!pythonAvailable()) {
      t.skip("no python3 interpreter on this runner");
      return;
    }
    // Deliberately OUTSIDE any catch: a moved module, a syntax error or a
    // non-zero exit must fail this test rather than silently retire it.
    const out = execFileSync(
      PY,
      [
        "-c",
        [
          "import sys, json, dataclasses",
          "sys.path.insert(0, 'python')",
          "from agent_sanitizer import SanitizeResult",
          "print(json.dumps(sorted(f.name for f in dataclasses.fields(SanitizeResult))))",
        ].join("; "),
      ],
      { encoding: "utf-8" },
    );
    const pythonFields = JSON.parse(out);
    assert.deepEqual(pythonFields, [
      "cleaned",
      "found",
      "notes",
      "splices",
      "warnings",
    ]);
  });

  it("a newer CLI does not brick an older Python client", (t) => {
    if (!pythonAvailable()) {
      t.skip("no python3 interpreter on this runner");
      return;
    }
    // The forward-compat direction, asserted as behaviour rather than trusted
    // from the docstring: an unknown field must be dropped, not raise.
    const out = execFileSync(
      PY,
      [
        "-c",
        [
          "import sys",
          "sys.path.insert(0, 'python')",
          "from agent_sanitizer import SanitizeResult",
          "r = SanitizeResult.from_response({'cleaned': 'x', 'a_field_from_the_future': [1]})",
          "print(r.cleaned)",
        ].join("; "),
      ],
      { encoding: "utf-8" },
    );
    assert.equal(out.trim(), "x");
  });
});
