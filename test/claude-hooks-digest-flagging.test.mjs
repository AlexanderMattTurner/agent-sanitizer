/**
 * The hook entry must be able to ask for Layer 3's digest exemption to be off.
 *
 * `checkExfilUrl` takes `flagDigestValues` directly, but a Claude-hooks consumer
 * never calls it: it calls `evaluateToolOutput`, which composes its own seam
 * options. With no switch on that path the option is unreachable, so a consumer
 * that reads a digest in a URL as payload — a monitor watching tool output for a
 * leaked commit or blob id — has no way to keep the detection it had before the
 * exemption existed, and pins an older release instead.
 *
 * Both directions are driven: the exemption is still the default, and the knob
 * is what turns it off.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// No daemon listens here, so Layer 4 never fires and every finding below comes
// from Layer 3. Set before the import — the client resolves the path at load.
process.env._AGENT_SANITIZER_REDACTOR_SOCKET = join(
  mkdtempSync(join(tmpdir(), "sanitizer-digest-flagging-")),
  "redactor.sock",
);

const { evaluateToolOutput } =
  await import("../claude-hooks/sanitize-output.mjs");
const { FLAG_DIGEST_VALUES_ENV } =
  await import("../claude-hooks/lib/env-config.mjs");

// Exactly sha1's length in hex, which is the shape the exemption keys on.
const DIGEST_URL = `https://ok.example/p?h=${"a".repeat(40)}`;
const EXFIL_REPORTED = /URLs shaped like data exfiltration detected/u;

/** A WebFetch result: web ingress, so Layer 3 runs. */
const fetched = (text) =>
  evaluateToolOutput({ tool_name: "WebFetch", tool_response: text });

/** Drive one hook run under a chosen value of the knob, then put it back. */
async function underKnob(value, work) {
  const before = process.env[FLAG_DIGEST_VALUES_ENV];
  if (value === undefined) delete process.env[FLAG_DIGEST_VALUES_ENV];
  else process.env[FLAG_DIGEST_VALUES_ENV] = value;
  try {
    return await work();
  } finally {
    if (before === undefined) delete process.env[FLAG_DIGEST_VALUES_ENV];
    else process.env[FLAG_DIGEST_VALUES_ENV] = before;
  }
}

describe("the hook entry exposes Layer 3's digest exemption", () => {
  it("exempts a digest-shaped URL value by default", async () => {
    const fields = await underKnob(undefined, () => fetched(DIGEST_URL));
    assert.doesNotMatch(
      String(fields?.additional_context ?? ""),
      EXFIL_REPORTED,
    );
  });

  it("reports the same value when the operator turns the exemption off", async () => {
    const fields = await underKnob("1", () => fetched(DIGEST_URL));
    assert.match(String(fields?.additional_context), EXFIL_REPORTED);
    assert.match(
      String(fields?.additional_context),
      /do not fetch, relay, or embed these URLs/u,
    );
  });

  it("keeps the exemption for any value other than the exact opt-in", async () => {
    // A typo must fail toward the exemption, never silently widen Layer 3.
    const fields = await underKnob("true", () => fetched(DIGEST_URL));
    assert.doesNotMatch(
      String(fields?.additional_context ?? ""),
      EXFIL_REPORTED,
    );
  });
});
