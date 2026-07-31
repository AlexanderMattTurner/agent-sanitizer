/**
 * The host override for the cold-start hookgate marker.
 *
 * The hooks wait out an in-flight `session-setup` by polling a marker file whose
 * path they DERIVE from `CLAUDE_PROJECT_DIR`. A host whose own setup script
 * already writes a marker — under its own naming convention — otherwise has two
 * choices, both bad: adopt this package's stem and digest verbatim (pinning
 * itself to our path forever), or run a second wait loop against a path nothing
 * writes. `configureHookgateMarker` is the third option, and this file pins its
 * two properties:
 *
 *   - LOAD-BEARING WHEN SUPPLIED. Every consumer that resolves through
 *     `hookgateMarkerPath()` — the module-scope wait in lib/control-plane.mjs,
 *     the lazy reload in scan-invisible-chars — sees the host's path, and the
 *     trust check that guards the wait accepts a real file there.
 *   - LOUD, NOT FATAL, WHEN LATE. control-plane.mjs resolves the marker at module
 *     scope, so a configure call that lands after that import cannot steer the
 *     wait it was meant to steer. That is reported on stderr and not thrown: a
 *     throw at a bundle entry's top level kills the hook before it writes a
 *     response, and a hook that emits nothing is read as non-blocking — a
 *     fail-OPEN, which is a far worse outcome than a mis-timed override.
 *
 * hook-io is imported ALONE here, and nothing resolves a marker before the first
 * test: importing a hook module would run control-plane's module-scope
 * resolution first, and the before-anything-resolved case could then never be
 * observed at all.
 */
import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const { configureHookgateMarker, hookgateMarkerPath, markerIsTrusted } =
  await import("../claude-hooks/lib/hook-io.mjs");

const dir = mkdtempSync(join(tmpdir(), "sanitizer-marker-"));
const HOST_MARKER = join(dir, "host-hookgate-inflight");

/** Run `fn` with stderr captured, returning what it wrote. */
function captureStderr(fn) {
  /** @type {string[]} */
  const written = [];
  const original = process.stderr.write;
  // @ts-expect-error -- narrower than the overloaded write signature; the
  // callers here only ever pass a string chunk.
  process.stderr.write = (chunk) => {
    written.push(String(chunk));
    return true;
  };
  try {
    fn();
  } finally {
    process.stderr.write = original;
  }
  return written.join("");
}

describe("configureHookgateMarker", () => {
  it("replaces the derived path for every consumer", () => {
    const warning = captureStderr(() => configureHookgateMarker(HOST_MARKER));
    // Nothing has resolved a marker yet, so this call is in time and silent.
    assert.equal(warning, "");
    assert.equal(hookgateMarkerPath(), HOST_MARKER);
    // Explicit arguments lose to the override too: a host that named its marker
    // is naming it for every consumer, not just the env-derived ones.
    assert.equal(
      hookgateMarkerPath("/work/proj", "/run/user/1000"),
      HOST_MARKER,
    );
  });

  it("hands the wait a marker the trust check accepts", () => {
    writeFileSync(HOST_MARKER, `${process.pid}\n`);
    // markerIsTrusted is what gates the cold-start poll; resolving to a path it
    // rejects would leave the wait permanently unarmed.
    assert.equal(markerIsTrusted(hookgateMarkerPath()), true);
  });

  it("restores the derivation when passed null", () => {
    captureStderr(() => configureHookgateMarker(null));
    const derived = hookgateMarkerPath("/work/proj", "");
    assert.ok(derived?.startsWith("/tmp/agent-sanitizer-hookgate-inflight-"));
    assert.equal(hookgateMarkerPath("", ""), null);
  });

  it("warns rather than throws when it lands after a resolution", () => {
    const warning = captureStderr(() => configureHookgateMarker(HOST_MARKER));
    assert.match(warning, /configureHookgateMarker called after/u);
    // The late call still governs every LATER resolution — the warning names
    // what it could not reach, it does not discard the override.
    assert.equal(hookgateMarkerPath(), HOST_MARKER);
  });
});

after(() => rmSync(dir, { recursive: true, force: true }));
