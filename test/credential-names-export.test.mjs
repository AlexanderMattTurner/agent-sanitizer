/**
 * The credential-noun vocabulary is a PUBLIC export, reachable from JavaScript as
 * the `agent-sanitizer/credential-names` subpath and from Python as the
 * `agent_sanitizer.secrets` accessors — one file, so the two ecosystems cannot
 * drift apart.
 *
 * These drive Node's real exports resolution (`import.meta.resolve` against the
 * package's own name, which is what a consumer's bare import does) rather than
 * reading the file by relative path: a broken `exports` entry is invisible to a
 * relative read but breaks every consumer. The tarball half — that the resolved
 * file is actually packed — is asserted in package-exports.test.mjs, which drives
 * `npm pack`.
 *
 * The vocabulary's own contract (per-noun rendering, the env-name/field-value
 * separation, fail-closed validation) is asserted in
 * tests/secrets/test_credential_names.py, where the renderings and the redactor
 * they feed both exist; this file deliberately does not restate it, and checks
 * only what a JavaScript consumer depends on: that the data resolves, parses, and
 * carries parts safe to interpolate into a pattern unescaped.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const SUBPATH = "agent-sanitizer/credential-names";
const KNOWN_USES = new Set(["env-name", "field-value"]);

// Self-reference: a package with an `exports` map can resolve its own name, so
// this is the same resolution a consumer's `import "agent-sanitizer/credential-names"`
// performs — an exports entry that points at a missing or unmapped file throws here.
const resolved = fileURLToPath(import.meta.resolve(SUBPATH));
const spec = JSON.parse(readFileSync(resolved, "utf8"));

describe("credential-names is resolvable through the package exports map", () => {
  it("resolves the subpath to a .json file", () => {
    assert.match(resolved, /credential-names\.json$/);
  });

  it("carries a non-empty noun list and non-secret suffix list", () => {
    assert.ok(Array.isArray(spec.nouns) && spec.nouns.length > 0);
    assert.ok(
      Array.isArray(spec.nonSecretSuffixes) &&
        spec.nonSecretSuffixes.length > 0,
    );
  });
});

describe("every published noun is safe to interpolate into a pattern", () => {
  for (const noun of spec.nouns) {
    const label = noun.parts?.join("_") ?? JSON.stringify(noun);
    it(`${label} has a-z0-9 parts and known uses`, () => {
      assert.ok(Array.isArray(noun.parts) && noun.parts.length > 0);
      for (const part of noun.parts) assert.match(part, /^[a-z0-9]+$/);
      assert.ok(Array.isArray(noun.uses) && noun.uses.length > 0);
      for (const use of noun.uses)
        assert.ok(KNOWN_USES.has(use), `${label}: unknown use ${use}`);
    });
  }

  for (const suffix of spec.nonSecretSuffixes) {
    it(`non-secret suffix ${suffix.join("_")} has a-z0-9 parts`, () => {
      assert.ok(Array.isArray(suffix) && suffix.length > 0);
      for (const part of suffix) assert.match(part, /^[a-z0-9]+$/);
    });
  }

  it("marks at least one noun for each use (else a rendering is empty)", () => {
    for (const use of KNOWN_USES)
      assert.ok(
        spec.nouns.some((n) => n.uses.includes(use)),
        `no noun is marked ${use}`,
      );
  });
});
