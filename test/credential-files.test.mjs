// Twin of tests/secrets/test_credential_files.py over the same cases file.
import { it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import fc from "fast-check";

import {
  credentialFiles,
  credentialPathMatcher as matcher,
  parseCredentialFiles as parse,
} from "../src/credential-files.mjs";

// Resolved through the real exports map, the way a consumer's bare import is.
const resolved = fileURLToPath(
  import.meta.resolve("agent-sanitizer/credential-files"),
);
const SPEC = JSON.parse(readFileSync(resolved, "utf8"));
const { inert, cases, emptySpecs, badEntries } = JSON.parse(
  readFileSync(
    new URL("../tests/data/credential-files.cases.json", import.meta.url),
    "utf8",
  ),
);
const holds = matcher();

it("resolves the packaged vocabulary through the exports map", () => {
  assert.match(resolved, /credential-files\.json$/);
  assert.deepEqual(parse(SPEC), credentialFiles());
});

// An entry alone, in an otherwise inert spec, must match its own instance.
for (const field of ["nameGlobs", "pathGlobs", "directories"])
  for (const entry of SPEC[field])
    it(`${field}: ${entry} alone matches`, () => {
      const alone = matcher({ spec: { ...inert, [field]: [entry] } });
      const example =
        field === "directories"
          ? `/home/u/${entry}/x`
          : entry.replaceAll("*", "x");
      assert.equal(alone(example), true);
      assert.equal(alone("/home/u/project/main.py"), false);
    });

it("loads a corpus with both verdicts and unique paths", () => {
  assert.ok(cases.length >= 30, `only ${cases.length} cases`);
  assert.equal(new Set(cases.map(([path]) => path)).size, cases.length);
  assert.equal(new Set(cases.map(([, ok]) => ok)).size, 2);
});
for (const [path, expected, why] of cases)
  it(`${JSON.stringify(path)} is ${expected}`, () =>
    assert.equal(holds(path), expected, why));

it("walks a long leaf with no stall and counts an astral character as one", () => {
  assert.equal(holds("/home/u/\u{1F511}.key"), true);
  assert.equal(holds(`/home/u/${"a*".repeat(50_000)}credentialz`), true);
  assert.equal(holds(`/home/u/${"secre".repeat(40_000)}`), false);
});

it("holds three properties over arbitrary paths", () => {
  fc.assert(
    fc.property(fc.string({ unit: "binary" }), (p) => {
      assert.equal(typeof holds(p), "boolean");
    }),
  );
  fc.assert(
    fc.property(fc.stringMatching(/^[a-zA-Z0-9_./~-]{0,40}$/), (p) => {
      assert.equal(holds(p.toUpperCase()), holds(p.toLowerCase()));
    }),
  );
  fc.assert(
    fc.property(
      fc.constantFrom(...SPEC.directories),
      fc
        .stringMatching(/^[a-z0-9_.-]{1,12}$/)
        .filter((leaf) => leaf !== "." && leaf !== ".."),
      (dir, leaf) => assert.equal(holds(`/home/u/${dir}/${leaf}`), true),
    ),
  );
});

const refuse = (spec, message) => {
  assert.throws(() => parse(spec), message);
  assert.throws(() => matcher({ spec }), message);
};
for (const [field, value] of emptySpecs)
  it(`refuses ${field}: ${JSON.stringify(value)}`, () =>
    refuse({ ...inert, [field]: value ?? undefined }, /is empty or missing/));
for (const [field, values] of Object.entries(badEntries))
  for (const value of values)
    it(`refuses ${field}: ${JSON.stringify(value)}`, () =>
      refuse({ ...inert, [field]: [value] }, /bad entr/));

it("drops a repeated entry and keeps first-occurrence order", () =>
  assert.deepEqual(
    parse({ ...inert, nameGlobs: [".b", ".a", ".b"] }).nameGlobs,
    [".b", ".a"],
  ));
