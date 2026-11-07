/**
 * The credential-FILE vocabulary and the path matcher built from it.
 *
 * The vocabulary is a PUBLIC export (`agent-sanitizer/credential-files`), resolved
 * here through Node's real exports map the way a consumer's bare import is. The
 * matcher is a hand-written twin of `agent_sanitizer.secrets.credential_path_matcher`,
 * so both suites assert the SAME literal verdicts from
 * `tests/data/credential-files.cases.json`. That file is read by relative path:
 * a test fixture has no business in the published surface.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import fc from "fast-check";
import { fileURLToPath } from "node:url";

import {
  credentialFiles,
  credentialPathMatcher,
  parseCredentialFiles,
} from "../src/credential-files.mjs";

const resolved = fileURLToPath(
  import.meta.resolve("agent-sanitizer/credential-files"),
);
const SPEC = JSON.parse(readFileSync(resolved, "utf8"));
const CORPUS = JSON.parse(
  readFileSync(
    new URL("../tests/data/credential-files.cases.json", import.meta.url),
    "utf8",
  ),
);

// A list that matches nothing, so one list under test is the only way in.
const INERT = {
  nameGlobs: ["inert.placeholder"],
  pathGlobs: ["*/inert/placeholder"],
  directories: ["inert-dir"],
};

describe("credential-files is resolvable through the package exports map", () => {
  it("resolves the subpath to the packaged JSON, which validates", () => {
    assert.match(resolved, /credential-files\.json$/);
    assert.deepEqual(parseCredentialFiles(SPEC), credentialFiles());
  });

  it("carries the three non-empty lists", () => {
    for (const field of ["nameGlobs", "pathGlobs", "directories"])
      assert.ok(SPEC[field].length > 0, field);
  });
});

describe("every vocabulary entry matches a real example, and does so alone", () => {
  for (const [field, examples] of Object.entries(CORPUS.globExamples)) {
    it(`${field}: the corpus has an example for each entry and no stale one`, () => {
      assert.deepEqual(Object.keys(examples).sort(), [...SPEC[field]].sort());
    });
    for (const [entry, example] of Object.entries(examples))
      it(`${field}: ${entry} matches ${example}`, () => {
        const holds = credentialPathMatcher({
          spec: { ...INERT, [field]: [entry] },
        });
        assert.equal(holds(example), true);
        assert.equal(holds("/home/u/project/main.py"), false);
      });
  }
});

describe("the shared conformance corpus", () => {
  it("is not empty, and every case is well-formed", () => {
    assert.ok(CORPUS.cases.length >= 30, `only ${CORPUS.cases.length} cases`);
    for (const c of CORPUS.cases) {
      assert.equal(typeof c.path, "string", c.id);
      assert.equal(typeof c.expected, "boolean", c.id);
    }
    assert.equal(
      new Set(CORPUS.cases.map((c) => c.id)).size,
      CORPUS.cases.length,
    );
    assert.ok(CORPUS.cases.some((c) => c.expected));
    assert.ok(CORPUS.cases.some((c) => !c.expected));
  });

  const holds = credentialPathMatcher();
  for (const c of CORPUS.cases)
    it(`${c.id}`, () => {
      assert.equal(holds(c.path), c.expected, `${c.path}: ${c.why}`);
    });
});

describe("matching rules the corpus does not spell out", () => {
  const holds = credentialPathMatcher();

  it("compares the leaf name, not an inner directory, against nameGlobs", () => {
    assert.equal(holds("/home/u/.npmrc/readme.txt"), false);
    assert.equal(holds("/home/u/.npmrc"), true);
  });

  it("walks a long path with no stall", () => {
    const path = `/${"a*".repeat(50_000)}/credentialz`;
    assert.equal(holds(path), true);
    assert.equal(holds(`/${"secre".repeat(40_000)}/x`), false);
  });

  it("counts an astral character as one character", () => {
    assert.equal(holds("/home/u/\u{1F511}.key"), true);
  });
});

describe("properties over arbitrary paths", () => {
  const holds = credentialPathMatcher();

  it("never throws, and always answers a boolean", () => {
    fc.assert(
      fc.property(fc.string({ unit: "binary" }), (path) => {
        assert.equal(typeof holds(path), "boolean");
      }),
    );
  });

  it("ignores ASCII letter case", () => {
    fc.assert(
      fc.property(fc.stringMatching(/^[a-zA-Z0-9_./~-]{0,40}$/), (path) => {
        assert.equal(holds(path.toUpperCase()), holds(path.toLowerCase()));
      }),
    );
  });

  it("flags every path under a credential directory", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...SPEC.directories),
        fc.stringMatching(/^[a-z0-9_.-]{1,12}$/),
        (dir, leaf) => {
          assert.equal(holds(`/home/u/${dir}/${leaf}`), true);
        },
      ),
    );
  });
});

describe("a malformed spec throws rather than matching nothing", () => {
  const good = { ...INERT };
  const bad = [
    [{}, /nameGlobs is empty or missing/],
    [{ ...good, nameGlobs: [] }, /nameGlobs is empty or missing/],
    [{ ...good, nameGlobs: "env" }, /nameGlobs is empty or missing/],
    [{ ...good, pathGlobs: [] }, /pathGlobs is empty or missing/],
    [{ ...good, directories: [] }, /directories is empty or missing/],
    [{ ...good, nameGlobs: [7] }, /bad entr/],
    [{ ...good, nameGlobs: ["*"] }, /bad entr/],
    [{ ...good, nameGlobs: ["**"] }, /bad entr/],
    [{ ...good, nameGlobs: [".ENV"] }, /bad entr/],
    [{ ...good, nameGlobs: ["a/b"] }, /bad entr/],
    [{ ...good, nameGlobs: ["a[bc]"] }, /bad entr/],
    [{ ...good, nameGlobs: ["a?"] }, /bad entr/],
    [{ ...good, nameGlobs: ["env\n"] }, /bad entr/],
    [{ ...good, nameGlobs: [""] }, /bad entr/],
    [{ ...good, pathGlobs: [".docker/config.json"] }, /bad entr/],
    [{ ...good, pathGlobs: ["*/*"] }, /bad entr/],
    [{ ...good, directories: ["*"] }, /bad entr/],
    [{ ...good, directories: ["a/b"] }, /bad entr/],
    [{ ...good, directories: [".."] }, /bad entr/],
    [{ ...good, directories: ["."] }, /bad entr/],
  ];
  for (const [spec, message] of bad)
    it(`refuses ${JSON.stringify(spec)}`, () => {
      assert.throws(() => parseCredentialFiles(spec), message);
      assert.throws(() => credentialPathMatcher({ spec }), message);
    });

  it("drops a repeated entry and keeps first-occurrence order", () => {
    assert.deepEqual(
      parseCredentialFiles({ ...good, nameGlobs: [".b", ".a", ".b"] })
        .nameGlobs,
      [".b", ".a"],
    );
  });
});
