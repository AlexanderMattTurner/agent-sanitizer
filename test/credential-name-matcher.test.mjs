/**
 * The exported NAME matcher: the rule, not just the words.
 *
 * `credential-names-export.test.mjs` covers the vocabulary as data — that the
 * subpath resolves and every noun is safe to interpolate. This file covers the
 * matcher built from it, and the cases here are the ones a consumer's own matcher
 * has got wrong: case sensitivity, a noun sitting mid-name, a multi-word noun
 * compared piecewise, a non-secret suffix redacted anyway, and a name long enough
 * to stall a matcher that renders the vocabulary as one alternation.
 *
 * The scope cases assert the DIFFERENCE between the two rules rather than each in
 * isolation, because a matcher that behaved identically under both would make the
 * option a lie — and the leak this export exists to prevent is precisely a
 * consumer applying the trailing rule where it needed the wider one.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  credentialNameMatcher,
  credentialNames,
  parseCredentialNames,
} from "../src/credential-names.mjs";

const MODULE_PATH = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "src",
  "credential-names.mjs",
);

const SPEC = {
  nouns: [
    { parts: ["api", "key"], uses: ["env-name", "field-value"] },
    { parts: ["access", "token"], uses: ["env-name", "field-value"] },
    { parts: ["token"], uses: ["env-name"] },
    { parts: ["password"], uses: ["env-name", "field-value"] },
  ],
  nonSecretSuffixes: [
    ["key", "id"],
    ["public", "key"],
  ],
};

describe("the packaged vocabulary builds a matcher", () => {
  it("renders both spellings of a multi-word noun", () => {
    const { segments } = credentialNames();
    assert.ok(segments.includes("API_KEY"));
    assert.ok(segments.includes("APIKEY"));
  });

  it("matches a credential name and declines a look-alike", () => {
    const holds = credentialNameMatcher();
    assert.ok(holds("GITHUB_TOKEN"));
    assert.ok(holds("DEPLOY_API_KEY"));
    // Names that merely CONTAIN a noun. PATH matters most: a scrub that strips it
    // leaves the command it was protecting unable to find its own executable.
    for (const name of [
      "PATH",
      "TOKENIZERS_PARALLELISM",
      "UV_KEYRING_PROVIDER",
    ])
      assert.ok(!holds(name), `${name} should not match`);
  });

  it("folds case, because the lowercase channel is real", () => {
    // npm renders its config into the environment as `npm_config_<key>` and reads
    // the same names back out of it, so a registry `_authToken` arrives lowercase
    // without anyone exporting a variable that looks like a credential.
    const holds = credentialNameMatcher();
    assert.ok(holds("npm_config__authToken"));
    assert.ok(holds("aws_secret_access_key"));
  });
});

describe("scope selects the rule, and the rules differ", () => {
  const trailing = credentialNameMatcher({ spec: SPEC });
  const anywhere = credentialNameMatcher({ spec: SPEC, scope: "any-segment" });

  // Real shapes: a CI PAT suffixed with its scope, and a numbered fallback tier.
  // Both hold a credential and neither ends in a credential noun, so a
  // trailing-only matcher reports "not a credential" for a live secret.
  for (const name of [
    "TEMPLATE_SYNC_TOKEN_ORG",
    "OAUTH_ACCESS_TOKEN_FALLBACK_4",
  ]) {
    it(`${name}: trailing declines, any-segment matches`, () => {
      assert.equal(trailing(name), false);
      assert.equal(anywhere(name), true);
    });
  }

  it("compares a multi-word noun as ONE run, not word by word", () => {
    // ACCESS_TOKEN is the noun; ACCESS and TOKEN_ACCESS are not. Without whole-run
    // comparison, ACCESS_LOG_LEVEL matches on its first word alone.
    assert.equal(anywhere("SERVICE_ACCESS_TOKEN_V2"), true);
    assert.equal(anywhere("ACCESS_LOG_LEVEL"), false);
  });

  it("rejects an unknown scope rather than picking one", () => {
    assert.throws(
      () => credentialNameMatcher({ spec: SPEC, scope: "suffix" }),
      /unknown scope/,
    );
  });
});

describe("a non-secret suffix is declined, unless the caller says otherwise", () => {
  it("declines an identifier and a public key by default", () => {
    const holds = credentialNameMatcher({ spec: SPEC });
    assert.equal(holds("AWS_ACCESS_KEY_ID"), false);
    assert.equal(holds("SIGNING_PUBLIC_KEY"), false);
  });

  // One name, both settings: DEPLOY_API_KEY_ID carries a noun mid-name AND ends in
  // a non-secret marker, so it is exactly where the two error directions disagree.
  it("declines it under any-segment, where the noun is otherwise found", () => {
    const holds = credentialNameMatcher({ spec: SPEC, scope: "any-segment" });
    assert.equal(holds("DEPLOY_API_KEY_ID"), false);
  });

  it("declineNonSecret: false keeps it, for a scrub that prefers over-stripping", () => {
    const holds = credentialNameMatcher({
      spec: SPEC,
      scope: "any-segment",
      declineNonSecret: false,
    });
    assert.equal(holds("DEPLOY_API_KEY_ID"), true);
  });
});

describe("an unusable vocabulary throws rather than matching nothing", () => {
  // Every one of these would otherwise render an empty noun set, and a matcher
  // over an empty set reports "no credential here" for every name it is asked
  // about — a scrub that forwards every secret while reporting success.
  const unusable = [
    [{}, /nouns is empty or missing/],
    [{ nouns: [] }, /nouns is empty or missing/],
    [
      { nouns: [{ parts: ["token"], uses: ["env-name"] }] },
      /nonSecretSuffixes/,
    ],
    [
      { nouns: ["token"], nonSecretSuffixes: [["key", "id"]] },
      /nouns\[0\] is not an object/,
    ],
    [
      {
        nouns: [{ parts: [], uses: ["env-name"] }],
        nonSecretSuffixes: [["key", "id"]],
      },
      /nouns\[0\]\.parts is empty/,
    ],
    [
      {
        nouns: [{ parts: ["(?:"], uses: ["env-name"] }],
        nonSecretSuffixes: [["key", "id"]],
      },
      /bad part/,
    ],
    [
      {
        nouns: [{ parts: ["token"], uses: ["env-nam"] }],
        nonSecretSuffixes: [["key", "id"]],
      },
      /unknown use/,
    ],
    [
      {
        nouns: [{ parts: ["token"], uses: [] }],
        nonSecretSuffixes: [["key", "id"]],
      },
      /nouns\[0\]\.uses is empty/,
    ],
    [
      {
        nouns: [{ parts: ["token"] }],
        nonSecretSuffixes: [["key", "id"]],
      },
      /nouns\[0\]\.uses is empty/,
    ],
    [
      {
        nouns: [{ parts: ["token"], uses: ["env-name"] }],
        nonSecretSuffixes: [["key", "id"]],
      },
      /no noun is marked field-value/,
    ],
    [
      {
        nouns: [{ parts: ["token"], uses: ["field-value"] }],
        nonSecretSuffixes: [["key", "id"]],
      },
      /no noun is marked env-name/,
    ],
    [
      {
        nouns: [{ parts: ["token"], uses: ["env-name"] }],
        nonSecretSuffixes: [[]],
      },
      /nonSecretSuffixes\[0\] is empty/,
    ],
  ];
  for (const [spec, message] of unusable) {
    it(`throws on ${JSON.stringify(spec)}`, () => {
      assert.throws(() => parseCredentialNames(spec), message);
      assert.throws(() => credentialNameMatcher({ spec }), message);
    });
  }

  it("an unreadable data file throws instead of rendering an empty vocabulary", async () => {
    // The reader's own failure, which no `spec` case reaches: every branch above
    // drives the pure validator, and a missing FILE never gets that far. It is
    // worth pinning because the tempting repair — catching the read and returning
    // an empty vocabulary so start-up survives — turns the matcher into one that
    // answers "not a credential" for every name, with no error anywhere.
    //
    // Driven by importing a COPY of the module from a directory where its data
    // file's relative path resolves to nothing. `DATA_FILE` is a module constant
    // derived from `import.meta.url`, so there is no in-process seam to redirect;
    // this costs no coverage, because the fail-closed branches this file's other
    // cases exercise all live in `parseCredentialNames`, which is already driven
    // directly.
    const directory = mkdtempSync(join(tmpdir(), "credential-names-"));
    const copy = join(directory, "credential-names.mjs");
    writeFileSync(copy, readFileSync(MODULE_PATH));
    try {
      const { credentialNames: orphaned, parseCredentialNames: validator } =
        await import(pathToFileURL(copy).href);
      // The validator still works from the copy, so the throw below is the
      // missing file and not a broken import.
      assert.ok(validator(SPEC).segments.length > 0);
      assert.throws(() => orphaned(), /ENOENT|no such file/);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("no spec at all means the packaged vocabulary, not an empty one", () => {
    // The one absent-spec case that must NOT throw: omitting `spec` is how every
    // ordinary caller asks for the published nouns.
    assert.equal(
      credentialNameMatcher({ spec: undefined })("GITHUB_TOKEN"),
      true,
    );
    assert.throws(() => parseCredentialNames(undefined), /nouns is empty/);
  });
});

describe("a hostile variable NAME cannot stall the matcher", () => {
  // The bound asserted is the COUNT of membership tests, not elapsed time. Both
  // say the same thing about the algorithm, but a wall-clock threshold also
  // reports on the machine that ran it: the linear/quadratic ratio on this input
  // is ~20000, so any threshold separating them passes locally and reds under
  // load. `invisible.test.mjs` carries the scar from that — its ratio test flaked
  // while passing locally, and its replacement is still a wall clock. A count has
  // no machine-dependent term at all: the same number every run, everywhere.
  it("stays linear in the name's segment count", () => {
    // The caller does not choose these names: an env-var scrub is handed whatever
    // the surrounding process exported. One alternation of the 28 renderings is a
    // pattern a redos analyzer measures as polynomial on exactly this input, and
    // an unbounded run walk is quadratic on it.
    const segments = 20_000;
    const name = `${"A_".repeat(segments)}TOKENISH`;
    const realHas = Set.prototype.has;
    let lookups = 0;
    Set.prototype.has = function countingHas(value) {
      lookups += 1;
      return realHas.call(this, value);
    };
    try {
      assert.equal(
        credentialNameMatcher({ scope: "any-segment" })(name),
        false,
      );
    } finally {
      Set.prototype.has = realHas;
    }
    // Linear: at most `maxRun` runs per starting segment. The longest noun in the
    // packaged vocabulary is 3 words, so 4x the segment count is generous headroom
    // over the true bound and still four orders of magnitude under the quadratic
    // walk's ~2e8 for this input.
    assert.ok(
      lookups <= 4 * segments,
      `${lookups} membership tests for ${segments} segments is not linear`,
    );
  });
});
