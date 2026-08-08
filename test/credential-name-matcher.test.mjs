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
import { readFileSync } from "node:fs";

import {
  credentialNameMatcher,
  credentialNames,
  parseCredentialNames,
} from "../src/credential-names.mjs";

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

describe("the shared conformance corpus: the rule, checked across the language boundary", () => {
  // The vocabulary is one file; the RULE built from it is two hand-written twins,
  // and npm cannot import the Python one. `credential-names.cases.json` is the
  // seam: the same cases with the same literal verdicts run here and in
  // tests/secrets/test_credential_names.py, so a divergence reds in whichever
  // language broke instead of shipping to one ecosystem only. Read by relative
  // path, not through the package exports map — a test fixture has no business
  // in the published surface.
  const CASES = JSON.parse(
    readFileSync(
      new URL(
        "../python/agent_sanitizer/secrets/data/credential-names.cases.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ).cases;

  it("is not empty, and every case is well-formed", () => {
    // Non-vacuity: a corpus that failed to load would pass every loop below
    // while asserting nothing, in both languages at once.
    assert.ok(CASES.length >= 100, `only ${CASES.length} conformance cases`);
    for (const c of CASES) {
      assert.equal(typeof c.name, "string", c.id);
      assert.ok(["trailing", "any-segment"].includes(c.scope), c.id);
      assert.equal(typeof c.declineNonSecret, "boolean", c.id);
      assert.equal(typeof c.expected, "boolean", c.id);
    }
    assert.equal(new Set(CASES.map((c) => c.id)).size, CASES.length);
  });

  it("covers every rendering the packaged vocabulary produces", () => {
    // The contract that keeps the corpus from falling behind the words: add a
    // noun to credential-names.json without a case here and this reds, rather
    // than leaving the new noun's rule unchecked in one language.
    const names = new Set(CASES.map((c) => c.name));
    const { segments, nonSecretSegments } = credentialNames();
    for (const form of [...segments, ...nonSecretSegments])
      assert.ok(names.has(form), `no conformance case for ${form}`);
  });

  const matchers = new Map();
  const matcherFor = ({ scope, declineNonSecret }) => {
    const key = `${scope}/${declineNonSecret}`;
    if (!matchers.has(key))
      matchers.set(key, credentialNameMatcher({ scope, declineNonSecret }));
    return matchers.get(key);
  };

  let consumed = 0;
  for (const c of CASES)
    it(`${c.id}`, () => {
      assert.equal(
        matcherFor(c)(c.name),
        c.expected,
        `${JSON.stringify(c.name)} under scope=${c.scope} declineNonSecret=${c.declineNonSecret}: ${c.why}`,
      );
      consumed += 1;
    });

  it("ran every case", () => {
    // A case silently dropped (a filter, a `continue`, a malformed entry) is a
    // hole in exactly the coverage this corpus exists to provide.
    assert.equal(consumed, CASES.length);
  });
});
