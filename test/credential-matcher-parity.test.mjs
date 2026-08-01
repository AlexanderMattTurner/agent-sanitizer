/**
 * The Python and JavaScript name matchers must answer every name identically.
 *
 * `credential_name_matcher` and `credentialNameMatcher` are two implementations
 * of one rule over one vocabulary file, and a consumer binds BOTH on the same
 * tool call: agent-glovebox binds the Python one to its redactor daemon and the
 * JavaScript one to the tool-output gate that runs in front of it, under the same
 * policy. A name the two answer differently is therefore a credential one path
 * redacts and the other forwards to the transcript.
 *
 * Nothing pinned that agreement before this file. Each language's suite tested
 * its own copy against cases a human had transcribed into both — which is how the
 * copies drifted the last time: Python's `$` also matches just before a trailing
 * newline and JavaScript's does not, so `MY_TOKEN\n` was credential-bearing to one
 * side and not the other. Transcribed cases cannot catch that, because whoever
 * writes them writes the same case twice.
 *
 * So the assertions here are DIFFERENTIAL: they compare the two implementations
 * against each other over names derived from the vocabulary, rather than either
 * against a hand-written expectation. The vocabulary is read at run time, so a
 * noun added to the JSON is covered with no edit to this file.
 *
 * `python-credential-matcher.mjs` drives the real Python matcher over one
 * long-lived worker; see its header for the protocol.
 *
 * # covers: src/credential-names.mjs
 * # covers: python/agent_sanitizer/secrets/credential_names.py
 */
import { after, describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  credentialNameMatcher,
  credentialNames,
} from "../src/credential-names.mjs";
import {
  pythonHoldsCredential,
  pythonNounAlphabetFolding,
  pythonParseRejection,
  stopPythonCredentialMatcher,
} from "./python-credential-matcher.mjs";

after(stopPythonCredentialMatcher);

// The two policies agent-glovebox actually binds, and they want opposite trades.
// Both are asserted, because a divergence that showed up under only one would be
// a live leak on the other consumer.
const POLICIES = [
  // The redactor daemon's environment, and the tool-output gate in front of it.
  { label: "redactor", scope: "trailing", declineNonSecret: true },
  // The env scrub, which prefers over-stripping to forwarding a secret.
  { label: "scrub", scope: "any-segment", declineNonSecret: false },
];

const { segments, nonSecretSegments } = credentialNames();
const MAX_RUN = Math.max(...segments.map((noun) => noun.split("_").length));

/** Assert the two implementations agree on every name, naming the first that splits.
 *
 * Returns the JavaScript verdicts so a caller can add a DIRECTIONAL assertion on
 * top: agreement alone is satisfied by two implementations that both answer
 * "false" to everything, so every use of this is paired with a check that the
 * corpus is one the matcher genuinely discriminates.
 *
 * @param {typeof POLICIES[number]} policy @param {string[]} names
 * @returns {Promise<boolean[]>} */
async function assertAgreement(policy, names) {
  const js = names.map(credentialNameMatcher(policy));
  const py = await pythonHoldsCredential(policy, names);
  const split = names.findIndex((_, i) => js[i] !== py[i]);
  if (split !== -1)
    assert.fail(
      `${policy.label}: ${JSON.stringify(names[split])} — js=${js[split]} python=${py[split]}`,
    );
  return js;
}

describe("the vocabulary is enumerable and non-empty", () => {
  // Non-vacuity for every enumeration below: an empty vocabulary would make each
  // per-member test a loop over nothing, which reports as a passing suite.
  it("renders segments and non-secret markers to enumerate", () => {
    assert.ok(segments.length > 0);
    assert.ok(nonSecretSegments.length > 0);
  });

  // `maxRun` is derived from the NOUNS alone, so it bounds how far back either
  // matcher looks for a non-secret marker too. A marker longer than the longest
  // noun would sit outside every trailing run and never decline anything — in
  // both languages at once, so the differential tests below could not see it.
  for (const marker of nonSecretSegments)
    it(`${marker} is short enough for the trailing-run walk to reach it`, () => {
      assert.ok(
        marker.split("_").length <= MAX_RUN,
        `${marker} is ${marker.split("_").length} words but the walk stops at ${MAX_RUN}`,
      );
    });
});

describe("every env-name segment, in both languages", () => {
  for (const segment of segments)
    for (const policy of POLICIES)
      it(`${segment} under ${policy.label}`, async () => {
        // The spellings a real environment produces, plus the trailing newline
        // that split the two implementations before.
        const names = [
          segment,
          `DEPLOY_${segment}`,
          `deploy_${segment.toLowerCase()}`,
          `${segment}\n`,
          `DEPLOY_${segment}\n`,
          `${segment}_ORG`,
          `PREFIX_${segment}_FALLBACK_4`,
        ];
        const js = await assertAgreement(policy, names);
        // Directional, so agreement on "false everywhere" cannot pass this.
        assert.equal(js[1], true, `DEPLOY_${segment} must hold a credential`);
      });
});

describe("every non-secret marker, in both languages", () => {
  // Built from the vocabulary rather than named, so a new noun or marker needs no
  // edit here. The first env-name segment supplies a real credential noun to put
  // in front of the marker.
  const noun = segments[0];
  for (const marker of nonSecretSegments)
    it(`${marker} declines under the redactor and not under the scrub`, async () => {
      const name = `${noun}_${marker}`;
      const names = [name, name.toLowerCase(), `${name}\n`];
      const [redactor, scrub] = POLICIES;
      const jsRedactor = await assertAgreement(redactor, names);
      const jsScrub = await assertAgreement(scrub, names);
      // The two policies must actually split on this name, or `declineNonSecret`
      // is decorative: the redactor declines an identifier, the scrub keeps it.
      assert.equal(
        jsRedactor[0],
        false,
        `${name} must be declined as non-secret`,
      );
      assert.equal(
        jsScrub[0],
        true,
        `${name} must survive a scrub that over-strips`,
      );
    });
});

describe("a generated corpus agrees across the language boundary", () => {
  // Every token the vocabulary renders, crossed with the shapes a real
  // environment produces. The tails are the point: a trailing newline is what
  // Python's `$` accepts and JavaScript's rejects, so it is the one character
  // that separates a correctly anchored implementation from a plausible one.
  const PREFIXES = ["", "DEPLOY_", "npm_config_", "A_B_"];
  const SUFFIXES = ["", "_ID", "_ORG", "_V2", "_FALLBACK_4"];
  const CASINGS = [
    (s) => s,
    (s) => s.toLowerCase(),
    (s) => `${s.slice(0, 1)}${s.slice(1).toLowerCase()}`,
  ];
  const TAILS = ["", "\n", "\r\n", " ", "_"];

  const corpus = [
    ...new Set(
      [...segments, ...nonSecretSegments].flatMap((token) =>
        PREFIXES.flatMap((prefix) =>
          SUFFIXES.flatMap((suffix) =>
            CASINGS.flatMap((casing) =>
              TAILS.map((tail) => casing(`${prefix}${token}${suffix}`) + tail),
            ),
          ),
        ),
      ),
    ),
  ];

  it("is large enough to be worth comparing", () => {
    assert.ok(corpus.length > 1000, `${corpus.length} names is too few`);
    // The case the bug hid in must actually be present.
    assert.ok(corpus.some((name) => name.endsWith("\n")));
  });

  for (const policy of POLICIES)
    it(`${policy.label}: same verdict for all ${corpus.length} names`, async () => {
      const js = await assertAgreement(policy, corpus);
      // Agreement on an all-false corpus would be worthless. Both directions must
      // occur, so the comparison is over a set the matcher genuinely discriminates.
      assert.ok(js.some(Boolean) && js.some((v) => !v));
    });
});

describe("hostile names agree too", () => {
  // A scrub does not choose these — it is handed whatever the surrounding process
  // exported, so a name can carry anything a process environment can carry.
  const HOSTILE = [
    "",
    "_",
    "__",
    "TOKEN ",
    " TOKEN",
    "TOKEN.*",
    "(?:TOKEN)",
    "TOKEN$",
    "^TOKEN",
    "TOKEN[",
    "TOKEN\\",
    // Written as escapes, never as raw bytes: a literal NUL makes the source
    // read as binary to grep and the diff tools, and a raw U+2028 is a line
    // terminator to some JavaScript parsers.
    "TOKEN\0",
    "TOKEN\t",
    "TOKEN\u00A0",
    "TOKEN\u2028",
    "TOKEN\u2029",
    "TOKEN\r",
    "TOKEN\u{1F600}",
    // Lone surrogates: legal in both languages' string types, illegal as UTF-8.
    "TOKEN\uD800",
    "\uDFFFTOKEN",
    // Case-folding shapes where one character upper-cases into several.
    "TOKENß",
    "ıTOKEN",
    "TOKENﬁ",
    "ſECRET_KEY",
    // Normalization: the same name in NFC and NFD must not split the two.
    "TÖKEN_KEY".normalize("NFC"),
    "TÖKEN_KEY".normalize("NFD"),
    // Long enough that a quadratic walk would be visible, on both sides.
    "A".repeat(20_000),
    `${"A_".repeat(10_000)}TOKEN`,
    `${"_".repeat(5_000)}KEY`,
  ];

  for (const policy of POLICIES)
    it(`${policy.label}: same verdict for every hostile name`, async () => {
      const js = await assertAgreement(policy, HOSTILE);
      // Both directions, so this cannot pass on two implementations that agree
      // only because a hostile name makes them both give up. `ſECRET_KEY` is the
      // one that matters: the long s upper-cases to S in both languages, so the
      // name really does hold a credential and really must be matched.
      assert.equal(js[HOSTILE.indexOf("ſECRET_KEY")], true);
      assert.ok(js.some((v) => !v));
    });
});

describe("the case-folding step is portable", () => {
  // This is WHY the corpus above agrees, and it generalizes past any corpus.
  // Upper-casing is the matcher's only text transform, and the vocabulary is pure
  // [A-Z0-9_]; so the two languages answer every name alike exactly when they
  // agree on which code points fold INTO that alphabet, and on the images.
  //
  // The assertion is deliberately not "str.upper() and toUpperCase() agree
  // everywhere" — they do not. 55 code points differ between the runtimes here,
  // all of them Unicode-version skew between Node's ICU and CPython's tables, and
  // that count moves whenever either is upgraded. None of them reaches the noun
  // alphabet, which is the property that actually matters and the one that holds
  // across versions.
  it("both languages fold the same code points into the noun alphabet", async () => {
    const NOUN_ALPHABET = /^[A-Z0-9_]+$/;
    /** @type {Map<number, string>} */
    const js = new Map();
    for (let cp = 0; cp <= 0x10ffff; cp++) {
      if (cp >= 0xd800 && cp <= 0xdfff) continue;
      const upper = String.fromCodePoint(cp).toUpperCase();
      if (NOUN_ALPHABET.test(upper)) js.set(cp, upper);
    }
    const python = new Map(await pythonNounAlphabetFolding());

    assert.ok(js.size > 0, "the sweep found nothing — it is not running");
    // Non-vacuity of the interesting half: the set must include characters that
    // are not already ASCII, or it proves only that A-Z maps to itself.
    assert.ok(
      [...js].some(([cp]) => cp > 0x7f),
      "no non-ASCII code point folds in — the sweep missed the hard cases",
    );
    assert.deepEqual(
      [...python].sort(([a], [b]) => a - b),
      [...js].sort(([a], [b]) => a - b),
    );
  });
});

describe("both languages refuse the same unusable vocabularies", () => {
  // Fail-closed parity. An empty rendering is the dangerous one: it compiles to a
  // matcher that answers "not a credential" for every name, so a consumer that
  // got it would forward every credential silently, with no error anywhere. One
  // language raising while the other builds it is that leak on one of the two
  // paths.
  const GOOD_NOUN = { parts: ["token"], uses: ["env-name", "field-value"] };
  const UNUSABLE = [
    ["no spec at all", {}],
    ["empty noun list", { nouns: [], nonSecretSuffixes: [["key", "id"]] }],
    ["no non-secret suffixes", { nouns: [GOOD_NOUN], nonSecretSuffixes: [] }],
    [
      "empty parts",
      {
        nouns: [{ parts: [], uses: ["env-name"] }],
        nonSecretSuffixes: [["key", "id"]],
      },
    ],
    [
      "empty non-secret suffix",
      { nouns: [GOOD_NOUN], nonSecretSuffixes: [[]] },
    ],
    [
      "a regex metacharacter in a part",
      {
        nouns: [{ parts: [".*"], uses: ["env-name", "field-value"] }],
        nonSecretSuffixes: [["key", "id"]],
      },
    ],
    [
      "an anchor in a part",
      {
        nouns: [{ parts: ["^token$"], uses: ["env-name", "field-value"] }],
        nonSecretSuffixes: [["key", "id"]],
      },
    ],
    // The two anchoring cases, as DATA. Python's `$` matches before a trailing
    // newline and JavaScript's does not, so a validator anchored `^…$` on the
    // Python side accepts these and its JavaScript twin rejects them — the exact
    // split that let a token smuggle a newline past one of the two.
    [
      "a trailing newline in a part",
      {
        nouns: [{ parts: ["token\n"], uses: ["env-name", "field-value"] }],
        nonSecretSuffixes: [["key", "id"]],
      },
    ],
    [
      "a trailing newline in a non-secret suffix",
      { nouns: [GOOD_NOUN], nonSecretSuffixes: [["key", "id\n"]] },
    ],
    [
      "a leading newline in a part",
      {
        nouns: [{ parts: ["\ntoken"], uses: ["env-name", "field-value"] }],
        nonSecretSuffixes: [["key", "id"]],
      },
    ],
    [
      "no noun marked env-name",
      {
        nouns: [{ parts: ["token"], uses: ["field-value"] }],
        nonSecretSuffixes: [["key", "id"]],
      },
    ],
    [
      "no noun marked field-value",
      {
        nouns: [{ parts: ["token"], uses: ["env-name"] }],
        nonSecretSuffixes: [["key", "id"]],
      },
    ],
    [
      "an unknown use",
      {
        nouns: [{ parts: ["token"], uses: ["env-nam"] }],
        nonSecretSuffixes: [["key", "id"]],
      },
    ],
  ];

  for (const [label, spec] of UNUSABLE)
    it(`${label}: both raise`, async () => {
      assert.throws(
        () => credentialNameMatcher({ spec }),
        `javascript accepted an unusable vocabulary: ${label}`,
      );
      assert.notEqual(
        await pythonParseRejection(spec),
        null,
        `python accepted an unusable vocabulary: ${label}`,
      );
    });

  it("and both accept the good one, so the refusals mean something", async () => {
    const spec = {
      nouns: [GOOD_NOUN],
      nonSecretSuffixes: [["key", "id"]],
    };
    assert.equal(
      credentialNameMatcher({ spec, scope: "trailing" })("DEPLOY_TOKEN"),
      true,
    );
    assert.equal(await pythonParseRejection(spec), null);
  });
});
