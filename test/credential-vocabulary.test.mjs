/**
 * The hook-side credential-var-NAME matcher derives its vocabulary from the
 * published `credential-names.json` — the same file `agent_sanitizer.secrets`
 * renders in Python — so the two ecosystems cannot recognize different sets of
 * credential-bearing variable names.
 *
 * This closes a real fail-open. The matcher previously read a hand-curated
 * `claude-hooks/config/credential-var-names.json` carrying 16 of the
 * vocabulary's 28 segments, so a variable named `…_ACCESS_TOKEN`,
 * `…_CLIENT_SECRET`, `…_BEARER`, `…_AUTHORIZATION` or `…_PRIVATEKEY` was not
 * recognized as credential-bearing: its name never entered
 * `envBoundSecretVars()`, its value was never sent to the redactor as an
 * env-bound secret, and `hasEnvBoundSecret` never fired on it — so the value
 * reached the model verbatim.
 *
 * The completeness test below is driven FROM the vocabulary rather than from a
 * restated list, so a noun added to the published file is covered here the day it
 * lands. That is one source read by a consumer, not two copies policed for
 * agreement: there is no second list to drift.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  deriveCredentialVocabulary,
  looksLikeCredentialVar,
} from "../claude-hooks/lib/env-config.mjs";

// Resolved through the exports map, the same way a consumer reaches it — so this
// asserts against the file the package actually publishes.
const spec = JSON.parse(
  readFileSync(
    fileURLToPath(import.meta.resolve("agent-sanitizer/credential-names")),
    "utf8",
  ),
);

const ENV_NAME_USE = "env-name";
const envNameNouns = spec.nouns.filter((noun) =>
  noun.uses.includes(ENV_NAME_USE),
);

describe("the name matcher covers every published env-name noun", () => {
  it("finds env-name nouns to check (non-vacuous)", () => {
    assert.ok(envNameNouns.length > 0, "no noun is marked env-name");
  });

  // Both spellings, because the matcher anchors on underscore-delimited segments
  // and sees `API_KEY` and `APIKEY` as different tokens.
  for (const noun of envNameNouns) {
    const joined = noun.parts.join("_").toUpperCase();
    const bare = noun.parts.join("").toUpperCase();
    it(`recognizes DEPLOY_${joined} and DEPLOY_${bare}`, () => {
      assert.equal(looksLikeCredentialVar(`DEPLOY_${joined}`), true);
      assert.equal(looksLikeCredentialVar(`DEPLOY_${bare}`), true);
    });
  }
});

describe("the name matcher excludes every published non-secret suffix", () => {
  it("finds non-secret suffixes to check (non-vacuous)", () => {
    assert.ok(spec.nonSecretSuffixes.length > 0);
  });

  // A name ending in one of these looks like a credential but holds an
  // identifier or a public value; redacting it would strip real content.
  for (const suffix of spec.nonSecretSuffixes) {
    const joined = suffix.join("_").toUpperCase();
    const bare = suffix.join("").toUpperCase();
    it(`refuses AWS_${joined} and AWS_${bare}`, () => {
      assert.equal(looksLikeCredentialVar(`AWS_${joined}`), false);
      assert.equal(looksLikeCredentialVar(`AWS_${bare}`), false);
    });
  }

  it("refuses a non-secret run that IS the whole name", () => {
    // The exclusion rendered a leading underscore into its tokens, so it was
    // reachable only when something preceded the run: `PUBLIC_KEY` matched on
    // its trailing `KEY` and its value was cut out of every tool output
    // carrying it. Asserted for every published run, bare and joined.
    for (const suffix of spec.nonSecretSuffixes) {
      const joined = suffix.join("_").toUpperCase();
      const bare = suffix.join("").toUpperCase();
      assert.equal(looksLikeCredentialVar(joined), false, joined);
      assert.equal(looksLikeCredentialVar(bare), false, bare);
    }
  });

  it("refuses the ssh-agent socket, whose value is a path", () => {
    assert.equal(looksLikeCredentialVar("SSH_AUTH_SOCK"), false);
  });

  it("refuses ordinary variables", () => {
    for (const name of ["HOME", "PATH", "LANG"])
      assert.equal(looksLikeCredentialVar(name), false, name);
  });
});

describe("deriveCredentialVocabulary fails closed on a malformed spec", () => {
  // Each of these would otherwise render an empty or under-populated
  // alternation, which matches nothing and forwards every credential.
  const bad = {
    "missing nouns": { nonSecretSuffixes: [["key", "id"]] },
    "missing nonSecretSuffixes": {
      nouns: [{ parts: ["token"], uses: [ENV_NAME_USE] }],
    },
    "nouns not an array": {
      nouns: "token",
      nonSecretSuffixes: [["key", "id"]],
    },
    "empty parts": {
      nouns: [{ parts: [], uses: [ENV_NAME_USE] }],
      nonSecretSuffixes: [["key", "id"]],
    },
    "metacharacter in a part": {
      nouns: [{ parts: ["to.en"], uses: [ENV_NAME_USE] }],
      nonSecretSuffixes: [["key", "id"]],
    },
    "upper-case part": {
      nouns: [{ parts: ["TOKEN"], uses: [ENV_NAME_USE] }],
      nonSecretSuffixes: [["key", "id"]],
    },
  };
  for (const [label, spec_] of Object.entries(bad))
    it(`throws on ${label}`, () => {
      assert.throws(() => deriveCredentialVocabulary(spec_), {
        message: /credential-names\.json/u,
      });
    });
});

describe("the derived vocabulary is safe to interpolate unescaped", () => {
  const derived = deriveCredentialVocabulary(spec);

  it("renders both segment forms and both exclude forms", () => {
    assert.ok(derived.segments.length >= envNameNouns.length);
    assert.equal(
      derived.excludeSuffixes.length,
      new Set(
        spec.nonSecretSuffixes.flatMap((s) => [
          `_${s.join("_").toUpperCase()}`,
          `_${s.join("").toUpperCase()}`,
        ]),
      ).size,
    );
  });

  it("carries no regex metacharacter in any token", () => {
    for (const token of [
      ...derived.segments,
      ...derived.excludeSuffixes,
      ...derived.excludeNames,
    ])
      assert.match(token, /^[A-Z0-9_]+$/u, token);
  });
});
