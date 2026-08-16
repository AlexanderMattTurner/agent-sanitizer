/**
 * Property/fuzz tests for Layer 3's confusable-host detector.
 *
 * `detectConfusableHosts` eats attacker-controlled documents: it runs a
 * markdown parser and the WHATWG URL parser over untrusted text, decodes every
 * punycode label it finds, and owns its own `found` category and model-facing
 * warning. confusable-host.test.mjs scores the RULE against a benign/attack
 * corpus of isolated labels; this file pins the DETECTOR's invariants over
 * whole generated documents, where extraction, neighbouring links and filler
 * prose could bleed one URL's verdict into another's.
 *
 * The precision invariant is the one that matters most here. A false positive
 * rewrites the operator's own content out of the channel, so the headline
 * property is stated in that direction: a document whose hosts hold no `xn--`
 * label cannot produce a finding, because the WHATWG parser returns the A-label
 * form and a host with no A-label held no non-ASCII code point to begin with.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import fc from "fast-check";

import { detectConfusableHosts } from "../src/html.mjs";
import { SEVERITY } from "../src/severity.mjs";
import { fcRunOptions } from "./test-helpers.mjs";

const runOptions = fcRunOptions({ numRuns: 300 });

const repoRoot = execFileSync("git", ["rev-parse", "--show-toplevel"], {
  encoding: "utf8",
}).trim();
const CORPUS = JSON.parse(
  readFileSync(path.join(repoRoot, "test/data/confusable-hosts.json"), "utf8"),
);

const SEVERITIES = new Set(Object.values(SEVERITY));

/** Prose that carries no URL of its own, so only the seeded hosts are judged. */
const filler = fc
  .array(
    fc.constantFrom(
      "see the notes",
      "step 2",
      "# heading",
      "- bullet",
      "`code`",
      "**bold** text",
      "a paragraph, with punctuation.",
      "",
    ),
    { minLength: 0, maxLength: 6 },
  )
  .map((lines) => lines.join("\n"));

/** An ASCII host that can never decode to a non-ASCII label. */
const asciiHost = fc
  .array(
    fc
      .stringMatching(/^[a-z][a-z0-9-]{0,10}$/)
      .filter((l) => !l.includes("xn")),
    { minLength: 2, maxLength: 3 },
  )
  .map((labels) => labels.join("."));

const attackLabel = fc.constantFrom(...CORPUS.attacks.map((a) => a.label));

/** A markdown link, an image, a bare autolink, or a link reference definition. */
const linkTo = (host) =>
  fc
    .tuple(
      fc.constantFrom("link", "image", "autolink", "definition"),
      fc.constantFrom("", "/path", "/a?q=1#frag"),
    )
    .map(([shape, tail]) => {
      const url = `https://${host}${tail}`;
      if (shape === "image") return `![alt](${url})`;
      if (shape === "autolink") return `<${url}>`;
      if (shape === "definition") return `[ref]: ${url}`;
      return `[text](${url})`;
    });

const documentOf = (hosts) =>
  fc
    .tuple(filler, fc.tuple(...hosts.map(linkTo)), filler)
    .map(([head, links, tail]) => [head, ...links, tail].join("\n\n"));

/** Every finding's shape, asserted wherever a result is inspected. */
const assertFindingShape = (findings) => {
  assert.ok(findings === null || Array.isArray(findings));
  if (findings === null) return;
  assert.ok(findings.length > 0, "an empty array must be reported as null");
  for (const finding of findings) {
    assert.ok(
      SEVERITIES.has(finding.severity),
      `bad severity: ${finding.severity}`,
    );
    assert.equal(typeof finding.description, "string");
    assert.ok(finding.description.length > 0);
  }
};

describe("property: detectConfusableHosts never throws and reports a legal shape", () => {
  it("survives arbitrary text", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 400 }), (text) => {
        assertFindingShape(detectConfusableHosts(text));
      }),
      runOptions,
    );
  });

  it("survives arbitrary documents built from real link shapes", () => {
    fc.assert(
      fc.property(
        fc
          .array(
            fc.oneof(
              asciiHost,
              attackLabel.map((l) => `${l}.com`),
            ),
            {
              minLength: 1,
              maxLength: 4,
            },
          )
          .chain((hosts) => documentOf(hosts)),
        (document) => {
          assertFindingShape(detectConfusableHosts(document));
        },
      ),
      runOptions,
    );
  });
});

describe("property: precision — an all-ASCII document is never flagged", () => {
  it("no finding when no host carries a punycode label", () => {
    fc.assert(
      fc.property(
        fc
          .array(asciiHost, { minLength: 1, maxLength: 4 })
          .chain((hosts) => documentOf(hosts)),
        (document) => {
          assert.ok(
            !document.toLowerCase().includes("xn--"),
            "the generator leaked a punycode label, so this property is vacuous",
          );
          assert.equal(detectConfusableHosts(document), null);
        },
      ),
      runOptions,
    );
  });
});

describe("property: recall — a corpus attack host is found wherever it sits", () => {
  it("a deceptive host embedded in ordinary prose is reported", () => {
    assert.ok(
      CORPUS.attacks.length > 0,
      "the attack corpus is empty, so this property would pass over nothing",
    );
    fc.assert(
      fc.property(
        attackLabel.chain((label) =>
          fc
            .array(asciiHost, { minLength: 0, maxLength: 3 })
            .chain((benign) => documentOf([`${label}.com`, ...benign])),
        ),
        (document) => {
          const findings = detectConfusableHosts(document);
          assert.ok(
            findings !== null,
            `a corpus attack host went unreported in:\n${document}`,
          );
          assertFindingShape(findings);
        },
      ),
      runOptions,
    );
  });
});

describe("property: one deception is one finding, however often it is written", () => {
  it("repeating a host does not multiply its finding", () => {
    fc.assert(
      fc.property(
        attackLabel,
        fc.integer({ min: 2, max: 5 }),
        (label, repeats) => {
          const host = `${label}.com`;
          const once = detectConfusableHosts(`[a](https://${host})`);
          const many = detectConfusableHosts(
            Array.from(
              { length: repeats },
              (_unused, i) => `[a${i}](https://${host}/p${i})`,
            ).join("\n\n"),
          );
          assert.notEqual(once, null, "the single-link case reported nothing");
          assert.deepEqual(many, once);
        },
      ),
      runOptions,
    );
  });

  it("is deterministic over the same document", () => {
    fc.assert(
      fc.property(
        fc
          .array(
            fc.oneof(
              asciiHost,
              attackLabel.map((l) => `${l}.org`),
            ),
            {
              minLength: 1,
              maxLength: 4,
            },
          )
          .chain((hosts) => documentOf(hosts)),
        (document) => {
          assert.deepEqual(
            detectConfusableHosts(document),
            detectConfusableHosts(document),
          );
        },
      ),
      runOptions,
    );
  });
});
