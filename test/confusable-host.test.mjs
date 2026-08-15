/**
 * The confusable-host rule, scored against test/data/confusable-hosts.json.
 *
 * The corpus is the single source: the benign half (real internationalized
 * domain labels across Latin, Cyrillic, Greek, Han, Hiragana, Hangul, Arabic,
 * Devanagari and Thai) must produce ZERO findings, and the attack half must
 * produce the severity it declares. Recall alone would reward a rule that flags
 * everything, so the false-positive half is the half that decides whether the
 * number means anything — and every assertion here is paired with a non-vacuity
 * check so an emptied corpus or a rule that stopped firing fails loudly instead
 * of passing over nothing.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import path from "node:path";
import {
  confusableLabel,
  confusableHost,
  describeConfusableHost,
} from "../src/confusable-host.mjs";
import { detectConfusableHosts } from "../src/html.mjs";
import { sanitize } from "../src/index.mjs";
import { SEVERITY } from "../src/severity.mjs";
import { CATEGORY } from "../src/invisible.mjs";

const repoRoot = execFileSync("git", ["rev-parse", "--show-toplevel"], {
  encoding: "utf8",
}).trim();
const CORPUS = JSON.parse(
  readFileSync(path.join(repoRoot, "test/data/confusable-hosts.json"), "utf8"),
);

describe("corpus: the benign half produces zero findings", () => {
  it("no real internationalized label is flagged", () => {
    assert.ok(
      CORPUS.benign.length >= 50,
      `benign corpus has only ${CORPUS.benign.length} labels — too small to be evidence of a false-positive rate`,
    );
    const flagged = CORPUS.benign
      .map((entry) => ({ ...entry, severity: confusableLabel(entry.label) }))
      .filter((entry) => entry.severity !== null);
    assert.deepEqual(
      flagged,
      [],
      "legitimate IDN labels flagged as confusable — a false positive here " +
        "rewrites the operator's own content out of the channel",
    );
  });

  it("the benign half spans many scripts, so the zero is not a Latin-only zero", () => {
    const scripts = new Set(CORPUS.benign.map((entry) => entry.script));
    assert.ok(
      scripts.size >= 8,
      `benign corpus covers only ${scripts.size} scripts: ${[...scripts].join(", ")}`,
    );
  });
});

describe("corpus: the attack half produces the declared severity", () => {
  it("every attack label is caught at its declared tier", () => {
    assert.ok(CORPUS.attacks.length > 0, "attack corpus is empty");
    const wrong = CORPUS.attacks
      .map((entry) => ({
        label: entry.label,
        expected: entry.severity,
        actual: confusableLabel(entry.label),
      }))
      .filter((entry) => entry.actual !== entry.expected);
    assert.deepEqual(wrong, []);
  });

  it("both tiers are exercised, so neither arm is dead", () => {
    const tiers = new Set(CORPUS.attacks.map((entry) => entry.severity));
    assert.deepEqual([...tiers].sort(), [SEVERITY.NOTE, SEVERITY.WARNING]);
  });

  it("the reported reading is the ASCII name the label impersonates", () => {
    for (const entry of CORPUS.attacks) {
      const found = confusableHost(`https://${entry.label}.example`);
      assert.ok(found, entry.label);
      assert.equal(found.reads, `${entry.reads}.example`);
    }
  });
});

describe("corpus: the declared misses really are missed", () => {
  it("each residual is a tested fact, not a claim in a doc", () => {
    assert.ok(CORPUS.misses.length > 0, "misses list is empty");
    for (const entry of CORPUS.misses)
      assert.equal(
        confusableLabel(entry.label),
        null,
        `${entry.label} is now caught — move it out of "misses" and into "attacks"`,
      );
  });
});

describe("unit: confusableHost over whole URLs", () => {
  it("reports the deceptive form, the punycode, and the ASCII reading", () => {
    const found = confusableHost("https://аpple.com/security");
    assert.deepEqual(found, {
      severity: SEVERITY.WARNING,
      host: "аpple.com",
      ascii: "xn--pple-43d.com",
      reads: "apple.com",
    });
    assert.equal(
      describeConfusableHost(found),
      'аpple.com (xn--pple-43d.com) reads as "apple.com"',
    );
  });

  it("catches the already-punycoded spelling of the same host", () => {
    assert.deepEqual(
      confusableHost("https://xn--pple-43d.com/"),
      confusableHost("https://аpple.com/"),
    );
  });

  it("reads the host through userinfo, port and path", () => {
    const found = confusableHost("https://user:pw@аpple.com:8443/a?b=c#d");
    assert.equal(found.host, "аpple.com");
  });

  it("a spoofed label anywhere in the host raises the whole host", () => {
    assert.equal(
      confusableHost("https://login.аpple.com/").severity,
      SEVERITY.WARNING,
    );
  });

  it("one WARNING label outranks a NOTE label on the same host", () => {
    const found = confusableHost("https://аppleм.аpple.com/");
    assert.equal(found.severity, SEVERITY.WARNING);
  });

  it("fails open on a URL no parser accepts, rather than guessing", () => {
    assert.equal(confusableHost("not a url"), null);
    assert.equal(confusableHost("https://exa mple.com/p"), null);
    // Undecodable punycode: the URL parser runs IDNA ToASCII itself and rejects
    // the host outright, so the rule never sees a half-decoded name.
    assert.equal(confusableHost("https://xn--a.com/"), null);
  });

  it("declines an all-ASCII host, and a scheme that carries no host at all", () => {
    assert.equal(confusableHost("https://apple.com/security"), null);
    assert.equal(confusableHost("data:text/html,<b>x</b>"), null);
    assert.equal(confusableHost("javascript:alert(1)"), null);
    // A relative URL resolves against no base here, which is the fail-open path.
    assert.equal(confusableHost("/docs/index.html"), null);
  });
});

describe("integration: detectConfusableHosts over the shared URL walk", () => {
  const SPOOF = "https://аpple.com/x";
  const carriers = {
    "markdown link": `see [docs](${SPOOF})`,
    "markdown image": `![logo](${SPOOF})`,
    "markdown definition": `[ref]: ${SPOOF}\n\nsee [ref][ref]`,
    "html src": `<img src="${SPOOF}">`,
    "html href": `<a href="${SPOOF}">x</a>`,
    "html form action": `<form action="${SPOOF}"></form>`,
    // A bare URL is a GFM autolink literal, which remark resolves to the same
    // link node — so it is covered wherever the pre-gate lets the walk run.
    "gfm autolink beside a link": `see [a](https://ok.example) and ${SPOOF}`,
  };

  for (const [name, doc] of Object.entries(carriers))
    it(`finds the host in a ${name}`, () => {
      const threats = detectConfusableHosts(doc);
      assert.equal(threats?.length, 1, name);
      assert.equal(threats[0].severity, SEVERITY.WARNING);
      assert.match(threats[0].description, /reads as "apple\.com"/u);
    });

  it("reports one deception per host, not one per occurrence", () => {
    const threats = detectConfusableHosts(
      `[a](${SPOOF}) and [b](https://аpple.com/y) and <img src="${SPOOF}">`,
    );
    assert.equal(threats.length, 1);
  });

  it("is independent of the exfil-shape test: a plain spoofed link still fires", () => {
    // The same document draws no exfil finding — no payload-shaped query, no
    // credential, no off-origin form — so this coverage is the confusable
    // rule's alone.
    assert.equal(detectConfusableHosts(`see [docs](${SPOOF})`)?.length, 1);
  });

  it("stays silent on a document whose IDN hosts are all legitimate", () => {
    assert.equal(
      detectConfusableHosts(
        "[a](https://россия.рф/n) " +
          "[b](https://münchen.de/x) [c](https://apple.com/y)",
      ),
      null,
    );
  });

  it("returns null when the pre-gate finds no link or tag to walk", () =>
    assert.equal(detectConfusableHosts("plain prose, no links or tags"), null));
});

describe("integration: sanitize() surfaces the finding", () => {
  it("reports the confusable-host code and a WARNING for a host reading as an ASCII name", async () => {
    const result = await sanitize(
      "See [the docs](https://аpple.com/security).",
      { html: true },
    );
    assert.deepEqual(result.found, [CATEGORY.CONFUSABLE_HOST]);
    assert.equal(result.warnings.length, 1);
    assert.match(result.warnings[0], /reads as "apple\.com"/u);
    assert.equal(result.notes.length, 0);
    // Detection only: the URL is left byte-identical, because folding it here
    // would launder the attacker's host into the real name.
    assert.match(result.cleaned, /https:\/\/аpple\.com\/security/u);
  });

  it("reports a mixed-script host keeping an unmapped glyph at the quieter NOTE tier", async () => {
    const result = await sanitize("See [x](https://аppleм.com/a).", {
      html: true,
    });
    assert.deepEqual(result.found, [CATEGORY.CONFUSABLE_HOST]);
    assert.equal(result.warnings.length, 0);
    assert.equal(result.notes.length, 1);
  });

  it("says nothing about a legitimate IDN link", async () => {
    const result = await sanitize("Читайте на [сайте](https://россия.рф/n).", {
      html: true,
    });
    assert.deepEqual(result.found, []);
    assert.deepEqual(result.warnings, []);
    assert.deepEqual(result.notes, []);
  });
});
