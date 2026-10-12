import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { MD_LINK_HINT, matchesSecretHint } from "../src/gates.mjs";

/**
 * Targeted mutation-kill assertions for `src/gates.mjs`. Each case feeds an
 * input that the original pattern and the surviving Stryker mutant classify
 * differently, then asserts the exact boolean the ORIGINAL produces — so the
 * assertion flips (fails) under the mutant. Exercised only through the public
 * exports (`MD_LINK_HINT`, `matchesSecretHint`).
 *
 * The one gates survivor left uncovered is the `-us[0-9]{1,2}` → `-us[0-9]`
 * quantifier on the Mailchimp arm of SECRET_HINT_EXT: the arm has no trailing
 * anchor, so `{1}` accepts every string `{1,2}` does and no boolean input can
 * separate them (equivalent mutant).
 */

describe("MD_LINK_HINT reference-definition arm", () => {
  // Mutant: `^[ \t]*` → `^[^ \t]*` (negated leading-whitespace class).
  // A ref def with a real leading space: original's `[ \t]*` eats the space
  // then matches `[label]:`; the mutant's `[^ \t]*` cannot cross the space
  // while anchored at `^`, so it fails. Original true, mutant false.
  it("matches a reference definition indented by a space", () => {
    assert.equal(MD_LINK_HINT.test(" [ref]: x"), true);
  });

  // Mutant: `^[ \t]*\[…` → `[ \t]*\[…` (the `^` line anchor removed).
  // `[label]:` preceded by non-space, non-line-start text: the anchored
  // original cannot reach it (no `](` / `![` either), but the unanchored
  // mutant matches mid-line. Original false, mutant true.
  it("does not match a bracket label mid-line with no line anchor", () => {
    assert.equal(MD_LINK_HINT.test("xx[label]: y"), false);
  });
});

describe("SECRET_HINT quantifier arms (removed {N} → exactly one char)", () => {
  // For each: prefix + exactly ONE trailing char. The original needs the full
  // run length so it does NOT match; the mutant (quantifier removed → one
  // char) DOES. Asserting `false` fails under every such mutant.
  const oneCharShort = [
    // (?:A3T|AKIA|…|ASIA)[A-Z0-9]{16} → […][A-Z0-9]
    ["AWS-key AKIA prefix + 1 char", "AKIAB"],
    // gl[a-z]{2,12}-[0-9A-Za-z_-]{20} → …-[0-9A-Za-z_-]
    ["GitLab glpat- + 1 char", "glpat-x"],
    // AIza[0-9A-Za-z_-]{35} → AIza[0-9A-Za-z_-]
    ["Google AIza + 1 char", "AIzaX"],
    // hv[sb]\.[A-Za-z0-9_-]{20} → hv[sb]\.[A-Za-z0-9_-]
    ["Vault hvs. + 1 char", "hvs.X"],
    // do[opr]_v1_[a-f0-9]{16} → …_v1_[a-f0-9]
    ["DigitalOcean dop_v1_ + 1 hex", "dop_v1_a"],
    // sk-or-[0-9a-z_-]{16} → sk-or-[0-9a-z_-]
    ["OpenRouter sk-or- + 1 char", "sk-or-a"],
    // gsk_[A-Za-z0-9]{16} → gsk_[A-Za-z0-9]
    ["Groq gsk_ + 1 char", "gsk_A"],
    // xai-[A-Za-z0-9]{16} → xai-[A-Za-z0-9]
    ["xAI xai- + 1 char", "xai-A"],
    // r8_[A-Za-z0-9]{16} → r8_[A-Za-z0-9]
    ["Replicate r8_ + 1 char", "r8_A"],
  ];
  for (const [label, sample] of oneCharShort) {
    it(`does not shape-match a one-char-short ${label}`, () => {
      assert.equal(matchesSecretHint(sample), false);
    });
  }
});

describe("SECRET_HINT_EXT quantifier arms (removed {N} → exactly one char)", () => {
  const A22 = "a".repeat(22);
  const oneCharShort = [
    // SG\.[…]{22}\.[…]{43} → trailing {43} removed. Full 22-run + dot + 1 char.
    ["SendGrid SG. body + 1-char tail", "SG." + A22 + ".b"],
    // sq0csp-[0-9A-Za-z_-]{43} → sq0csp-[0-9A-Za-z_-]
    ["Square sq0csp- + 1 char", "sq0csp-x"],
    // (?<![0-9])[0-9]{8,10}:[…]{35} → trailing {35} removed. Boundary via space.
    ["Telegram digits: + 1-char tail", " 12345678:x"],
    // (?<!…)[MNO][…]{23,25}\.[…]{6}\.[…]{27} → trailing {27} removed.
    [
      "JWT M-head + 1-char final segment",
      "M" + "a".repeat(24) + "." + "b".repeat(6) + ".c",
    ],
    // (?<![A-Za-z0-9])AP[0-9A-Fa-f][A-Za-z0-9]{8} → trailing {8} removed.
    ["Asana AP + hex + 1 char", " AP0a"],
    // (?<![A-Za-z0-9])AKC[A-Za-z0-9]{10} → trailing {10} removed.
    ["Alibaba AKC + 1 char", " AKCa"],
    // (?:key|pw|pass)["']?[\s:=>]+["']?[A-Za-z0-9_/+-]{20} → trailing {20} removed.
    ["key= + 1-char value", "key=a"],
  ];
  for (const [label, sample] of oneCharShort) {
    it(`does not shape-match a one-char-short ${label}`, () => {
      assert.equal(matchesSecretHint(sample), false);
    });
  }

  // Mutant: `[MNO]` → `[^MNO]` on the JWT-head arm. The head is at string
  // start (no leading char the negated class could consume), so the original
  // matches `M` while the mutant — needing a non-M/N/O head at that boundary —
  // cannot match anywhere. Original true, mutant false.
  it("shape-matches a JWT-style head starting with M", () => {
    const jwt =
      "M" + "a".repeat(24) + "." + "b".repeat(6) + "." + "c".repeat(27);
    assert.equal(matchesSecretHint(jwt), true);
  });

  // Mutant: first `["']?` → `[^"']?` on the key/pw/pass arm. Input `key"=…`:
  // the original's optional quote eats the `"`, then `[\s:=>]+` eats `=`; the
  // mutant's `[^"']?` cannot consume the `"` (excluded) and then `[\s:=>]+`
  // faces `"` and fails. Original true, mutant false.
  it('shape-matches a quoted key assignment key"=<20 chars>', () => {
    assert.equal(matchesSecretHint('key"=' + "a".repeat(20)), true);
  });
});
