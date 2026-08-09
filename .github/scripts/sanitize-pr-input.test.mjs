// Behavior tests for sanitize-pr-input.mjs: feed untrusted text on stdin and
// assert the cleaned stdout and the stderr report. Drives the real script (which
// wraps agent-sanitizer), so an import-path or option regression fails
// here, not only in CI. Injection bytes are built with String.fromCharCode,
// never embedded literally — a literal Cf/ANSI byte in this source would be
// stripped by the tool layer that renders it and silently skew the assertion.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCRIPT = join(__dirname, "sanitize-pr-input.mjs");

const ZWSP = String.fromCharCode(0x200b); // zero-width space (general category Cf)
const ESC = String.fromCharCode(0x1b); // ANSI/SGR introducer

// Run the filter over `input`; returns { out, report } (stdout / stderr).
function run(input) {
  const r = spawnSync("node", [SCRIPT], { input, encoding: "utf8" });
  assert.equal(r.status, 0, `exit ${r.status}: ${r.stderr}`);
  return { out: r.stdout, report: r.stderr };
}

describe("sanitize-pr-input: neutralizes injection vectors", () => {
  it("strips zero-width (Cf) characters and ANSI escapes from stdout", () => {
    const { out, report } = run(`a${ZWSP}b ${ESC}[31mRED${ESC}[0m c`);
    assert.equal(out, "ab RED c");
    assert.match(report, /cf-format/);
    assert.match(report, /ansi/);
  });

  it("leaves clean input byte-identical and reports nothing", () => {
    const clean = "const x = 1;\nfunction f() { return x; }\n";
    const { out, report } = run(clean);
    assert.equal(out, clean);
    assert.equal(report, "");
  });

  it("preserves accented Latin (not a format char)", () => {
    const { out, report } = run("café résumé naïve");
    assert.equal(out, "café résumé naïve");
    assert.equal(report, "");
  });
});

describe("sanitize-pr-input: exfil-URL scan is non-destructive", () => {
  it("reports an exfil-shaped markdown link but leaves the bytes intact", () => {
    const input =
      "diff text [a](https://evil.example/x?d=SGVsbG8gd29ybGQgbG9uZyBiYXNlNjQgcGF5bG9hZA) more\n";
    const { out, report } = run(input);
    assert.equal(out, input);
    assert.match(report, /URLs shaped like data exfiltration/);
    assert.match(report, /left intact/);
    assert.match(report, /evil\.example/);
    // The whole header line, not a substring: `exfil-urls` is a DETECTIVE
    // category, so the header may not claim those bytes were neutralized — the
    // review agent's prompt reads neutralized content as a supply-chain signal.
    // Pinning the exact line keeps the deliberately-accepted `exfil-urls`
    // membership from drifting back into a "neutralized" claim.
    assert.equal(report.split("\n")[0], "Categories flagged: exfil-urls");
  });

  it("does not flag an ordinary markdown link", () => {
    const input = "see [the docs](https://example.com/guide) for details\n";
    const { out, report } = run(input);
    assert.equal(out, input);
    assert.equal(report, "");
  });
});
