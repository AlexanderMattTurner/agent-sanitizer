/**
 * Guards the cross-language golden against drift.
 *
 * `tests/golden.json` is a recording of `sanitize`'s output over the shared
 * corpus (`tests/golden-corpus.json`), consumed by the Python client's
 * byte-for-byte test. It is a derived artifact of `src/`, so if `src/` changes
 * the committed golden must be regenerated in the same commit — otherwise the
 * Python golden test asserts against a stale recording. This re-runs the
 * generator in `--check` mode and fails if the committed file is stale.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..");

describe("cross-language golden corpus", () => {
  // drift-guard-ok: a tool-generated artifact, guarded by exactly this
  // committed == regenerate(src/) freshness check (see generate-golden.mjs).
  it("committed tests/golden.json is in lockstep with src/ (regenerate if this fails)", () => {
    // Exit 0 == fresh; non-zero == stale, with a message on stderr.
    execFileSync(
      process.execPath,
      [join(here, "generate-golden.mjs"), "--check"],
      {
        cwd: repoRoot,
        stdio: "pipe",
      },
    );
  });

  it("every corpus case is recorded for both plain and html", () => {
    const corpus = JSON.parse(
      readFileSync(join(repoRoot, "tests", "golden-corpus.json"), "utf8"),
    );
    const golden = JSON.parse(
      readFileSync(join(repoRoot, "tests", "golden.json"), "utf8"),
    );
    assert.ok(corpus.cases.length > 0, "corpus must be non-empty");
    assert.equal(golden.cases.length, corpus.cases.length);
    const corpusNames = corpus.cases.map((c) => c.name);
    const goldenNames = golden.cases.map((c) => c.name);
    assert.deepEqual(goldenNames, corpusNames);
    for (const c of golden.cases) {
      assert.ok(c.plain && Array.isArray(c.plain.cleaned), `${c.name} plain`);
      assert.ok(c.html && Array.isArray(c.html.cleaned), `${c.name} html`);
    }
  });

  // Precision negatives: legitimate glyphs that the Layer-1 carve-out must pass
  // through UNTOUCHED, plus a positive control proving a malformed tag run is
  // still stripped. Asserted directly against the recorded golden (not just its
  // freshness) so a regression that starts mangling flags / variation sequences
  // — or stops stripping a partial tag run — fails here. The JS and Python
  // clients both read this one recording, so neither can silently disagree
  // with it.
  const corpus = JSON.parse(
    readFileSync(join(repoRoot, "tests", "golden-corpus.json"), "utf8"),
  );
  const golden = JSON.parse(
    readFileSync(join(repoRoot, "tests", "golden.json"), "utf8"),
  );
  const inputUnits = (name) => corpus.cases.find((c) => c.name === name).units;
  const recorded = (name) => golden.cases.find((c) => c.name === name);

  for (const name of [
    "flag_tag_scotland",
    "standardized_variation_empty_set",
    "ideographic_variation_ge",
  ]) {
    it(`${name} survives verbatim with no findings (both modes)`, () => {
      const rec = recorded(name);
      assert.ok(rec, `${name} missing from golden`);
      const input = inputUnits(name);
      for (const mode of ["plain", "html"]) {
        assert.deepEqual(rec[mode].cleaned, input, `${name} ${mode} cleaned`);
        assert.deepEqual(rec[mode].found, [], `${name} ${mode} found`);
      }
    });
  }

  it("malformed_tag_run is still stripped to the bare flag base (positive control)", () => {
    const rec = recorded("malformed_tag_run");
    const input = inputUnits("malformed_tag_run");
    // Bare WAVING BLACK FLAG U+1F3F4 = surrogate pair [0xD83C, 0xDFF4].
    for (const mode of ["plain", "html"]) {
      assert.deepEqual(rec[mode].cleaned, [0xd83c, 0xdff4], `${mode} cleaned`);
      assert.notDeepEqual(rec[mode].cleaned, input, `${mode} actually changed`);
      assert.ok(rec[mode].found.includes("cf-format"), `${mode} reports cf`);
    }
  });
});
