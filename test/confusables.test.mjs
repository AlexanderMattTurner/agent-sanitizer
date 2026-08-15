/**
 * Unit/example tests for the confusable-folding core. The confusable scanner is
 * INJECTED as a deterministic fake `scan` returning the documented findings
 * shape ({ index, char, latinEquivalent }), so these tests pin the folding,
 * offset-handling, reporting-cap, dedup, fast-path, and field-map behavior
 * independently of any heavy real engine.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  DEFAULT_FIELDS,
  EXEMPT_TOOLS,
  EXEMPT_TOOL_PATTERNS,
  hasNonAscii,
  normalizeContext,
  foldConfusables,
  normalizeConfusables,
  scopeFor,
  selectFoldableFindings,
} from "../src/confusables.mjs";
import { cp } from "./test-helpers.mjs";
import { liveToolSurface } from "./helpers/tool-surface.mjs";

const CYR_A = cp(0x0430); // Cyrillic а → ASCII "a"
const CYR_O = cp(0x043e); // Cyrillic о → ASCII "o"

// Cyrillic → ASCII map for the fake scanner.
const CYR_TO_ASCII = {
  [cp(0x0430)]: "a",
  [cp(0x043e)]: "o",
  [cp(0x0435)]: "e",
  [cp(0x0440)]: "p",
  [cp(0x0441)]: "c",
  [cp(0x0445)]: "x",
  [cp(0x0443)]: "y",
  [cp(0x0456)]: "i",
  [cp(0x0455)]: "s",
  [cp(0x0458)]: "j",
};
// Astral mathematical-bold confusables (2 UTF-16 units each).
const ASTRAL_TO_ASCII = {
  [cp(0x1d400)]: "a",
  [cp(0x1d401)]: "b",
};
const FOLD_MAP = { ...CYR_TO_ASCII, ...ASTRAL_TO_ASCII };

/**
 * A deterministic confusable scanner: emits one finding per code point that
 * appears in FOLD_MAP, with its UTF-16 offset, the matched glyph, and its ASCII
 * canon. Iterates by code point so astral chars report their leading-unit
 * offset and full 2-unit `char`.
 */
function makeScan(map = FOLD_MAP) {
  return (text) => {
    const findings = [];
    let index = 0;
    for (const ch of text) {
      if (Object.prototype.hasOwnProperty.call(map, ch))
        findings.push({ index, char: ch, latinEquivalent: map[ch] });
      index += ch.length; // 2 for astral, 1 otherwise
    }
    return { findings };
  };
}

const scan = makeScan();

// ─── hasNonAscii ─────────────────────────────────────────────────────────────

describe("hasNonAscii", () => {
  for (const [name, value, expected] of [
    ["false for empty string", "", false],
    ["false for plain ASCII", "/etc/passwd", false],
    ["false for ASCII controls (tab/newline)", "a\tb\nc", false],
    ["true for a Cyrillic letter", `/${CYR_A}`, true],
    ["true for an astral char (surrogate >= 0xD800)", cp(0x1f389), true],
    ["true at the boundary U+0080", cp(0x80), true],
    ["false at the boundary U+007F", cp(0x7f), false],
  ]) {
    it(name, () => assert.equal(hasNonAscii(value), expected));
  }
});

// ─── normalizeContext ────────────────────────────────────────────────────────

describe("normalizeContext", () => {
  it("names every normalized field in the context line", () => {
    assert.match(
      normalizeContext(["file_path", "command"]),
      /^Confusable characters normalized in: file_path, command\./,
    );
  });
  it("mentions the on-disk-name caveat", () => {
    assert.match(normalizeContext(["file_path"]), /fails to resolve/);
  });
});

// ─── foldConfusables ─────────────────────────────────────────────────────────

describe("foldConfusables", () => {
  it("returns the input unchanged when there are no findings", () => {
    assert.equal(foldConfusables("/etc/passwd", []), "/etc/passwd");
  });

  it("folds a single isolated confusable (no ASCII anchor)", () => {
    const text = `/${CYR_A}`;
    assert.equal(foldConfusables(text, scan(text).findings), "/a");
  });

  it("folds multiple confusables in one field", () => {
    const text = `/${CYR_O}${CYR_A}`;
    assert.equal(foldConfusables(text, scan(text).findings), "/oa");
  });

  it("splices highest-index-first so length-changing astral folds stay aligned", () => {
    // Two adjacent astral confusables; a left-to-right fold would shift the
    // second finding's offset and corrupt the output.
    const text = `${cp(0x1d400)}${cp(0x1d401)}`;
    assert.equal(foldConfusables(text, scan(text).findings), "ab");
  });

  it("does not require findings to be pre-sorted", () => {
    const text = `${CYR_A}${CYR_O}`; // offsets 0 and 1
    // Pass findings in reverse order; the internal sort must still produce "ao".
    const findings = [
      { index: 1, char: CYR_O, latinEquivalent: "o" },
      { index: 0, char: CYR_A, latinEquivalent: "a" },
    ];
    assert.equal(foldConfusables(text, findings), "ao");
  });

  it("throws when a finding's char does not match the bytes at its index", () => {
    // Adversarial scanner: claims a 2-char glyph "аа" at index 1 of "/xyz".
    // Splicing blindly would corrupt to "/Zz"; the guard must fail loud instead.
    assert.throws(
      () =>
        foldConfusables("/xyz", [
          { index: 1, char: `${CYR_A}${CYR_A}`, latinEquivalent: "Z" },
        ]),
      /does not match input at index 1/,
    );
  });

  it("does not throw when a correct finding matches the bytes at its index", () => {
    assert.equal(
      foldConfusables(`/${CYR_A}`, [
        { index: 1, char: CYR_A, latinEquivalent: "a" },
      ]),
      "/a",
    );
  });

  it("throws on a negative index instead of silently corrupting the text", () => {
    // startsWith(char, -1) clamps to 0 and returns true when `char` is a prefix,
    // so without the explicit range check this used to splice to "abxabc".
    assert.throws(
      () =>
        foldConfusables("abc", [
          { index: -1, char: "a", latinEquivalent: "x" },
        ]),
      /out-of-range index -1/,
    );
  });

  it("throws on a non-integer index", () => {
    assert.throws(
      () =>
        foldConfusables("abc", [
          { index: 1.5, char: "b", latinEquivalent: "x" },
        ]),
      /out-of-range index 1\.5/,
    );
  });

  it("throws when latinEquivalent is non-ASCII (fold would stay a confusable)", () => {
    // Adversarial scanner: "fold" Cyrillic а to Cyrillic е — still a homoglyph,
    // so the cross-script deny-rule bypass would survive. Must fail loud.
    const CYR_E = "е";
    assert.throws(
      () =>
        foldConfusables(`/${CYR_A}b`, [
          { index: 1, char: CYR_A, latinEquivalent: CYR_E },
        ]),
      /is not ASCII/,
    );
  });

  it("throws when latinEquivalent is empty (would silently delete the glyph)", () => {
    // An empty canon slips past the ASCII loop (never iterates) and would splice
    // the glyph to nothing: foldConfusables("/аb", …) → "/b". Must fail loud,
    // matching the non-ASCII guard, rather than delete a path/command character.
    assert.throws(
      () =>
        foldConfusables(`/${CYR_A}b`, [
          { index: 1, char: CYR_A, latinEquivalent: "" },
        ]),
      /empty latinEquivalent/,
    );
  });

  it("throws when char is empty (would insert without consuming and then crash)", () => {
    // An empty char makes startsWith("", i) vacuously true for any index, so the
    // splice inserts latinEquivalent without consuming a glyph (silent
    // insertion-corruption) and describeFolds later crashes on "".codePointAt(0).
    // Must fail loud, matching the other finding-shape guards.
    assert.throws(
      () =>
        foldConfusables(`/${CYR_A}b`, [
          { index: 1, char: "", latinEquivalent: "a" },
        ]),
      /empty char/,
    );
  });

  it("throws when char is ASCII (not a confusable the gate can reason about)", () => {
    // The contract says `char` is the matched look-alike GLYPH. An ASCII char is
    // already its own canon, and the fold gate decides a token's fate by which
    // of its non-ASCII code points are flagged — a finding naming an ASCII
    // character is uninterpretable there, so refuse it rather than guess.
    assert.throws(
      () =>
        foldConfusables(`/${CYR_A}b`, [
          { index: 2, char: "b", latinEquivalent: "b" },
        ]),
      /names an ASCII char/,
    );
  });

  it("allows a multi-character ASCII canon (e.g. a ligature fold)", () => {
    // Precision: a legitimate one-to-many ASCII fold (½ → 1/2, œ → oe) must NOT
    // be rejected by the ASCII guard — only non-ASCII replacements are refused.
    assert.equal(
      foldConfusables("½ x", [{ index: 0, char: "½", latinEquivalent: "1/2" }]),
      "1/2 x",
    );
  });
});

// ─── normalizeConfusables: folding positive cases ────────────────────────────

describe("normalizeConfusables: folding", () => {
  for (const [name, tool, input, field, expected] of [
    [
      "normalizes Cyrillic in file_path",
      "Read",
      { file_path: `/etc/p${CYR_A}sswd` },
      "file_path",
      "/etc/passwd",
    ],
    [
      "normalizes a lone confusable anchored by an ASCII letter",
      "Read",
      { file_path: `/${CYR_A}b` },
      "file_path",
      "/ab",
    ],
    [
      "normalizes an all-confusable token with no ASCII anchor",
      "Read",
      { file_path: `/${CYR_O}${CYR_A}` },
      "file_path",
      "/oa",
    ],
    [
      "normalizes Cyrillic in Bash command",
      "Bash",
      { command: `c${CYR_A}t /tmp/x` },
      "command",
      "cat /tmp/x",
    ],
    [
      "normalizes Cyrillic in MultiEdit file_path",
      "MultiEdit",
      {
        file_path: `/etc/p${CYR_A}sswd`,
        edits: [{ old_string: "a", new_string: "b" }],
      },
      "file_path",
      "/etc/passwd",
    ],
  ]) {
    it(name, () => {
      const result = normalizeConfusables(tool, input, { scan });
      assert.equal(result.updatedInput[field], expected);
      assert.match(
        normalizeContext(result.normalized),
        /Confusable.*normalized/,
      );
    });
  }

  // The read/search/list tools must be covered: a Cyrillic homoglyph in a
  // Grep/Glob pattern is exactly the CVE-2025-54794 cross-script deny-rule
  // bypass this module exists to close. Pin the required (tool → fields) set so
  // dropping any of them from DEFAULT_FIELDS fails here, not silently.
  for (const [tool, expectedFields] of [
    ["Grep", ["pattern", "path"]],
    ["Glob", ["pattern", "path"]],
    ["Read", ["file_path"]],
    ["LS", ["path"]],
  ]) {
    it(`covers ${tool} with fields ${expectedFields.join(", ")}`, () => {
      assert.deepEqual(DEFAULT_FIELDS[tool], expectedFields);
    });
  }

  // SSOT-driven: every field of every tool in DEFAULT_FIELDS must be folded.
  // Iterating per (tool, field) means adding a tool/field without a test is
  // impossible — the loop generates a case for it automatically.
  for (const [tool, fieldList] of Object.entries(DEFAULT_FIELDS)) {
    for (const key of fieldList) {
      it(`folds the ${key} field of ${tool}`, () => {
        const result = normalizeConfusables(
          tool,
          { [key]: `/p${CYR_A}th` },
          { scan },
        );
        assert.deepEqual(result, {
          updatedInput: { [key]: "/path" },
          normalized: [`${key} (U+0430 → "a")`],
        });
      });
    }
  }

  it("names each fold (code point → ASCII) so a broken legit path is explainable", () => {
    const result = normalizeConfusables(
      "Read",
      { file_path: `/etc/p${CYR_A}sswd` },
      { scan },
    );
    assert.deepEqual(result.normalized, ['file_path (U+0430 → "a")']);
  });

  it("folds only mapped fields, leaving siblings untouched", () => {
    const result = normalizeConfusables(
      "Edit",
      { file_path: `/${CYR_A}b`, old_string: CYR_A },
      { scan },
    );
    assert.deepEqual(result, {
      updatedInput: { file_path: "/ab", old_string: CYR_A },
      normalized: ['file_path (U+0430 → "a")'],
    });
  });

  it("folds length-changing astral confusables in offset order", () => {
    const result = normalizeConfusables(
      "Read",
      { file_path: `${cp(0x1d400)}${cp(0x1d401)}` },
      { scan },
    );
    assert.deepEqual(result, {
      updatedInput: { file_path: "ab" },
      normalized: ['file_path (U+1D400 → "a", U+1D401 → "b")'],
    });
  });

  it("caps the reported fold list at 8 with a trailing ellipsis on a glyph-stuffed input", () => {
    // 10 distinct Cyrillic confusables: more than MAX_REPORTED_FOLDS (8).
    const glyphs = [
      0x0430, 0x043e, 0x0435, 0x0440, 0x0441, 0x0445, 0x0443, 0x0456, 0x0455,
      0x0458,
    ]
      .map(cp)
      .join("");
    const result = normalizeConfusables(
      "Bash",
      { command: `echo ${glyphs}` },
      { scan },
    );
    const note = result.normalized[0];
    assert.match(note, /, …\)$/);
    // Exactly 8 folds shown before the ellipsis.
    assert.equal((note.match(/U\+/g) || []).length, 8);
  });

  it("dedups identical folds in the report (same glyph repeated)", () => {
    // Three Cyrillic а in a row: one unique fold entry, all three replaced.
    const result = normalizeConfusables(
      "Bash",
      { command: `${CYR_A}${CYR_A}${CYR_A}` },
      { scan },
    );
    assert.deepEqual(result, {
      updatedInput: { command: "aaa" },
      normalized: ['command (U+0430 → "a")'],
    });
  });

  it("normalizes multiple mapped fields independently when a custom fields map covers more than one", () => {
    const fields = { Tool: ["a", "b"] };
    const result = normalizeConfusables(
      "Tool",
      { a: `/${CYR_A}x`, b: `/${CYR_O}x` },
      { scan, fields },
    );
    assert.deepEqual(result, {
      updatedInput: { a: "/ax", b: "/ox" },
      normalized: ['a (U+0430 → "a")', 'b (U+043E → "o")'],
    });
  });
});

// ─── selectFoldableFindings: the per-token precision gate ───────────────────

// Real words spelled with the fake scanner's mapped glyphs where they belong.
// Written as escapes because the whole point is which code points they carry;
// the comment gives the readable form.
const PRIVET = `П${cp(0x0440)}ив${cp(0x0435)}т`; // Привет — р/е mapped, П/и/в/т not
const PAROL = `п${cp(0x0430)}${cp(0x0440)}${cp(0x043e)}ль`; // пароль — а/р/о mapped

describe("selectFoldableFindings", () => {
  it("keeps every finding when the token folds to pure ASCII", () => {
    const text = `/etc/p${CYR_A}sswd`;
    assert.deepEqual(
      selectFoldableFindings(text, scan(text).findings),
      scan(text).findings,
    );
  });

  it("drops findings in a token that keeps an unmapped non-ASCII glyph", () => {
    // Non-vacuity: the scanner DOES flag glyphs here (р and е of Привет) — the
    // gate is what rejects them, not an empty scan.
    assert.equal(scan(PRIVET).findings.length, 2);
    assert.deepEqual(selectFoldableFindings(PRIVET, scan(PRIVET).findings), []);
  });

  it("judges each token independently within one field", () => {
    const text = `/etc/p${CYR_A}sswd ${PRIVET}`;
    const kept = selectFoldableFindings(text, scan(text).findings);
    // Three flagged glyphs: the path's а, and Привет's р and е.
    assert.equal(scan(text).findings.length, 3);
    assert.deepEqual(kept, [{ index: 6, char: CYR_A, latinEquivalent: "a" }]);
  });

  it("still validates every finding before judging it (fails loud, not silent)", () => {
    // A bogus finding inside a token the gate would REJECT must still throw:
    // dropping it quietly would let an adversarial scanner hide behind prose.
    assert.throws(
      () =>
        selectFoldableFindings(PRIVET, [
          { index: 0, char: CYR_A, latinEquivalent: "a" },
        ]),
      /does not match input at index 0/,
    );
  });

  it("returns an empty list for no findings", () => {
    assert.deepEqual(selectFoldableFindings("/etc/passwd", []), []);
  });

  it("counts every offset a multi-code-point match covers as flagged", () => {
    // A scanner may report one finding spanning several code points. Only its
    // START offset being treated as flagged would leave the rest looking
    // unmapped, and the gate would reject a token that does fold to ASCII.
    const text = `${CYR_A}${CYR_O}`;
    const finding = {
      index: 0,
      char: `${CYR_A}${CYR_O}`,
      latinEquivalent: "ao",
    };
    assert.deepEqual(selectFoldableFindings(text, [finding]), [finding]);
  });
});

// ─── normalizeConfusables: precision on genuine non-Latin text ───────────────

describe("normalizeConfusables: non-Latin prose precision", () => {
  for (const [name, tool, input] of [
    [
      "leaves Cyrillic prose in a Bash command alone",
      "Bash",
      { command: `gh issue create --body "${PRIVET} ми${cp(0x0440)}"` },
    ],
    [
      "leaves a Cyrillic filename alone",
      "Read",
      { file_path: `/home/user/${PAROL}.txt` },
    ],
    [
      "leaves a Cyrillic Grep pattern alone",
      "Grep",
      { pattern: PRIVET, path: "/tmp" },
    ],
    // The one-letter prepositions/conjunctions — "с" (with), "о" (about), "у"
    // (at), "а" (and/but) — are among the most frequent words in Russian, and
    // every one of them is a mapped confusable standing alone as its own token.
    // Only the lone-glyph rule keeps these whole; without it the motivating bug
    // survives at the level of ordinary sentences.
    [
      "leaves a one-letter Cyrillic preposition alone",
      "Bash",
      { command: `git commit -m "р${cp(0x0430)}бота ${cp(0x0441)} файлом"` },
    ],
  ]) {
    it(name, () => {
      // Non-vacuity: the scanner flags glyphs in every one of these — null comes
      // from the gate, not from an input the engine never looked at.
      const field = Object.values(input).find((v) => scan(v).findings.length);
      assert.ok(field, "no field carries a flagged glyph — test is vacuous");
      assert.equal(normalizeConfusables(tool, input, { scan }), null);
    });
  }

  it("folds a disguised path while leaving prose in the same command verbatim", () => {
    const result = normalizeConfusables(
      "Bash",
      { command: `cat /etc/p${CYR_A}sswd # ${PRIVET}` },
      { scan },
    );
    assert.deepEqual(result, {
      updatedInput: { command: `cat /etc/passwd # ${PRIVET}` },
      normalized: ['command (U+0430 → "a")'],
    });
  });

  it("folds an all-confusable disguised word (no unmapped glyph to stop it)", () => {
    // The homoglyph attack with no ASCII anchor at all: every glyph maps, so the
    // token folds to ASCII and the deny-rule bypass is closed.
    const disguised = `${cp(0x0440)}${cp(0x0430)}${cp(0x0455)}${cp(0x0455)}wd`;
    const result = normalizeConfusables(
      "Bash",
      { command: `cat ${disguised}` },
      { scan },
    );
    assert.equal(result.updatedInput.command, "cat passwd");
  });

  it("declines a disguised token carrying an unmapped suppressor glyph", () => {
    // The gate is a two-way trade, and this is the side that costs recall: an
    // attacker who splices ONE glyph the engine does not map into an otherwise
    // all-confusable token turns the fold off. Pinned so the cost is visible
    // rather than discovered. It buys nothing on its own — the unmapped glyph
    // is still in the field, so the token cannot match an ASCII deny rule
    // either; a filter reading the raw field is what closes this, not folding.
    const suppressed = `p${CYR_A}sswd${cp(0x4e2d)}`; // 中 — non-ASCII, unmapped
    assert.equal(
      normalizeConfusables("Bash", { command: `cat /${suppressed}` }, { scan }),
      null,
    );
  });

  it("still folds a multi-letter all-confusable foreign word (accepted residual)", () => {
    // "со" (Russian "with") is two glyphs, both mapped, so it is byte-for-byte
    // indistinguishable from a disguised ASCII "co" and folds. This is the
    // documented residual in THREAT-MODEL.md — asserted so a future change to
    // the gate has to confront it deliberately instead of silently shifting it.
    const so = `${cp(0x0441)}${cp(0x043e)}`; // со
    const result = normalizeConfusables(
      "Bash",
      { command: `git commit -m "${so} мной"` },
      { scan },
    );
    assert.equal(result.updatedInput.command, 'git commit -m "co мной"');
  });

  it("reports only the folds applied, not the glyphs merely scanned", () => {
    // The rejected token's glyphs are still in the field the model sees, so
    // naming them in the context line would be a lie.
    const result = normalizeConfusables(
      "Bash",
      { command: `cat /${CYR_O}pt # ${PAROL}` },
      { scan },
    );
    assert.deepEqual(result.normalized, ['command (U+043E → "o")']);
  });
});

// ─── normalizeConfusables: null / no-op cases ────────────────────────────────

describe("normalizeConfusables: null cases", () => {
  it("ASCII fast-path returns null WITHOUT calling scan", () => {
    let called = false;
    const spyScan = (text) => {
      called = true;
      return scan(text);
    };
    assert.equal(
      normalizeConfusables("Bash", { command: "ls -la" }, { scan: spyScan }),
      null,
    );
    assert.equal(called, false);
  });

  it("passes benign non-ASCII (scan flags nothing) and returns null", () => {
    // An astral emoji reaches the engine (non-ASCII) but is not a confusable.
    const result = normalizeConfusables(
      "Bash",
      { command: `echo ${cp(0x1f389)}` },
      { scan },
    );
    assert.equal(result, null);
  });

  it("returns null for an unknown tool even with a confusable", () => {
    assert.equal(
      normalizeConfusables("WebSearch", { query: `c${CYR_A}t` }, { scan }),
      null,
    );
  });

  // An MCP tool name is attacker/third-party influenced. `fields` (typically
  // DEFAULT_FIELDS) is a plain object literal, so a tool literally named
  // "constructor" etc. resolves through Object.prototype to a truthy builtin
  // function — without an own-property guard, `keys.filter(...)` a few lines
  // later throws `keys.filter is not a function` instead of returning null
  // like any other unrecognized tool name.
  for (const tool of ["constructor", "toString", "hasOwnProperty", "__proto__"])
    it(`returns null (does not throw) for the Object.prototype-named tool "${tool}"`, () => {
      assert.equal(
        normalizeConfusables(tool, { command: `c${CYR_A}t` }, { scan }),
        null,
      );
    });

  for (const [name, toolInput] of [
    ["null toolInput", null],
    ["undefined toolInput", undefined],
  ]) {
    it(`returns null for ${name}`, () => {
      assert.equal(normalizeConfusables("Bash", toolInput, { scan }), null);
    });
  }

  it("skips a non-string field value (command: null)", () => {
    assert.equal(
      normalizeConfusables("Bash", { command: null }, { scan }),
      null,
    );
  });

  it("returns null when the mapped field is absent", () => {
    assert.equal(
      normalizeConfusables("Read", { unrelated: CYR_A }, { scan }),
      null,
    );
  });

  it("returns null when the mapped field is all-ASCII", () => {
    assert.equal(
      normalizeConfusables("Read", { file_path: "/etc/passwd" }, { scan }),
      null,
    );
  });

  it("skips Write content (only file_path is mapped)", () => {
    assert.equal(
      normalizeConfusables(
        "Write",
        { file_path: "/tmp/x", content: `text${CYR_A}` },
        { scan },
      ),
      null,
    );
  });

  it("skips Edit old/new_string (only file_path is mapped)", () => {
    assert.equal(
      normalizeConfusables(
        "Edit",
        { file_path: "/tmp/x", old_string: "a", new_string: `${CYR_A}` },
        { scan },
      ),
      null,
    );
  });

  it("returns null when a non-ASCII candidate field has no findings", () => {
    // A field reaches scan (non-ASCII) but the injected scanner flags nothing,
    // exercising the `findings.length === 0 → continue` then final null path.
    const emptyScan = () => ({ findings: [] });
    assert.equal(
      normalizeConfusables("Read", { file_path: `/café` }, { scan: emptyScan }),
      null,
    );
  });

  it("uses DEFAULT_FIELDS when no fields map is passed", () => {
    const result = normalizeConfusables(
      "Read",
      { file_path: `/${CYR_A}x` },
      { scan },
    );
    assert.deepEqual(result, {
      updatedInput: { file_path: "/ax" },
      normalized: ['file_path (U+0430 → "a")'],
    });
  });
});

// ─── The default engine ──────────────────────────────────────────────────────
// Every test above injects a fake `scan`, which is what makes them independent
// of any real map — and is also how a caller who FORGOT to wire an engine used
// to get silent zero coverage. These drive the shipped default instead.

describe("the scanner defaults to namespace-guard when none is injected", () => {
  it("folds a disguised command with no options argument at all", () => {
    assert.deepEqual(
      normalizeConfusables("Bash", {
        command: `${cp(0x0441)}at /etc/p${CYR_A}sswd`,
      }),
      {
        updatedInput: { command: "cat /etc/passwd" },
        normalized: ['command (U+0441 → "c", U+0430 → "a")'],
      },
    );
  });

  it("leaves genuine Cyrillic prose alone under the default engine too", () => {
    assert.equal(
      normalizeConfusables("Bash", { command: "echo Привет мир" }),
      null,
    );
  });

  it("an injected scan still overrides the default", () => {
    // The default engine WOULD fold this; the injected one finds nothing, so a
    // null result proves the override reached the fold rather than the default.
    assert.equal(
      normalizeConfusables(
        "Bash",
        { command: `${cp(0x0441)}at /etc/p${CYR_A}sswd` },
        { scan: () => ({ findings: [] }) },
      ),
      null,
    );
  });
});

// ─── Declared tool scope ─────────────────────────────────────────────────────
// The fold's TOOL SCOPE is a declared partition, not a silent fallthrough.
// Returning null is the right BEHAVIOUR for a tool with no path or command
// field, but "no field to fold" and "nobody has looked at this tool" used to be
// the same line of code, so an unlisted tool left no record that a decision had
// been made. Mirrors test/claude-hooks-authored-scope.test.mjs, over the same
// live tool surface.

describe("the fold's tool scope is a declared partition", () => {
  it("every tool is covered or exempt, never both, never neither", () => {
    const unclassified = [];
    const doubleClassified = [];
    for (const tool of liveToolSurface()) {
      const covered = Object.hasOwn(DEFAULT_FIELDS, tool);
      const exempt = scopeFor(tool).kind === "exempt";
      if (!covered && !exempt) unclassified.push(tool);
      if (covered && exempt) doubleClassified.push(tool);
    }
    assert.deepEqual(
      unclassified,
      [],
      "tools the fold has taken no position on — add a field list to " +
        "DEFAULT_FIELDS or an entry (with a reason) to EXEMPT_TOOLS / " +
        "EXEMPT_TOOL_PATTERNS",
    );
    assert.deepEqual(doubleClassified, []);
  });

  it("every exemption states a reason", () => {
    const entries = Object.entries(EXEMPT_TOOLS);
    assert.ok(entries.length > 0, "EXEMPT_TOOLS is empty — partition vacuous");
    for (const [tool, reason] of entries)
      assert.ok(
        typeof reason === "string" && reason.length > 20,
        `EXEMPT_TOOLS.${tool} carries no usable rationale`,
      );
    assert.ok(EXEMPT_TOOL_PATTERNS.length > 0, "EXEMPT_TOOL_PATTERNS is empty");
    for (const { pattern, reason } of EXEMPT_TOOL_PATTERNS)
      assert.ok(
        pattern instanceof RegExp &&
          typeof reason === "string" &&
          reason.length > 20,
        `EXEMPT_TOOL_PATTERNS entry for ${pattern} carries no usable rationale`,
      );
  });

  it("positive marker: every covered tool folds a disguise in every declared field", () => {
    const tools = Object.entries(DEFAULT_FIELDS);
    assert.ok(tools.length > 0, "DEFAULT_FIELDS is empty — markers vacuous");
    for (const [tool, fields] of tools) {
      assert.ok(fields.length > 0, `${tool} declares no fields`);
      for (const field of fields) {
        const result = normalizeConfusables(
          tool,
          { [field]: `p${CYR_A}sswd` },
          { scan },
        );
        assert.ok(result, `${tool}.${field} left a disguise in place`);
        assert.equal(result.updatedInput[field], "passwd");
      }
    }
  });

  it("negative marker: an exempt tool is a real pass-through, not a claim", () => {
    // Every field name any covered tool declares, so the pass-through is proven
    // against the shapes the fold knows how to rewrite — not an empty input.
    const everyField = {};
    for (const fields of Object.values(DEFAULT_FIELDS))
      everyField[fields[0]] = `p${CYR_A}sswd`;
    for (const tool of [
      ...Object.keys(EXEMPT_TOOLS),
      "mcp__github__create_issue",
    ]) {
      assert.equal(scopeFor(tool).kind, "exempt", tool);
      assert.equal(
        normalizeConfusables(tool, everyField, { scan }),
        null,
        tool,
      );
    }
  });

  it("a tool on neither side is undeclared, not silently covered", () => {
    assert.deepEqual(scopeFor("TodoWrite"), { kind: "undeclared" });
    assert.equal(
      normalizeConfusables("TodoWrite", { path: `p${CYR_A}` }),
      null,
    );
  });

  it("an inherited Object.prototype key is undeclared, not a field list", () => {
    // `tool` comes from an untrusted payload, so every lookup in scopeFor is an
    // Object.hasOwn: `DEFAULT_FIELDS.constructor` is a truthy function a plain
    // `in`/index check would hand to the field loop as if it were a field list.
    for (const key of ["constructor", "toString", "__proto__", "valueOf"])
      assert.deepEqual(scopeFor(key), { kind: "undeclared" }, key);
    assert.equal(
      normalizeConfusables("constructor", { path: `p${CYR_A}` }),
      null,
    );
  });
});
