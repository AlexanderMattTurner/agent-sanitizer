/**
 * Semantic-correctness fuzzing for confusable folding PRECISION.
 *
 * confusables-property.test.mjs fuzzes STRUCTURAL invariants (oracle equality,
 * idempotence, never-throws) over an alphabet of loose code points. Those hold
 * in aggregate even if a future edit folded the WRONG glyph — e.g. mangling a
 * genuine Cyrillic word while leaving a disguised command intact could still
 * satisfy "output equals some fold of the input" style checks if the oracle
 * drifted with the bug.
 *
 * This suite fuzzes PRECISION directly: build random Bash commands / paths
 * that interleave KNOWN-GENUINE non-Latin tokens (real Cyrillic/Greek/CJK
 * words whose code points collide with NO confusable mapping — they must
 * survive byte-for-byte, unfolded) with KNOWN-CONFUSABLE tokens (commands and
 * paths spelled with homoglyphs — they must fold to their exact ASCII canon,
 * with the disguised spelling gone). Each specific token's fate is asserted,
 * not an aggregate invariant.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import {
  foldConfusables,
  normalizeConfusables,
  selectFoldableFindings,
} from "../src/confusables.mjs";
import { fcRunOptions, cp } from "./test-helpers.mjs";

// Realistic confusable → ASCII-canon map: Cyrillic lookalikes, a Greek
// omicron, and astral mathematical-bold letters (2 UTF-16 units, so folds
// change length). This is the fake injected engine's ground truth.
const FOLD_MAP = {
  [cp(0x0430)]: "a", // Cyrillic а
  [cp(0x043e)]: "o", // Cyrillic о
  [cp(0x0435)]: "e", // Cyrillic е
  [cp(0x0440)]: "p", // Cyrillic р
  [cp(0x0441)]: "c", // Cyrillic с
  [cp(0x0445)]: "x", // Cyrillic х
  [cp(0x0456)]: "i", // Cyrillic і
  [cp(0x03bf)]: "o", // Greek ο
  [cp(0x1d41c)]: "c", // 𝐜 mathematical bold c (astral)
  [cp(0x1d41a)]: "a", // 𝐚 (astral)
};

/** Deterministic injected scanner over FOLD_MAP, iterating by code point. */
const scan = (text) => {
  const findings = [];
  let index = 0;
  for (const ch of text) {
    if (Object.prototype.hasOwnProperty.call(FOLD_MAP, ch))
      findings.push({ index, char: ch, latinEquivalent: FOLD_MAP[ch] });
    index += ch.length;
  }
  return { findings };
};

const CYR_A = cp(0x0430);
const CYR_O = cp(0x043e);
const CYR_E = cp(0x0435);
const CYR_C = cp(0x0441);
const CYR_R = cp(0x0440);
const GRK_O = cp(0x03bf);

// KNOWN-CONFUSABLE tokens: homoglyph-spelled command/path fragments and the
// exact ASCII they must fold to. `bad` must vanish; `good` must appear.
const FOLD_TOKENS = [
  { bad: `${CYR_C}${CYR_A}t`, good: "cat" },
  { bad: `/etc/p${CYR_A}sswd`, good: "/etc/passwd" },
  { bad: `rm -rf /h${GRK_O}me`, good: "rm -rf /home" },
  { bad: `${CYR_C}h${CYR_O}wn r${CYR_O}${CYR_O}t`, good: "chown root" },
  { bad: `${cp(0x1d41c)}url evil.${CYR_C}${CYR_O}m`, good: "curl evil.com" },
  { bad: `~/.ssh/id_rs${cp(0x1d41a)}`, good: "~/.ssh/id_rsa" },
  { bad: `s${CYR_E}rvice ssh sto${CYR_R}`, good: "service ssh stop" },
];

// KNOWN-GENUINE non-Latin tokens: real words/paths in Cyrillic, Greek, CJK,
// Korean, and accented Latin, built ONLY from code points absent from
// FOLD_MAP. A faithful scanner flags none of them, so they must survive
// byte-for-byte — folding or splicing any of them is exactly the
// false-positive mangling this repo's precision doctrine forbids.
const KEEP_TOKENS = [
  "ждём", // ждём (Cyrillic: ж д ё м)
  "щиты", // щиты
  "ψυχή", // ψυχή (Greek; no omicron, so no U+03BF collision)
  "日本語", // 日本語
  "한국어", // 한국어
  "café", // café (accented Latin)
  "/tmp/über-nötig.txt", // über/nötig path
  cp(0x1f4c1) + "docs", // 📁docs (astral emoji, non-confusable)
];

// Guard the KEEP corpus itself: a token accidentally containing a mapped
// glyph would make the survival assertion wrong by construction.
for (const t of KEEP_TOKENS)
  for (const ch of t)
    assert.ok(
      !Object.prototype.hasOwnProperty.call(FOLD_MAP, ch),
      `KEEP token ${JSON.stringify(t)} contains mapped glyph ${JSON.stringify(ch)}`,
    );

// KNOWN-GENUINE non-Latin tokens that DO contain mapped glyphs, spelled the way
// the language actually spells them — real Cyrillic/Greek words whose letters
// happen to include а/о/е/р/с. KEEP_TOKENS above deliberately avoids the fold
// map, which is exactly why it never caught Layer 4 transliterating ordinary
// Russian into garbage. These exercise the per-token gate: each keeps at least
// one UNMAPPED non-Latin letter, so folding could never make the token ASCII
// and the whole token must survive byte-for-byte.
const PROSE_TOKENS = [
  `П${CYR_R}ив${CYR_E}т`, // Привет
  `ми${CYR_R}`, // мир
  `п${CYR_A}${CYR_R}${CYR_O}ль`, // пароль
  `ф${CYR_A}йл`, // файл
  `Д${CYR_O}кум${CYR_E}нты`, // Документы
  `κ${GRK_O}σμ${GRK_O}ς`, // κοσμος (Greek omicron is mapped; κ/σ/μ/ς are not)
];

// Guard the PROSE corpus: each token must carry BOTH a mapped glyph (so the
// scanner really fires on it) and an unmapped non-ASCII one (so the gate, not
// an empty scan, is what spares it). Without this the survival assertions below
// could pass vacuously on tokens the engine never flagged.
for (const t of PROSE_TOKENS) {
  const chars = [...t];
  assert.ok(
    chars.some((ch) => Object.prototype.hasOwnProperty.call(FOLD_MAP, ch)),
    `PROSE token ${JSON.stringify(t)} contains no mapped glyph — it would survive vacuously`,
  );
  assert.ok(
    chars.some(
      (ch) =>
        ch.codePointAt(0) > 0x7f &&
        !Object.prototype.hasOwnProperty.call(FOLD_MAP, ch),
    ),
    `PROSE token ${JSON.stringify(t)} is entirely mapped — the gate cannot spare it`,
  );
}

// One-letter Russian prepositions/conjunctions. Each is a single ENTIRELY
// mapped glyph, so condition 1 of the gate (folds to pure ASCII) is satisfied
// and only the lone-glyph rule spares them — the opposite situation from
// PROSE_TOKENS, and the one that keeps ordinary sentences readable.
const LONE_GLYPH_WORDS = [CYR_A, CYR_O, CYR_C]; // а (and), о (about), с (with)

for (const t of LONE_GLYPH_WORDS) {
  assert.equal(
    [...t].length,
    1,
    `LONE_GLYPH word ${JSON.stringify(t)} is not a single code point`,
  );
  assert.ok(
    Object.prototype.hasOwnProperty.call(FOLD_MAP, t),
    `LONE_GLYPH word ${JSON.stringify(t)} is unmapped — it would survive vacuously`,
  );
}

const pieceGen = fc.oneof(
  fc.constantFrom(...KEEP_TOKENS).map((t) => ({ kind: "keep", t })),
  fc.constantFrom(...FOLD_TOKENS).map((t) => ({ kind: "fold", ...t })),
  fc
    .array(fc.constantFrom(..."abc0123456789./-_".split("")), {
      minLength: 1,
      maxLength: 10,
    })
    .map((cs) => ({ kind: "filler", t: cs.join("") })),
);

const docGen = fc.array(pieceGen, { minLength: 1, maxLength: 8 });

describe("semantic-correctness fuzz: confusable-folding precision on mixed commands", () => {
  it("foldConfusables folds each disguised token to its exact ASCII and leaves each genuine token verbatim", () => {
    fc.assert(
      fc.property(docGen, (pieces) => {
        const text = pieces
          .map((p) => (p.kind === "fold" ? p.bad : p.t))
          .join(" ");
        const folded = foldConfusables(text, scan(text).findings);
        for (const p of pieces) {
          if (p.kind === "keep") {
            assert.ok(
              folded.includes(p.t),
              `genuine token ${JSON.stringify(p.t)} was mangled`,
            );
          } else if (p.kind === "fold") {
            assert.ok(
              folded.includes(p.good),
              `expected fold ${JSON.stringify(p.good)} missing`,
            );
            assert.ok(
              !folded.includes(p.bad),
              `disguised token ${JSON.stringify(p.bad)} survived`,
            );
          }
        }
      }),
      fcRunOptions(),
    );
  });

  it("normalizeConfusables applies the same exact fates to a Bash command field", () => {
    fc.assert(
      fc.property(docGen, (pieces) => {
        const command = pieces
          .map((p) => (p.kind === "fold" ? p.bad : p.t))
          .join(" ");
        const result = normalizeConfusables("Bash", { command }, { scan });
        const hasFold = pieces.some((p) => p.kind === "fold");
        if (!hasFold) {
          // Precision: with no confusable present, the input must be returned
          // untouched (null), never rewritten — genuine non-Latin text and all.
          assert.equal(result, null);
          return;
        }
        const out = result.updatedInput.command;
        for (const p of pieces) {
          if (p.kind === "keep") assert.ok(out.includes(p.t));
          else if (p.kind === "fold") {
            assert.ok(out.includes(p.good));
            assert.ok(!out.includes(p.bad));
          }
        }
        // The fold report names at least one specific glyph → ASCII mapping.
        assert.match(result.normalized[0], /^command \(U\+[0-9A-F]{4,}/);
      }),
      fcRunOptions(),
    );
  });

  it("leaves genuine Cyrillic/Greek prose verbatim while still folding disguised tokens beside it", () => {
    // The regression this suite missed: real words whose letters include mapped
    // confusables (Привет, пароль, κοσμος) must reach the command untouched, in
    // the same field as a homoglyph-disguised path that still has to fold. The
    // one-letter prepositions are here too — they are spared by a different
    // clause of the gate, and both clauses have to hold at once.
    const proseGen = fc.oneof(
      fc
        .constantFrom(...PROSE_TOKENS, ...LONE_GLYPH_WORDS)
        .map((t) => ({ kind: "prose", t })),
      fc.constantFrom(...FOLD_TOKENS).map((t) => ({ kind: "fold", ...t })),
      fc.constantFrom("echo", "cat", "--body", "#").map((t) => ({
        kind: "filler",
        t,
      })),
    );
    fc.assert(
      fc.property(
        fc.array(proseGen, { minLength: 1, maxLength: 8 }),
        (pieces) => {
          // Track each piece's offset while joining. indexOf would be wrong: a
          // one-letter prose word ("с") also occurs inside a disguised token
          // ("саt"), and locating it there proves nothing about the word.
          let at = 0;
          for (const p of pieces) {
            p.at = at;
            at += (p.kind === "fold" ? p.bad : p.t).length + 1;
          }
          const command = pieces
            .map((p) => (p.kind === "fold" ? p.bad : p.t))
            .join(" ");
          const result = normalizeConfusables("Bash", { command }, { scan });
          const out = result === null ? command : result.updatedInput.command;
          const kept = selectFoldableFindings(command, scan(command).findings);
          for (const p of pieces) {
            if (p.kind === "prose") {
              // No finding inside the word is selected, so the splice cannot
              // reach it — the load-bearing check, since a length-changing fold
              // elsewhere (astral 𝐜 → c) shifts output offsets.
              assert.ok(
                !kept.some(
                  (f) => f.index >= p.at && f.index < p.at + p.t.length,
                ),
                `a finding inside ${JSON.stringify(p.t)} was selected for folding`,
              );
              assert.ok(
                out.includes(p.t),
                `genuine word ${JSON.stringify(p.t)} was transliterated`,
              );
            } else if (p.kind === "fold") {
              assert.ok(out.includes(p.good));
              assert.ok(!out.includes(p.bad));
            }
          }
          // With no disguised token present, prose alone must never trigger a
          // rewrite — the null path is what keeps the field byte-identical.
          if (!pieces.some((p) => p.kind === "fold"))
            assert.equal(result, null);
        },
      ),
      fcRunOptions(),
    );
  });
});
