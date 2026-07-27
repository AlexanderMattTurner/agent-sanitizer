/**
 * Semantic-correctness fuzzing for Edit re-anchoring (rehydrate.mjs +
 * view-map.mjs).
 *
 * rehydrate-property.test.mjs fuzzes STRUCTURAL invariants (no mis-anchor,
 * round-trip, never-throws) over one fuzzed edit per generated file. Those
 * hold even if the layer denies edits it should have translated, or passes
 * through edits it should have rewritten — a precision failure the aggregate
 * invariants cannot see, because "deny" and "null" are always legal shapes.
 *
 * This suite fuzzes PRECISION directly: build random multi-line files that
 * interleave labeled constructs, then assert each construct's EXACT fate:
 *
 *   KEEP (must produce updatedInput anchored to exact disk bytes):
 *     - a redacted secret line edited via its placeholder,
 *     - a distinctly-placeholdered (typed) secret line,
 *     - a line with an interior zero-width char (hint-free re-anchor),
 *     - an ANSI-colored line (boundary run preserved, interior run replaced);
 *   PASS-THROUGH (must return null, never a rewrite or deny):
 *     - a plain line whose bytes match disk verbatim;
 *   DENY (must refuse with the specific documented reason, never guess):
 *     - an old_string cut mid-placeholder,
 *     - a new_string naming a secret outside the matched span,
 *     - two view-identical lines hiding distinct secrets (ambiguous anchor),
 *     - replace_all across those distinct-secret twins,
 *     - a greedy-alignment collision (ANSI final "m" abutting kept "m"s).
 *
 * The redactor is NOT re-implemented here. Each construct's model-visible view
 * is read back from the REAL Python engine (`agent_sanitizer.secrets`)
 * over a long-lived worker — the single source of truth — so a placeholder the
 * test edits against is exactly the one production redaction emits, never a
 * hand-rolled stand-in that could drift on detection or offsets. The fuzzing
 * varies the surrounding document (ordering, neighbors, count) to prove each
 * verdict is decided by the construct itself, not by fixture shape.
 *
 * Every scenario is grounded in a deterministic case from rehydrate.test.mjs.
 */
import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import { rehydrateRedacted } from "../src/rehydrate.mjs";
import { applyLayer1 } from "../src/layer1.mjs";
import { occurrences } from "../src/view-map.mjs";
import { fcRunOptions, cp } from "./test-helpers.mjs";
import {
  realRedactMap,
  realRedact,
  stopRealRedactor,
} from "./real-redactor.mjs";

const ZW = cp(0x200b);
const ESC = cp(0x1b);
const GREEN = `${ESC}[32m`;
const RESET = `${ESC}[0m`;

// Tear the shared redactor worker down once the file's tests finish.
after(stopRealRedactor);

// io backed by the real Python redactor — the single source of truth. rehydrate
// Layer-1-cleans `content` internally, then calls redactMap on the cleaned text.
const realIo = (content) => ({
  readFile: () => content,
  redactMap: (text) => realRedactMap(text),
  redact: (text) => realRedact(text),
});

/** The model-visible view of `content`: Layer 1 (JS) then the real redactor —
 * exactly what rehydrate sees when it calls the injected io on cleaned bytes. */
async function modelView(content) {
  const { cleaned } = applyLayer1(content);
  const view = await realRedactMap(cleaned);
  return view.text;
}

// Distinct, prefix-free secret values per piece. Assembled at runtime so no
// complete token literal trips push protection; the trailing "q" keeps values
// prefix-free across indices (…z1q vs …z12q).
const secretFor = (i) => ["hunter2hunter2", `hunter2z${i}q`].join("");
// High-entropy value that trips the keyword+entropy detector to a *typed*
// placeholder ([REDACTED: Secret Keyword]), distinct from the bare [REDACTED]
// a named field emits — so a document can carry two different placeholders.
const entropyFor = (i) => ["Zx91mKp4vNqR8", `tLw2sYb7cH${i}dFj3aUe`].join("");

/**
 * A labeled construct at document position `i`. Each returns the disk line(s)
 * it contributes; the model-visible view line(s) are read back from the real
 * engine at assert time. Index tags make every construct's view line unique.
 */
const PIECES = {
  // Named-field secret: the value after PASSWORD= redacts to a bare [REDACTED];
  // a placeholder edit must rehydrate to the real on-disk value.
  secret: (i) => ({ disk: [`L${i} PASSWORD=${secretFor(i)}`] }),
  // Keyword+entropy secret: redacts to a *typed* placeholder, so docs mixing
  // this with `secret` carry two distinct placeholder texts.
  typed: (i) => ({ disk: [`M${i} secret = "${entropyFor(i)}"`] }),
  // Interior zero-width char: hint-free edit must re-attach the stripped byte.
  zw: (i) => ({ disk: [`fn${i}(a${ZW}, b);`] }),
  // ANSI color: leading run is a boundary (preserved), reset is interior.
  ansi: (i) => ({
    disk: [`${GREEN}log${i}${RESET} ok`],
    diskAnchor: `log${i}${RESET} ok`, // leading GREEN stays outside the span
  }),
  // Plain line: bytes match disk verbatim, layer must not touch the edit.
  plain: (i) => ({ disk: [`plain line ${i} text`] }),
  // Greedy-alignment collision: the ANSI sequence's final "m" abuts kept "m"s,
  // so the deleted run's placement is ambiguous. Editing across it must be
  // denied, not anchored to a guessed run boundary.
  collide: (i) => ({ disk: [`C${i} m${GREEN}mm`] }),
  // Two view-identical lines hiding DISTINCT secrets: both named-field values
  // redact to the SAME [REDACTED], so any edit addressed by the shared view
  // text is ambiguous and must be denied, never guessed.
  dupPair: (i) => ({
    disk: [
      `DUP${i}=PASSWORD=${secretFor(i)}A`,
      `DUP${i}=PASSWORD=${secretFor(i)}B`,
    ],
  }),
};

const kindGen = fc.constantFrom(...Object.keys(PIECES));
const docGen = fc
  .array(kindGen, { minLength: 1, maxLength: 8 })
  .map((kinds) => {
    let cursor = 0;
    const pieces = kinds.map((kind, i) => {
      const spec = PIECES[kind](i);
      const piece = {
        kind,
        i,
        lineStart: cursor,
        nLines: spec.disk.length,
        ...spec,
      };
      cursor += spec.disk.length;
      return piece;
    });
    const diskLines = pieces.flatMap((p) => p.disk);
    const content = `${diskLines.join("\n")}\n`;
    return { pieces, content, diskLines };
  });

const editCall = (content, old_string, new_string, extra = {}) =>
  rehydrateRedacted(
    "Edit",
    { file_path: "/f", old_string, new_string, ...extra },
    realIo(content),
  );

/** Assert an exact translation: rewritten to precisely these disk bytes. */
function assertKeep(out, oldDisk, newDisk, label) {
  assert.ok(out && "updatedInput" in out, `${label}: expected a rewrite`);
  assert.equal(out.updatedInput.old_string, oldDisk, `${label}: old_string`);
  assert.equal(out.updatedInput.new_string, newDisk, `${label}: new_string`);
}

/** Assert a deny carrying the specific documented reason. */
function assertDeny(out, reason, label) {
  assert.ok(out && "deny" in out, `${label}: expected a deny`);
  assert.match(out.deny, reason, `${label}: deny reason`);
  assert.equal(out.updatedInput, undefined, `${label}: deny with rewrite`);
}

describe("semantic-correctness fuzz: rehydrate precision on mixed documents", () => {
  it("each construct's edit gets its exact verdict regardless of neighbors", async () => {
    await fc.assert(
      fc.asyncProperty(docGen, async (doc) => {
        // Read the whole document's view back from the real engine ONCE, then
        // address each construct's edit by the exact line(s) the engine emits.
        const viewLines = (await modelView(doc.content)).split("\n");
        // Layer 1 + redaction rewrite spans in place; neither adds nor drops
        // lines, so view lines map 1:1 to disk lines (+1 trailing empty).
        assert.equal(
          viewLines.length,
          doc.diskLines.length + 1,
          "view/disk line count diverged — positional mapping broke",
        );

        for (const p of doc.pieces) {
          const view = viewLines[p.lineStart];
          const disk = doc.diskLines[p.lineStart];

          if (p.kind === "secret" || p.kind === "typed") {
            // The engine must actually have redacted this line (precondition
            // for the placeholder-anchoring assertions below — never vacuous).
            assert.ok(
              view.includes("[REDACTED") && view !== disk,
              `${p.kind}#${p.i}: expected a redacted view, got ${JSON.stringify(view)}`,
            );
            // KEEP: placeholder edit rehydrates to the exact on-disk secret.
            assertKeep(
              await editCall(doc.content, view, `${view} # rotated`),
              disk,
              `${disk} # rotated`,
              `${p.kind}#${p.i} rotate`,
            );
            // KEEP: whole-line deletion anchors to the exact secret bytes.
            assertKeep(
              await editCall(doc.content, `${view}\n`, ""),
              `${disk}\n`,
              "",
              `${p.kind}#${p.i} delete`,
            );
            // DENY: an old_string cut mid-placeholder must never be guessed.
            const [prefix] = view.split("]");
            assertDeny(
              await editCall(doc.content, prefix, "x"),
              /include each placeholder whole/,
              `${p.kind}#${p.i} mid-placeholder`,
            );
          } else if (p.kind === "zw") {
            // KEEP: hint-free edit re-attaches the interior stripped byte.
            assertKeep(
              await editCall(doc.content, view, `fn${p.i}(a, b, c);`),
              disk,
              `fn${p.i}(a, b, c);`,
              `zw#${p.i}`,
            );
          } else if (p.kind === "ansi") {
            // KEEP: interior reset replaced with the span, leading run kept.
            assertKeep(
              await editCall(doc.content, view, `log${p.i} EDITED`),
              p.diskAnchor,
              `log${p.i} EDITED`,
              `ansi#${p.i}`,
            );
          } else if (p.kind === "collide") {
            // DENY: greedy alignment cannot place the deleted run; anchoring
            // anyway could splice the edit across the wrong bytes.
            assertDeny(
              await editCall(doc.content, view, `C${p.i} nnn`),
              /cannot be\s+re-anchored unambiguously/,
              `collide#${p.i}`,
            );
          } else if (p.kind === "plain") {
            // PASS-THROUGH: verbatim disk bytes need no translation; a rewrite
            // or deny here would corrupt/block a perfectly ordinary edit.
            assert.equal(view, disk, `plain#${p.i}: view must equal disk`);
            assert.equal(
              await editCall(doc.content, view, `edited ${p.i}`),
              null,
              `plain#${p.i}`,
            );
          } else {
            // dupPair — the two lines must render to the IDENTICAL view text
            // (distinct secrets, same [REDACTED]); assert that ambiguity holds,
            // then DENY both ways: single-target and replace_all are ambiguous.
            const twin = viewLines[p.lineStart + 1];
            assert.equal(
              view,
              twin,
              `dupPair#${p.i}: twins must share one view text (the ambiguity)`,
            );
            assert.equal(
              occurrences(viewLines.join("\n"), view).length,
              2,
              `dupPair#${p.i}: shared view text must occur exactly twice`,
            );
            assertDeny(
              await editCall(doc.content, view, `${view}x`),
              /matches 2 locations/,
              `dupPair#${p.i}`,
            );
            assertDeny(
              await editCall(doc.content, view, `${view}x`, {
                replace_all: true,
              }),
              /on-disk bytes differ/,
              `dupPair#${p.i} replace_all`,
            );
          }
        }

        // DENY: a new_string naming a secret OUTSIDE the matched span must be
        // refused (writing it literally would persist placeholder text; guessing
        // would splice a secret the model never matched).
        const inSpan = doc.pieces.find((p) => p.kind === "secret");
        const outside = doc.pieces.find((p) => p.kind === "typed");
        if (inSpan && outside) {
          const inView = viewLines[inSpan.lineStart];
          const outView = viewLines[outside.lineStart];
          assertDeny(
            await editCall(
              doc.content,
              inView,
              `${inView}\nCOPY=${outView.split("=").slice(1).join("=")}`,
            ),
            /outside\s+the matched old_string/,
            "outside-span placeholder",
          );
        }
      }),
      fcRunOptions({ numRuns: 150 }),
    );
  });
});
