/**
 * Layer 1: ANSI + invisible-character stripping. The zero-dependency core shared
 * by the convenience `sanitize` (index.mjs), the tool-output pipeline
 * (output.mjs), and the Edit-repair rehydrator (rehydrate.mjs) — a single
 * implementation so every consumer derives the EXACT view the model was shown (a
 * re-implementation would drift, and rehydration's soundness gate depends on
 * re-cleaning reproducing the view).
 *
 * Lone-surrogate normalization is NOT applied by {@link applyLayer1} itself: it
 * is exported as {@link LONE_SURROGATE_RE} for consumers to apply at the boundary
 * that needs a well-formed string (the redactor input in output.mjs's
 * processLayer1 / re-redact, and before the HTML tokenizer), because that is the
 * point where a lone surrogate would otherwise corrupt a match or a parse.
 */
import { stripInvisibleWithReport, CATEGORY } from "./invisible.mjs";
import { CONTROL_INTRODUCER_SOURCE, scanAnsi, TOKEN_KIND } from "./ansi.mjs";

// The ANSI grammar and the introducer charset live in ./ansi.mjs so this module
// and invisible.mjs (which owns the public isSgrOnly / SGR_RE and cannot import
// this one) scan with the SAME tokenizer. Re-exported here because layer1 is the
// ANSI entry point every other consumer already imports.
export { scanAnsi, TOKEN_KIND } from "./ansi.mjs";

// The residual sweep: every raw control introducer, whatever the grammar made of
// it. This — not the sequence matching — is the guarantee that no introducer
// survives Layer 1.
const CONTROL_INTRODUCER_RE = new RegExp(CONTROL_INTRODUCER_SOURCE, "g");

// Unpaired UTF-16 surrogates (high not followed by low, or low not preceded by
// high). Normalized before any HTML parser, which throws on a stray byte —
// which would otherwise let a single malformed code unit suppress all output.
export const LONE_SURROGATE_RE =
  /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

const MAX_ANSI_PASSES = 3;

/**
 * Splice out every complete ANSI sequence {@link scanAnsi} finds — SGR, other
 * CSI/two-byte escapes, and whole OSC strings. An ORPHAN introducer (one that
 * starts no sequence) is deliberately LEFT: deleting it here would drop the
 * `ESC` out of `ESC`<ZWSP>`[32m` before the invisible pass could reconstitute
 * the sequence, turning a hidden control into visible `[32m` in the model's
 * view. Orphans are removed by applyLayer1's residual sweep, once no
 * reconstitution is possible.
 * @param {string} text
 * @returns {string}
 */
function stripAnsiOnce(text) {
  let out = "";
  let last = 0;
  for (const token of scanAnsi(text)) {
    if (token.kind === TOKEN_KIND.ORPHAN) continue;
    out += text.slice(last, token.start);
    last = token.end;
  }
  if (last === 0) return text;
  return out + text.slice(last);
}

/**
 * Strip ANSI escape sequences to a fixed point. Removing one sequence can
 * reconstitute another around it (a lone ESC left of `ESC[32m[0m` gains the
 * trailing `[0m` once the inner sequence is removed, forming a brand-new valid
 * sequence the single pass would miss), so iterate — but only a fixed few
 * times. Bounding by the input's ESC count is quadratic on attacker-controlled
 * text: `("\x1b[").repeat(n) + "m".repeat(n)` reconstitutes exactly ONE
 * sequence per pass, so n full O(n) scans run, and 48 KB already costs seconds.
 * The passes are not what makes Layer 1 safe — applyLayer1's residual
 * CONTROL_INTRODUCER_RE sweep is, and it removes every ESC/C1 byte whatever
 * survives here. Past the bound a reconstituted sequence therefore degrades to
 * VISIBLE text rather than a hidden control, which is the fail-open direction.
 * @param {string} input
 * @returns {string}
 */
export function stripAnsiFully(input) {
  let prev = input;
  let out = stripAnsiOnce(prev);
  for (let pass = 1; pass < MAX_ANSI_PASSES && out !== prev; pass++) {
    prev = out;
    out = stripAnsiOnce(prev);
  }
  return out;
}

// How many times the {ANSI strip, invisible strip} composition may re-run before
// the sweep is forced. Each iteration deletes at least one character, so the
// loop terminates on its own; the bound is a DoS guard on the same quadratic
// argument as MAX_ANSI_PASSES (n rounds of O(n) scans on adversarial input).
// Three rounds is what the deepest REAL reconstitution needs — strip
// invisibles, remove the ANSI they hid, strip the joiners that ANSI removal
// made adjacent, confirm — so four leaves a round of margin. Deeper nesting is
// not reachable through the carve-out: preserving a joiner requires cursive or
// emoji neighbours on BOTH sides, so a preserved joiner can never sit inside an
// escape sequence, and every joiner that hides one is therefore stripped by the
// FIRST invisible pass. Past the bound the composition simply stops early — the
// final sweep still holds the no-introducer guarantee, and what is left degrades
// to visible text (the fail-open direction), exactly as with MAX_ANSI_PASSES.
const MAX_LAYER1_PASSES = 4;

/**
 * Layer 1: ANSI + invisible-char strip with a result guaranteed free of every
 * raw ANSI control introducer (7-bit ESC U+001B and the whole 8-bit C1 control
 * block U+0080–U+009F: CSI, the DCS/SOS/OSC/PM/APC string introducers, and ST).
 *
 * The two passes FEED each other in both directions, so neither ordering is
 * enough on its own and the composition is iterated to a fixed point instead:
 * removing an invisible char reconstitutes an escape its split hid
 * (`ESC`<ZWSP>`[32m` → `ESC[32m`), and removing an escape makes two invisibles
 * ADJACENT that were not (`م ZWJ ESC[m ZWJ م` → a joiner run the invisible pass
 * classifies as a payload channel rather than linguistic). A pipeline with a
 * fixed number of alternations always leaves one of those unanswered — this used
 * to re-strip ANSI after the invisible pass and stop, so `applyLayer1` was not
 * idempotent and the rehydrator's "re-cleaning reproduces the view" assumption
 * did not hold.
 *
 * The residual sweep runs only once the composition is STABLE, because sweeping
 * an introducer early destroys the sequence a later ANSI pass would have removed
 * whole, promoting a hidden control to visible text. A final UNCONDITIONAL sweep
 * follows the loop so the no-raw-introducer guarantee does not depend on the
 * pass bound.
 *
 * `deAnsi` is the ANSI strip of the ORIGINAL text (invisible runs intact), the
 * scope a LONG_RUN payload check needs — not an intermediate of the loop.
 * @param {string} text
 * @returns {{ cleaned: string, deAnsi: string, found: string[] }}
 */
export function applyLayer1(text) {
  const deAnsi = stripAnsiFully(text);
  /** @type {Set<string>} Union of the categories every iteration reported. */
  const found = new Set();
  let cleaned = text;
  let ansiFound = false;

  for (let pass = 0; pass < MAX_LAYER1_PASSES; pass++) {
    const afterAnsi = pass === 0 ? deAnsi : stripAnsiFully(cleaned);
    if (afterAnsi !== cleaned) ansiFound = true;
    // stripInvisibleWithReport returns `found` for exactly the categories it
    // removed — so a ZWNJ/ZWJ the carve-out PRESERVES never registers as a
    // strip. The second argument stays the ORIGINAL `text` on every iteration:
    // the leading-BOM exception is defined against what the user actually sent,
    // so a BOM that was interior before an ANSI strip shifted it to index 0 is
    // treated as interior and stripped, not preserved.
    const { cleaned: afterInvis, found: passFound } = stripInvisibleWithReport(
      afterAnsi,
      text,
    );
    for (const category of passFound) found.add(category);
    if (afterInvis !== cleaned) {
      cleaned = afterInvis;
      continue;
    }
    // {ANSI, invisible} is stable: nothing left can reconstitute, so the
    // residual introducers can be swept without hiding a sequence from a later
    // pass. A sweep that changes the text feeds one more round (removing an
    // introducer can make invisibles adjacent, exactly as removing a sequence
    // can); one that changes nothing means the whole composition has converged.
    const swept = cleaned.replace(CONTROL_INTRODUCER_RE, "");
    if (swept === cleaned) break;
    cleaned = swept;
    ansiFound = true;
  }

  const swept = cleaned.replace(CONTROL_INTRODUCER_RE, "");
  if (swept !== cleaned) {
    cleaned = swept;
    ansiFound = true;
  }

  if (ansiFound) found.add(CATEGORY.ANSI);
  return { cleaned, deAnsi, found: [...found] };
}
