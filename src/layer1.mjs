/**
 * Layer 1: ANSI + invisible-character stripping. The zero-dependency core shared
 * by the convenience `sanitize` (index.mjs), the tool-output pipeline
 * (output.mjs), and the Edit-repair rehydrator (rehydrate.mjs) — a single
 * implementation so every consumer derives the EXACT view the model was shown (a
 * re-implementation would drift, and rehydration's soundness gate depends on
 * re-cleaning reproducing the view).
 *
 * Lone-surrogate normalization is NOT applied by {@link applyLayer1} itself. It
 * belongs at the boundary that needs a well-formed string — the redactor input
 * in output.mjs's processLayer1 / re-redact, and before the HTML tokenizer —
 * because that is the point where a lone surrogate would otherwise corrupt a
 * match or a parse. Prefer {@link normalizeLoneSurrogates} at each such
 * boundary, the one definition of that substitution, which output.mjs's
 * processLayer1 and rehydrate.mjs both call — not a fresh `.replace` over
 * {@link LONE_SURROGATE_RE}.
 *
 * So {@link applyLayer1} alone is NOT the string the tool-output pipeline shows a
 * model: on an input carrying an unpaired surrogate the two differ at exactly
 * that code unit. {@link applyLayer1WellFormed} is the composition the pipeline
 * runs, and a consumer deriving offsets for redaction or view mapping wants that
 * one — see its own doc for why the choice matters.
 */
import { stripInvisibleWithReport, CATEGORY } from "./invisible.mjs";
import {
  CONTROL_INTRODUCER_SOURCE,
  isOrphanKind,
  orphanKindFor,
  scanAnsi,
  TOKEN_KIND,
} from "./ansi.mjs";

// The ANSI grammar and the introducer charset live in ./ansi.mjs so this module
// and invisible.mjs (which owns the public isSgrOnly / SGR_RE and cannot import
// this one) scan with the SAME tokenizer.

// The residual sweep: every raw control introducer, whatever the grammar made of
// it. This — not the sequence matching — is the guarantee that no introducer
// survives Layer 1.
const CONTROL_INTRODUCER_RE = new RegExp(CONTROL_INTRODUCER_SOURCE, "g");

/**
 * Run the residual sweep, recording the orphan kind of every introducer it
 * removes. The sweep sees bare characters rather than tokens, so the kind comes
 * from {@link orphanKindFor} — the same decision the tokenizer makes, not a
 * second spelling of it — fed the following character from the text being
 * swept, which is the context a terminal reading this introducer would have.
 * @param {string} text
 * @param {Set<string>} kinds
 * @returns {string}
 */
function sweepIntroducers(text, kinds) {
  return text.replace(CONTROL_INTRODUCER_RE, (ch, offset) => {
    kinds.add(orphanKindFor(ch, text[offset + 1]));
    return "";
  });
}

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
 * @param {Set<string>} [kinds]  collects the {@link TOKEN_KIND} of every
 *   sequence this pass actually removed, so a caller can tell a display-only
 *   colour strip from a cursor/erase/OSC one without re-scanning (see
 *   {@link isBenignAnsiKinds}).
 * @returns {string}
 */
function stripAnsiOnce(text, kinds) {
  let out = "";
  let last = 0;
  for (const token of scanAnsi(text)) {
    if (isOrphanKind(token.kind)) continue;
    kinds?.add(token.kind);
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
 * @param {Set<string>} [kinds]  see {@link stripAnsiOnce}; accumulates across passes
 * @returns {string}
 */
export function stripAnsiFully(input, kinds) {
  let prev = input;
  let out = stripAnsiOnce(prev, kinds);
  for (let pass = 1; pass < MAX_ANSI_PASSES && out !== prev; pass++) {
    prev = out;
    out = stripAnsiOnce(prev, kinds);
  }
  return out;
}

/**
 * What a reader is told when the ONLY thing a strip removed was inert ANSI (see
 * {@link isBenignAnsiKinds}).
 *
 * It lives here, beside the predicate that decides it, because every entry point
 * that can reach that verdict must say the same thing: the tool-output pipeline,
 * the prompt gate's pass-with-note, and any host wiring its own. The wording is
 * deliberately not `describeStripped`'s — "Stripped: ANSI escapes" names a
 * category that reads like an attack, when the honest report is "these were
 * colour codes, and here is how to look at the raw bytes".
 */
export const INERT_ANSI_NOTE =
  "Inert ANSI stripped (display-only colour and/or a stray escape byte that " +
  "formed no control sequence); pipe through cat -v to inspect raw escapes.";

/**
 * True when the ANSI a Layer-1 strip removed was INERT: every removed sequence
 * was either a display-only SGR colour token or a LONE 7-bit `ESC` that opened
 * nothing at all (a stray byte in a file, a truncated write, a log fragment cut
 * mid-escape).
 *
 * The two other orphan kinds are deliberately NOT inert. A raw C1 orphan
 * (TOKEN_KIND.ORPHAN_C1): legit UTF-8 text does not carry raw C1 bytes, so an
 * unrecognized one means a terminal may still act on what follows it. An
 * incomplete CSI (TOKEN_KIND.ORPHAN_CSI)
 * for the same reason at 7 bits: the CSI parser keeps consuming until a final
 * byte, so `hello ESC[12 world` hides ` w` from the human while the model reads
 * the whole prompt.
 *
 * This draws a severity line, not a presence line: the bytes are stripped
 * either way, so all that rides on the answer is whether the operator sees a
 * WARNING or a terse note. An orphan introducer cannot move the cursor, erase
 * the screen, relabel a window, or open an OSC string — every one of those needs
 * a COMPLETE token, which {@link scanAnsi} classifies as CSI or OSC and this
 * rejects. Warning on a lone `ESC` is the false positive that costs the most: one
 * pre-existing `ESC` in a markdown file, echoed back in an Edit result, raises
 * the same alarm as a cursor-spoofing payload, and an alarm that fires on inert
 * bytes is the one operators learn to scroll past.
 *
 * It takes the kinds the STRIP recorded, never a fresh scan of the raw text,
 * and that is the whole point: a scan of the raw text answers about sequences
 * that have not been reconstituted yet, so `ESC` + `ESC[m` + `[2J` (a bare ESC,
 * an SGR, then plain text) reads as orphan-only there while the strip's second
 * pass actually removes a CSI erase. Recording what each pass removed reports
 * the sequences that really existed at Layer 1's fixed point.
 * @param {readonly string[] | Set<string>} kinds  {@link TOKEN_KIND} values removed
 * @returns {boolean}
 */
export function isBenignAnsiKinds(kinds) {
  return [...kinds].every(
    (kind) => kind === TOKEN_KIND.SGR || kind === TOKEN_KIND.ORPHAN,
  );
}

/**
 * {@link isBenignAnsiKinds} for callers that hold only the text — it runs the
 * full Layer-1 composition to get the fixed-point view. Callers that already
 * ran {@link applyLayer1} must read its `ansiKinds` instead of paying for a
 * second strip.
 * @param {string} text
 * @returns {boolean}
 */
export function isBenignAnsi(text) {
  return isBenignAnsiKinds(applyLayer1(text).ansiKinds);
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
 *
 * `ansiKinds` is the {@link TOKEN_KIND} of every ANSI sequence the composition
 * removed, deduped — the severity detail `found`'s single ANSI category cannot
 * carry (see {@link isBenignAnsiKinds}). It is also what DERIVES that category:
 * a kind is recorded exactly when bytes were removed, so "we reported ANSI" and
 * "here is what the ANSI was" can no longer disagree.
 * @param {string} text
 * @returns {{ cleaned: string, deAnsi: string, found: string[], ansiKinds: string[] }}
 */
export function applyLayer1(text) {
  /** @type {Set<string>} TOKEN_KINDs removed by every ANSI pass below. */
  const ansiKinds = new Set();
  const deAnsi = stripAnsiFully(text, ansiKinds);
  /** @type {Set<string>} Union of the categories every iteration reported. */
  const found = new Set();
  let cleaned = text;

  for (let pass = 0; pass < MAX_LAYER1_PASSES; pass++) {
    const afterAnsi = pass === 0 ? deAnsi : stripAnsiFully(cleaned, ansiKinds);
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
    const swept = sweepIntroducers(cleaned, ansiKinds);
    if (swept === cleaned) break;
    cleaned = swept;
  }

  cleaned = sweepIntroducers(cleaned, ansiKinds);

  // Derived, not tracked in parallel: a kind is recorded exactly when an ANSI
  // pass or the sweep removed bytes, so the category and the severity detail
  // are two readings of one fact.
  if (ansiKinds.size > 0) found.add(CATEGORY.ANSI);
  return { cleaned, deAnsi, found: [...found], ansiKinds: [...ansiKinds] };
}

/**
 * Map every lone UTF-16 surrogate to U+FFFD. Load-bearing on ANY path that feeds
 * text to an injected redactor: a secret split by an interposed lone surrogate
 * reads as adjacent to a model rendering its own UTF-16 but as broken to a
 * redactor (Node maps the lone surrogate to U+FFFD en route), so a secret
 * reconstituted across the surrogate survives redaction unless the text is
 * normalized first. It also keeps an HTML tokenizer from throwing on a stray
 * code unit. The substitution is same-LENGTH — one UTF-16 unit for one — so
 * offsets computed against the un-normalized string stay valid against this one.
 * @param {string} text
 * @returns {string}
 */
export function normalizeLoneSurrogates(text) {
  return text.replace(LONE_SURROGATE_RE, "\uFFFD");
}

/**
 * {@link applyLayer1} followed by {@link normalizeLoneSurrogates} — the exact
 * composition `output.mjs`'s processLayer1 runs before Layers 2+ see the text,
 * so this is the string a model is actually shown.
 *
 * Take this one, not `applyLayer1`, whenever the result feeds a redactor, an
 * offset calculation or a view map: those consumers compare their own string to
 * the model-facing view, and an unpaired surrogate is exactly where the two
 * spellings diverge. Take `applyLayer1` when you want Layer 1's removals alone
 * and intend to hand a possibly ill-formed string onward unchanged.
 *
 * `found` gains {@link CATEGORY.LONE_SURROGATES} exactly when the normalization
 * changed the text, matching what the pipeline reports for the same input.
 * `deAnsi` is untouched: it is the ANSI strip of the ORIGINAL text, the scope
 * the long-run payload check needs.
 * @param {string} text
 * @returns {{ cleaned: string, deAnsi: string, found: string[], ansiKinds: string[] }}
 */
export function applyLayer1WellFormed(text) {
  const result = applyLayer1(text);
  const cleaned = normalizeLoneSurrogates(result.cleaned);
  if (cleaned === result.cleaned) return result;
  return {
    ...result,
    cleaned,
    found: [...result.found, CATEGORY.LONE_SURROGATES],
  };
}
