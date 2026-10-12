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
import { stripInvisibleWithReport, CATEGORY, STRIP } from "./invisible.mjs";
import {
  CONTROL_INTRODUCER_SOURCE,
  DEFAULT_RENDITION,
  foregroundMatchesBackground,
  isCancelledOrphan,
  isOrphanKind,
  orphanKindFor,
  scanAnsi,
  sgrRendition,
  TOKEN_KIND,
} from "./ansi.mjs";

/** @typedef {import("./ansi.mjs").SgrRendition} SgrRendition */

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

/**
 * Splice out every complete ANSI sequence {@link scanAnsi} finds — SGR, other
 * CSI/escapes, aborted sequences and whole control strings — in ONE pass, which
 * is already a fixed point: a token ends only where a terminal's parser would,
 * and a cancelled orphan (see {@link isCancelledOrphan}) goes with it, so no
 * removal can join what is left into a new sequence. Any other ORPHAN
 * introducer is deliberately LEFT: deleting it here would drop the `ESC` out of
 * `ESC`<ZWSP>`[32m` before the invisible pass could reconstitute the sequence,
 * turning a hidden control into visible `[32m` in the model's view. Orphans are
 * removed by applyLayer1's residual sweep, once no reconstitution is possible.
 * @param {string} input
 * @param {Set<string>} [kinds]  collects the {@link TOKEN_KIND} of every
 *   sequence actually removed, so a caller can tell a display-only colour strip
 *   from a cursor/erase/OSC one without re-scanning (see
 *   {@link isBenignAnsiKinds}).
 * @returns {string}
 */
export function stripAnsiFully(input, kinds) {
  let out = "";
  let last = 0;
  for (const token of scanAnsi(input)) {
    if (isOrphanKind(token.kind) && !isCancelledOrphan(input, token)) continue;
    kinds?.add(token.kind);
    out += input.slice(last, token.start);
    last = token.end;
  }
  if (last === 0) return input;
  return out + input.slice(last);
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
 * How many SGR sequences may sit back to back, with nothing that RENDERS between
 * them, before the run is read as a covert channel rather than styling.
 *
 * A styling emitter puts colour AROUND text: `ls --color`, chalk and pygments
 * chain at most a handful of attributes before the glyphs they style. A run of
 * escape sequences that puts no glyph on the screen renders as literally nothing
 * to a human while a model reads every byte, so past some length the run is not
 * styling any more — it is a message, in the same shape (and for the same
 * reason) as the invisible layer's LONG_RUN_THRESHOLD. Ten matches that
 * threshold and sits well above what a real emitter chains.
 */
export const SGR_RUN_THRESHOLD = 10;

/**
 * True when nothing in `gap` puts a glyph on the screen — the one primitive both
 * arms of {@link sgrCarriesPayload} ask about. {@link STRIP} is the engine's
 * single definition of a character with no visible presence, so a zero-width
 * separator between two sequences is transparent here exactly as it is to a
 * terminal, while a SPACE is not.
 * @param {string} gap
 * @returns {boolean}
 */
function rendersNothing(gap) {
  return gap.replace(STRIP, "") === "";
}

/**
 * True when the SGR sequences in `text` do more than style visible text — the
 * question a consumer must answer before PRESERVING escapes rather than
 * stripping them. Three arms, all model-sees/human-sees divergences:
 *
 *   1. CONCEAL is on while text that would otherwise render goes by. Only SGR
 *      moves that state (see {@link sgrRendition}) — a cursor move or an erase
 *      leaves a terminal exactly as concealed as it was.
 *   2. The foreground is the background while a glyph goes by (`ESC[30;40m`):
 *      concealment by colour, judged only where the match is unambiguous (see
 *      {@link foregroundMatchesBackground}). Block Elements are the one
 *      exception judged across the whole text rather than per glyph (see
 *      {@link drawsSecondBlockElement}).
 *   3. {@link SGR_RUN_THRESHOLD} sequences with nothing that renders between
 *      them: the run puts no glyph on the screen, so it carries data rather than
 *      styling.
 *
 * CONCEAL or a matching foreground still in force when the text ENDS is a
 * refusal too, whatever the tail holds: rendition outlives the bytes that set
 * it, so a file ending in `ESC[8m` or `ESC[30;40m` blanks everything the
 * terminal prints after it is `cat`ed — a latent spoof rather than styling.
 *
 * What it does NOT claim: a message spread thinly through legitimately coloured
 * text — one sequence per line, say — is indistinguishable from styling, and
 * this answers no for it. That is the same bargain the invisible layer's
 * thresholds strike, and the same direction: an unprovable payload is left alone
 * rather than costing every colourized file its colour.
 *
 * Scans the RAW text in one pass, which is what a terminal does with these
 * bytes — no reconstitution across passes, because a preserved byte is never
 * removed to complete a sequence around it.
 * @param {string} text
 * @returns {boolean}
 */
export function sgrCarriesPayload(text) {
  /** @type {Readonly<SgrRendition>} */
  let rendition = DEFAULT_RENDITION;
  let run = 0;
  let previousEnd = 0;
  /** @type {Set<string>} */
  const solidBlocks = new Set();
  for (const token of scanAnsi(text)) {
    const gap = text.slice(previousEnd, token.start);
    const blankGap = rendersNothing(gap);
    previousEnd = token.end;
    if (token.kind !== TOKEN_KIND.SGR) {
      run = 0;
      continue;
    }
    // This refusal is what blocks `ESC[8m` (or a foreground painted in its own
    // background) from hiding text from the human while leaving its bytes for
    // the model.
    if (hidesText(rendition, gap, solidBlocks)) return true;
    run = blankGap ? run + 1 : 1;
    if (run >= SGR_RUN_THRESHOLD) return true;
    rendition = sgrRendition(text.slice(token.start, token.end), rendition);
  }
  return rendition.concealed || foregroundMatchesBackground(rendition);
}

// A glyph whose identity a foreground painted in its own background hides:
// anything but whitespace (which looks the same either way) and the Block
// Elements, which drawsSecondBlockElement judges instead.
const COLOUR_HIDDEN_GLYPH = /[^\s\u2580-\u259F]/u;
const BLOCK_ELEMENT = /[\u2580-\u259F]/gu;

/**
 * True when `gap`, drawn in a foreground matching its background, brings the
 * text's count of distinct Block Elements (U+2580-U+259F) so drawn past one.
 *
 * In matching colours every Block Element paints the same solid cell, so the
 * glyph CHOICE is hidden from a human while a model reads it — a channel of up
 * to five bits a cell. One glyph throughout carries no choice, and that is what
 * a half-block image renderer emits (catimg-style `▀` with the top pixel as
 * foreground and the bottom as background, equal wherever the image is flat),
 * so a single distinct glyph stays styling and a second one is the refusal.
 * `seen` spans the whole text, so the choice cannot be spread one glyph per
 * sequence. Bounded: it never holds more than one glyph between calls.
 * @param {string} gap @param {Set<string>} seen
 * @returns {boolean}
 */
function drawsSecondBlockElement(gap, seen) {
  for (const [glyph] of gap.matchAll(BLOCK_ELEMENT)) {
    seen.add(glyph);
    if (seen.size > 1) return true;
  }
  return false;
}

/**
 * True when `rendition` hides some of `gap` from a human: CONCEAL blanks every
 * glyph, and a foreground matching its background hides every
 * {@link COLOUR_HIDDEN_GLYPH} and the choice among Block Elements.
 * @param {Readonly<SgrRendition>} rendition @param {string} gap
 * @param {Set<string>} solidBlocks  the Block Elements already drawn in
 *   matching colours, across the whole text
 * @returns {boolean}
 */
function hidesText(rendition, gap, solidBlocks) {
  if (rendition.concealed) return !rendersNothing(gap);
  if (!foregroundMatchesBackground(rendition)) return false;
  return (
    COLOUR_HIDDEN_GLYPH.test(gap.replace(STRIP, "")) ||
    drawsSecondBlockElement(gap, solidBlocks)
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

/**
 * True when the escapes in `text` may be let through rather than blocked or
 * stripped: every removed kind is inert ({@link isBenignAnsiKinds}) AND the SGR
 * is still just styling ({@link sgrCarriesPayload}). THE answer for every
 * surface that preserves or waves through escapes — the prompt gate's
 * pass-with-note and the write path's colour carve-out — so `ESC[8m` cannot be
 * "inert colour" to one of them while it hides text in the other.
 * @param {string} text  the raw text, as a terminal would receive it
 * @param {Iterable<string>} [kinds]  the {@link TOKEN_KIND}s a strip of `text`
 *   removed, when the caller already has them; defaults to Layer 1's
 * @returns {boolean}
 */
export function escapesPreservable(text, kinds = applyLayer1(text).ansiKinds) {
  return isBenignAnsiKinds([...kinds]) && !sgrCarriesPayload(text);
}

// How many times the {ANSI strip, invisible strip} composition may re-run before
// it falls back to {@link stripLayer1Monotone}. Each iteration deletes at least
// one character, so the loop terminates on its own; the bound is a DoS guard: n
// rounds of O(n) scans on adversarial input is quadratic. Three rounds is what
// the deepest REAL reconstitution needs (strip invisibles, remove the ANSI they
// hid, strip the joiners that removal made adjacent, confirm). Adversarial input
// can need more — a registered variation selector preserved INSIDE an escape,
// whose preserve budget shrinks as each removal shortens the text.
const MAX_LAYER1_PASSES = 4;

/**
 * Remove every complete ANSI sequence and then every raw control introducer
 * left over. The output holds no introducer, so no later pass can find an
 * escape in it: a fixed point by construction.
 * @param {string} text
 * @param {Set<string>} [kinds]  collects the {@link TOKEN_KIND} of every removal
 * @returns {string}
 */
export function stripTerminalFully(text, kinds = new Set()) {
  return sweepIntroducers(stripAnsiFully(text, kinds), kinds);
}

/**
 * The carve-out-free Layer 1 a non-converging composition falls back to: EVERY
 * invisible first (preserved joiners and selectors included), then every
 * escape and introducer. Its output holds neither, so re-running Layer 1 on it
 * changes nothing — the fixed point the iterated composition could not reach
 * within its bound, bought by giving up the carve-out on adversarial input only.
 * It starts from what the caller SENT, not the composition's last state: a
 * round that swept the introducer off an escape still split by a preserved
 * selector has already turned that escape's body into text, which no later
 * strip can tell from prose.
 * @param {string} text  what the caller sent
 * @param {Set<string>} found  collects the invisible CATEGORY codes removed
 * @param {Set<string>} kinds  collects the {@link TOKEN_KIND} of every removal
 * @returns {string}
 */
function stripLayer1Monotone(text, found, kinds) {
  const bulk = stripInvisibleWithReport(text, text, { carveOut: false });
  for (const category of bulk.found) found.add(category);
  return stripTerminalFully(bulk.cleaned, kinds);
}

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
 * whole, promoting a hidden control to visible text. A composition that has not
 * converged within the pass bound falls back to a carve-out-free strip whose
 * output holds no invisible and no introducer, so both the no-raw-introducer
 * guarantee and idempotence hold whatever the bound.
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
  let converged = false;

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
    if (swept === cleaned) {
      converged = true;
      break;
    }
    cleaned = swept;
  }

  // This fallback is what keeps Layer 1 a FIXED POINT past the pass bound: an
  // unconverged state re-cleans to something else (a re-clean of the view
  // would then disagree with the view), and can still hold an escape the next
  // round would have removed, which the sweep alone turns into visible text.
  if (!converged) cleaned = stripLayer1Monotone(text, found, ansiKinds);

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
