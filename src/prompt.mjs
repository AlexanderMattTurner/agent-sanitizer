/**
 * User-prompt verdict: classify a submitted prompt as pass / pass-with-note /
 * block on payload-capable invisible Unicode and ANSI escapes.
 *
 * A prompt pasted from a tampered web page can carry tag characters or
 * zero-width sequences the model reads but the user cannot see, and a
 * prompt-submission channel typically cannot rewrite the prompt in place — so
 * the only way to neutralize a payload is to block. This is the pure decision;
 * a host wraps it in whatever its agent's prompt-submission hook expects.
 *
 * One carve-out: a prompt whose only escape content is INERT — SGR color/style
 * codes (`ESC [ params m`) and/or an orphan introducer that completes no
 * sequence — passes with a note instead of blocking. Pasting colored terminal
 * output (test runs, build logs) is the single most common debugging action,
 * and SGR is display-only by the ECMA-48 grammar; an orphan `ESC` is not a
 * sequence at all. Neither can move the cursor, erase the screen, or carry an
 * OSC payload. Anything that IS a complete CSI/OSC token still blocks, as do
 * the invisible-char thresholds.
 */
import {
  CHECKS,
  CATEGORY,
  CATEGORY_LABELS,
  LONG_RUN_THRESHOLD,
  SCATTERED_THRESHOLD,
  countEffectiveInvisible,
  payloadLongRunSample,
} from "./invisible.mjs";
import { isBenignAnsi, stripAnsiFully } from "./layer1.mjs";
import { CONTROL_INTRODUCER_SOURCE } from "./ansi.mjs";

// Every raw ANSI control a prompt can carry: 7-bit ESC (U+001B) and the entire
// 8-bit C1 block (U+0080-U+009F). Gating on ESC alone -- or on only CSI/OSC --
// is blind to a pure-C1 sequence whose escape content is, e.g., `U+009B 2J`
// (CSI erase), `U+009D 0;...BEL` (OSC), or the string introducers DCS (U+0090),
// SOS (U+0098), PM (U+009E), APC (U+009F): Layer 1 strips it, dropping the
// invisible count to zero, so the prompt reads clean and passes. This gate must
// match Layer 1's residual sweep exactly -- no raw C1 control belongs in a
// legitimate prompt (the SGR color carve-out is applied separately, after SGR
// removal), so the whole block is gated, not a hand-picked subset that lets
// DCS/SOS/PM/APC through. Built from the SHARED charset source instead of a
// third hand-written copy: a hand-written third copy has no drift check
// beyond a prose reminder in a comment, and a spelling difference between two
// hand-written copies (e.g. how each spells ESC) is exactly what a grep-based
// drift check would miss.
const ANSI_INTRODUCER = new RegExp(CONTROL_INTRODUCER_SOURCE);

/**
 * Human-facing block reason: what was detected, the thresholds, a code-point
 * sample of the long run (if any), and how to recover.
 * @param {string[]} categories
 * @param {number} invisibleCount
 * @param {string | null} longRunSample
 * @returns {string}
 */
export function formatReason(categories, invisibleCount, longRunSample) {
  const parts = [
    `Detected: ${categories.join(", ")}.`,
    `Invisible char count: ${invisibleCount} (long-run threshold: ${LONG_RUN_THRESHOLD}, scattered threshold: ${SCATTERED_THRESHOLD}).`,
  ];
  if (longRunSample) {
    const cps = [...longRunSample]
      .slice(0, 16)
      .map(
        (ch) =>
          "U+" +
          /** @type {number} */ (ch.codePointAt(0))
            .toString(16)
            .toUpperCase()
            .padStart(4, "0"),
      )
      .join(" ");
    parts.push(`Long-run sample (first 16 code points): ${cps}.`);
  }
  parts.push(
    "Resubmit the prompt with invisible/ANSI characters removed. If you pasted this from a webpage, the source may be carrying a prompt-injection payload.",
  );
  return parts.join(" ");
}

/**
 * Pure verdict for a user prompt: pass through, pass with an SGR note, or
 * block. `strip` (the ANSI stripper, defaulting to the package's
 * {@link stripAnsiFully}) runs on every prompt so invisibles smuggled *inside*
 * an ANSI sequence (an OSC string) are stripped before the invisible-char
 * thresholds are counted; it is injectable so a host can substitute its own
 * stripper or exercise the fail-closed path.
 * @param {string} prompt
 * @param {(s: string) => string} [strip]
 * @returns {{action:"pass"} | {action:"note"} | {action:"block", reason:string}}
 */
export function classifyPrompt(prompt, strip = stripAnsiFully) {
  if (!prompt) return { action: "pass" };

  const hasAnsi = ANSI_INTRODUCER.test(prompt);
  const deAnsi = strip(prompt);

  // Both gates read the SHARED definitions in ./invisible.mjs rather than
  // spelling their own: what counts as a hidden run, and how many invisibles a
  // text really carries once the carve-out's preserved joiners and its
  // over-budget surplus are accounted for. See payloadLongRunSample /
  // countEffectiveInvisible — including why the run probe masks the invisibles
  // the strip layer would PRESERVE, so a legitimate emoji sequence cannot block
  // a prompt that the strip layer would not even have flagged.
  const longRunSample = payloadLongRunSample(deAnsi);
  const invisibleCount = countEffectiveInvisible(deAnsi);
  const invisiblesBelowThreshold =
    longRunSample === null && invisibleCount < SCATTERED_THRESHOLD;

  if (!hasAnsi && invisiblesBelowThreshold) return { action: "pass" };

  // Inert escapes in an otherwise clean prompt — display-only colour and/or an
  // orphan introducer that forms no sequence: pass with a note instead of
  // blocking, so pasted colored logs and log fragments cut mid-escape remain
  // usable. isBenignAnsi judges from what Layer 1's strip actually removed, so
  // it covers the whole C1 block and any sequence that only reconstitutes
  // during the strip; a complete CSI/OSC token falls through to the block.
  if (hasAnsi && invisiblesBelowThreshold && isBenignAnsi(prompt))
    return { action: "note" };

  // CHECKS pairs a machine-readable category code with its detector; map each
  // matched code to its human label for the user-facing block reason.
  const categories = CHECKS.filter(([, re]) => deAnsi.search(re) !== -1).map(
    ([code]) => CATEGORY_LABELS[code],
  );
  if (hasAnsi) categories.push(CATEGORY_LABELS[CATEGORY.ANSI]);
  return {
    action: "block",
    reason: formatReason(categories, invisibleCount, longRunSample),
  };
}
