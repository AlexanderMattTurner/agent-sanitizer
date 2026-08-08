/**
 * The one place a finding's LOUDNESS is decided, and the vocabulary every layer
 * reports in.
 *
 * Every layer of this pipeline used to have exactly one volume. A cursor-spoofing
 * ANSI payload and a single stray escape byte in a README produced the same
 * `WARNING: Tool output sanitized` banner; so did one soft hyphen, and so did
 * the `<script>` tag that every fetched web page carries. That is the failure
 * mode a detector dies of: a banner that fires on every ordinary page teaches its
 * reader to skip the banner, and then the one that mattered scrolls past too.
 *
 * So a finding carries a SEVERITY, and the two tiers mean specific things:
 *
 *   WARNING — this text is injection-shaped. Something was hidden from a human
 *             reader, something was removed that a payload would have used, or a
 *             secret was redacted. Worth interrupting the reader for.
 *   NOTE    — this happened, and here is how to look at it, but nothing about it
 *             is attack-shaped. Incidental bytes, or content that was PRESERVED
 *             and merely described.
 *
 * The tier never changes what the pipeline DOES: the same bytes are stripped,
 * spliced and redacted either way, and a note is still reported. All that rides
 * on it is which banner the operator sees, which is why a note is the right
 * answer whenever the evidence is thin — an under-loud true finding is still
 * delivered, while an over-loud false one costs the channel its credibility.
 *
 * Mechanism only, deliberately: WHICH findings qualify is each layer's own
 * judgement, made where that layer's evidence lives (see isBenignAnsiKinds in
 * ./layer1.mjs, isIncidentalInvisible in ./invisible.mjs, and the exfil/HTML
 * tiers in ./output.mjs and ./index.mjs). This module owns the enum, the constructors and the
 * queries so nobody spells `severity === "warning"` by hand.
 */

/**
 * The closed severity vocabulary. Stable, machine-readable values: branch on
 * these, not on the prose.
 */
export const SEVERITY = Object.freeze({
  NOTE: "note",
  WARNING: "warning",
});

/**
 * @typedef {{ severity: string, message: string }} Finding
 *   A single reportable outcome and how loudly to report it.
 */

/**
 * A WARNING-severity finding: injection-shaped, worth the banner.
 * @param {string} message
 * @returns {Finding}
 */
export function warning(message) {
  return { severity: SEVERITY.WARNING, message };
}

/**
 * A NOTE-severity finding: reported, not alarming.
 * @param {string} message
 * @returns {Finding}
 */
export function note(message) {
  return { severity: SEVERITY.NOTE, message };
}

/**
 * A finding at `severity` — the constructor for a caller that has already
 * computed the tier as a boolean and would otherwise write the ternary itself.
 * @param {boolean} isWarning
 * @param {string} message
 * @returns {Finding}
 */
export function finding(isWarning, message) {
  return isWarning ? warning(message) : note(message);
}

/**
 * The messages of every WARNING-severity finding, in order.
 * @param {readonly Finding[]} findings
 * @returns {string[]}
 */
export function warningMessages(findings) {
  return findings
    .filter((entry) => entry.severity === SEVERITY.WARNING)
    .map((entry) => entry.message);
}

/**
 * The messages of every NOTE-severity finding, in order.
 * @param {readonly Finding[]} findings
 * @returns {string[]}
 */
export function noteMessages(findings) {
  return findings
    .filter((entry) => entry.severity === SEVERITY.NOTE)
    .map((entry) => entry.message);
}
