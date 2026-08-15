/**
 * Confusable-host detection for URLs in model-facing text. DETECTION ONLY.
 *
 * A homoglyph domain — Cyrillic `аpple.com`, all-Cyrillic `раураӏ.com` — reads
 * as a name it is not. The model comprehends it fine; that is the problem. What
 * cannot tell the difference is the byte-level machinery around the model: deny
 * rules, injection classifiers, log greps, and the human reading an approval
 * dialog.
 *
 * WHY THIS NEVER REWRITES, unlike the fold in ./confusables.mjs: folding a URL
 * in model-facing text would rewrite the attacker's `аpple.com` to the real
 * `apple.com`, laundering the deception into a name the model then reports with
 * confidence. The fold is sound only where the folded value is matched against
 * an ASCII deny target and the original bytes are re-derived (paths, commands).
 * Here the URL stays byte-identical and the finding names the deception.
 *
 * THE RULE, per DNS label: a label is a pretender when it holds a non-ASCII code
 * point and its TR39 skeleton is pure ASCII — it claims to be an ASCII word it
 * is not. That is the same argument the fold gate makes ("folds to pure ASCII"),
 * so it inherits the same precision story: a label keeping an unmapped glyph
 * after skeletoning (`россия` → `poccия`) is a real word in its own script, not
 * a disguise, and passes untouched. A weaker second tier, reported quietly,
 * covers the label that keeps an unmapped glyph but mixes scripts — see
 * {@link confusableLabel}.
 */

import { domainToUnicode } from "node:url";
import { scan, skeleton } from "namespace-guard";
import { hasNonAscii } from "./confusables.mjs";
import { SEVERITY } from "./severity.mjs";

/**
 * The deceptive reading of `label`, or null when it is not pretending to be an
 * ASCII name. Split from {@link confusableHost} so the rule is testable on a
 * bare label, without an URL around it.
 *
 * The two tiers are evidential strength, not attack class:
 *
 * WARNING — the WHOLE label skeletons to ASCII, so it reads as an ASCII name
 * outright, and no glyph in it survives as evidence of a real foreign word.
 * NOTE — the label carries a cross-script confusable but keeps an unmapped
 * glyph, so it does not read as any ASCII name. That is the "unmapped glyph
 * spliced in to suppress the strong rule" shape, and it is also what an ordinary
 * word with one look-alike letter produces, so the evidence is thin and the
 * finding stays quiet.
 * @param {string} label a single DNS label, already decoded from punycode
 * @returns {string | null} the label's severity, or null when it is not pretending
 */
export function confusableLabel(label) {
  if (!hasNonAscii(label)) return null;
  if (!hasNonAscii(skeleton(label))) return SEVERITY.WARNING;
  // `mixedScript` is namespace-guard's own judgement that this glyph sits in a
  // token holding Latin letters too; deriving it here from a hand-listed set of
  // "lookalike scripts" would be a second, drifting copy of its script data.
  const mixed = scan(label).findings.some((finding) => finding.mixedScript);
  return mixed ? SEVERITY.NOTE : null;
}

/**
 * The loudest confusable finding among `url`'s DNS labels, or null.
 *
 * `new URL()` is the only host parser here — hand-splitting an authority would
 * get userinfo, ports and IPv6 literals wrong — but it hands back the IDNA
 * A-label form (`xn--pple-43d.com`), which is the punycode, not the deception.
 * `domainToUnicode` reverses that, so a URL written either way reaches the rule
 * in the same shape. Both are `node:url` built-ins, so this costs no dependency.
 *
 * Fails OPEN on a URL the parser rejects: an unparseable authority is not
 * evidence of a disguise, and this repo weighs a false flag as the worse failure
 * (see the precision doctrine in CLAUDE.md). The parser runs IDNA ToASCII itself
 * and rejects undecodable punycode (`xn--a.com`) there, so `domainToUnicode`
 * below is only ever handed a host it can decode.
 * @param {string} url
 * @returns {{ severity: string, host: string, ascii: string, reads: string } | null}
 */
export function confusableHost(url) {
  let ascii;
  try {
    ascii = new URL(url).hostname;
  } catch {
    return null;
  }
  // ASCII fast-path: `new URL()` returns the A-label form, so a hostname with no
  // `xn--` label held no non-ASCII code point to begin with and cannot decode to
  // one. Skips the IDNA decode on the overwhelmingly common case. (The parser
  // lowercases the hostname, so an `XN--` spelling has already been folded.)
  if (!ascii.includes("xn--")) return null;
  const host = domainToUnicode(ascii);

  const severities = host
    .split(".")
    .map((label) => confusableLabel(label))
    .filter((severity) => severity !== null);
  if (severities.length === 0) return null;
  // Loudest member wins: one label that reads as an ASCII name is enough to make
  // the whole host read as one.
  const severity = severities.includes(SEVERITY.WARNING)
    ? SEVERITY.WARNING
    : SEVERITY.NOTE;
  // The reading is of the WHOLE host — a reader is deceived by `apple.com`, not
  // by the label `apple` — while the verdict above stays per-label, since a
  // label is the unit the skeleton rule can judge as a word.
  return { severity, host, ascii, reads: skeleton(host) };
}

/**
 * Operator-facing description of a confusable host: the deceptive form, the
 * punycode a resolver actually sees, and the ASCII name it reads as. All three,
 * because each answers a different question — what was written, what will be
 * fetched, and what the reader thought they saw.
 * @param {{ host: string, ascii: string, reads: string }} found
 * @returns {string}
 */
export function describeConfusableHost({ host, ascii, reads }) {
  return `${host} (${ascii}) reads as "${reads}"`;
}
