/**
 * Cheap, dependency-free pre-gates shared by the HTML layer (Layers 2 & 3) and
 * re-exported from both the package root and the `./html` subpath.
 *
 * These are pulled out of `html.mjs` so the package root can re-export them
 * without dragging in the heavy remark/rehype/unified graph: a static
 * `export … from "./html.mjs"` would eagerly evaluate that ~200ms module on
 * every root import, defeating the lazy-load design. This module imports
 * nothing, so re-exporting it is free.
 *
 * INVARIANT: every gate is a SUPERSET of its parser (a narrower one silently
 * turns its layer off; a needless fire only costs a parse), checked by
 * test/gates-superset.test.mjs.
 */

// ─── Cheap pre-gates ─────────────────────────────────────────────────────────

/**
 * Matches every point where the HTML tokenizer leaves the data state: `<` then
 * an ASCII letter, `/`, `!` or `?`. No closing `>` on purpose: a comment holding
 * `1 < 2`, or left unterminated, still hides everything after it. Gate for
 * Layer 2 and the HTML img/a exfil path in Layer 3.
 */
export const HTML_TAG_PRESENT = /<[a-zA-Z/!?]/;

/**
 * Matches markdown link/image syntax (`](`, `![`) and reference link
 * definitions (`[label]: url` at a line start, also nested in a blockquote or
 * list item). The label admits backslash escapes and line endings, as
 * CommonMark labels do, but no unescaped `[`, which also keeps the scan linear.
 * Gate for Layer 3 (markdown exfiltration detection).
 */
export const MD_LINK_HINT =
  /\]\(|!\[|^[ \t]*(?:(?:>|[-+*]|\d{1,9}[.)])[ \t]*)*\[(?:[^\\[\]]|\\[\s\S])+\]:/m;

/**
 * True when `text` is worth handing to the heavy remark/rehype graph at all:
 * Layers 2 and 3 can only find something in text that carries an HTML tag or a
 * markdown link. THE pre-gate for both entry points that run those layers
 * (`sanitize()` in ./index.mjs, `sanitizeText()` in ./output.mjs) — it lives
 * here, next to the two regexes it composes, so the two cannot gate on
 * different conditions and pay (or skip) the ~200ms import for different inputs.
 * @param {string} text
 * @returns {boolean}
 */
export function needsMarkdownPipeline(text) {
  return HTML_TAG_PRESENT.test(text) || MD_LINK_HINT.test(text);
}

/**
 * Matches the start of every URL a GFM autolink literal yields (`http://`,
 * `https://`, scheme-less `www.`). Gate for the Layer-3 URL detectors, which
 * find a look-alike host or exfil-shaped query in bare prose. (A bare e-mail
 * becomes a host-less `mailto:` URL that neither detector can flag.)
 */
export const URL_PRESENT = /https?:\/\/|www\./i;

/**
 * True when Layer 3 (exfil + confusable-host detection) can find something.
 * A superset of {@link needsMarkdownPipeline}: a markup-bearing document can
 * carry a relative exfil target (`[x](/collect?d=…)`), and a plain-prose one
 * can carry an absolute URL with no markup at all. Layer 2 keeps the narrower
 * gate — it can only splice what a tag delimits.
 * @param {string} text
 * @returns {boolean}
 */
export function needsUrlScan(text) {
  return URL_PRESENT.test(text) || needsMarkdownPipeline(text);
}

// A comment / bogus-comment open: hides everything after it, closed or not.
const MARKUP_DECLARATION_OPEN = /<[!?]/;

/**
 * POLICY, not a gate: true when `text` reads as HTML rather than data that
 * merely holds a `<` (a comment open, or a tag open with a `>` after it). The
 * output hook uses it to decide whether an MCP result earns the Layer-2 splice,
 * so `a<b` stays verbatim; kept apart from {@link HTML_TAG_PRESENT} so widening
 * the gate never widens the policy. Linear, unlike a `<…[^>]*>` regex.
 * @param {string} text
 * @returns {boolean}
 */
export function isHtmlShaped(text) {
  if (MARKUP_DECLARATION_OPEN.test(text)) return true;
  const open = text.search(HTML_TAG_PRESENT);
  return open !== -1 && text.includes(">", open + 2);
}

// ─── Secret-shape pre-gate (Layer 3 URL-param reuse) ─────────────────────────
// Cheap shape match that decides whether a URL parameter value carries a
// credential (Layer 3). This hand-duplicates credential-shape knowledge that
// also lives in the Python detect-secrets detectors (python/.../secret-detectors.json)
// — a deliberately BROADER, shorter-run superset that adds keyword and
// non-detector shapes (AWS `AKIA…`, JWT `eyJ…`, Slack `xox…`, …) and trims each
// opaque run for ReDoS-safety. It is NOT derivable from that JSON: inlining the
// detector regexes would reintroduce the cross-arm polynomial backtracking the
// two-alternation split below exists to prevent, so this is a distinct
// representation for a distinct constraint, not a copy. drift-guard-ok: that
// duplication can't be collapsed to one source, so a test instead guards it —
// test/secret-detectors-portability.test.mjs drives from the JSON and fails
// the moment a detector is added/changed without a matching arm here —
// extend SECRET_HINT when that fires.
// Split across TWO regexes, combined by matchesSecretHint:
// one alternation of every arm makes a redos analyzer see cross-arm polynomial
// backtracking (each arm is linear alone, but the union was a 3rd-degree
// polynomial on a long alnum run). Testing two independently-safe literals with
// || is linear and keeps each under the analyzer's bar. The `(?<!...)`
// lookbehinds on the EXT run-matching arms pin them to a token boundary so they
// can't be retried at every offset; the atlasv1 arm in SECRET_HINT does the same.
/** @type {RegExp} */
export const SECRET_HINT =
  /secret|token|password|passwd|pwd|bearer|credential|authorization|contrase[nñ]a|-----BEGIN|(?:api|auth|service|account|db|database|priv|private|client|access)[_-]?key|(?:db|database|key)[_-]?pass|(?:A3T|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]|github_pat_|gl[a-z]{2,12}-[0-9A-Za-z_-]{20}|sk-ant-|AIza[0-9A-Za-z_-]{35}|sk_live_|sk_test_|rk_live_|rk_test_|xox[bpasr]-|eyJ[A-Za-z0-9]|do[opr]_v1_[a-f0-9]{16}|v1\.0-[a-f0-9]{24}-|hv[sb]\.[A-Za-z0-9_-]{20}|(?<![a-z0-9])[a-z0-9]{14}\.atlasv1\.|sk-or-|gsk_[A-Za-z0-9]{16}|xai-[A-Za-z0-9]{16}|r8_[A-Za-z0-9]{16}/i;

// Second alternation (see SECRET_HINT): kept a separate literal so a redos
// analyzer vets each alternation in isolation.
/** @type {RegExp} */
export const SECRET_HINT_EXT =
  /(?:AC|SK)[a-z0-9]{32}|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}|sq0csp-[0-9A-Za-z_-]{43}|(?<![0-9])[0-9]{8,10}:[0-9A-Za-z_-]{35}|(?<![0-9a-z])[0-9a-z]{32}-us[0-9]{1,2}|(?<![A-Za-z0-9_-])[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}|T3BlbkFJ|pypi-AgE|(?<![A-Za-z0-9])AKC[A-Za-z0-9]{10}|(?<![A-Za-z0-9])AP[0-9A-Fa-f][A-Za-z0-9]{8}|:\/\/[^\s:/@]{1,64}:[^\s:/@]{1,64}@|(?:key|pw|pass)["']?[\s:=>]+["']?[A-Za-z0-9_/+-]{20}/i;

/**
 * Either alternation against `text` exactly as written.
 * @param {string} text
 * @returns {boolean}
 */
function hintMatchesView(text) {
  return SECRET_HINT.test(text) || SECRET_HINT_EXT.test(text);
}

/**
 * True when either pre-gate alternation shape-matches `text`, or the same text
 * with every `\n` removed (the view the engine's `_redact_cross_line` scans, so
 * this stays a superset of the redactor). Two literals OR'd so neither grows
 * into a polynomial-backtracking shape (see SECRET_HINT).
 * @param {string} text
 * @returns {boolean}
 */
export function matchesSecretHint(text) {
  if (hintMatchesView(text)) return true;
  return text.includes("\n") && hintMatchesView(text.replace(/\n/g, ""));
}
