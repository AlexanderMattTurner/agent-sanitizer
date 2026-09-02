/**
 * Top-level convenience entry for agent-sanitizer.
 *
 * `sanitize` always runs the zero-dependency Layer 1 (invisible-char + ANSI
 * stripping, lone-surrogate normalization) and, when `html` is requested,
 * lazy-loads the heavier HTML layer (Layers 2 & 3) so the remark/rehype graph
 * is only paid for by callers that ask for it.
 *
 * Layers 1-3 are NOT implemented here: this module is a facade over the single
 * implementation in `./output.mjs` (`sanitizeText`). A hand-synced copy would
 * drift apart in its warning prose, so the layer bodies live in exactly one
 * place and this file only translates the facade's option/result shape.
 * Importing `./output.mjs` costs nothing at module scope — its graph is
 * dependency-free and it lazy-loads `./html.mjs` on the same terms this facade
 * does.
 *
 * The low-level building blocks stay public via the `./invisible` and `./html`
 * subpath entries; import those directly when you want a single layer without
 * the convenience wrapper.
 */
import { sanitizeText } from "./output.mjs";

// Layer 1 lives in the zero-dependency `./layer1.mjs`, shared verbatim with the
// tool-output pipeline (`./output`) and the Edit-repair rehydrator
// (`./rehydrate`) so every consumer derives the identical model-facing view.
export {
  applyLayer1,
  applyLayer1WellFormed,
  isBenignAnsi,
  isBenignAnsiKinds,
  normalizeLoneSurrogates,
  stripAnsiFully,
  LONE_SURROGATE_RE,
} from "./layer1.mjs";

// The SGR grammar's own module: whether preserving a text's escapes (rather than
// stripping them) would hand a model something a human cannot see. Layer 1 has
// no view of it — it strips either way — so this rides straight from the
// tokenizer that owns the parameter semantics.
export { sgrCarriesPayload, SGR_RUN_THRESHOLD } from "./ansi.mjs";

export {
  stripInvisible,
  stripInvisibleWithReport,
  isSgrOnly,
  STRIP,
  SGR_RE,
  CHECKS,
  CATEGORY,
  CATEGORY_LABELS,
  LINGUISTIC_SCRIPTS,
  VS,
  BLANK_NON_CF,
  LONG_RUN_RE,
  LONG_RUN_THRESHOLD,
  SCATTERED_THRESHOLD,
  findLongRuns,
  hasLongRun,
} from "./invisible.mjs";

// Layer 2/3 cheap pre-gates. Re-exported from the dependency-free `./gates.mjs`
// (not `./html.mjs`) so consumers can share the exact HTML-tag/markdown-link
// hints and secret-shape pre-gate without duplicating the regexes — and without
// pulling in the heavy remark/rehype graph that a re-export from `./html.mjs`
// would eagerly load on every root import.
export {
  HTML_TAG_PRESENT,
  MD_LINK_HINT,
  SECRET_HINT,
  SECRET_HINT_EXT,
  matchesSecretHint,
} from "./gates.mjs";

/**
 * Sanitize untrusted text before any LLM sees it.
 *
 * Always runs Layer 1 (invisible-char + ANSI stripping, lone-surrogate
 * normalization). When `html` is true, also lazy-loads the HTML layer to splice
 * out human-invisible HTML (comments, hidden elements — Layer 2) and detect
 * data-exfil-shaped URLs (Layer 3); the heavy remark/rehype dependency is only
 * imported on that path. The exfil scan runs on the pre-splice text so a beacon
 * URL hidden inside a `display:none` element is still reported, not buried by
 * its own removal.
 *
 * `found` names the categories neutralized; `warnings` carries the
 * operator-facing notices and `notes` the quiet tier (see `./severity.mjs`).
 * `cleaned` is always a string, and a change only
 * ever carries a warning (no silent suppression). `options` is optional and
 * tolerates an explicit `null`/`undefined` (treated the same as omitted) —
 * only a genuinely malformed `text` (not a string) throws, deliberately: a
 * caller passing the wrong TYPE for `text` gets a clear, named error instead
 * of an internal TypeError leaking implementation details (or a silent, wrong
 * coercion of e.g. a number to a string).
 *
 * The layer bodies live in `./output.mjs`; this is a facade over them, not a
 * second implementation (see the module doc). It narrows `sanitizeText`'s result
 * to the fields this entry promises — `modified`/`sgrNote` describe the
 * tool-output pipeline's banner, and `reveal` is produced only by options this
 * facade does not expose. `splices` IS passed through (present only when Layer 2
 * spliced): the placeholder→original pairs a caller needs to rehydrate keyed
 * Layer-2 placeholders — same field, same shape as `sanitizeText`'s, since this
 * facade wraps the same layers (grammar in `./html.mjs`: `layer2Placeholder` /
 * `LAYER2_PLACEHOLDER_RE`). `html` selects Layers 2 AND 3 together here, which
 * is the surface this entry has always had; `exfilScan` exposes Layer 3's
 * non-destructive detection on its own (unconditionally implied by `html`,
 * which it can add to but never switch off) for callers that must keep the
 * visible bytes intact — e.g. a PR diff where the Layer-2 splice would corrupt
 * legitimate markup — matching the separate flags `sanitizeText` takes for the
 * tool-output pipeline, which needs Layer 3's detection without Layer 2's
 * splice.
 *
 * `flagDigestValues` widens Layer 3 only: it drops the digest exemption, so an
 * exact-digest-length hex value under a generic parameter name is reported as
 * payload rather than read as a cache-buster or an ETag. Off by default, and
 * like `exfilScan` it can only ADD detection.
 * @param {string} text
 * @param {{ html?: boolean, exfilScan?: boolean, flagDigestValues?: boolean } | null} [options]
 * @returns {Promise<{ cleaned: string, found: string[], warnings: string[], notes: string[], splices?: Array<{ placeholder: string, original: string }> }>}
 */
export async function sanitize(text, options) {
  if (typeof text !== "string")
    throw new TypeError("sanitize(text, options): text must be a string");
  const {
    html = false,
    exfilScan = false,
    flagDigestValues = false,
  } = options ?? {};
  const { cleaned, found, warnings, notes, splices } = await sanitizeText(
    text,
    {
      html,
      // `html` implies the scan unconditionally, and `exfilScan` can only ADD it:
      // an opt-OUT would make `{ html: true, exfilScan: false }` splice Layer 2
      // while silently dropping Layer 3's report — a fail-open the docs deny.
      exfilScan: exfilScan || html,
      flagDigestValues,
    },
  );
  return {
    cleaned,
    found,
    warnings,
    notes,
    ...(splices !== undefined && { splices }),
  };
}
