/**
 * Top-level convenience entry for agent-sanitizer.
 *
 * `sanitize` always runs the zero-dependency Layer 1 (invisible-char + ANSI
 * stripping, lone-surrogate normalization) and, when `html` is requested,
 * lazy-loads the heavier HTML layer (Layers 2 & 3) so the remark/rehype graph
 * is only paid for by callers that ask for it.
 *
 * The low-level building blocks stay public via the `./invisible` and `./html`
 * subpath entries; import those directly when you want a single layer without
 * the convenience wrapper.
 */
import { CATEGORY, describeStripped } from "./invisible.mjs";
import { needsMarkdownPipeline } from "./gates.mjs";
import { applyLayer1, LONE_SURROGATE_RE } from "./layer1.mjs";
import {
  describeExfil,
  describeHtmlSanitized,
  describeWarned,
  LONE_SURROGATE_WARNING,
} from "./warnings.mjs";
import {
  finding,
  note,
  noteMessages,
  warning,
  warningMessages,
} from "./severity.mjs";

// Layer 1 lives in the zero-dependency `./layer1.mjs`, shared verbatim with the
// tool-output pipeline (`./output`) and the Edit-repair rehydrator
// (`./rehydrate`) so every consumer derives the identical model-facing view.
export {
  applyLayer1,
  isBenignAnsi,
  isBenignAnsiKinds,
  stripAnsiFully,
  LONE_SURROGATE_RE,
} from "./layer1.mjs";

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
 * `found` names the categories neutralized. Notices come back SPLIT BY
 * SEVERITY (see ./severity.mjs): `warnings` is the injection-shaped set a
 * caller must surface, `notes` is what happened but is not alarming — the
 * preserved `<script>` that nearly every fetched page carries, and a
 * deliberately-followed link whose URL merely looks exfil-shaped. A caller that
 * ignores `notes` is no louder than before, and `warnings` keeps exactly the
 * meaning it always had. Layer 1's own findings stay LOUD here whatever their
 * size, unlike in `./output`: that pipeline downgrades an incidental strip only
 * under its `sgrCarveOut` (the caller asserting local, first-party output),
 * while this door has no such signal and must assume untrusted ingress — the
 * one channel where a single hidden character was PUT there.
 *
 * `cleaned` is always a string, and a change only ever carries a notice (no
 * silent suppression). `options` is optional and
 * tolerates an explicit `null`/`undefined` (treated the same as omitted) —
 * only a genuinely malformed `text` (not a string) throws, deliberately: a
 * caller passing the wrong TYPE for `text` gets a clear, named error instead
 * of an internal TypeError leaking implementation details (or a silent, wrong
 * coercion of e.g. a number to a string).
 * @param {string} text
 * @param {{ html?: boolean } | null} [options]
 * @returns {Promise<{ cleaned: string, found: string[], warnings: string[], notes: string[] }>}
 */
export async function sanitize(text, options) {
  if (typeof text !== "string")
    throw new TypeError("sanitize(text, options): text must be a string");
  const { html = false } = options ?? {};
  /** @type {string[]} */ const found = [];
  /** @type {import("./severity.mjs").Finding[]} */ const findings = [];

  const { cleaned: layer1, deAnsi, found: invisFound } = applyLayer1(text);
  let cleaned = layer1;
  // Every return goes through here, so no exit can forget to split the tiers.
  const report = () => ({
    cleaned,
    found,
    warnings: warningMessages(findings),
    notes: noteMessages(findings),
  });
  if (invisFound.length > 0) {
    found.push(...invisFound);
    findings.push(warning(describeStripped(invisFound, deAnsi)));
  }

  const wellFormed = cleaned.replace(LONE_SURROGATE_RE, "\uFFFD");
  if (wellFormed !== cleaned) {
    cleaned = wellFormed;
    found.push(CATEGORY.LONE_SURROGATES);
    findings.push(warning(LONE_SURROGATE_WARNING));
  }

  // Layers 2 and 3 can only find something in text carrying an HTML tag or a
  // markdown link, so the shared pre-gate decides whether the heavy
  // remark/rehype graph is imported at all — the same gate `sanitizeText()`
  // applies, so both entry points pay for (and skip) the import on exactly the
  // same inputs.
  if (!html || !needsMarkdownPipeline(cleaned)) return report();

  let sanitizeHtml, detectExfil;
  /* c8 ignore start -- a rejected dynamic import of a module that ships in
     this very package (not an optional peer dep) requires corrupting
     node_modules or the filesystem to trigger; there's no clean way to force
     this from a test without fragile module-loader mocking (Node's
     mock.module needs --experimental-test-module-mocks, which isn't wired
     into this repo's test script). Fail loudly with context if it ever fires. */
  try {
    ({ sanitizeHtml, detectExfil } = await import("./html.mjs"));
  } catch (importErr) {
    throw new Error(
      "sanitize: failed to load HTML module (is the optional HTML dependency installed?)",
      { cause: importErr },
    );
  }
  /* c8 ignore stop */
  // Scan for exfil URLs on the text BEFORE Layer 2 splices anything out — a
  // beacon URL hidden in a comment or hidden element is more suspicious, not
  // less, yet Layer 2 would otherwise remove it from view before the scan.
  const preSplice = cleaned;

  const layer2 = sanitizeHtml(cleaned);
  if (layer2) {
    if (layer2.text !== cleaned) {
      cleaned = layer2.text;
      if (layer2.removed.comments > 0) found.push(CATEGORY.HTML_COMMENTS);
      if (layer2.removed.hidden > 0) found.push(CATEGORY.HIDDEN_HTML);
      // A WARNING: these bytes were invisible to a human reading the rendered
      // page and are gone from the model's view too — the shape of a
      // hidden-instruction payload.
      findings.push(warning(describeHtmlSanitized(layer2.removed)));
    }
    // A NOTE: nothing was removed and nothing was hidden (see describeWarned).
    const preserved = describeWarned(layer2.warned);
    if (preserved) findings.push(note(preserved));
  }

  const threats = detectExfil(preSplice);
  if (threats) {
    found.push(CATEGORY.EXFIL_URLS);
    // Severity tracks who does the fetching: an auto-fetched target (an image,
    // a stylesheet, a form action, a meta refresh) exfiltrates the moment the
    // content renders, with nobody deciding anything, while a plain link cannot
    // until the model chooses to follow it — and the sentence it is reported in
    // is precisely the instruction not to. One auto-fetched threat raises the
    // whole finding, since they share one line.
    findings.push(
      finding(
        threats.some((threat) => threat.autoFetched),
        describeExfil(threats),
      ),
    );
  }

  return report();
}
