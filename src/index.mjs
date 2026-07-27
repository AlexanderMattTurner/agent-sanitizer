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
import { applyLayer1, LONE_SURROGATE_RE } from "./layer1.mjs";

// Layer 1 lives in the zero-dependency `./layer1.mjs`, shared verbatim with the
// tool-output pipeline (`./output`) and the Edit-repair rehydrator
// (`./rehydrate`) so every consumer derives the identical model-facing view.
export { applyLayer1, stripAnsiFully, LONE_SURROGATE_RE } from "./layer1.mjs";

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

/** @param {{ comments: number, hidden: number }} removed */
function describeRemoved(removed) {
  const parts = [];
  if (removed.comments > 0) parts.push(`${removed.comments} HTML comment(s)`);
  if (removed.hidden > 0) parts.push(`${removed.hidden} hidden element(s)`);
  return parts.join(", ");
}

/** @param {{ tags: Record<string, number>, dataSrc: number }} warned */
function describeWarned(warned) {
  const parts = Object.entries(warned.tags).map(
    ([tag, count]) => `${tag}×${count}`,
  );
  if (warned.dataSrc > 0) parts.push(`data: URI×${warned.dataSrc}`);
  return parts.length > 0
    ? `Preserved but reported (page source kept inspectable): ${parts.join(", ")}`
    : "";
}

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
 * operator-facing notices. `cleaned` is always a string, and a change only
 * ever carries a warning (no silent suppression). `options` is optional and
 * tolerates an explicit `null`/`undefined` (treated the same as omitted) —
 * only a genuinely malformed `text` (not a string) throws, deliberately: a
 * caller passing the wrong TYPE for `text` gets a clear, named error instead
 * of an internal TypeError leaking implementation details (or a silent, wrong
 * coercion of e.g. a number to a string).
 * @param {string} text
 * @param {{ html?: boolean } | null} [options]
 * @returns {Promise<{ cleaned: string, found: string[], warnings: string[] }>}
 */
export async function sanitize(text, options) {
  if (typeof text !== "string")
    throw new TypeError("sanitize(text, options): text must be a string");
  const { html = false } = options ?? {};
  /** @type {string[]} */ const found = [];
  /** @type {string[]} */ const warnings = [];

  const { cleaned: layer1, deAnsi, found: invisFound } = applyLayer1(text);
  let cleaned = layer1;
  if (invisFound.length > 0) {
    found.push(...invisFound);
    warnings.push(describeStripped(invisFound, deAnsi));
  }

  const wellFormed = cleaned.replace(LONE_SURROGATE_RE, "\uFFFD");
  if (wellFormed !== cleaned) {
    cleaned = wellFormed;
    found.push(CATEGORY.LONE_SURROGATES);
    warnings.push("Normalized lone UTF-16 surrogates");
  }

  if (!html) return { cleaned, found, warnings };

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
      warnings.push(
        `HTML sanitized: ${describeRemoved(layer2.removed)} replaced with placeholders`,
      );
    }
    const preserved = describeWarned(layer2.warned);
    if (preserved) warnings.push(preserved);
  }

  const threats = detectExfil(preSplice);
  if (threats) {
    found.push(CATEGORY.EXFIL_URLS);
    const reasons = [
      ...new Set(
        threats.map(
          (threat) =>
            `${threat.isImage ? "image" : "link"} to ${threat.target}: ${threat.reason}`,
        ),
      ),
    ];
    warnings.push(`Exfil-shaped URLs detected: ${reasons.join("; ")}`);
  }

  return { cleaned, found, warnings };
}
