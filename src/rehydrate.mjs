/**
 * Edit-repair: re-anchor an Edit/Write composed from a sanitized file view back
 * onto the real on-disk bytes.
 *
 * Sanitizing the model's view of a file makes that view diverge from disk in
 * two ways: Layer 1 strips ANSI escapes and payload-capable invisible
 * characters, and secret redaction replaces secrets with [REDACTED…]
 * placeholders. An Edit whose old_string was copied from that view then fails
 * exact-match against the real file, and a whole-file Write would persist
 * placeholder text over the real secret. This module closes the loop without
 * ever showing the model a secret: it re-derives the sanitized view of the
 * target file (the shared {@link applyLayer1}, then the injected redactor's
 * map mode), locates the model's old_string in that view, and maps it
 * span-exact back to the on-disk bytes — across both placeholder expansion and
 * stripped invisible runs (the offset machinery lives in `./view-map.mjs`).
 * Placeholders in new_string are substituted with the secrets they stand for;
 * invisible characters inside the replaced region go with it, while runs
 * outside the span are preserved untouched. The secret flows disk → tool input
 * only; the model's next view is sanitized again.
 *
 * Security invariant: rehydration must never *expose a secret this call
 * rehydrated*. Before rewriting, the would-be post-edit content is
 * re-sanitized and the call is denied if any secret THIS EDIT resolved from a
 * placeholder would survive in the model's next view of the file (e.g. an
 * edit whose old_string/new_string carries a `[REDACTED…]` placeholder and
 * relabels `password=` to a field the redactor skips).
 *
 * Scope: this check only runs for edits that touch a placeholder. An edit
 * that relabels a field WITHOUT altering its placeholder or value at all
 * (e.g. old_string: "password=", new_string: "notes=" — neither string
 * contains a placeholder) never reaches the exposure simulation; see the
 * early-exit comments near `rehydrateEdit`'s "span is byte-identical" check
 * and `rehydrateRedacted`'s "hint-free, view matches disk" check below. That
 * gap is an accepted scope limit, not an oversight: simulating full-file
 * exposure on every relabel-adjacent edit would re-run redaction over the
 * whole file on every Edit call, and a broader check risks false denials on a
 * legitimate relabel in a large file — this module's fail-open-on-ambiguity
 * doctrine prefers the false negative there. Catching a bare relabel (no
 * placeholder touched) is the redactor's own field-name heuristics' job, if
 * it has any — not this module's. Every unresolvable case this module DOES
 * cover fails closed as a deny whose reason tells the model how to
 * restructure the call; nothing this module rehydrates is ever silently
 * written with placeholder text standing in for a secret.
 *
 * MultiEdit is GATED, not rehydrated. Its edits apply sequentially, each
 * against the file state the previous edit produced, so the span-exact
 * view↔disk mapping performed for a single Edit has no sound equivalent —
 * after the first splice the disk no longer matches the view the remaining
 * old_strings were copied from. A MultiEdit passes through only when the view
 * provably equals disk and no edit names a placeholder (the common case);
 * every other case — a divergent view, an unmappable or defective map, or
 * placeholder text over a pristine file (the same foreign-placeholder rule a
 * byte-identical Write is denied under) — is denied via {@link multiEditDeny}
 * with guidance to re-issue the changes as single Edit calls, which ARE
 * re-anchored. The previous full pass-through was both a silent clobber
 * (placeholder persisted over a secret) and the same char-extraction oracle
 * the Edit path's hidden-span rule (R1) closes.
 *
 * I/O is INJECTED through `io`: the caller supplies file reads and the secret
 * redactor (its map/plain contract). The package never bundles a redactor —
 * detect-secrets, a daemon, or any other engine is the caller's to wire.
 */
import { applyLayer1, LONE_SURROGATE_RE } from "./layer1.mjs";
import {
  occurrences,
  overlapAwareCount,
  orderedMatches,
  spliceOrdered,
  alignDeletions,
  resolveSpan,
  rehydrateNewString,
  makeFileView,
  pairDiskSpans,
  viewMapDefect,
} from "./view-map.mjs";

// Cheap gate: every redaction placeholder the canonical redactor emits starts
// with this. A caller whose placeholders differ overrides it via the `hint`
// option below.
export const DEFAULT_HINT = "[REDACTED";

/**
 * Map-mode response from the redactor: either the mappable view (text + ordered
 * (placeholder, original, start) pairs) or an unmappable verdict carrying its
 * reason — a discriminated pair.
 * @typedef {{text: string, pairs: {placeholder: string, original: string, start: number}[]}
 *   | {unmappable: string}} RedactMapView
 */

/**
 * Injected I/O. `readFile` returns the file's bytes (throwing on a missing or
 * unreadable path). `redactMap` returns the redacted view of (Layer-1-cleaned)
 * file text plus the ordered (placeholder, original, start) pairs, or an
 * `{unmappable}` verdict. `redact` returns the plain redacted text, or null
 * when nothing was redacted. `redactMap`/`redact` are the only secret-engine
 * seam; they may be async and are awaited.
 * @typedef {{ readFile: (path: string) => string,
 *   redactMap: (text: string) => Promise<RedactMapView> | RedactMapView,
 *   redact: (text: string) => Promise<string|null> | (string|null) }} RehydrateIo
 */

/**
 * Layer 1, then the same lone-surrogate normalization `output.mjs`'s
 * `processLayer1` applies before any further layer (including redaction)
 * runs — so text handed to the redactor here, and matched against the
 * model's old_string, is byte-identical to what the model was actually
 * shown. `layer1Cleaned` (pre-normalization) is also returned: callers that
 * need `alignDeletions` require a true subsequence of the original text, and
 * the normalization is a same-length SUBSTITUTION (one lone-surrogate UTF-16
 * unit -> one U+FFFD unit), not a deletion — folding it into the deletion
 * calculation would break that subsequence invariant. Because the
 * substitution never changes length, deletions computed against
 * `layer1Cleaned` stay position-valid against `cleaned`.
 * @param {string} text
 * @returns {{layer1Cleaned: string, cleaned: string}}
 */
function layer1View(text) {
  const { cleaned: layer1Cleaned } = applyLayer1(text);
  return {
    layer1Cleaned,
    cleaned: layer1Cleaned.replace(LONE_SURROGATE_RE, "\uFFFD"),
  };
}

/**
 * Count of secrets the model's *next* sanitized view of `newContent` would
 * reveal, excluding any already visible in the prior view (no regression
 * there). The next view is Layer 1 (+ lone-surrogate normalization) then
 * redaction, exactly as a PostToolUse sanitizer derives it.
 * @param {string[]} secrets rehydrated values written into newContent
 * @param {string} priorView sanitized view of the file before the change
 * @param {string} newContent would-be post-change file content
 * @param {RehydrateIo} io
 * @returns {Promise<number>}
 */
async function exposedSecrets(secrets, priorView, newContent, io) {
  const candidates = [...new Set(secrets)].filter(
    (value) => !priorView.includes(value),
  );
  if (candidates.length === 0) return 0;
  const { cleaned } = layer1View(newContent);
  const redacted = (await io.redact(cleaned)) ?? cleaned;
  return candidates.filter((value) => redacted.includes(value)).length;
}

/** @param {number} count */
function exposureDeny(count) {
  return (
    `this change would move ${count} secret value(s) into a context the redactor no ` +
    `longer recognizes, so the next read of the file would reveal them; keep each ` +
    `secret under its recognizable field name, or ask the user to make this change`
  );
}

/**
 * @param {{file_path: string, old_string: string, new_string: string, replace_all?: boolean}} ti
 * @param {string} content disk bytes
 * @param {string} cleaned Layer-1 view of `content`
 * @param {import("./view-map.mjs").FileView} view
 * @param {{start: number, deleted: string}[]} deletions
 * @param {RehydrateIo} io
 * @param {boolean} hinted the input itself carries placeholders
 * @param {string} hint placeholder prefix
 */
async function rehydrateEdit(
  ti,
  content,
  cleaned,
  view,
  deletions,
  io,
  hinted,
  hint,
) {
  const oldS = ti.old_string;
  // An empty old_string is not a view span the model copied — in real Edit it
  // is the create/insert-at-anchor case, which Edit handles itself. There is
  // nothing to re-anchor; pass through (null) so Edit surfaces its own
  // behavior and the empty needle never reaches occurrences.
  if (oldS === "") return null;
  // Resolve against the VIEW first — it is the only thing the model can have
  // copied from. A verbatim disk match is only trusted when the view has no
  // match: on a divergent file, raw bytes can contain an accidental match
  // spanning a stripped sequence's tail, which would mis-anchor the edit.
  const viewOcc = occurrences(view.text, oldS);
  if (viewOcc.length === 0) {
    // Not in the model's view. A verbatim disk match means the input targets
    // literal bytes (e.g. literal "[REDACTED]" prose); new_string still goes
    // through the resolver (with an empty span) so a placeholder referencing a
    // secret elsewhere in the file is denied with guidance instead of being
    // written out literally.
    if (content.includes(oldS)) {
      // R1: the old_string is invisible in the model's view yet matches disk.
      // If a disk match cuts INTO a redacted secret's on-disk span without
      // covering the whole secret, the model is targeting bytes it never saw —
      // a stray match, or a probe (`old:"-" → "\n-"`) that splits the secret so
      // the next redaction pass stops matching it, leaking it. That is never a
      // legitimate re-anchor; fail closed. A match that WHOLLY contains a secret
      // (the model supplied the secret's real bytes itself, e.g. a rotation)
      // extracts nothing and is left to the literal resolver below.
      const diskSpans = pairDiskSpans(view, deletions);
      let intrusion = null;
      for (const matchStart of occurrences(content, oldS)) {
        const matchEnd = matchStart + oldS.length;
        const secret = diskSpans.find(
          (span) =>
            matchStart < span.end &&
            span.start < matchEnd &&
            !(matchStart <= span.start && span.end <= matchEnd),
        );
        if (secret) {
          intrusion = { matchStart, matchEnd, secret };
          break;
        }
      }
      // Report both byte ranges. The refusal is conservative — it fires on an
      // overlap with the redacted span the caller cannot see — so the caller
      // needs the ranges to tell a true overlap from a mis-sized redaction.
      if (intrusion)
        return {
          deny:
            `old_string does not appear in the sanitized view of ${ti.file_path}; on disk ` +
            `it matches bytes ${intrusion.matchStart}-${intrusion.matchEnd}, which fall ` +
            `inside a ${hint}…] redacted secret at bytes ${intrusion.secret.start}-` +
            `${intrusion.secret.end} that are hidden from your view; edit only text you ` +
            `can see (include each placeholder whole), or ask the user to make this change`,
        };
      const literalRes = rehydrateNewString(
        oldS,
        ti.new_string,
        [],
        view.pairs,
      );
      return "deny" in literalRes ? literalRes : null;
    }
    // Without placeholders this is an ordinary stale/typo'd old_string; pass
    // through so the model gets Edit's familiar not-found error.
    if (!hinted) return null;
    return {
      deny:
        `old_string contains ${hint}…] placeholders but does not match the sanitized ` +
        `view of ${ti.file_path}; re-read the file and copy the placeholder text exactly`,
    };
  }
  // R5: `occurrences` steps by the needle length, so a self-overlapping
  // old_string ("aa" in "aaa") reports a single match and would slip past the
  // >1 gate — yet it has multiple anchors the view can differ from disk at.
  // Count with overlap awareness so the ambiguity is caught.
  const viewMatchCount = overlapAwareCount(view.text, oldS);
  if (viewMatchCount > 1 && !ti.replace_all)
    return {
      deny:
        `old_string matches ${viewMatchCount} locations in the sanitized view of ` +
        `${ti.file_path}, and the view can differ from disk at each (redacted ` +
        `secrets, stripped invisible characters); add surrounding context to make it unique`,
    };

  const spans = [];
  for (const start of viewOcc) {
    const resolved = resolveSpan(
      content,
      cleaned,
      view,
      deletions,
      start,
      start + oldS.length,
    );
    if (resolved === null)
      return {
        deny: `old_string starts or ends inside a ${hint}…] placeholder; include each placeholder whole`,
      };
    spans.push(resolved);
  }
  if (new Set(spans.map((span) => span.diskText)).size > 1)
    return {
      deny:
        `replace_all matched occurrences whose on-disk bytes differ (distinct secrets ` +
        `or invisible characters) in ${ti.file_path}; edit each occurrence separately ` +
        `with unique context`,
    };

  // Identical view spans hide identical disk text, so every span carries the
  // same placeholder/original sequence — resolve new_string against the first.
  const span = spans[0];
  // R2: replace_all rewrites EVERY on-disk occurrence of the resolved bytes, but
  // only the sanitized-view occurrences were vetted. Each view occurrence maps to
  // exactly one disk occurrence, so a larger disk count means extra matches exist
  // where the view can't show them — inside a redacted secret's on-disk span, or
  // a stripped run. real Edit would splice those hidden bytes too (splitting a
  // secret so the redactor stops matching it, or corrupting it); fail closed.
  const diskMatchCount = occurrences(content, span.diskText).length;
  if (ti.replace_all && diskMatchCount !== viewOcc.length)
    return {
      deny:
        `replace_all would rewrite ${diskMatchCount} on-disk occurrence(s) of the matched ` +
        `text but only ${viewOcc.length} are visible in the sanitized view of ` +
        `${ti.file_path}; the rest are hidden inside redacted secrets or stripped ` +
        `characters. Edit each visible occurrence separately with unique context, or ask ` +
        `the user to make this change`,
    };
  // Soundness gate (see resolveSpan): greedy deletion alignment can anchor a
  // view span to the wrong disk bytes when a stripped run abuts kept text it
  // resembles. Refuse on either symptom:
  //   (a) the resolved bytes do not re-clean to the span's view — the run stole
  //       a visible character (an ANSI sequence ending in "m" before a kept "m");
  //   (b) the bytes carry an interior stripped run yet the plain old_string also
  //       exists verbatim on disk — a purely-invisible collision (e.g. a
  //       zero-width char inside an otherwise-identical run) re-cleans cleanly,
  //       so (a) misses it, but a verbatim clean occurrence means the model's
  //       text could equally well anchor there. Either way the anchor is
  //       ambiguous; fail closed rather than edit the wrong region.
  const anchorAmbiguous =
    layer1View(span.diskText).cleaned !== span.cleanedText ||
    (span.diskText !== oldS && content.includes(oldS));
  if (anchorAmbiguous)
    return {
      deny:
        `the matched region sits next to stripped control sequences that cannot be ` +
        `re-anchored unambiguously in ${ti.file_path}; edit a smaller region away ` +
        `from them, or ask the user to make this change`,
    };
  const newRes = rehydrateNewString(
    oldS,
    ti.new_string,
    span.pairs,
    view.pairs,
  );
  if ("deny" in newRes) return newRes;

  // The span is byte-identical to disk (no pairs, no interior runs): nothing
  // to translate. The empty-span resolver above already vetted new_string.
  // No placeholder was touched, so this exit also skips the exposure
  // simulation below — in scope per the module doc's "Security invariant"
  // note: a relabel that never names a placeholder is an accepted gap, not
  // covered here.
  if (span.diskText === oldS && newRes.text === ti.new_string) return null;

  // Simulate the post-edit content for the exposure check. When the disk
  // old_string is not unique and replace_all is off, Edit itself will refuse
  // the call, so nothing is written and there is nothing to check.
  const diskOcc = occurrences(content, span.diskText);
  let updated = null;
  if (ti.replace_all) updated = content.split(span.diskText).join(newRes.text);
  else if (diskOcc.length === 1)
    updated =
      content.slice(0, diskOcc[0]) +
      newRes.text +
      content.slice(diskOcc[0] + span.diskText.length);
  if (updated !== null) {
    const exposed = await exposedSecrets(
      newRes.secrets,
      view.text,
      updated,
      io,
    );
    if (exposed > 0) return { deny: exposureDeny(exposed) };
  }

  const notes = [
    span.pairs.length > 0 &&
      `${hint}…] placeholders were resolved to the file's real secret values (still hidden from you)`,
    span.invisibleBytes > 0 &&
      `the matched region carries ${span.invisibleBytes} invisible/control character(s) stripped from your view; they are replaced along with it`,
  ].filter(Boolean);
  return {
    updatedInput: { ...ti, old_string: span.diskText, new_string: newRes.text },
    context: `Edit input was translated to the file's actual on-disk bytes: ${notes.join("; ")}.`,
  };
}

/**
 * Foreign redaction placeholders surviving in post-substitution content `out`:
 * hint-prefixed, placeholder-shaped tokens that are neither introduced by a
 * substituted secret (they fall inside `secretSpans`) nor already present
 * verbatim in the file's own sanitized `viewText` (a genuine same-file
 * placeholder, or literal prose like `[REDACTEDXYZ]` that merely shares the hint
 * prefix). A non-empty result means the Write pasted a `[REDACTED…]` placeholder
 * from another file or context that would be persisted verbatim in place of a
 * real secret. Comparing the actual token strings — not scalar hint counts —
 * catches a count-offsetting edit (drop one literal hint, add one foreign
 * placeholder) that a scalar `>` gate lets through.
 * @param {string} out post-substitution content
 * @param {string} hint placeholder prefix
 * @param {string} viewText the file's own sanitized view
 * @param {{start: number, end: number}[]} secretSpans byte ranges of substituted secrets in `out`
 * @returns {string[]}
 */
function foreignPlaceholders(out, hint, viewText, secretSpans) {
  const foreign = [];
  for (const start of occurrences(out, hint)) {
    if (secretSpans.some((span) => span.start <= start && start < span.end))
      continue;
    // Extend the token to the placeholder's closing "]"; a hint with no closing
    // bracket is malformed, so treat the rest of the string as its text and let
    // the same-view check below decide (an unclosed hint absent from the view
    // is foreign, failing closed).
    const close = out.indexOf("]", start + hint.length);
    const token = close === -1 ? out.slice(start) : out.slice(start, close + 1);
    // Genuine same-file text: the exact token already exists in the file's own
    // sanitized view (an own placeholder, or hint-prefixed prose it documents).
    if (viewText.includes(token)) continue;
    foreign.push(token);
  }
  return foreign;
}

/**
 * @param {{file_path: string, content: string}} ti
 * @param {import("./view-map.mjs").FileView} view
 * @param {RehydrateIo} io
 * @param {string} hint placeholder prefix
 */
async function rehydrateWrite(ti, view, io, hint) {
  const texts = [...new Set(view.pairs.map((pair) => pair.placeholder))].filter(
    (phText) => ti.content.includes(phText),
  );
  // None of THIS file's redaction placeholders appear in the new content.
  // isCandidate already guaranteed ti.content contains the hint prefix (e.g.
  // "[REDACTED"), so an empty `texts` here means the content carries a
  // placeholder-shaped string that names a secret from a DIFFERENT file or
  // context (or a stale/mistyped one) — not literal prose. Persisting it
  // verbatim would silently write "[REDACTED:…]" into the file where the
  // model likely intended an actual secret value; deny instead.
  if (texts.length === 0)
    return {
      deny:
        `the ${hint}…] placeholder in the new content does not match any secret in ` +
        `${ti.file_path}, so a whole-file Write cannot copy a placeholder from another ` +
        `file or context; request the source file's content and rehydrate a same-file ` +
        `Edit instead, or write the secret's real value directly`,
    };

  // Resolve each of this file's placeholder texts to its single secret first,
  // then splice in ONE ordered pass (R6) via the shared `spliceOrdered` — see
  // its doc for why a chained `out.split(ph).join(secret)` per placeholder is
  // unsound.
  const valueByPh = new Map();
  for (const phText of texts) {
    const produced = view.pairs.filter((pair) => pair.placeholder === phText);
    if (occurrences(view.text, phText).length > produced.length)
      return {
        deny:
          `${ti.file_path} mixes literal "${phText}" text with a redacted secret sharing ` +
          `that placeholder; cannot tell which occurrences in the new content are ` +
          `which — use Edit with unique surrounding context instead`,
      };
    const values = [...new Set(produced.map((pair) => pair.original))];
    if (values.length > 1)
      return {
        deny:
          `multiple distinct secrets in ${ti.file_path} share the placeholder "${phText}", ` +
          `so a whole-file Write cannot tell which is which; use Edit with unique ` +
          `surrounding context for each`,
      };
    valueByPh.set(phText, values[0]);
  }
  // `secretSpans`: byte ranges in `out` occupied by the substituted secret
  // values. A hint occurrence inside one of these is a pathological secret whose
  // bytes contain the hint prefix, NOT a placeholder the model pasted — so it is
  // excluded from the foreign-placeholder scan below.
  const { text: out, spans: secretSpans } = spliceOrdered(
    ti.content,
    orderedMatches(ti.content, texts),
    (match) => valueByPh.get(match.text),
  );
  const secrets = [...valueByPh.values()];

  // R3: the new content may mix a valid same-file placeholder (substituted
  // above) with a FOREIGN one — a placeholder pasted from another file/context
  // that shares the hint prefix but is not one of this file's own. Those were
  // left untouched and would be persisted verbatim over a real secret. Compare
  // the ACTUAL placeholder STRINGS, not scalar hint counts: a scalar comparison
  // is defeated by an edit that drops one literal hint and adds one foreign
  // placeholder (the counts net to zero), which would then persist the foreign
  // placeholder. Deny when any genuinely-foreign placeholder survives.
  if (foreignPlaceholders(out, hint, view.text, secretSpans).length > 0)
    return {
      deny:
        `the new content still carries a ${hint}…] placeholder that does not match any ` +
        `secret in ${ti.file_path}, so a whole-file Write cannot copy a placeholder from ` +
        `another file or context; request the source file's content and rehydrate a ` +
        `same-file Edit instead, or write the secret's real value directly`,
    };

  const exposed = await exposedSecrets(secrets, view.text, out, io);
  if (exposed > 0) return { deny: exposureDeny(exposed) };

  return {
    updatedInput: { ...ti, content: out },
    context:
      `Write content contained ${hint}…] placeholders; they were resolved to the ` +
      `file's real secret values on disk (still hidden from you), so the secrets ` +
      `are preserved in the written file.`,
  };
}

/**
 * The one deny shape every unresolvable MultiEdit takes (see the module doc:
 * MultiEdit is gated, not rehydrated). Rather than splice at guessed anchors
 * (the silent clobber) or pass hidden-span probes through (the extraction
 * oracle R1 closes for Edit), every case that cannot be proven
 * view==disk-and-hint-free is denied with the same restructuring guidance:
 * single Edit calls, which ARE re-anchored.
 * @param {string} filePath
 * @param {string} why
 * @returns {{deny: string}}
 */
function multiEditDeny(filePath, why) {
  return {
    deny:
      `MultiEdit cannot be applied to ${filePath}: ${why}; apply each change as ` +
      `a separate Edit call (single Edits are re-anchored onto the file's real ` +
      `bytes), or ask the user to make this change`,
  };
}

/**
 * Verdict when the redactor could not produce — or produced a provably
 * wrong — map of the file: MultiEdit is always denied (its pass-through
 * requires a VERIFIED view==disk), a hinted Edit/Write is denied (its
 * placeholder cannot be resolved), and an unhinted Edit/Write passes through
 * to the real tool's semantics (nothing placeholder-shaped to mis-persist,
 * and no splice is attempted — the module doctrine's fail-open arm).
 * @param {string} tool
 * @param {string} filePath
 * @param {string} reason
 * @param {boolean} hinted
 * @returns {{deny: string} | null}
 */
function unresolvableVerdict(tool, filePath, reason, hinted) {
  if (tool === "MultiEdit")
    return multiEditDeny(
      filePath,
      `the sanitized view of the file cannot be verified (${reason})`,
    );
  if (!hinted) return null;
  return {
    deny: `cannot resolve redaction placeholders in ${filePath}: ${reason}`,
  };
}

/**
 * True when this tool call could need re-anchoring against the target file's
 * sanitized view: any well-formed Edit (the view may differ from disk even
 * without placeholders, via stripped invisible characters), any well-formed
 * MultiEdit (gated on the same grounds), or a Write whose content carries a
 * placeholder.
 * @param {string} tool
 * @param {any} ti
 * @param {string} hint
 */
function isCandidate(tool, ti, hint) {
  if (typeof ti?.file_path !== "string") return false;
  if (tool === "Edit")
    return (
      typeof ti.old_string === "string" && typeof ti.new_string === "string"
    );
  if (tool === "MultiEdit")
    return (
      Array.isArray(ti.edits) &&
      ti.edits.length > 0 &&
      ti.edits.every(
        (/** @type {any} */ edit) =>
          typeof edit?.old_string === "string" &&
          typeof edit?.new_string === "string",
      )
    );
  if (tool === "Write")
    return typeof ti.content === "string" && ti.content.includes(hint);
  return false;
}

/**
 * Re-anchor an Edit/Write input composed from a sanitized file view back onto
 * the on-disk bytes (secrets rehydrated, stripped invisible runs re-attached),
 * and gate MultiEdit (pass-through only on a verified view==disk with no
 * placeholder in any edit; denied otherwise — see the module doc). Returns the
 * rewritten input plus a model-facing context line, a deny with an instructive
 * reason when the input is unresolvable or would expose a secret, or null when
 * there is nothing to do. Throws only on internal error (the caller fails
 * closed).
 *
 * `io` is the injected I/O (file read + redactor map/plain). `hint` is the
 * redaction-placeholder prefix (defaults to {@link DEFAULT_HINT}); override it
 * only if the injected redactor emits a different placeholder shape.
 * @param {string} tool
 * @param {any} toolInput
 * @param {RehydrateIo} io
 * @param {{ hint?: string }} [options]
 * @returns {Promise<{updatedInput: any, context: string} | {deny: string} | null>}
 */
export async function rehydrateRedacted(
  tool,
  toolInput,
  io,
  { hint = DEFAULT_HINT } = {},
) {
  // A notebook cell carrying a placeholder would persist it verbatim over the
  // secret; mapping .ipynb JSON is not supported, so refuse with guidance.
  if (
    tool === "NotebookEdit" &&
    typeof toolInput?.new_source === "string" &&
    toolInput.new_source.includes(hint)
  )
    return {
      deny:
        `new_source contains a ${hint}…] placeholder, which stands for a secret ` +
        `hidden from your view; rehydration is not supported for notebooks. Keep ` +
        `the secret-bearing cell unchanged, or ask the user to edit it.`,
    };
  if (!isCandidate(tool, toolInput, hint)) return null;
  const hinted =
    tool === "Write" ||
    (tool === "MultiEdit"
      ? toolInput.edits.some(
          (/** @type {{old_string: string, new_string: string}} */ edit) =>
            edit.old_string.includes(hint) || edit.new_string.includes(hint),
        )
      : toolInput.old_string.includes(hint) ||
        toolInput.new_string.includes(hint));

  let content;
  try {
    content = io.readFile(toolInput.file_path);
  } catch (err) {
    // The catch binding is `unknown` under strict TS; io's contract only
    // promises Node-shaped read failures (a real `readFile`'s throw), so
    // narrow once here rather than re-deriving the cast at every use below.
    const nodeErr = /** @type {NodeJS.ErrnoException} */ (err);
    // ENOENT (missing target): a non-create Edit fails on its own (nothing to
    // re-anchor), so pass through. But any call that would CREATE the file
    // with hinted content — a Write (always hinted; isCandidate requires the
    // prefix), a hinted MultiEdit (its first edit may create), or a hinted
    // Edit whose empty old_string is the create form — persists its
    // placeholder verbatim, standing for a secret that does NOT exist on this
    // new path. R4: that is the same cross-file/stale-placeholder mistake a
    // same-file Write is denied for; refuse with the same guidance rather
    // than write the placeholder text as a real value.
    if (nodeErr?.code === "ENOENT") {
      if (!hinted || (tool === "Edit" && toolInput.old_string !== ""))
        return null;
      return {
        deny:
          `${toolInput.file_path} does not exist, so the ${hint}…] placeholder in the ` +
          `new content stands for no secret on disk; a new file cannot copy a placeholder ` +
          `from another file or context. Write the secret's real value directly, or ask ` +
          `the user to make this change`,
      };
    }
    // Any OTHER read failure (EACCES, EMFILE, a transient I/O error, …) means
    // the target very likely still EXISTS with real bytes on disk — the read
    // failed, the file didn't vanish. A hinted call's content may carry
    // placeholder text that must never be persisted literally over whatever
    // secret is actually there, so fail closed with a deny instead of the
    // silent pass-through above. A non-hinted call was never going to write a
    // secret-shaped placeholder either way, and the underlying tool call will
    // hit this exact same read error itself, so let it propagate rather than
    // swallow an unexpected failure.
    if (!hinted) throw err;
    return {
      deny:
        `could not read ${toolInput.file_path} to rehydrate its secrets ` +
        `(${nodeErr?.code ?? nodeErr?.message}); the file likely still exists, so writing ` +
        `the placeholder text as-is risks overwriting a real secret. Retry the read, or ` +
        `ask the user to make this change directly`,
    };
  }
  const { layer1Cleaned, cleaned } = layer1View(content);
  // A Layer-1-clean file's view differs from disk ONLY at redacted secrets.
  // R1: if nothing is redacted, a hint-free old_string cannot touch a hidden
  // span, so keep the fast pass-through (a verbatim match needs no translation;
  // a mismatch is an ordinary stale old_string Edit reports itself) and never
  // invoke the redactor's map mode. But if the file DOES hold secrets, a
  // hint-free old_string can still match disk bytes INSIDE a redacted span the
  // model never saw — the char-by-char extraction oracle. Fall through to the
  // resolver so its overlap/exposure guards run before any such byte is spliced
  // raw. `io.redact` (plain mode) is the cheap secrets-present probe; it returns
  // null exactly when the file has no secrets.
  if (!hinted && cleaned === content && (await io.redact(cleaned)) === null)
    return null;

  // alignDeletions needs a true subsequence of `content`; the lone-surrogate
  // normalization folded into `cleaned` is a substitution, not a deletion
  // (see layer1View), so deletions are computed against the pre-normalization
  // text. The substitution is same-length, so the resulting offsets remain
  // valid against `cleaned` throughout the rest of this module.
  const deletions = alignDeletions(content, layer1Cleaned);
  const mapped = await io.redactMap(cleaned);
  if ("unmappable" in mapped)
    return unresolvableVerdict(
      tool,
      toolInput.file_path,
      mapped.unmappable,
      hinted,
    );
  // The redactor emits code-point offsets; the offset machinery below works in
  // UTF-16. makeFileView normalizes once, into a fresh frozen carrier, so an
  // astral char before a placeholder can't mis-anchor the edit (a no-op for
  // BMP-only files) AND the redactor's own object is never written through —
  // a redactor that memoizes its map result would otherwise hand back an
  // already-converted object and get converted twice. See makeFileView.
  //
  // The map is TRUSTED by every splice below, and it came from the injected
  // redactor — the one component with a real defect rate. A wrong map
  // (mis-ordered or out-of-range pairs, a placeholder not at its stated
  // offset, originals that do not splice back to the file's bytes) would
  // anchor an edit onto the WRONG disk bytes and corrupt the file. Verify it
  // before acting: construction re-checks range/ordering (the throws in
  // pairsToUtf16), viewMapDefect proves the view reconstructs `cleaned`
  // exactly. A defective map is handled as unmappable — denied for MultiEdit
  // and hinted input, passed through to real tool semantics otherwise — and
  // deliberately NOT allowed to throw out of this module: a throw lands in
  // the host's failure posture, whose shipped default is fail OPEN, i.e. the
  // unsanitized placeholder write this module exists to prevent.
  let view;
  try {
    view = makeFileView(mapped.text, mapped.pairs);
  } catch (err) {
    return unresolvableVerdict(
      tool,
      toolInput.file_path,
      `the redactor's map violates its contract (${/** @type {Error} */ (err).message})`,
      hinted,
    );
  }
  const mapDefect = viewMapDefect(cleaned, view);
  if (mapDefect !== null)
    return unresolvableVerdict(
      tool,
      toolInput.file_path,
      `the redactor's map is inconsistent with the file's bytes (${mapDefect})`,
      hinted,
    );
  // View identical to disk: any placeholders in an Edit's old_string are
  // literal text, so there is nothing to re-anchor. `cleaned === content` also
  // rules out a lone-surrogate-only divergence (view.pairs/deletions alone
  // would miss that, since the normalization is neither a redaction pair nor a
  // Layer-1 deletion). Hinted Writes and MultiEdits are the exception: their
  // input still carries the hint prefix, and with no own placeholder to
  // resolve that hint is a FOREIGN [REDACTED…] placeholder that would be
  // persisted verbatim over pristine bytes. Fall through so each denies with
  // the cross-file guidance — the same verdict a Write onto a secret-bearing
  // or absent target already gets.
  const viewEqualsDisk =
    view.pairs.length === 0 && deletions.length === 0 && cleaned === content;
  if (
    viewEqualsDisk &&
    !(tool === "Write" && toolInput.content.includes(hint)) &&
    !(tool === "MultiEdit" && hinted)
  )
    return null;

  if (tool === "MultiEdit")
    return viewEqualsDisk
      ? multiEditDeny(
          toolInput.file_path,
          `the edits carry a ${hint}…] placeholder but the file holds no ` +
            `redacted secret, so the placeholder names a secret from another ` +
            `file or context and would be persisted literally`,
        )
      : multiEditDeny(
          toolInput.file_path,
          `the sanitized view of the file differs from its on-disk bytes ` +
            `(redacted secrets or stripped invisible characters), and ` +
            `sequential edits cannot be re-anchored across that divergence`,
        );

  return tool === "Edit"
    ? rehydrateEdit(
        toolInput,
        content,
        cleaned,
        view,
        deletions,
        io,
        hinted,
        hint,
      )
    : rehydrateWrite(toolInput, view, io, hint);
}
