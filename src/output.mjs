/**
 * Tool-output sanitization pipeline (Layers 1–4) plus an optional, secure
 * Layer-5 slot.
 *
 *   Layer 1  invisible-char + ANSI strip, lone-surrogate normalization (always)
 *   Layer 2  splice hidden HTML from rendered-page ingress      (opt: `html`)
 *   Layer 3  flag data-exfil-shaped URLs                        (opt: `exfilScan`)
 *   Layer 4  redact secrets via an INJECTED redactor            (opt: `redact`)
 *   Layer 5  semantic prompt-injection filtering, "return verbatim spans to
 *            delete" contract                                    (opt: `filterInjection`)
 *
 * Everything agent-specific is a plain option, not baked in: WHICH tools count
 * as web vs. MCP ingress, which secret engine runs, and whether a live second
 * LLM does Layer 5 are all the caller's policy. Layers 2 & 3 lazy-load the heavy
 * HTML graph only when a cheap pre-gate matches, so plain-text output never pays
 * for it.
 *
 * Layer 5 is deliberately a thin, SAFE slot: the injected filter returns
 * verbatim spans to delete (never replacement text), so even a compromised
 * filter can at most remove legitimate content — it can never inject new bytes
 * into the model's view. A consumer running a live LLM filter wires it here.
 * Because a span deletion joins the bytes on either side of the deleted span,
 * Layer 4 (`redact`) is re-run on the post-deletion text whenever Layer 5
 * actually removes something, so a secret that a deletion reconstitutes is
 * still caught before this function returns.
 */
import {
  CATEGORY,
  describeStripped,
  isIncidentalInvisible,
} from "./invisible.mjs";
import { needsMarkdownPipeline, needsUrlScan } from "./gates.mjs";
import {
  applyLayer1,
  INERT_ANSI_NOTE,
  isBenignAnsiKinds,
  normalizeLoneSurrogates,
} from "./layer1.mjs";
import {
  describeConfusableHosts,
  describeExfil,
  describeHtmlSanitized,
  HTML_UNPARSEABLE_WARNING,
  describeWarned,
  LONE_SURROGATE_WARNING,
} from "./warnings.mjs";
import {
  finding,
  note,
  noteMessages,
  SEVERITY,
  warning,
  warningMessages,
} from "./severity.mjs";
import { orderedMatches, spliceOrdered } from "./view-map.mjs";

/**
 * Closed enum of LIBRARY-OWNED Layer-5 warning codes — the ONLY warning values
 * the injected `filterInjection` seam may return. This mirrors the `found`-code
 * contract (`CATEGORY` in ./invisible.mjs): the seam speaks a fixed vocabulary
 * of codes, and the LIBRARY owns the human-readable string each maps to. Free
 * text from the filter is REFUSED (see `mapFilterWarning`), because the filter
 * runs on attacker-influenced content and its output is concatenated into the
 * model-facing context WITHOUT passing back through Layer 1 — so a compromised
 * or prompt-injected filter that could emit arbitrary `warning` text would
 * defeat the "a compromised filter can only remove bytes, never inject" seam
 * contract. Branch on these codes; the prose below is not part of the contract.
 * @type {Readonly<{ SPANS_REMOVED: "spans-removed", FILTER_FLAGGED: "filter-flagged", FILTER_ERROR: "filter-error" }>}
 */
export const FILTER_WARNING = Object.freeze({
  // The filter removed one or more verbatim spans it judged to be injection.
  SPANS_REMOVED: "spans-removed",
  // The filter flagged the content as a possible injection without deleting.
  FILTER_FLAGGED: "filter-flagged",
  // The filter reported an internal error while scanning (non-fatal — the
  // pipeline still returns the Layer-1..4 output; a fatal filter should throw).
  FILTER_ERROR: "filter-error",
});

// code -> library-owned human label, the ONLY text a Layer-5 warning can put
// into `warnings`. Decoupled from FILTER_WARNING so the prose can be reworded
// without a breaking change to anyone branching on the codes.
/** @type {Readonly<Record<string, string>>} */
const FILTER_WARNING_LABELS = Object.freeze({
  [FILTER_WARNING.SPANS_REMOVED]:
    "Layer-5 injection filter removed one or more verbatim spans it flagged as prompt injection",
  [FILTER_WARNING.FILTER_FLAGGED]:
    "Layer-5 injection filter flagged this tool output as a possible prompt injection (content not modified)",
  [FILTER_WARNING.FILTER_ERROR]:
    "Layer-5 injection filter reported an internal error while scanning this tool output",
});

/**
 * Map a Layer-5 filter `warning` value to its library-owned message, or THROW
 * if it is not a known {@link FILTER_WARNING} code. Failing loud here is the
 * seam contract: the filter may only speak the closed code vocabulary, never
 * push its own bytes into the model-facing `warnings`.
 * @param {unknown} code
 * @returns {string}
 */
function mapFilterWarning(code) {
  // Object.hasOwn, not a bare index: a bare `FILTER_WARNING_LABELS[code]` would
  // resolve inherited Object.prototype members ("valueOf", "toString",
  // "constructor", …) to real functions instead of undefined, letting a filter
  // smuggle a non-code value past the enum guard.
  const label =
    typeof code === "string" && Object.hasOwn(FILTER_WARNING_LABELS, code)
      ? FILTER_WARNING_LABELS[code]
      : undefined;
  if (label === undefined)
    throw new Error(
      `Layer-5 filterInjection returned an unrecognized warning value ${JSON.stringify(
        code,
      )}; it must be one of the FILTER_WARNING enum codes ` +
        `(${Object.values(FILTER_WARNING).join(", ")}). Free-text filter ` +
        "warnings are refused so a compromised filter cannot inject bytes into " +
        "the model-facing context.",
    );
  return label;
}

/**
 * Message from a caught value (`unknown` under strict mode), with one level of
 * cause chain appended so a wrapped failure reads "outer: root".
 * @param {unknown} err
 * @returns {string}
 */
function errMessage(err) {
  if (!(err instanceof Error)) return String(err);
  const cause = err.cause instanceof Error ? `: ${err.cause.message}` : "";
  return err.message + cause;
}

/**
 * @typedef {{ text: string, found: string[], note?: string }} RedactResult
 *   Layer-4 result: the redacted text, the category labels redacted, and an
 *   optional caller-supplied annotation appended to the warning.
 * @typedef {"spans-removed" | "filter-flagged" | "filter-error"} FilterWarningCode
 *   A {@link FILTER_WARNING} enum code — the closed vocabulary the Layer-5 seam
 *   may return in `warning`. See FILTER_WARNING for the meanings.
 * @typedef {{ removeSpans?: string[], warning?: FilterWarningCode }} Layer5Result
 *   Layer-5 result: verbatim spans to delete (the only mutation a filter may
 *   request) and/or a warning CODE (never free text — the library owns the
 *   message). Null means the filter made no finding.
 */

/**
 * @typedef {{ text: string, found: string[], findings: import("./severity.mjs").Finding[], modified: boolean, unreportedChange: boolean }} PipelineState
 *   The running state of one {@link sanitizeText} call. Layers read `text` and
 *   mutate it ONLY through {@link applyMutation}. Findings carry their own
 *   severity (see ./severity.mjs) and are split into `warnings`/`notes` at the
 *   single exit, so no layer can push into the wrong list. `found` is the
 *   machine-readable twin, unaffected by the split: the {@link CATEGORY} codes
 *   for whatever Layers 1-3 neutralized or flagged.
 */

/**
 * THE only way a layer may change `state.text`. Every byte mutation invalidates
 * the same three stage invariants, so all three are re-established in one place
 * rather than at each mutation site:
 *
 *   1. lone surrogates are normalized. The module doc promises this "always",
 *      but each mutation can BREAK it again: a Layer-5 span deletion joins the
 *      bytes on either side of the deleted span and can leave a lone surrogate
 *      the model renders as a broken glyph and the redactor reads as U+FFFD.
 *      Repairing it inside whichever layer happens to need it — e.g. only in
 *      the post-span-deletion re-redact, so it runs only when a redactor is
 *      configured — would make an invariant of Layer 1 conditional on an
 *      unrelated option.
 *   2. `modified` is set — the caller's "bytes changed" banner.
 *   3. `unreportedChange` is set. A mutation that pushed no finding — a Layer-5
 *      span deletion whose filter returned no warning code — is a change the
 *      caller was never told about, and the returned `sgrNote` ("nothing here
 *      rose above a note") must not invite a quiet banner over one. A mutation
 *      that DID report itself is covered by its own WARNING, so this flag only
 *      ever costs a note that would have been misleading.
 *
 * Callers decide WHETHER a mutation happened (each layer already knows: a
 * changed splice output, a redactor finding, a removed span) and call this with
 * the new bytes; a no-op call would falsely set `modified`.
 *
 * No warning is pushed for the normalization: the mutation that created the
 * lone surrogate reported itself, and a second "Normalized lone UTF-16
 * surrogates" line would describe the library repairing its own splice rather
 * than a finding about the input.
 * @param {PipelineState} state
 * @param {string} nextText
 * @returns {void}
 */
function applyMutation(state, nextText) {
  state.text = normalizeLoneSurrogates(nextText);
  state.modified = true;
  state.unreportedChange = true;
}

/**
 * Run Layer 4 (`redact`) over the state's current text and fold any finding
 * back in. The single Layer-4 invocation site FOR THE PIPELINE STATE: the first
 * pass and the re-scan after a Layer-5 span deletion are the same call, so they
 * share one fail-closed handling, warning prose and post-redaction invariant.
 *
 * One other site runs Layer 4 deliberately: {@link vetStageValue}, which vets a
 * stage value on its way out and has no `PipelineState` to fold a finding into.
 * It shares the post-redaction invariant (normalize what the redactor's own
 * output may have stranded) but NOT the fail-closed policy — it withholds the
 * one field rather than suppressing the whole output. Adding a third site means
 * re-deciding both halves, so route through one of these two instead.
 *
 * Fails CLOSED: a redactor we could not run might have let a secret through, so
 * the throw is rethrown wrapped and the caller suppresses the output rather than
 * emitting an unvetted value with a warning.
 * @param {PipelineState} state
 * @param {(text: string) => Promise<RedactResult|null> | (RedactResult|null)} redact
 * @returns {Promise<void>}
 */
async function runRedact(state, redact) {
  /** @type {RedactResult|null} */
  let secrets;
  try {
    secrets = await redact(state.text);
  } catch (l4err) {
    throw new Error(
      `CRITICAL: secret redaction failed (${errMessage(l4err)}). ` +
        "Failing closed — tool output suppressed.",
      { cause: l4err },
    );
  }
  if (!secrets) return;
  applyMutation(state, secrets.text);
  // Always a WARNING: a secret reached this output, and the caller-supplied
  // `note` (which credential, from where) is the part an operator acts on.
  state.findings.push(
    warning(
      `API keys/secrets redacted: ${secrets.found.join(", ")}${secrets.note ?? ""}${REDACTION_DOCTRINE}`,
    ),
  );
}

/**
 * The doctrine clause riding every redaction warning — the one moment
 * placeholders enter the model's view. Without it the model has no way to know
 * that a placeholder written back through any path but Edit/Write (a heredoc,
 * sed/tee, an MCP file tool) is persisted literally, destroying the secret —
 * making that route-around an honest mistake rather than a warned one.
 * Exported so tests assert the composed warning by reference instead of
 * re-typing the prose.
 */
export const REDACTION_DOCTRINE =
  " (placeholders rehydrate only via Edit/Write on the owning file; other " +
  "write paths persist the placeholder text and lose the secret)";

/**
 * The warning prose for a value the caller asked for and is not getting,
 * because the redactor could not vet it for secrets.
 *
 * Exported so the hook layer composes the same sentence for the artifacts it
 * withholds itself (the reveal sidecar) rather than restating the wording.
 * @param {string} label what was withheld, as a noun phrase
 * @returns {string}
 */
export function withheldWarning(label) {
  return `Withheld the ${label}: it could not be vetted for secrets`;
}

// Layer 2/3 pre-gate and warning prose are shared with the root entry
// (./index.mjs), which runs the same layers; re-exported here because both were
// part of this module's public surface before they moved.
export { needsMarkdownPipeline };
export { describeExfil, describeRemoved, describeWarned } from "./warnings.mjs";

/**
 * Delete each verbatim span in `spans` from `text`. The secure Layer-5
 * primitive: a filter can only ask for deletions, so this can never inject
 * bytes. Returns the new text and how many span occurrences were removed (0
 * when no span was present).
 *
 * Every occurrence is located in the ORIGINAL `text` and the deletions applied
 * in one ordered pass ({@link spliceOrdered}), so every removed byte lies inside
 * a match some span had in the INPUT. Deleting span-by-span with a
 * chained `split`/`join` would not hold that line: an earlier deletion joins the
 * bytes on either side of it and can CREATE a match for a later span that never
 * occurred in the input — `deleteVerbatimSpans("PRE-XX-POST", ["-XX-", "PREPOST"])`
 * then deletes the whole document. That would widen the Layer-5 seam's blast
 * radius (see the module doc) from "a compromised filter can at most remove the
 * content it named" to "it can remove content it never named".
 *
 * Overlapping spans are resolved first-match-wins, so `removed` counts the
 * occurrences actually spliced out, never a double-count of the same bytes.
 * @param {string} text
 * @param {string[]} spans
 * @returns {{ text: string, removed: number }}
 */
export function deleteVerbatimSpans(text, spans) {
  // Keep only non-empty STRING spans. The filter is untrusted JS, not a
  // type-checked caller, so the array can hold anything: `indexOf(123)` would
  // silently match the literal text "123" (deleting content the filter never
  // named), and `occurrences` steps by `needle.length` — `undefined` for a
  // number — making `indexOf(needle, NaN)` clamp back to the same index and
  // loop forever. Fail open on a malformed entry rather than mangle bytes or
  // hang the pipeline.
  const usable = spans.filter(
    (span) => typeof span === "string" && span !== "",
  );
  const spliced = spliceOrdered(text, orderedMatches(text, usable), () => "");
  return { text: spliced.text, removed: spliced.spans.length };
}

/**
 * The tier for what Layer 1 removed.
 *
 * INCIDENTAL means both axes are: the ANSI was display-only (or a stray escape
 * that opened nothing) AND there were too few invisible characters to spell
 * anything. Either axis alone keeps the WARNING — a cursor move beside one soft
 * hyphen is still a cursor move, and ten tag characters beside a colour code are
 * still ten ASCII letters.
 *
 * The whole downgrade is gated on `sgrCarveOut`, the caller asserting local,
 * first-party output. Without it — a fetched page, an MCP connector — a single
 * hidden character is not incidental at all; that is the channel where one gets
 * PUT there.
 *
 * When the strip was inert AND nothing but ANSI was found, the note says so in
 * its own words ({@link INERT_ANSI_NOTE}) rather than reciting a stripped
 * category, because "we removed some colour codes" is the whole finding.
 * @param {string[]} invisFound
 * @param {string[]} ansiKinds
 * @param {string} deAnsi
 * @param {boolean} sgrCarveOut
 * @returns {import("./severity.mjs").Finding}
 */
function layer1Finding(invisFound, ansiKinds, deAnsi, sgrCarveOut) {
  const incidental =
    sgrCarveOut &&
    isBenignAnsiKinds(ansiKinds) &&
    isIncidentalInvisible(deAnsi);
  const ansiOnly = invisFound.length === 1 && invisFound[0] === CATEGORY.ANSI;
  if (incidental && ansiOnly) return note(INERT_ANSI_NOTE);
  return finding(!incidental, describeStripped(invisFound, deAnsi));
}

/**
 * Layer 1 + surrogate normalisation: invisible chars, ANSI, lone surrogates.
 * Findings carry their own tier (see {@link layer1Finding}); a lone-surrogate
 * normalisation is always loud, since splitting a secret across one is how a
 * redactor is evaded.
 * @param {string} text
 * @param {boolean} sgrCarveOut
 * @returns {{ cleaned: string, found: string[], findings: import("./severity.mjs").Finding[], modified: boolean }}
 */
function processLayer1(text, sgrCarveOut) {
  /** @type {import("./severity.mjs").Finding[]} */
  const findings = [];
  /** @type {string[]} */
  const found = [];
  let modified = false;
  const {
    cleaned: layer1,
    deAnsi,
    found: invisFound,
    ansiKinds,
  } = applyLayer1(text);
  let cleaned = layer1;
  if (invisFound.length > 0) {
    found.push(...invisFound);
    modified = true;
    findings.push(layer1Finding(invisFound, ansiKinds, deAnsi, sgrCarveOut));
  }
  // Normalize lone UTF-16 surrogates for ALL output: a secret split by an
  // interposed lone surrogate reads as adjacent to a model rendering its own
  // UTF-16 but as broken to a redactor (Node maps the lone surrogate to U+FFFD
  // on the way there), so normalizing here keeps both views identical. It also
  // keeps an HTML tokenizer from throwing on a stray byte below.
  const wellFormed = normalizeLoneSurrogates(cleaned);
  if (wellFormed !== cleaned) {
    cleaned = wellFormed;
    modified = true;
    found.push(CATEGORY.LONE_SURROGATES);
    findings.push(warning(LONE_SURROGATE_WARNING));
  }
  return { cleaned, found, findings, modified };
}

/**
 * Layers 2+3: HTML sanitisation (`html`) and exfil-URL detection (`exfilScan`),
 * folded into `state`. Returns the pre-splice text when Layer 2 removed bytes so
 * the caller can hand it back for later inspection of what the splice hid (the
 * model cannot otherwise tell a benign `<!-- TODO -->` from an injection
 * payload), and `undefined` otherwise — plus Layer 2's `splices`, the
 * placeholder→original pairs a rehydrator needs (in document order; the
 * per-splice offsets are dropped here because later layers may mutate the text,
 * making offsets into this stage's text meaningless). Both are STAGE VALUES,
 * not results: neither has been through Layer 4, so {@link sanitizeText} must
 * vet them before they leave. The transform itself stays pure — the caller owns
 * any persistence.
 * @param {PipelineState} state
 * @param {{ html?: boolean, exfilScan?: boolean, flagDigestValues?: boolean, deadline?: Deadline }} options
 * @returns {Promise<{ reveal: string | undefined, splices: Array<{ placeholder: string, original: string }> }>}
 */
async function applyMarkdownPipeline(
  state,
  { html, exfilScan, flagDigestValues, deadline },
) {
  const inputText = state.text;
  /** @type {string | undefined} */
  let reveal;
  /** @type {Array<{ placeholder: string, original: string }>} */
  const splices = [];
  // Each layer carries its OWN pre-gate: Layer 2 can only splice what a tag
  // delimits, while Layer 3's detectors read a bare `https://…` in prose that
  // holds no markup at all. Gating both on the markup test hid every plain-text
  // look-alike host and exfil URL from the scan.
  const runLayer2 = Boolean(html) && needsMarkdownPipeline(inputText);
  const runLayer3 = Boolean(exfilScan) && needsUrlScan(inputText);
  if (!runLayer2 && !runLayer3) return { reveal: undefined, splices };
  // INVARIANT: this refusal stops a layer below from STARTING with no budget
  // left. Each parses the whole document in ONE synchronous call, so nothing
  // interrupts it, and a host that kills the overrun hook shows the RAW text.
  // Called before EACH parse: Layer 2 spends the budget Layer 3 then runs on.
  // After the pre-gate: a declined call costs no time. Fail closed, as Layer 4.
  const refuseIfSpent = () => {
    if (deadline && deadline.remainingMs() <= 0)
      throw new Error(
        "CRITICAL: the sanitization time budget ran out before the hidden-HTML " +
          "and exfil-URL layers finished, so this text was not fully checked. " +
          "Failing closed — tool output suppressed.",
      );
  };
  refuseIfSpent();
  let sanitizeHtml, detectExfil, detectConfusableHosts;
  /* c8 ignore start -- a rejected dynamic import of a module that ships in
     this very package (not an optional peer dep) requires corrupting
     node_modules or the filesystem to trigger; there's no clean way to force
     this from a test without fragile module-loader mocking (Node's
     mock.module needs --experimental-test-module-mocks, which isn't wired
     into this repo's test script). Fail loudly with context if it ever fires. */
  try {
    ({ sanitizeHtml, detectExfil, detectConfusableHosts } =
      await import("./html.mjs"));
  } catch (importErr) {
    throw new Error(
      "agent-sanitizer: failed to load ./html.mjs, so Layers 2/3 could not run " +
        "(are the package's remark/rehype dependencies installed?)",
      { cause: importErr },
    );
  }
  /* c8 ignore stop */
  // Layer 2 — strips what a rendered page would not show (comments, hidden
  // elements); scripting/resource tags preserved+reported. Each cut leaves a
  // keyed placeholder whose original bytes ride out in `splices`.
  if (runLayer2) {
    const layer2 = sanitizeHtml(state.text);
    if (layer2) {
      if (layer2.text !== state.text) {
        reveal = state.text;
        // Keep only {placeholder, original}: the offsets sanitizeHtml returns
        // point into THIS stage's text, which Layers 4/5 may still mutate.
        for (const { placeholder, original } of layer2.splices)
          splices.push({ placeholder, original });
        applyMutation(state, layer2.text);
        if (layer2.removed.comments > 0)
          state.found.push(CATEGORY.HTML_COMMENTS);
        if (layer2.removed.hidden > 0) state.found.push(CATEGORY.HIDDEN_HTML);
        // A WARNING: these bytes were invisible to a human reading the rendered
        // page and are now gone from the model's view too — the exact shape of
        // a hidden-instruction payload, and the model cannot check what it was
        // without the reveal sidecar. The unparseable fail-closed path withheld
        // the WHOLE output, not a spliced span, so it gets its own sentence
        // rather than a misleading "1 hidden element(s) replaced".
        state.findings.push(
          warning(
            layer2.unparseable
              ? HTML_UNPARSEABLE_WARNING
              : describeHtmlSanitized(layer2.removed),
          ),
        );
      }
      // A NOTE: nothing was removed and nothing was hidden. This line says "the
      // page had scripts, treat their contents as data", which is true of nearly
      // every page fetched — at WARNING volume it trained the reader to skip the
      // banner Layer 2's actual splice needs.
      const preserved = describeWarned(layer2.warned);
      if (preserved) state.findings.push(note(preserved));
    }
  }
  // Layer 3 — detection only: the URLs stay intact, the model is told not to
  // use them. Scan the ORIGINAL text, not the Layer-2 splice output: a beacon
  // URL hidden inside a display:none element or an HTML comment is MORE
  // suspicious, not less, yet Layer 2 has already removed it from `cleaned`.
  if (runLayer3) {
    refuseIfSpent();
    const threats = detectExfil(inputText, { flagDigestValues });
    // Severity tracks who does the fetching. An auto-fetched target — an image,
    // a stylesheet, a form action, a meta refresh — exfiltrates the moment the
    // content renders, with nobody deciding anything: a WARNING. A plain LINK
    // cannot exfiltrate unless the model chooses to follow it, and the sentence
    // it is reported in is precisely the instruction not to, so it is a NOTE.
    // One auto-fetched threat raises the whole finding — the loudest member
    // wins, since they share one line.
    if (threats) {
      state.found.push(CATEGORY.EXFIL_URLS);
      state.findings.push(
        finding(
          threats.some((threat) => threat.autoFetched),
          describeExfil(threats),
        ),
      );
    }
    // Confusable hosts ride the same scan flag but are a SEPARATE finding: a
    // look-alike domain needs no exfil-shaped query to be the whole attack, and
    // the two say different things to a reader. Tier per ./confusable-host.mjs,
    // and the loudest member wins the shared line.
    refuseIfSpent();
    const confusable = detectConfusableHosts(inputText);
    if (confusable) {
      state.found.push(CATEGORY.CONFUSABLE_HOST);
      state.findings.push(
        finding(
          confusable.some((threat) => threat.severity === SEVERITY.WARNING),
          describeConfusableHosts(confusable),
        ),
      );
    }
  }
  return { reveal, splices };
}

/**
 * Vet a pipeline STAGE value on its way out of {@link sanitizeText}. Only
 * `cleaned` traverses every layer; anything else a caller is handed (today the
 * Layer-2 `reveal`) is a snapshot from the middle of the pipeline and still
 * carries whatever the layers after it would have removed. `reveal` and each
 * splice's `original` are PRE-splice text, so they hold exactly the bytes
 * Layer 2 hid — and Layer 4 only ever saw the POST-splice text, meaning a
 * secret inside a spliced-out HTML comment has never been redacted. The
 * documented use of these fields is to persist them, i.e. to write that secret
 * to a log, sidecar, or rehydrated file.
 *
 * Fails CLOSED by WITHHOLDING rather than throwing: a redactor failure here must
 * not discard the already-vetted `cleaned` the caller needs, and dropping the
 * convenience side channel leaks nothing. The warning is fixed library-owned
 * prose (no error text) — it reaches the model-facing context, and the redactor
 * runs on attacker-influenced content. `label` names the withheld field in that
 * warning and comes from the call site below, never from a seam.
 *
 * Normalizes the redactor's output for the same reason {@link applyMutation}
 * does — a redaction that cuts between the halves of an astral pair strands a
 * code unit, and this string is persisted and read back. It cannot USE
 * `applyMutation`: that folds into the `PipelineState`, and a stage value is not
 * the pipeline text — setting `modified`/`sgrNote` from a sidecar's redaction
 * would describe `cleaned`, which this call never touches. Only the
 * normalization is shared. `text` arrives post-Layer-1, so the no-redactor and
 * no-finding paths are already well-formed.
 * @param {string} text
 * @param {SanitizeTextOptions["redact"]} redact
 * @param {import("./severity.mjs").Finding[]} findings
 * @param {string} label
 * @returns {Promise<string | undefined>} vetted text, or undefined if withheld
 */
async function vetStageValue(text, redact, findings, label) {
  if (!redact) return text;
  try {
    const secrets = await redact(text);
    return secrets ? normalizeLoneSurrogates(secrets.text) : text;
  } catch {
    // A WARNING: the caller asked for this field and is not getting it, and the
    // reason is an unrunnable redactor — the same fault that fails `cleaned`
    // closed, just with a survivable remedy here.
    findings.push(warning(withheldWarning(label)));
    return undefined;
  }
}

/**
 * @typedef {{
 *   html?: boolean,
 *   exfilScan?: boolean,
 *   flagDigestValues?: boolean,
 *   redact?: (text: string) => Promise<RedactResult|null> | (RedactResult|null),
 *   filterInjection?: (text: string) => Promise<Layer5Result|null> | (Layer5Result|null),
 *   sgrCarveOut?: boolean,
 *   deadline?: Deadline,
 * }} SanitizeTextOptions
 */

/**
 * A caller's shared wall-clock budget across one run of this pipeline.
 * `remainingMs()` returns the milliseconds left; at or below zero it is spent.
 * Layer 4's injected redactor reads its own copy of the same budget, so this
 * option is what lets the layers inside this module read it too. Omitted means
 * no budget, which is the standalone default: every layer runs to completion.
 * @typedef {{ remainingMs: () => number }} Deadline
 */

/**
 * Run the configured layers over a single text blob. Layer 1 always runs; the
 * rest are opt-in via `options`. Layer 4 (`redact`) is the fail-closed path: a
 * redactor that throws is rethrown wrapped, so the caller suppresses the
 * output rather than emitting an unvetted value. That fail-closed behavior
 * also applies to Layer 4's re-scan after a Layer-5 span deletion (see Layer
 * 5, below) — a redactor failure there fails the whole call closed too.
 * `reveal` is the pre-Layer-2 text, present only when the HTML splice removed
 * bytes, so a caller can persist what was hidden for later inspection (see
 * {@link applyMarkdownPipeline}); the field is omitted otherwise, and also when
 * it could not be vetted (see {@link vetStageValue}). `splices` is its
 * per-placeholder twin — Layer 2's placeholder→original pairs, in document
 * order, so a hook can rehydrate individual splices (the keyed-placeholder
 * grammar lives in ./html.mjs: `layer2Placeholder`/`LAYER2_PLACEHOLDER_RE`).
 * Present only when Layer 2 spliced; each `original` is vetted like `reveal`,
 * and one that cannot be vetted is WITHHELD (dropped from the array) under the
 * same doctrine — Layer 4 never saw pre-splice text.
 *
 * Every byte mutation goes through {@link applyMutation} and every Layer-4 call
 * through {@link runRedact}, so a layer cannot re-establish some of the
 * post-mutation invariants and forget the rest, and every string in the returned
 * object has traversed Layer 4.
 *
 * Findings come back SPLIT BY SEVERITY (see ./severity.mjs): `warnings` holds
 * everything injection-shaped — the banner a caller must show — and `notes`
 * holds what happened but is not alarming. `warnings` therefore keeps exactly
 * the meaning it always had, and a caller that ignores `notes` is no louder
 * than before, just quieter about incidental bytes.
 *
 * `found` is the machine-readable twin, and the severity split does NOT reach
 * it — the {@link CATEGORY} codes for what Layers 1-3 neutralized or flagged,
 * in the order the layers ran, whichever tier described them. Layers 4 and 5
 * have no category codes (their findings are the injected seam's own
 * vocabulary), so they contribute findings only.
 * @param {string} text
 * @param {SanitizeTextOptions} [options]
 * @returns {Promise<{ cleaned: string, found: string[], warnings: string[], notes: string[], modified: boolean, sgrNote: boolean, reveal?: string, splices?: Array<{ placeholder: string, original: string }> }>}
 */
export async function sanitizeText(text, options = {}) {
  const { redact, filterInjection, sgrCarveOut = false } = options;
  const { findings, found, cleaned, modified } = processLayer1(
    text,
    sgrCarveOut,
  );
  /** @type {PipelineState} */
  const state = {
    text: cleaned,
    found,
    findings,
    modified,
    unreportedChange: false,
  };

  const { reveal: revealText, splices: stageSplices } =
    await applyMarkdownPipeline(state, options);

  // Layer 4 — fail closed (see runRedact).
  if (redact) await runRedact(state, redact);

  // Layer 5 — secure span-deletion slot (see module doc). A warning-only result
  // flags without changing bytes; only a deleted span sets `modified`. Awaited
  // so an async filter (e.g. a live second LLM, per the module doc) is actually
  // run: calling it without `await` would silently no-op, since a Promise is
  // always truthy but its `.removeSpans`/`.warning` are `undefined`.
  if (filterInjection) {
    const res = await filterInjection(state.text);
    if (res) {
      if (res.removeSpans && res.removeSpans.length > 0) {
        const out = deleteVerbatimSpans(state.text, res.removeSpans);
        if (out.removed > 0) {
          applyMutation(state, out.text);
          // A span deletion joins the bytes on either side of it, which can
          // reconstitute a secret Layer 4 never saw intact (it ran on the
          // ORIGINAL text, before the join). Re-vet the post-deletion text so a
          // compromised filter can still only ever REMOVE legitimate content,
          // never smuggle an unvetted secret through by splicing around it.
          if (redact) await runRedact(state, redact);
        }
      }
      // A filter warning is a library-owned ENUM CODE, mapped here to its fixed
      // message; free text is refused (throws) so no filter-supplied byte ever
      // reaches the model-facing context. `null`/`undefined` means no warning.
      if (res.warning != null)
        state.findings.push(warning(mapFilterWarning(res.warning)));
    }
  }

  // The single exit. `reveal` is the one value that skipped the layers after the
  // one that produced it, so it is vetted HERE rather than where it was captured
  // — a future "hand me the pre-X text" field gets the same treatment by
  // construction. Omitted unless Layer 2 spliced, so the common-case result
  // shape stays minimal (callers gate on its presence).
  const reveal =
    revealText === undefined
      ? undefined
      : await vetStageValue(
          revealText,
          redact,
          state.findings,
          "pre-splice copy of the removed HTML",
        );
  // Each splice `original` skipped Layer 4 the same way `reveal` did, so it
  // gets the same exit vetting. A splice whose original cannot be vetted is
  // WITHHELD — dropped from the array — mirroring the reveal doctrine: better
  // an unrecoverable splice than an unvetted secret handed out for persistence.
  /** @type {Array<{ placeholder: string, original: string }>} */
  const splices = [];
  for (const splice of stageSplices) {
    const vetted = await vetStageValue(
      splice.original,
      redact,
      state.findings,
      "original text of a removed-HTML splice",
    );
    if (vetted !== undefined)
      splices.push({ placeholder: splice.placeholder, original: vetted });
  }
  const warnings = warningMessages(state.findings);
  const notes = noteMessages(state.findings);
  return {
    cleaned: state.text,
    found: state.found,
    warnings,
    notes,
    modified: state.modified,
    // Kept under its original name (it is a published field, and renaming a
    // published field for a wording win is a breaking change) but derived
    // rather than tracked: "nothing here rose above a note". The inert-ANSI
    // strip is simply the most common way to end up note-only, not the only
    // one this field now covers.
    sgrNote:
      notes.length > 0 && warnings.length === 0 && !state.unreportedChange,
    ...(reveal !== undefined && { reveal }),
    // Presence-gated like `reveal`: the field exists only when Layer 2 spliced
    // and at least one original survived vetting, so the common-case result
    // shape stays minimal.
    ...(splices.length > 0 && { splices }),
  };
}

/**
 * Maximum container nesting `sanitizeValue` / `suppressToolOutput` will descend
 * before failing closed. The JS engine's own call-stack limit is many thousands
 * of frames deep, so 200 is a wide safety margin below it: a real tool output
 * never nests this far, while a hostile 200k-deep array (or a self-referential
 * cycle) would otherwise blow the stack as an UNHANDLED async rejection — the
 * output then escapes sanitization entirely (fail-open DoS). Past this depth the
 * subtree is replaced with a placeholder and a warning is recorded, so the
 * caller still emits a sanitized, flagged result instead of crashing.
 */
export const MAX_DEPTH = 200;

/**
 * True only for arrays and PLAIN objects — the two shapes whose contents are
 * safe to walk via `Object.entries` without silently dropping data. An exotic
 * object (Map/Set/Date/RegExp/typed array/class instance) carries its data in
 * internal slots that `Object.entries` does not enumerate, so descending into
 * one and rebuilding it from its entries corrupts it to `{}` (or an empty
 * clone). Those pass through as OPAQUE LEAVES instead — unchanged — preserving
 * the tool-output shape a harness matches on. A null-prototype object is treated
 * as plain (its own enumerable string keys are the whole story).
 * @param {any} value
 * @returns {boolean}
 */
export function isWalkableContainer(value) {
  if (Array.isArray(value)) return true;
  if (value === null || typeof value !== "object") return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

const DEPTH_PLACEHOLDER = `[withheld: structured output nested beyond ${MAX_DEPTH} levels]`;
const CYCLE_PLACEHOLDER = "[withheld: circular reference in structured output]";

/**
 * Cache of a walked subtree keyed by `(node, depth)` — the pair the walk's
 * result actually depends on. Both walkers below truncate past
 * {@link MAX_DEPTH}, so the SAME node yields different output at different
 * depths: withheld on a long path, walked on a short one. Keying by node
 * identity alone therefore caches a path-dependent answer, and a shared node
 * first reached deep withholds real content everywhere it is reached later —
 * the module's own "a node withheld for depth on a long path must still be
 * walked on a shorter one" rule, silently violated.
 *
 * Taking `depth` as a mandatory argument is the point: there is no API here that
 * can key by identity alone. Refusing to cache truncated subtrees instead would
 * NOT work — truncation propagates to every ancestor, so a hostile diamond DAG
 * with a deep tail would go uncached and re-walk once per path, re-opening the
 * exponential blow-up the memo exists to prevent. Work stays bounded at
 * O(nodes × distinct depths), i.e. at most {@link MAX_DEPTH} entries per node.
 *
 * Residual, unchanged from before: the CYCLE placeholder also depends on the
 * ancestor `seen` set, which is not part of the key. Two paths reaching a node
 * at the same depth with different ancestors can therefore share a cached
 * result. Encoding `seen` in the key means storing every node a subtree walked
 * and re-checking it on lookup — the memo's cost becomes the walk it replaces —
 * and refusing to cache cyclic subtrees hits the same exponential wall as
 * above. A cycle is already a fail-closed pathological shape, so this trades a
 * placeholder's exact placement for a hard work bound.
 * @template T
 */
function depthMemo() {
  /** @type {WeakMap<object, Map<number, T>>} */
  const byNode = new WeakMap();
  return {
    /**
     * @param {object} value
     * @param {number} depth
     * @returns {T | undefined}
     */
    get(value, depth) {
      return byNode.get(value)?.get(depth);
    },
    /**
     * @param {object} value
     * @param {number} depth
     * @param {T} result
     */
    set(value, depth, result) {
      const byDepth = byNode.get(value) ?? new Map();
      byDepth.set(depth, result);
      byNode.set(value, byDepth);
    },
  };
}

/**
 * Sanitize every string leaf of a tool-output value, preserving its shape (a
 * structured tool output whose shape changes would be ignored by a harness,
 * leaking the raw value). Non-string leaves pass through; `warnings` and
 * `notes` accumulate across leaves, split by severity (see ./severity.mjs).
 * `sgrNote` is the OR across leaves — true when SOME leaf was note-only — so a
 * caller can still pick the quiet banner when no leaf raised a warning.
 *
 * Fails CLOSED on two hostile shapes that would otherwise throw a `RangeError`
 * as an unhandled async rejection (a DoS that leaves the output un-sanitized):
 * nesting past {@link MAX_DEPTH}, and a reference cycle. Either replaces the
 * offending subtree with a placeholder string + a warning, never passing the
 * raw subtree through. Keys are also screened for hidden chars (see below).
 *
 * `reveals` accumulates each string leaf's pre-Layer-2 text (present only when
 * the HTML splice removed bytes) so a caller can persist what was hidden — the
 * structured-output analogue of {@link sanitizeText}'s `reveal`. Same
 * mutated-accumulator contract as `warnings`.
 *
 * `splices` accumulates each string leaf's Layer-2 placeholder→original pairs
 * (each `original` already vetted, withheld entries dropped — see
 * {@link sanitizeText}) — the per-placeholder twin of `reveals`, so a hook
 * caller gets them for object-shaped tool output too. Same mutated-accumulator
 * contract as `reveals`.
 * @param {any} value
 * @param {SanitizeTextOptions} options
 * @param {string[]} warnings
 * @param {string[]} [reveals]
 * @param {string[]} [notes]  the NOTE-severity counterpart of `warnings`;
 *   appended last so an existing positional caller keeps working (it simply
 *   discards the notes, which is exactly as loud as before the split)
 * @param {Array<{ placeholder: string, original: string }>} [splices]  appended
 *   after `notes` for the same positional-compatibility reason
 * @returns {Promise<{ value: any, modified: boolean, sgrNote: boolean }>}
 */
export async function sanitizeValue(
  value,
  options,
  warnings,
  reveals = [],
  notes = [],
  splices = [],
) {
  return sanitizeValueAt(
    value,
    options,
    warnings,
    notes,
    reveals,
    splices,
    0,
    new WeakSet(),
    depthMemo(),
  );
}

/**
 * Recursion core for {@link sanitizeValue}, carrying the current `depth` and the
 * `seen` set of ancestor containers on the active path (a WeakSet, so a value
 * reused across sibling branches — legitimate sharing, not a cycle — is not
 * mistaken for a back-edge; only a true ancestor still on the stack triggers
 * the cycle guard, and it is removed on the way back up).
 * @param {any} value
 * @param {SanitizeTextOptions} options
 * @param {string[]} warnings
 * @param {string[]} notes  accumulates each string leaf's NOTE-severity findings
 * @param {string[]} reveals  accumulates each string leaf's pre-Layer-2 text
 * @param {Array<{ placeholder: string, original: string }>} splices  accumulates
 *   each string leaf's Layer-2 placeholder→original pairs (already vetted)
 * @param {number} depth
 * @param {WeakSet<object>} seen
 * @param {ReturnType<typeof depthMemo<{ value: any, modified: boolean, sgrNote: boolean }>>} memo
 *   Cache of the FULLY-PROCESSED result, keyed by `(node, depth)` — see
 *   {@link depthMemo} for why the depth belongs in the key. Without a memo at
 *   all, a shared-substructure DAG (one node reached by many parents) is
 *   re-sanitized once per PATH — exponential in the number of shared nodes (a
 *   ~25-object diamond measured at 68 s, far under MAX_DEPTH) — since the path-
 *   scoped `seen` set only guards cycles, not repeated work. Because warnings
 *   dedup in composeContext, skipping a cached node's duplicate warnings is
 *   harmless. A cached node's `reveals` and `splices` are likewise not
 *   re-emitted, harmless for the same reason (the caller dedups reveals by
 *   content and splices by their content-addressed key).
 * @returns {Promise<{ value: any, modified: boolean, sgrNote: boolean }>}
 */
async function sanitizeValueAt(
  value,
  options,
  warnings,
  notes,
  reveals,
  splices,
  depth,
  seen,
  memo,
) {
  if (typeof value === "string") {
    const result = await sanitizeText(value, options);
    warnings.push(...result.warnings);
    notes.push(...result.notes);
    if (result.reveal !== undefined) reveals.push(result.reveal);
    if (result.splices !== undefined) splices.push(...result.splices);
    return {
      value: result.cleaned,
      modified: result.modified,
      sgrNote: result.sgrNote,
    };
  }
  // Memo hit: a shared node already fully sanitized AT THIS DEPTH on another
  // path. Returning the cached result (same reference) collapses the DAG to
  // linear work and preserves shape; it never short-circuits the cycle guard,
  // since an on-stack ancestor is not cached until its subtree completes.
  const isObject = value !== null && typeof value === "object";
  if (isObject) {
    const cached = memo.get(value, depth);
    if (cached !== undefined) return cached;
  }
  // Exotic objects (Map/Set/Date/typed array/…) pass through opaque: walking
  // them via Object.entries would drop their real contents (see
  // isWalkableContainer), corrupting the tool-output shape a harness matches on.
  if (!isWalkableContainer(value)) {
    // Fail-closed signal: an object with a non-plain prototype AND own
    // enumerable keys (a class instance / Object.create data holder) hides
    // string leaves that Object.entries WOULD reach — but walking + rebuilding
    // would flatten its prototype and corrupt the shape a harness matches on. We
    // refuse to mangle it (precision), yet must not silently vouch for it on the
    // redactor path, so we pass it through UNCHANGED and FLAG it. Standard value
    // objects keep their data in internal slots with no own enumerable keys
    // (Date/RegExp) or in a typed-array buffer of numbers (ArrayBuffer views) —
    // no reachable text to sanitize — so they stay silent, avoiding the alert
    // fatigue of flagging every benign Date. Map/Set are the exception: their
    // data lives in `.entries()`/values, not own enumerable keys, so the
    // `Object.keys` check below misses them entirely — flag any non-empty one
    // by the same "unreachable, can't vouch for it" logic.
    const isNonEmptyMapOrSet =
      (value instanceof Map || value instanceof Set) && value.size > 0;
    // A non-empty ArrayBuffer view (typed array / Buffer / DataView) carries raw
    // bytes we cannot walk or decode-sanitize without guessing an encoding, yet a
    // harness that stringifies it (e.g. Buffer.toString) can surface hidden text
    // to the model. Flag it — passed through unchanged (precision) but never
    // silently vouched for. An EMPTY view has no bytes, so it stays silent, like
    // an empty Map/Set, to avoid alert fatigue on benign zero-length buffers.
    const isNonEmptyArrayBufferView =
      ArrayBuffer.isView(value) && value.byteLength > 0;
    if (
      isNonEmptyMapOrSet ||
      isNonEmptyArrayBufferView ||
      (value !== null &&
        typeof value === "object" &&
        !ArrayBuffer.isView(value) &&
        Object.keys(value).length > 0)
    )
      warnings.push(
        "An object with a non-plain prototype (e.g. a class instance, Map, Set, or typed array/Buffer) in structured tool output was passed through unsanitized — its contents could not be walked without corrupting the object's shape",
      );
    // An opaque leaf is never walked, so its result does not actually depend on
    // depth; caching it under the shared per-depth key is still correct, it just
    // re-flags the same leaf once per distinct depth it appears at. The warnings
    // dedup in composeContext, so the model-facing text is unchanged.
    const leafResult = { value, modified: false, sgrNote: false };
    if (isObject) memo.set(value, depth, leafResult);
    return leafResult;
  }

  // Fail closed before descending into a container: a back-edge to an ancestor
  // (cycle) or a depth past the cap is replaced with a placeholder, never the
  // raw subtree. Both set modified so the caller flags the output as sanitized.
  if (seen.has(value)) {
    warnings.push("Withheld a circular reference in structured tool output");
    return { value: CYCLE_PLACEHOLDER, modified: true, sgrNote: false };
  }
  if (depth >= MAX_DEPTH) {
    warnings.push(
      `Structured tool output nested beyond ${MAX_DEPTH} levels — deeper content withheld`,
    );
    return { value: DEPTH_PLACEHOLDER, modified: true, sgrNote: false };
  }

  seen.add(value);
  try {
    if (Array.isArray(value)) {
      const out = [];
      let modified = false;
      let sgrNote = false;
      for (const item of value) {
        const result = await sanitizeValueAt(
          item,
          options,
          warnings,
          notes,
          reveals,
          splices,
          depth + 1,
          seen,
          memo,
        );
        out.push(result.value);
        if (result.modified) modified = true;
        if (result.sgrNote) sgrNote = true;
      }
      const arrResult = { value: out, modified, sgrNote };
      memo.set(value, depth, arrResult);
      return arrResult;
    }
    /** @type {Record<string, any>} */
    const out = {};
    let modified = false;
    let sgrNote = false;
    for (const [key, item] of Object.entries(value)) {
      // Screen the KEY for hidden chars (Layer 1). We FLAG but do NOT rewrite:
      // a sanitized key can collide with a sibling key (silently dropping a
      // field) or break a downstream schema that matches on the exact name, so
      // precision wins — we keep the original key and warn, letting an operator
      // decide, rather than mangle the object's shape. (A clean key is silent.)
      // A key-only finding does NOT set `modified`: `modified` means output
      // BYTES changed (see composeContext's contract), and the key is left
      // intact here on purpose — only the warning fires.
      const { cleaned: cleanKey } = applyLayer1(key);
      if (cleanKey !== key)
        warnings.push(
          "An object key in structured tool output carried hidden/invisible characters (key left intact, value sanitized)",
        );
      const result = await sanitizeValueAt(
        item,
        options,
        warnings,
        notes,
        reveals,
        splices,
        depth + 1,
        seen,
        memo,
      );
      // Bracket assignment on a literal "__proto__" key triggers the special
      // Object.prototype setter instead of creating an own property — the
      // field would silently vanish from `out`'s own keys and `out`'s
      // prototype would become attacker-controlled. defineProperty always
      // creates a normal own data property regardless of the key's name.
      Object.defineProperty(out, key, {
        value: result.value,
        enumerable: true,
        writable: true,
        configurable: true,
      });
      if (result.modified) modified = true;
      if (result.sgrNote) sgrNote = true;
    }
    const objResult = { value: out, modified, sgrNote };
    memo.set(value, depth, objResult);
    return objResult;
  } finally {
    seen.delete(value);
  }
}

/**
 * Compose the model-facing context line for a sanitized/flagged tool output.
 * `injectionAlert` is the caller's optional trailing alert (e.g. appended only
 * for untrusted-ingress tools where a semantic-injection filter actually ran).
 * @param {boolean} modified  output bytes were changed (vs. flagged only)
 * @param {string[]} warnings
 * @param {{ injectionAlert?: string }} [options]
 * @returns {string}
 */
export function composeContext(
  modified,
  warnings,
  { injectionAlert = "" } = {},
) {
  const prefix = modified
    ? "WARNING: Tool output sanitized. "
    : "WARNING: Tool output flagged (content not modified). ";
  return prefix + [...new Set(warnings)].join(". ") + "." + injectionAlert;
}

/**
 * Replace every string leaf of `value` with `message`, preserving shape so a
 * fail-closed placeholder matches the tool's output schema. Non-string leaves
 * pass through. An Anthropic content block is the one exception: it is
 * collapsed whole to `{ type: "text", text: message }`, because rewriting its
 * `type` tag produces a block the API rejects (see {@link isContentBlock}).
 *
 * Shares {@link sanitizeValue}'s depth/cycle guard for the same reason: this
 * runs on the fail-closed path (an already-suspect output), so a 200k-deep or
 * self-referential value must NOT blow the stack here — that would re-open the
 * very hole suppression exists to close. Past {@link MAX_DEPTH} or on a cycle it
 * substitutes `message` for the offending subtree (already the suppression
 * sentinel, so the placeholder is consistent with the rest of the output). A
 * recognised block collapses BEFORE either guard and recurses no further, so it
 * is subject to neither; a truncated subtree that is not itself a block is
 * still replaced by the bare string, block position or not.
 * @param {any} value
 * @param {string} message
 * @returns {any}
 */
export function suppressToolOutput(value, message) {
  return suppressAt(value, message, 0, new WeakSet(), depthMemo());
}

/**
 * @typedef {(v: any) => boolean} FieldShape  a content-block field's value test
 * @typedef {{ required: Record<string, FieldShape>, optional: Record<string, FieldShape> }} BlockSchema
 */

/** @type {FieldShape} */
const isString = (v) => typeof v === "string";
/** @type {FieldShape} */
const isRecord = (v) =>
  v !== null && typeof v === "object" && !Array.isArray(v);
/** @type {FieldShape} */
const isNullableString = (v) => v === null || isString(v);
/** @type {FieldShape} */
const isNullableArray = (v) => v === null || Array.isArray(v);
// The API marks every optional object-valued block field nullable, and an
// explicit null must not push the block back onto the walk that invalidates it.
/** @type {FieldShape} */
const isNullableRecord = (v) => v === null || isRecord(v);
/** @type {FieldShape} */
const isArray = (v) => Array.isArray(v);

/**
 * Schema of every Anthropic content block the suppressor recognises, from the
 * Messages API block shapes (https://docs.claude.com/en/api/messages). A block
 * is recognised only when its own keys match its tag's schema exactly — every
 * `required` key present, no key outside `required` ∪ `optional` ∪ `type` —
 * AND every present key's VALUE satisfies its predicate. Gating on the value's
 * shape and not the key name alone is what keeps an ordinary record like
 * `{ type: "image", source: "https://…/x.png" }` out: a real image block's
 * `source` is an object. An unrecognised object is walked as ordinary data.
 *
 * Both directions cost something, and they are not symmetric in the way the
 * rest of this module's precision rule assumes. Too LOOSE mangles an object
 * that was never a block. Too STRICT is fail-safe only for those same
 * non-blocks: for a REAL block it sends the walk over the `type` tag, which is
 * the permanently-rejected block this collapse exists to prevent. So a
 * predicate must admit every value the API admits — hence the nullable
 * variants below, since every optional object-valued field is `object | null`.
 *
 * A block whose tag PAIRS it with another block (`tool_use` ↔ `tool_result`,
 * and their server-tool twins) is deliberately absent: collapsing one to a text
 * block orphans its partner, which the API rejects exactly as permanently as
 * the rewritten tag this collapse exists to prevent. They keep the walk.
 *
 * Held as an entry list rather than annotated on the `new Map(...)` below
 * because only the element-wise annotation typechecks: annotating the map lets
 * tsc union the entry literals first, and that union's `source?: undefined`
 * members fail `BlockSchema`'s index signature.
 * @type {[string, BlockSchema][]}
 */
const CONTENT_BLOCK_SCHEMA_ENTRIES = [
  [
    "text",
    {
      required: { text: isString },
      // A response's text block carries `citations` as an array (or null); a
      // request's carries none.
      optional: { citations: isNullableArray, cache_control: isNullableRecord },
    },
  ],
  [
    "image",
    {
      required: { source: isRecord },
      optional: { cache_control: isNullableRecord },
    },
  ],
  [
    "document",
    {
      required: { source: isRecord },
      // A document's `citations` is the `{ enabled }` toggle, not a list.
      optional: {
        title: isNullableString,
        context: isNullableString,
        citations: isNullableRecord,
        cache_control: isNullableRecord,
      },
    },
  ],
  [
    "search_result",
    {
      required: { source: isString, title: isString, content: isArray },
      optional: {
        citations: isNullableRecord,
        cache_control: isNullableRecord,
      },
    },
  ],
  [
    "thinking",
    { required: { thinking: isString, signature: isString }, optional: {} },
  ],
  ["redacted_thinking", { required: { data: isString }, optional: {} }],
];

/** Tag → schema, keyed for {@link isContentBlock}'s lookup. */
const CONTENT_BLOCK_SCHEMAS = new Map(CONTENT_BLOCK_SCHEMA_ENTRIES);

/**
 * Whether `value` (already known to be a walkable container) is an Anthropic
 * content block — an object whose `type` tag names a known block shape AND
 * whose own keys and values match that shape exactly.
 * @param {any} value
 * @returns {boolean}
 */
function isContentBlock(value) {
  // An array with own `type`/`text` properties still occupies an array
  // position, where a block may not be substituted for the array itself.
  if (Array.isArray(value)) return false;
  const schema = CONTENT_BLOCK_SCHEMAS.get(value.type);
  // The own-key check is what blocks a polluted `Object.prototype.type`: the
  // `value.type` read above resolves through the prototype, so without it
  // `{ text: "leak" }` would tag itself a text block and be collapsed, dropping
  // a legitimate field on the fail-closed path.
  if (schema === undefined || !Object.hasOwn(value, "type")) return false;
  // Object.hasOwn, not a bare index: a bare lookup resolves inherited
  // Object.prototype members ("toString", "constructor") to real functions,
  // letting a key outside the schema pass as if it had a predicate.
  const isValidField = (/** @type {string} */ key) => {
    if (Object.hasOwn(schema.required, key))
      return schema.required[key](value[key]);
    if (Object.hasOwn(schema.optional, key))
      return schema.optional[key](value[key]);
    return false;
  };
  return (
    Object.keys(schema.required).every((key) => Object.hasOwn(value, key)) &&
    Object.keys(value).every((key) => key === "type" || isValidField(key))
  );
}

/**
 * Recursion core for {@link suppressToolOutput}; see {@link sanitizeValueAt} for
 * the depth/`seen` bookkeeping rationale.
 * @param {any} value
 * @param {string} message
 * @param {number} depth
 * @param {WeakSet<object>} seen
 * @param {ReturnType<typeof depthMemo<any>>} memo  cache of the suppressed
 *   subtree keyed by (node, depth), so a shared-substructure DAG collapses to
 *   linear work instead of being rebuilt once per path (see {@link depthMemo}
 *   for why the depth belongs in the key).
 * @returns {any}
 */
function suppressAt(value, message, depth, seen, memo) {
  if (typeof value === "string") return message;
  // Same opaque-leaf rule as sanitizeValueAt: only arrays and plain objects are
  // walked; an exotic object would be corrupted to an empty clone.
  if (!isWalkableContainer(value)) return value;
  // Walking a block's keys rewrites its `type` tag and the tagged unions under
  // it, yielding a block the API rejects with a 400 that then replays on every
  // later turn. Collapse to the one block shape `message` is legal in.
  if (isContentBlock(value)) return { type: "text", text: message };
  const cached = memo.get(value, depth);
  if (cached !== undefined) return cached;
  // Placeholders are not cached at all: they are O(1) to recompute, and the
  // cycle one depends on `seen` as well as on depth (see {@link depthMemo}).
  if (seen.has(value) || depth >= MAX_DEPTH) return message;

  seen.add(value);
  try {
    if (Array.isArray(value)) {
      const out = value.map((item) =>
        suppressAt(item, message, depth + 1, seen, memo),
      );
      memo.set(value, depth, out);
      return out;
    }
    /** @type {Record<string, any>} */
    const out = {};
    for (const [key, item] of Object.entries(value))
      // See sanitizeValueAt's identical guard: bracket assignment on a literal
      // "__proto__" key hits the special setter instead of creating an own
      // property, silently dropping the field and mutating out's prototype.
      Object.defineProperty(out, key, {
        value: suppressAt(item, message, depth + 1, seen, memo),
        enumerable: true,
        writable: true,
        configurable: true,
      });
    memo.set(value, depth, out);
    return out;
  } finally {
    seen.delete(value);
  }
}
