/**
 * Confusable / homoglyph folding for tool-call INPUT fields.
 *
 * Folding look-alike glyphs to their ASCII canon narrows the steganographic
 * channel a model-to-model paste can open and closes the cross-script deny-rule
 * bypass of CVE-2025-54794: a Cyrillic "а" dressed as ASCII "a" would not match
 * an ASCII deny rule, so an attacker could slip a denied path/command past a
 * filter by spelling it in look-alike code points.
 *
 * Folding is gated per TOKEN (a maximal run of ASCII alphanumerics and
 * non-ASCII glyphs — see isTokenBoundary): a token folds only when doing so
 * makes it pure ASCII, i.e. every non-ASCII code point in it is flagged. The
 * bypass requires the folded token to come out byte-equal to an ASCII deny-rule
 * target, so a token left holding an unmapped glyph could never match one
 * anyway — skipping it costs no enforcement. That still catches an ISOLATED
 * confusable with no ASCII anchor (a lone Cyrillic "а" in "/а", or an
 * all-Cyrillic "раѕѕwd"), which is exactly the bypass to close, while leaving
 * genuine non-Latin prose intact: "Привет" keeps unmapped П/и/в/т, so its
 * mapped р/е are not folded and the word survives byte-for-byte.
 *
 * WHY THE GATE: without it, folding mangled any Cyrillic/Greek text passing
 * through a command or path — a Russian commit message, issue body, or filename
 * came out transliterated into garbage. A false positive here rewrites content
 * the operator wrote, which this repo weighs as the worse failure.
 *
 * RESIDUAL: a short foreign word composed ENTIRELY of mapped confusables (the
 * Russian "сор" → "cop") is indistinguishable from a disguised ASCII token by
 * construction, and still folds. Documented in THREAT-MODEL.md, not worked
 * around — the alternatives (a field-level gate, a "looks like a path" shape
 * heuristic) either open a bypass or trade one guess for another.
 *
 * Genuine non-confusable non-ASCII (accented Latin, CJK, emoji) is untouched
 * regardless, since a faithful scanner does not flag it.
 *
 * The confusable scanner is INJECTED, never imported: the canonical engine
 * (namespace-guard's vision-weighted map) is a heavy, separately-owned peer.
 * Pass `{ scan }` where `scan(text)` returns `{ findings: [{ index, char,
 * latinEquivalent }] }` — `index` a UTF-16 offset, `char` the matched glyph
 * (possibly a 2-unit astral char), `latinEquivalent` its ASCII canon.
 */

/**
 * Default path/command fields to fold per tool. Agent-agnostic: the keys are
 * the conventional Claude/Anthropic tool names, but a caller with a different
 * tool surface passes its own `fields` map.
 * @type {Record<string, string[]>}
 */
export const DEFAULT_FIELDS = {
  Bash: ["command"],
  Edit: ["file_path"],
  Write: ["file_path"],
  Read: ["file_path"],
  MultiEdit: ["file_path"],
  NotebookEdit: ["notebook_path"],
  Grep: ["pattern", "path"],
  Glob: ["pattern", "path"],
  LS: ["path"],
};

/**
 * True iff any UTF-16 code unit is outside ASCII (> 0x7F). Surrogates (astral
 * chars) are >= 0xD800 so they count; ASCII control chars (tab, newline) stay
 * ASCII. A plain loop, not a regex, to avoid a control char in the pattern.
 * @param {string} value
 * @returns {boolean}
 */
export function hasNonAscii(value) {
  for (let i = 0; i < value.length; i++) {
    if (value.charCodeAt(i) > 0x7f) return true;
  }
  return false;
}

/**
 * Model-facing note naming the fields whose confusables were folded.
 * @param {string[]} normalized
 * @returns {string}
 */
export function normalizeContext(normalized) {
  return `Confusable characters normalized in: ${normalized.join(", ")}. If a path now fails to resolve, the on-disk name itself contains the look-alike glyph shown.`;
}

// Cap the per-field fold list so a glyph-stuffed input can't bloat the context.
const MAX_REPORTED_FOLDS = 8;

/** @param {Array<{ char: string, latinEquivalent: string }>} findings */
function describeFolds(findings) {
  const folds = [
    ...new Set(
      findings.map(
        (finding) =>
          // char is always a non-empty confusable glyph, so codePointAt(0) is
          // defined; the cast avoids an unreachable `?? 0` fallback branch.
          `U+${
            /** @type {number} */ (finding.char.codePointAt(0))
              .toString(16)
              .toUpperCase()
              .padStart(4, "0")
          } → "${finding.latinEquivalent}"`,
      ),
    ),
  ];
  const shown = folds.slice(0, MAX_REPORTED_FOLDS).join(", ");
  return folds.length > MAX_REPORTED_FOLDS ? `${shown}, …` : shown;
}

/**
 * Reject a finding that does not describe a real, foldable glyph at its reported
 * offset in `text`. Every consumer of a scanner finding runs this BEFORE acting
 * on it, so a buggy or adversarial scanner fails loud instead of silently
 * corrupting (or silently escaping the fold gate in) a path/command.
 * @param {string} text
 * @param {{ index: number, char: string, latinEquivalent: string }} finding
 * @returns {void}
 */
function assertFinding(text, finding) {
  // Fail loud on a finding that does not match the actual bytes at its offset:
  // a buggy/adversarial scanner reporting a wrong char/index would otherwise
  // silently corrupt the path/command, defeating the deny-rule protection.
  // A negative index is the gap the startsWith guard alone misses: when `char`
  // is a prefix of the text, `startsWith(char, -1)` is true (the offset is
  // clamped to 0), and the slice math below then mangles the string instead of
  // throwing — so range-check the index explicitly first.
  if (!Number.isInteger(finding.index) || finding.index < 0)
    throw new Error(
      `Confusable finding has an out-of-range index ${finding.index}`,
    );
  // An empty `char` makes startsWith("", i) vacuously true for ANY index, so
  // the splice inserts latinEquivalent without consuming a code point — silent
  // insertion-corruption — and describeFolds then crashes on "".codePointAt(0).
  // A finding must name a real matched glyph, so reject it loudly rather than
  // let a buggy/adversarial scanner corrupt the input.
  if (finding.char === "")
    throw new Error(
      `Confusable finding at index ${finding.index} has an empty char`,
    );
  if (!text.startsWith(finding.char, finding.index))
    throw new Error(
      `Confusable finding does not match input at index ${finding.index}: expected ${JSON.stringify(finding.char)}`,
    );
  // An empty `latinEquivalent` slips past the ASCII loop below (it never
  // iterates) and would splice the glyph to nothing — silently DELETING a
  // character from a path/command. That is the same class of silent corruption
  // the non-ASCII guard rejects, so fail loud here too rather than let a
  // buggy/adversarial scanner erase input.
  if (finding.latinEquivalent === "")
    throw new Error(
      `Confusable finding for ${JSON.stringify(
        finding.char,
      )} at index ${finding.index} has an empty latinEquivalent`,
    );
  // The replacement must be the ASCII canon the contract promises. A non-ASCII
  // `latinEquivalent` would fold one confusable into ANOTHER look-alike (e.g.
  // Cyrillic а → Cyrillic е), defeating the whole point — the cross-script
  // deny-rule bypass would survive — and silently break the fold-to-ASCII
  // invariant callers rely on, so reject it loudly.
  for (const ch of finding.latinEquivalent)
    if (/** @type {number} */ (ch.codePointAt(0)) > 0x7f)
      throw new Error(
        `Confusable latinEquivalent ${JSON.stringify(
          finding.latinEquivalent,
        )} is not ASCII`,
      );
}

/**
 * True for a code point that ends a token: any ASCII character that is not a
 * letter or digit (space, `/`, `.`, `-`, `_`, quotes, shell metacharacters). A
 * token is therefore a maximal run of ASCII alphanumerics and non-ASCII glyphs —
 * the unit a deny rule or a filesystem lookup actually matches on. Non-ASCII
 * never breaks a token, so a word of foreign prose stays whole.
 * @param {string} ch a single code point
 * @returns {boolean}
 */
function isTokenBoundary(ch) {
  if (hasNonAscii(ch)) return false;
  const code = ch.charCodeAt(0);
  const isDigit = code >= 0x30 && code <= 0x39;
  const isUpper = code >= 0x41 && code <= 0x5a;
  const isLower = code >= 0x61 && code <= 0x7a;
  return !isDigit && !isUpper && !isLower;
}

/**
 * Keep only the findings whose TOKEN folds to pure ASCII — i.e. every non-ASCII
 * code point in the token is itself flagged.
 *
 * This is the precision gate on the fold (see the module header). The
 * cross-script bypass it exists to close requires the folded token to come out
 * byte-equal to an ASCII deny-rule target, so a token that still holds an
 * unmapped non-ASCII glyph after folding cannot match one either way: declining
 * to fold it forfeits no enforcement, and folding it would mangle genuine
 * non-Latin text. `/etc/pаsswd`, a lone `/а`, and an all-Cyrillic `раѕѕwd` all
 * still fold; `Привет` (unmapped П/и/в/т remain) does not.
 *
 * The gate is per-TOKEN, never per-field: a field-level "any prose here → skip
 * the field" rule would let an attacker switch folding off for a whole command
 * by appending one foreign word.
 *
 * Every finding is validated before it is judged, so an adversarial scanner's
 * bogus finding throws rather than being quietly dropped by the gate.
 * @param {string} text
 * @param {Array<{ index: number, char: string, latinEquivalent: string }>} findings
 * @returns {Array<{ index: number, char: string, latinEquivalent: string }>}
 */
export function selectFoldableFindings(text, findings) {
  for (const finding of findings) assertFinding(text, finding);
  if (findings.length === 0) return [];

  // Every UTF-16 offset a finding covers, not just its start: a scanner is free
  // to report a multi-code-point match, and treating only the first offset as
  // flagged would read the rest as unmapped and reject an otherwise ASCII token.
  const flagged = new Set();
  for (const finding of findings)
    for (let i = 0; i < finding.char.length; i++)
      flagged.add(finding.index + i);

  // Mark the offsets belonging to a foldable token, so the per-finding lookup
  // below is O(1). An interval scan per finding would be quadratic on a
  // glyph-stuffed command — this runs on every tool call.
  const foldableAt = new Uint8Array(text.length);
  let start = 0;
  let foldable = true;
  let index = 0;
  /** @param {number} end */
  const closeToken = (end) => {
    if (foldable) foldableAt.fill(1, start, end);
    foldable = true;
  };
  for (const ch of text) {
    if (isTokenBoundary(ch)) {
      closeToken(index);
      start = index + ch.length;
    } else if (hasNonAscii(ch) && !flagged.has(index)) {
      // An unmapped non-ASCII glyph: this token cannot fold to ASCII.
      foldable = false;
    }
    index += ch.length;
  }
  closeToken(index);

  return findings.filter((finding) => foldableAt[finding.index] === 1);
}

/**
 * Replace every scan-flagged confusable with its ASCII (latin) equivalent.
 * `index` is a UTF-16 offset into `text` and `char` is the matched glyph (which
 * may be an astral, 2-unit char); splice highest-index first so a
 * length-changing fold never shifts the offsets of earlier findings.
 * @param {string} text
 * @param {Array<{ index: number, char: string, latinEquivalent: string }>} findings
 * @returns {string}
 */
export function foldConfusables(text, findings) {
  let folded = text;
  for (const finding of [...findings].sort(
    (lhs, rhs) => rhs.index - lhs.index,
  )) {
    // Validate against the partially-folded text: the highest-index-first order
    // leaves every not-yet-spliced offset byte-identical to `text`, so the
    // startsWith check still sees the original glyph at the reported index.
    assertFinding(folded, finding);
    folded =
      folded.slice(0, finding.index) +
      finding.latinEquivalent +
      folded.slice(finding.index + finding.char.length);
  }
  return folded;
}

/**
 * Normalize confusable/homoglyph chars in the path/command fields of a tool
 * call. Returns the updated input plus the fields touched, or null when nothing
 * changed. Throws if the injected scanner fails (the caller fails closed: an
 * un-normalized confusable could slip past a deny rule).
 *
 * `scan` is the injected confusable engine: `scan(text)` → `{ findings }` (an
 * empty `findings` means no confusables). `fields` maps a tool name to the
 * input keys to fold; defaults to {@link DEFAULT_FIELDS}.
 * @param {string} tool
 * @param {any} toolInput
 * @param {{ scan: (text: string) => { findings: Array<{ index: number, char: string, latinEquivalent: string }> }, fields?: Record<string, string[]> }} options
 * @returns {{ updatedInput: any, normalized: string[] } | null}
 */
export function normalizeConfusables(
  tool,
  toolInput,
  { scan, fields = DEFAULT_FIELDS },
) {
  const keys = Object.hasOwn(fields, tool) ? fields[tool] : undefined;
  if (!keys || toolInput === null || toolInput === undefined) return null;

  // ASCII fast-path: only a field carrying a non-ASCII code unit can hold a
  // confusable, so all-ASCII input never invokes the (heavy) scanner.
  const candidates = keys.filter(
    (k) => typeof toolInput[k] === "string" && hasNonAscii(toolInput[k]),
  );
  if (candidates.length === 0) return null;

  const normalized = [];
  const updatedInput = { ...toolInput };
  for (const k of candidates) {
    const { findings } = scan(toolInput[k]);
    if (findings.length === 0) continue;
    // Precision gate: fold only what a deny rule could actually match (see
    // selectFoldableFindings). Report the folds APPLIED, not the ones scanned —
    // naming a glyph the model can still see in the field would be a lie.
    const foldable = selectFoldableFindings(toolInput[k], findings);
    if (foldable.length === 0) continue;
    updatedInput[k] = foldConfusables(toolInput[k], foldable);
    normalized.push(`${k} (${describeFolds(foldable)})`);
  }

  if (normalized.length === 0) return null;
  return { updatedInput, normalized };
}
