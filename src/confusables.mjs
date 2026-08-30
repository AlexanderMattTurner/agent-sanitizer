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
 * non-ASCII glyphs — see isTokenBoundary). A token folds only when both hold:
 *
 *   1. Folding makes it pure ASCII — every non-ASCII code point in it is
 *      flagged. The bypass requires the folded token to come out byte-equal to
 *      an ASCII deny-rule target, so a token left holding an unmapped glyph
 *      could never match one anyway; skipping it costs no enforcement.
 *   2. It is more than a lone non-ASCII glyph standing between two boundaries.
 *      A one-code-point token is a one-letter foreign word — Russian "с", "о",
 *      "у", "а" are among the most frequent words in the language — as readily
 *      as it is a disguised argument, and no deny rule targets a single
 *      character, so the evidence does not support rewriting it.
 *
 * That still catches the all-confusable disguise ("раѕѕwd" → "passwd") and the
 * anchored one ("pаsswd" → "passwd"), which is exactly the bypass to
 * close, while leaving genuine non-Latin prose intact: "Привет" keeps unmapped
 * П/и/в/т, so its mapped р/е are not folded and the word survives byte-for-byte.
 *
 * WHY THE GATE: without it, folding mangled any Cyrillic/Greek text passing
 * through a command or path — a Russian commit message, issue body, or filename
 * came out transliterated into garbage. A false positive here rewrites content
 * the operator wrote, which this repo weighs as the worse failure.
 *
 * RESIDUAL: a multi-letter foreign word composed ENTIRELY of mapped confusables
 * (the Russian "сор" → "cop") is indistinguishable from a disguised ASCII token
 * by construction, and still folds. Documented in THREAT-MODEL.md, not worked
 * around — the alternatives (a field-level gate, a "looks like a path" shape
 * heuristic) either open a bypass or trade one guess for another.
 *
 * ORDERING: the soundness argument assumes no later layer erases code points
 * from the same field, which would let an unmapped glyph the gate relied on
 * disappear after the decision — a zero-width run padded into a token suppresses
 * the fold, and the erasing layer then removes the very evidence for skipping it.
 * This fold does NOT run last: on Bash.command the invisible-char strip follows
 * it. A caller that composes the two is therefore responsible for re-running
 * this fold on the post-erasure text until it reports nothing, which is what the
 * hook driver in claude-hooks/lib/layer-pipeline.mjs does.
 *
 * Genuine non-confusable non-ASCII (accented Latin, CJK, emoji) is untouched
 * regardless, since a faithful scanner does not flag it.
 *
 * The confusable scanner defaults to namespace-guard and is resolved LAZILY, on
 * the first field that actually carries a non-ASCII glyph: loading its
 * vision-weighted map costs ~29 ms, and this module sits on the PreToolUse hook
 * path, which pays module load on every tool call. Pass `{ scan }` to override
 * with another engine — `scan(text)` returns `{ findings: [{ index, char,
 * latinEquivalent }] }`, `index` a UTF-16 offset, `char` the matched glyph
 * (possibly a 2-unit astral char), `latinEquivalent` its ASCII canon.
 */
import { createRequire } from "node:module";

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

// The other half of the partition: tools this layer has LOOKED AT and decided
// carry no field a deny rule matches byte-for-byte, each with the reason.
// Together with DEFAULT_FIELDS this is a declared scope rather than a
// fallthrough — an omission becomes a reviewable line instead of the absence of
// one, and test/confusables.test.mjs fails when a tool the package elsewhere
// claims to know lands in neither side.
/** @type {Record<string, string>} */
export const EXEMPT_TOOLS = Object.freeze({
  WebFetch:
    "the url is matched by a resolver, not by an ASCII deny rule, so folding " +
    "it would rewrite the attacker's host to the real one it merely resembles " +
    "— laundering the deception into a name the model then reports with " +
    "confidence. Confusable URLs are DETECTED instead (see ./confusable-host.mjs).",
  WebSearch:
    "the query is free text a search engine tokenizes; no byte-equal deny-rule " +
    "target exists for it, and folding would rewrite what the user asked for",
  Task: "inputs are a prompt and an agent name — free text, with no path or command field",
});

// Prefix-shaped exemptions, for tool families no fixed list can enumerate.
/** @type {ReadonlyArray<{ pattern: RegExp, reason: string }>} */
export const EXEMPT_TOOL_PATTERNS = Object.freeze([
  Object.freeze({
    pattern: /^mcp__/u,
    reason:
      "MCP tool inputs follow a server-declared schema this package cannot see, " +
      "so there is no field it can name as a path or command. A blanket fold " +
      "over every string in the input would rewrite opaque IDs and protocol " +
      "fields the server parses. A deployment that wants a specific server's " +
      "path field folded adds it to `fields` by its full tool name.",
  }),
]);

/**
 * The single place an unlisted tool's fate is decided: covered by a field list,
 * exempt with a stated reason, or undeclared — nobody has classified it.
 *
 * `undeclared` is NOT a runtime alarm; every arm leaves the tool unfolded, which
 * is what an unlisted tool already got. The signal is the partition test, which
 * reads this function.
 * @param {string} tool
 * @param {Record<string, string[]>} [fields]
 * @returns {{ kind: "covered", fields: string[] } | { kind: "exempt", reason: string } | { kind: "undeclared" }}
 */
export function scopeFor(tool, fields = DEFAULT_FIELDS) {
  if (Object.hasOwn(fields, tool))
    return { kind: "covered", fields: fields[tool] };
  if (Object.hasOwn(EXEMPT_TOOLS, tool))
    return { kind: "exempt", reason: EXEMPT_TOOLS[tool] };
  for (const { pattern, reason } of EXEMPT_TOOL_PATTERNS)
    if (pattern.test(tool)) return { kind: "exempt", reason };
  return { kind: "undeclared" };
}

/**
 * The default scanner, resolved on first use. `require` rather than a static
 * import so a caller that never hands this module a non-ASCII field never pays
 * namespace-guard's map load — see the module header.
 *
 * This does NOT make the hook's own `scan` injection redundant: the plugin
 * bundle ships without a node_modules, where namespace-guard exists only as a
 * pre-registered inlined copy, so a bare require there resolves nothing. The
 * hook's registry-first seam is the path that works on such a host.
 * @type {((text: string) => { findings: Array<{ index: number, char: string, latinEquivalent: string }> }) | undefined}
 */
let defaultScan;

/** @returns {(text: string) => { findings: Array<{ index: number, char: string, latinEquivalent: string }> }} */
function resolveScan() {
  defaultScan ??= createRequire(import.meta.url)("namespace-guard").scan;
  return /** @type {any} */ (defaultScan);
}

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
 * offset. Every consumer of a scanner finding runs this BEFORE acting on it, so
 * a buggy or adversarial scanner fails loud instead of silently corrupting (or
 * silently escaping the fold gate in) a path/command. `actual` is the bytes that
 * sit at `finding.index` right now — from the input for an untouched region,
 * from the folded output for one the caller has already rewritten.
 * @param {{ index: number, char: string, latinEquivalent: string }} finding
 * @param {string} actual
 * @returns {void}
 */
function assertFinding(finding, actual) {
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
  // An ASCII `char` is not a confusable — it is already its own canon. Folding
  // it is a no-op at best, but the fold gate reads a non-ASCII code point's
  // flagged/unflagged status to decide a token's fate, so a scanner claiming an
  // ASCII character is confusable is reporting something the contract says
  // cannot happen. Fail loud rather than act on a finding we cannot interpret.
  if (!hasNonAscii(finding.char))
    throw new Error(
      `Confusable finding at index ${finding.index} names an ASCII char ${JSON.stringify(finding.char)}`,
    );
  if (!actual.startsWith(finding.char))
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
 * The bytes `finding.char` claims to sit on, read from `text`. Bounded to the
 * glyph's own length so validating a finding never copies the rest of the input.
 * @param {string} text
 * @param {{ index: number, char: string }} finding
 * @returns {string}
 */
function bytesAt(text, finding) {
  return text.slice(finding.index, finding.index + finding.char.length);
}

/**
 * True for a code point that ends a token: any ASCII character that is not a
 * letter or digit (space, `/`, `.`, `-`, `_`, quotes, shell metacharacters). A
 * token is therefore a maximal run of ASCII alphanumerics and non-ASCII glyphs.
 * That is not a shell word or a path segment — it is deliberately the SMALLEST
 * unit that still keeps a word of foreign prose whole, so one such word can
 * never switch folding off for the tokens around it.
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
 * Keep only the findings whose TOKEN is foldable — see the module header for the
 * two conditions (folds to pure ASCII; is not a lone glyph) and THREAT-MODEL.md
 * for why declining the rest forfeits no enforcement.
 *
 * Every finding is validated before it is judged, so an adversarial scanner's
 * bogus finding throws rather than being quietly dropped by the gate.
 * @param {string} text
 * @param {Array<{ index: number, char: string, latinEquivalent: string }>} findings
 * @returns {Array<{ index: number, char: string, latinEquivalent: string }>}
 */
export function selectFoldableFindings(text, findings) {
  for (const finding of findings)
    assertFinding(finding, bytesAt(text, finding));

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
  let glyphs = 0;
  let anchored = false;
  let index = 0;
  /**
   * Close the token ending at `end`, marking it foldable when it holds no
   * unmapped glyph and is more than a lone glyph, then reset for the next one.
   * @param {number} end
   */
  const flushToken = (end) => {
    if (foldable && (glyphs > 1 || anchored)) foldableAt.fill(1, start, end);
    foldable = true;
    glyphs = 0;
    anchored = false;
  };
  for (const ch of text) {
    if (isTokenBoundary(ch)) {
      flushToken(index);
      start = index + ch.length;
    } else {
      glyphs++;
      if (!hasNonAscii(ch)) anchored = true;
      // An unmapped non-ASCII glyph: this token cannot fold to ASCII.
      else if (!flagged.has(index)) foldable = false;
    }
    index += ch.length;
  }
  flushToken(index);

  // Every offset the finding covers, not just its first: `char` may span a
  // boundary into a token the gate rejected, and folding it would rewrite that
  // token — the exact mangling this gate exists to prevent.
  return findings.filter((finding) =>
    [...finding.char].every((_, i) => foldableAt[finding.index + i] === 1),
  );
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
  // The folded text is `text.slice(0, cursor)` followed by `tail` read
  // BACKWARDS: each finding appends the gap that follows it and then its
  // replacement, so the string is assembled once at the end. Splicing a fresh
  // string per finding instead costs O(findings x length) — a 128 KB command
  // stuffed with look-alikes took 1.8 s of the PreToolUse hook that way.
  /** @type {string[]} */
  const tail = [];
  let cursor = text.length;
  for (const finding of [...findings].sort(
    (lhs, rhs) => rhs.index - lhs.index,
  )) {
    const end = finding.index + finding.char.length;
    // Validate against the text as the fold has left it, so a scanner reporting
    // a glyph that is not there fails loud. Highest-index-first leaves every
    // offset below `cursor` byte-identical to `text`, so a finding ending there
    // is checked against `text` itself; one reaching PAST `cursor` overlaps a
    // fold already applied, and only the folded bytes carry what it now sits on.
    if (end <= cursor) {
      assertFinding(finding, bytesAt(text, finding));
      tail.push(text.slice(end, cursor));
    } else {
      // The overlap reaches at most `char.length` past `cursor`, and those bytes
      // are the ones pushed most recently, so take them off the tail instead of
      // re-joining all of it — a whole-tail rebuild per overlapping finding is
      // the O(findings x length) cost this assembly exists to avoid. Consuming
      // them is also what the fold means: `char` replaces those bytes.
      const overlap = takeFromTail(tail, end - cursor);
      assertFinding(finding, text.slice(finding.index, cursor) + overlap);
    }
    tail.push(finding.latinEquivalent);
    cursor = finding.index;
  }
  return text.slice(0, cursor) + [...tail].reverse().join("");
}

/**
 * Remove and return the first `count` characters of the folded tail. The tail is
 * stored back-to-front, so its lowest-offset bytes are the entries pushed most
 * recently and popping walks them in reading order; a partially consumed entry
 * is pushed back minus what was taken.
 * @param {string[]} tail
 * @param {number} count
 * @returns {string}
 */
function takeFromTail(tail, count) {
  /** @type {string[]} */
  const taken = [];
  let remaining = count;
  while (remaining > 0) {
    const entry = tail.pop();
    // A tail shorter than `count` means the finding claims bytes past the end of
    // the folded text — a mismatching finding, which the caller's assertion
    // rejects by name once it sees the short result. Stop rather than pretend.
    if (entry === undefined) break;
    if (entry.length > remaining) {
      taken.push(entry.slice(0, remaining));
      tail.push(entry.slice(remaining));
      break;
    }
    taken.push(entry);
    remaining -= entry.length;
  }
  return taken.join("");
}

/**
 * Normalize confusable/homoglyph chars in the path/command fields of a tool
 * call. Returns the updated input plus the fields touched, or null when nothing
 * changed. Throws if the scanner fails (the caller fails closed: an
 * un-normalized confusable could slip past a deny rule).
 *
 * `scan` overrides the confusable engine: `scan(text)` → `{ findings }` (an
 * empty `findings` means no confusables). Omit it to use namespace-guard, which
 * is resolved lazily. `fields` maps a tool name to the input keys to fold;
 * defaults to {@link DEFAULT_FIELDS}.
 * @param {string} tool
 * @param {any} toolInput
 * @param {{ scan?: (text: string) => { findings: Array<{ index: number, char: string, latinEquivalent: string }> }, fields?: Record<string, string[]> }} [options]
 * @returns {{ updatedInput: any, normalized: string[] } | null}
 */
export function normalizeConfusables(tool, toolInput, options = {}) {
  const { scan, fields = DEFAULT_FIELDS } = options;
  const scope = scopeFor(tool, fields);
  if (scope.kind !== "covered" || toolInput === null || toolInput === undefined)
    return null;
  const keys = scope.fields;

  // ASCII fast-path: only a field carrying a non-ASCII code unit can hold a
  // confusable, so all-ASCII input never invokes the (heavy) scanner — and never
  // loads it either, when the default engine is the one in use.
  const candidates = keys.filter(
    (k) => typeof toolInput[k] === "string" && hasNonAscii(toolInput[k]),
  );
  if (candidates.length === 0) return null;

  const runScan = scan ?? resolveScan();
  const normalized = [];
  const updatedInput = { ...toolInput };
  for (const k of candidates) {
    const { findings } = runScan(toolInput[k]);
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
