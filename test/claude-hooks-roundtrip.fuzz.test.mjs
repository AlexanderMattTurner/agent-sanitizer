/**
 * Whole-pipeline round-trip fuzz: PostToolUse sanitize → adversarial "model
 * edits" of the sanitized text → PreToolUse rehydration, iterated over multiple
 * rounds against the REAL hook entry points (evaluateToolOutput,
 * rehydrateLayer2, buildPreToolUseResponse). The per-primitive suites
 * (html-property, splice-property, claude-hooks-layer2-*) pin each stage in
 * isolation; this file pins the COMPOSITION — the loop an agent session
 * actually runs, where round n+1's tool output is round n's rehydrated write.
 *
 * The oracle re-derives every expectation instead of calling back into the
 * code under test: the placeholder grammar is restated as a LITERAL here (and
 * pinned against the hooks' copy, so a widened grammar fails rather than
 * silently moving the oracle with it), span bytes are read with raw
 * readFileSync rather than readSpan, the key rule is recomputed from sha256,
 * and the expected rehydrated text is spliced by hand. Invariants:
 *
 *   (a) every well-formed placeholder whose span persisted rehydrates to the
 *       stored bytes, byte-exact, at every round;
 *   (b) every byte outside a placeholder survives rehydration untouched
 *       (subsumed by the byte-exact expected-output equality);
 *   (c/g) the planted secret never appears in any model-visible surface or in
 *       any span file, any round;
 *   (d/f) the verdict trichotomy (updatedInput / deny / null) is total and
 *       predicted from key presence alone; a deny never carries updatedInput;
 *   (e) placeholder text is a fixed point of re-sanitization, and a secret-free
 *       splice round-trips to a byte-identical document under the SAME
 *       content-addressed key (recomputed here from sha256, independently).
 *
 * Known-lossy-by-design behavior is asserted POSITIVELY, never flagged:
 * mangled placeholders write through as literal text, fabricated well-formed
 * unknown keys deny naming the key, MultiEdit/NotebookEdit carrying keys deny,
 * Edit's old_string is never rehydrated, and lookalike prose is never treated
 * as a placeholder.
 */
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import fc from "fast-check";
import { fcRunOptions, startStubRedactorDaemon } from "./test-helpers.mjs";

// Stub redactor socket + project dir BEFORE the hook imports (the redactor
// client resolves its socket path at module load; the invisible-char gate
// hashes CLAUDE_PROJECT_DIR at load). Never restored: node --test forks one
// process per test file, so these writes cannot reach another suite. The
// sanitize budget is pinned high because one wall-clock deadline spans every
// leaf of every round, and an expiry mid-property would nondeterministically
// drop spans.
const socketDir = mkdtempSync(join(tmpdir(), "sanitizer-rt-fuzz-sock-"));
const socketPath = join(socketDir, "redactor.sock");
process.env._AGENT_SANITIZER_REDACTOR_SOCKET = socketPath;
process.env.AGENT_SANITIZER_SECRETS_ENABLED = "1";
process.env._AGENT_SANITIZER_SANITIZE_BUDGET_MS = "600000";
const projectDir = mkdtempSync(join(tmpdir(), "sanitizer-rt-fuzz-proj-"));
process.env.CLAUDE_PROJECT_DIR = projectDir;
const revealBase = mkdtempSync(join(tmpdir(), "sanitizer-rt-fuzz-store-"));

const { evaluateToolOutput } =
  await import("../claude-hooks/sanitize-output.mjs");
const { buildPreToolUseResponse, rehydrateLayer2 } =
  await import("../claude-hooks/pretooluse-sanitize.mjs");
const { LAYER2_PLACEHOLDER_RE } =
  await import("../claude-hooks/lib/placeholder-grammar.mjs");
const { PermissionDecision } = await import("../claude-hooks/lib/hook-io.mjs");

// The grammar as the ORACLE understands it. Restated as a literal rather than
// reused from the hooks so the two can disagree: were the shipped grammar
// widened (uppercase hex, a longer key, a new label), this suite would fail on
// the pin below instead of silently adopting the change and continuing to
// "pass".
const ORACLE_PLACEHOLDER_RE =
  /\[(?:hidden HTML|HTML comment) removed #([0-9a-f]{12})\]/g;

// Secrets are always planted WITH a hint word ("password") so the hint
// pre-gate provably routes the text to the daemon — a hintless secret
// legitimately bypasses redaction by design, and asserting on it would flag
// documented behavior.
const SECRET_VALUE = "hunter2hunter2hunter2";
const REDACTED_MARK = "[REDACTED: password]";

/** @type {import("node:net").Server} */
let daemon;
before(async () => {
  daemon = await startStubRedactorDaemon(socketPath, {
    secret: SECRET_VALUE,
    mark: REDACTED_MARK,
  });
});
after(async () => {
  await new Promise((resolve) => daemon.close(resolve));
  for (const dir of [socketDir, projectDir, revealBase])
    rmSync(dir, { recursive: true, force: true });
});

// One fresh span store PER fc ITERATION, shared across the rounds inside it:
// cross-round aliasing (a round-1 span satisfying a round-3 placeholder) and
// first-write-wins dedupe are exactly the content-addressed design under
// test, but a store shared across ITERATIONS would let an earlier draw's span
// satisfy a later draw's key and make shrunk counterexamples irreproducible.
// The previous iteration's store is removed as the next one is made, so the
// run holds one store at a time instead of ~2k of them.
let currentStore = null;
function freshStore() {
  if (currentStore !== null)
    rmSync(currentStore, { recursive: true, force: true });
  currentStore = mkdtempSync(join(revealBase, "store-"));
  process.env._AGENT_SANITIZER_REVEAL_DIR = currentStore;
  return currentStore;
}

/** The documented key rule, recomputed independently of the engine. */
const keyOf = (original) =>
  createHash("sha256").update(original, "utf8").digest("hex").slice(0, 12);

/** The exact context the Layer-2 rehydrator attaches on a successful restore. */
const restoredContext = (count, field) =>
  `${count} Layer-2 removed-content placeholder(s) in ${field} were restored ` +
  `to the stored original content (secrets inside were redacted before ` +
  `storage, so no raw secret is written).`;

// ---------------------------------------------------------------------------
// Non-vacuity counters, namespaced PER PROPERTY: one shared bag would let a
// whole property be deleted while its counters stayed green off another
// property's increments.
const newBag = (names) => Object.fromEntries(names.map((name) => [name, 0]));
const counters = {
  p1: newBag([
    "hiddenSplices",
    "commentSplices",
    "rehydrations",
    "denies",
    "unknownKeyDenies",
    "missingSpanDenies",
    "mangledWrittenThrough",
    "deepRehydrations",
    "keysReobservedAcrossRounds",
    "secretSpansRedacted",
    "mcpStructuredSplices",
    "oldStringPreserved",
  ]),
  p2: newBag([
    "hiddenSplices",
    "commentSplices",
    "rehydrations",
    "denies",
    "unknownKeyDenies",
    "cleanNoops",
  ]),
  p3: newBag([
    "multiEditDenies",
    "notebookDenies",
    "layer2Advisories",
    "secretAdvisories",
    "passThroughShapes",
    "unrehydratableShapes",
  ]),
  p4: newBag([
    "lookalikesPreserved",
    "mintedRehydrations",
    "nestedTokenLeftLiteral",
  ]),
  p5: newBag(["stableKeys"]),
};

// ---------------------------------------------------------------------------
// Corpus. Curated subsets duplicated module-local from the existing suites'
// module-local corpora (html-semantic-fuzz STRIP/KEEP tokens, html-property's
// round-trip pieces, rehydrate-property's astral filler) — deliberately NOT
// lifted into test-helpers.mjs, which would churn suites this change doesn't
// own.

// Flat hiding constructs: the splice covers the WHOLE construct, so a test can
// predict the exact placeholder from the construct's bytes.
const flatHiddenWraps = [
  (inner) => `<div hidden>${inner}</div>`,
  (inner) => `<span style="display:none">${inner}</span>`,
  (inner) => `<p style="visibility: hidden">${inner}</p>`,
  (inner) => `<div style="position:absolute;left:-9999px">${inner}</div>`,
  (inner) => `<span style="opacity: 0">${inner}</span>`,
];

const benignHiddenArb = fc
  .tuple(fc.constantFrom(...flatHiddenWraps), fc.nat(999))
  .map(([wrap, n]) => wrap(`STRIP${n} payload`));

const hiddenConstructArb = fc
  .tuple(
    fc.constantFrom(
      ...flatHiddenWraps,
      (inner) => `<div><div hidden>${inner}</div></div>`,
    ),
    fc.nat(999),
    // Some hidden payloads carry the planted (hinted) secret so the
    // span-persist redaction path runs; the rest are benign markers.
    fc.boolean(),
  )
  .map(([wrap, n, withSecret]) =>
    wrap(withSecret ? `password token: ${SECRET_VALUE}` : `STRIP${n} payload`),
  );

const commentConstructArb = fc
  .tuple(
    fc.constantFrom(
      (inner) => `<!-- ${inner} -->`,
      (inner) => `<!--${inner}-->`,
      (inner) => `<![CDATA[${inner}]]>`,
      (inner) => `<!bogus ${inner}>`,
    ),
    fc.nat(999),
  )
  .map(([wrap, n]) => wrap(`marker${n}`));

// Visible filler, including astral/CJK/combining glyphs so UTF-16 offsets and
// code-point offsets diverge around the placeholders.
const visibleFillerArb = fc.oneof(
  { weight: 3, arbitrary: fc.stringMatching(/^[a-zA-Z0-9 .,'!?_-]{1,30}$/) },
  fc.constantFrom(
    "<p>visible prose</p>",
    "<b>kept</b> text",
    "\u{1F511} key \u{1F510}",
    "日本語のテキスト",
    "café naïve",
    "\u{10348}\u{10349} hwair",
  ),
);

// ASCII-only filler for the full-pipeline property, where the confusables and
// authored-content layers must be provable no-ops on the edit material.
const asciiFillerArb = fc.stringMatching(/^[a-zA-Z0-9 .,'!?_-]{1,30}$/);

// Near-miss literals that must NEVER be treated as Layer-2 placeholders. The
// `[REDACTED: token]` entry is the one that also trips the SECRET advisory —
// tracked separately so property 3 can pin which advisory fired.
const SECRET_LOOKALIKE = "[REDACTED: token]";
const lookalikeArb = fc.constantFrom(
  "[hidden HTML removed]",
  "[hidden HTML removed #ABCDEF123456]",
  "[HTML comment removed #abc]",
  "[hidden HTML removed #0123456789abc]",
  "[hidden html removed #0123456789ab]",
  SECRET_LOOKALIKE,
  "see #a1b2c3d4e5f6 for details",
);

/** @param {import("fast-check").Arbitrary<string>} filler */
const docPiecesArb = (filler) =>
  fc.array(
    fc.oneof(
      { weight: 2, arbitrary: hiddenConstructArb },
      { weight: 2, arbitrary: commentConstructArb },
      { weight: 3, arbitrary: filler },
      { weight: 1, arbitrary: lookalikeArb },
    ),
    { minLength: 1, maxLength: 8 },
  );

const toolShapeArb = fc.constantFrom(
  { tool: "WebFetch", shape: "string" },
  { tool: "WebFetch", shape: "structured" },
  { tool: "mcp__web__fetch", shape: "string" },
  { tool: "mcp__web__fetch", shape: "structured" },
);

const hex12Arb = fc.stringMatching(/^[0-9a-f]{12}$/);

// Adversarial model-edit operators applied to the sanitized text each round.
const opArb = fc.oneof(
  fc.record({ op: fc.constant("passthrough") }),
  fc.record({
    op: fc.constant("insertProse"),
    at: fc.nat(1000),
    text: fc.stringMatching(/^[a-zA-Z0-9 .,'!?_-]{0,20}$/),
  }),
  fc.record({ op: fc.constant("duplicateKey"), pick: fc.nat(50) }),
  fc.record({ op: fc.constant("dropPlaceholder"), pick: fc.nat(50) }),
  fc.record({
    op: fc.constant("mangle"),
    pick: fc.nat(50),
    how: fc.constantFrom("upcaseHex", "truncHex", "breakBracket", "wrongWord"),
  }),
  fc.record({ op: fc.constant("fabricate"), hex: hex12Arb, at: fc.nat(1000) }),
);

const roundArb = fc.record({
  tool: fc.constantFrom("Write", "Edit"),
  ops: fc.array(opArb, { minLength: 1, maxLength: 3 }),
  // Edit only: whether old_string also carries the (placeholder-bearing) text,
  // which must come back untouched — old_string is never rehydrated.
  keysInOldString: fc.boolean(),
});

// ---------------------------------------------------------------------------
// Oracle helpers — grammar-literal re-derivations, independent of the hooks.

/** @param {string} text */
function placeholderMatches(text) {
  return [...text.matchAll(ORACLE_PLACEHOLDER_RE)].map((match) => ({
    token: match[0],
    index: /** @type {number} */ (match.index),
    key: match[1],
  }));
}

/** Deep-collect every string leaf of a sanitized tool_response. */
function flattenStrings(value, out = []) {
  if (typeof value === "string") out.push(value);
  else if (Array.isArray(value))
    for (const item of value) flattenStrings(item, out);
  else if (value !== null && typeof value === "object")
    for (const item of Object.values(value)) flattenStrings(item, out);
  return out;
}

/**
 * Run one PostToolUse sanitize round and return the sanitized document text
 * (the model's next view). A null response means nothing changed.
 */
async function sanitizeRound(toolName, shape, doc) {
  const tool_response =
    shape === "structured" ? { result: { content: doc, meta: "ok" } } : doc;
  const fields = await evaluateToolOutput({
    tool_name: toolName,
    tool_input: {},
    tool_response,
  });
  const mutated = fields?.mutated_output ?? tool_response;
  const text = shape === "structured" ? mutated.result.content : mutated;
  assert.equal(typeof text, "string");
  // (c) on the PostToolUse surfaces: the secret only ever rides inside a
  // hiding construct, so a splice (or its redaction) must keep it out of the
  // model's view and out of the advisory text.
  assert.ok(!flattenStrings(mutated).join("\n").includes(SECRET_VALUE));
  if (fields?.additional_context !== undefined)
    assert.ok(!fields.additional_context.includes(SECRET_VALUE));
  return text;
}

/**
 * Fold the placeholders visible in `text` into the iteration's ledger of
 * key → persisted span bytes, reading the store with raw readFileSync so the
 * oracle's view of the store never routes through the code under test. A
 * placeholder whose span never persisted stays OUT of the ledger — the oracle
 * then expects a deny for it, which is the documented fail-closed outcome.
 */
function ledgerUpdate(ledger, storeDir, text, bag) {
  for (const { key } of placeholderMatches(text)) {
    let bytes;
    try {
      bytes = readFileSync(join(storeDir, `span-${key}.txt`), "utf8");
    } catch (err) {
      // Only "this span was never persisted" is a documented outcome; any
      // other I/O failure is a broken store and must not read as one.
      if (err.code !== "ENOENT") throw err;
      continue;
    }
    if (ledger.has(key)) {
      // Content addressing plus first-write-wins: a key seen in a later round
      // must still name byte-identical stored content.
      assert.equal(bytes, ledger.get(key));
      bag.keysReobservedAcrossRounds++;
    } else {
      ledger.set(key, bytes);
    }
    // (g) plus the redaction proof: a span that carried the planted secret
    // must hold the daemon's redaction mark instead.
    assert.ok(!bytes.includes(SECRET_VALUE));
    if (bytes.includes(REDACTED_MARK)) bag.secretSpansRedacted++;
  }
}

/**
 * Apply the round's model-edit operators. Returns the edited text plus the
 * mangled tokens (expected to write through literally) and the fabricated
 * unknown-key tokens (expected to deny).
 */
function applyOps(text, ops, ledger) {
  const mangled = [];
  const fabricated = [];
  for (const op of ops) {
    const matches = placeholderMatches(text);
    if (op.op === "insertProse") {
      const at = op.at % (text.length + 1);
      text = text.slice(0, at) + op.text + text.slice(at);
    } else if (op.op === "duplicateKey" && matches.length > 0) {
      const pick = matches[op.pick % matches.length];
      text = `${text} ${pick.token}`;
    } else if (op.op === "dropPlaceholder" && matches.length > 0) {
      const pick = matches[op.pick % matches.length];
      text =
        text.slice(0, pick.index) + text.slice(pick.index + pick.token.length);
    } else if (op.op === "mangle" && matches.length > 0) {
      const pick = matches[op.pick % matches.length];
      const damaged =
        op.how === "upcaseHex"
          ? pick.token.replace(pick.key, pick.key.toUpperCase())
          : op.how === "truncHex"
            ? pick.token.replace(pick.key, pick.key.slice(0, 11))
            : op.how === "breakBracket"
              ? pick.token.slice(0, -1)
              : pick.token.replace(" removed #", " Removed #");
      // An all-digit key upcases to itself — the token is then still a live
      // placeholder, not a mangled one; treat the op as a no-op.
      if (damaged !== pick.token) {
        text =
          text.slice(0, pick.index) +
          damaged +
          text.slice(pick.index + pick.token.length);
        mangled.push(damaged);
      }
    } else if (op.op === "fabricate") {
      // A fabricated key colliding with a live one is just a duplicate, not an
      // unknown key — skip it so the deny expectation stays exact.
      if (ledger.has(op.hex)) continue;
      const token = `[hidden HTML removed #${op.hex}]`;
      const at = op.at % (text.length + 1);
      text = text.slice(0, at) + token + text.slice(at);
      fabricated.push(token);
    }
  }
  return { text, mangled, fabricated };
}

/**
 * The verdict the rehydrator MUST return for `fieldText` given the ledger —
 * re-derived from the grammar literal and the ledger alone.
 */
function expectedVerdict(fieldText, ledger) {
  const matches = placeholderMatches(fieldText);
  if (matches.length === 0) return { kind: "null" };
  const missing = [
    ...new Set(
      matches.filter((m) => !ledger.has(m.key)).map((match) => match.key),
    ),
  ];
  if (missing.length > 0) return { kind: "deny", missing };
  let out = "";
  let last = 0;
  for (const match of matches) {
    out += fieldText.slice(last, match.index) + ledger.get(match.key);
    last = match.index + match.token.length;
  }
  return { kind: "rehydrate", text: out + fieldText.slice(last), matches };
}

/**
 * True when `token` occurs in `text` at a position disjoint from every
 * grammar match. A mangled token can also occur as a SUBSTRING of a live
 * placeholder (breakBracket damage is a strict prefix of the valid token), and
 * a later op can re-damage the mangled occurrence itself — so only a
 * match-disjoint occurrence proves the literal survived as literal text.
 */
function occursOutsideMatches(text, token) {
  const spans = placeholderMatches(text).map((match) => [
    match.index,
    match.index + match.token.length,
  ]);
  for (let i = text.indexOf(token); i !== -1; i = text.indexOf(token, i + 1)) {
    const end = i + token.length;
    if (!spans.some(([start, stop]) => i < stop && end > start)) return true;
  }
  return false;
}

/**
 * Assert one rehydration verdict against the oracle. `actual` is normalized to
 * { updatedField, deny } | null by the callers so the same checks cover
 * rehydrateLayer2 and buildPreToolUseResponse.
 */
function assertVerdict(actual, expected, edited, bag) {
  if (expected.kind === "null") {
    assert.equal(actual, null);
    return;
  }
  if (expected.kind === "deny") {
    assert.ok(actual !== null && actual.deny !== undefined);
    // (f): a deny never carries a rewritten input.
    assert.equal(actual.updatedField, undefined);
    for (const key of expected.missing) assert.ok(actual.deny.includes(key));
    assert.ok(!actual.deny.includes(SECRET_VALUE));
    bag.denies++;
    const fabricatedKeys = new Set(
      edited.fabricated.flatMap((token) =>
        placeholderMatches(token).map((match) => match.key),
      ),
    );
    if (expected.missing.some((key) => fabricatedKeys.has(key)))
      bag.unknownKeyDenies++;
    // A key that was never fabricated but is still missing is a REAL
    // persistence gap (an unvettable or unpersistable splice) reaching the
    // documented fail-closed path.
    if (expected.missing.some((key) => !fabricatedKeys.has(key)))
      bag.missingSpanDenies++;
    return;
  }
  assert.ok(actual !== null && actual.deny === undefined);
  // (a) + (b): byte-exact — every ledgered placeholder becomes exactly the
  // stored bytes, every other byte survives untouched. This equality is what
  // pins the mangled tokens' literal write-through too; the loop below only
  // records that the case was exercised.
  assert.equal(actual.updatedField, expected.text);
  assert.ok(!actual.updatedField.includes(SECRET_VALUE));
  bag.rehydrations++;
  for (const token of edited.mangled)
    if (occursOutsideMatches(edited.text, token)) bag.mangledWrittenThrough++;
}

/** Compose the round's Write/Edit tool_input around the edited field text. */
function composeInput(round, fieldText) {
  if (round.tool === "Write")
    return {
      field: "content",
      input: { file_path: "/tmp/rt.md", content: fieldText },
    };
  return {
    field: "new_string",
    input: {
      file_path: "/tmp/rt.md",
      // old_string is deliberately never rehydrated, so it is drawn with and
      // without live keys and asserted unchanged either way.
      old_string: round.keysInOldString ? fieldText : "anchor text",
      new_string: fieldText,
    },
  };
}

/**
 * The next round's document: on a successful rehydration the write's content
 * (the loop a real session runs); otherwise the edited text with every
 * unresolvable placeholder stripped, so one deny doesn't pin every later round
 * to the identical denied input.
 */
function nextDoc(expected, edited, ledger) {
  if (expected.kind === "rehydrate") return expected.text;
  let doc = edited.text;
  for (const { token, key } of placeholderMatches(doc))
    if (!ledger.has(key)) doc = doc.replaceAll(token, "");
  return doc;
}

/** Count splice kinds (and the mcp+structured combination) for non-vacuity. */
function countSplices(text, toolName, shape, bag) {
  const hidden = (text.match(/\[hidden HTML removed #/g) ?? []).length;
  const comments = (text.match(/\[HTML comment removed #/g) ?? []).length;
  bag.hiddenSplices += hidden;
  bag.commentSplices += comments;
  if (
    bag.mcpStructuredSplices !== undefined &&
    toolName.startsWith("mcp__") &&
    shape === "structured"
  )
    bag.mcpStructuredSplices += hidden + comments;
}

// ---------------------------------------------------------------------------

describe("whole-pipeline Layer-2 round-trip fuzz", () => {
  it("the oracle's grammar literal still matches the shipped grammar", () => {
    // The pin that makes the oracle independent: if the hooks' grammar is
    // widened or relabelled, this fails instead of the oracle silently moving
    // with it.
    assert.equal(
      LAYER2_PLACEHOLDER_RE.source,
      ORACLE_PLACEHOLDER_RE.source,
      "hooks grammar drifted from the oracle's literal",
    );
    assert.equal(LAYER2_PLACEHOLDER_RE.flags, ORACLE_PLACEHOLDER_RE.flags);
  });

  it("sanitize → edit → rehydrateLayer2 over 2–4 rounds matches the byte-exact oracle", async () => {
    const bag = counters.p1;
    await fc.assert(
      fc.asyncProperty(
        docPiecesArb(visibleFillerArb),
        toolShapeArb,
        fc.array(roundArb, { minLength: 2, maxLength: 4 }),
        async (pieces, shape, rounds) => {
          const storeDir = freshStore();
          const ledger = new Map();
          let doc = pieces.join("\n");
          for (const [index, round] of rounds.entries()) {
            const sanitized = await sanitizeRound(shape.tool, shape.shape, doc);
            countSplices(sanitized, shape.tool, shape.shape, bag);
            ledgerUpdate(ledger, storeDir, sanitized, bag);
            const edited = applyOps(sanitized, round.ops, ledger);
            const expected = expectedVerdict(edited.text, ledger);
            const { field, input } = composeInput(round, edited.text);
            const result = rehydrateLayer2(round.tool, input);
            assertVerdict(
              result === null
                ? null
                : "deny" in result
                  ? { deny: result.deny, updatedField: undefined }
                  : {
                      deny: undefined,
                      updatedField: result.updatedInput[field],
                    },
              expected,
              edited,
              bag,
            );
            if (result !== null && "updatedInput" in result) {
              // A rewrite must not disturb the input's other fields — and
              // old_string keeps its placeholders even when it has them.
              assert.equal(result.updatedInput.file_path, input.file_path);
              if (field === "new_string") {
                assert.equal(result.updatedInput.old_string, input.old_string);
                if (round.keysInOldString && expected.matches.length > 0)
                  bag.oldStringPreserved++;
              }
              assert.equal(
                result.context,
                restoredContext(expected.matches.length, field),
              );
              // Composition depth: a rehydration that succeeded on a document
              // that is itself the product of an earlier restored round.
              if (index >= 1) bag.deepRehydrations++;
            }
            doc = nextDoc(expected, edited, ledger);
          }
        },
      ),
      fcRunOptions({ numRuns: 300 }),
    );
  });

  it("the same loop through buildPreToolUseResponse (real layer pipeline) matches the oracle", async () => {
    const bag = counters.p2;
    await fc.assert(
      fc.asyncProperty(
        // ASCII-only filler and edit prose: the confusables and
        // authored-content layers are provable no-ops on ASCII, so the strict
        // byte oracle holds on the emitted updatedInput too. (Unrestricted
        // unicode would make the oracle flag legitimate folding — precision
        // over recall.)
        docPiecesArb(asciiFillerArb),
        toolShapeArb,
        fc.array(roundArb, { minLength: 2, maxLength: 3 }),
        async (pieces, shape, rounds) => {
          const storeDir = freshStore();
          const ledger = new Map();
          let doc = pieces.join("\n");
          for (const round of rounds) {
            const sanitized = await sanitizeRound(shape.tool, shape.shape, doc);
            countSplices(sanitized, shape.tool, shape.shape, bag);
            ledgerUpdate(ledger, storeDir, sanitized, bag);
            const edited = applyOps(sanitized, round.ops, ledger);
            const expected = expectedVerdict(edited.text, ledger);
            const { field, input } = composeInput(round, edited.text);
            const response = await buildPreToolUseResponse(
              { tool_name: round.tool, tool_input: input },
              async () => null,
              () => {},
            );
            if (expected.kind === "deny") {
              assert.equal(
                response.permissionDecision,
                PermissionDecision.DENY,
              );
              assertVerdict(
                {
                  deny: response.permissionDecisionReason,
                  updatedField: response.updatedInput?.[field],
                },
                expected,
                edited,
                bag,
              );
            } else if (expected.kind === "rehydrate") {
              assert.equal(response.permissionDecision, undefined);
              assertVerdict(
                { deny: undefined, updatedField: response.updatedInput[field] },
                expected,
                edited,
                bag,
              );
              // Edit/Write are inside the rehydrated set, so the Layer-2
              // restore context is the ONLY context the pipeline attaches.
              assert.equal(
                response.additionalContext,
                restoredContext(expected.matches.length, field),
              );
            } else {
              // No placeholders and ASCII-safe material: the whole pipeline
              // must be a clean no-op.
              assert.equal(response, null);
              bag.cleanNoops++;
            }
            for (const text of flattenStrings(response ?? {}))
              assert.ok(!text.includes(SECRET_VALUE));
            doc = nextDoc(expected, edited, ledger);
          }
        },
      ),
      fcRunOptions({ numRuns: 300 }),
    );
  });

  it("MultiEdit/NotebookEdit deny on any key; Bash/MCP get a context-only advisory naming the span files", async () => {
    const bag = counters.p3;
    const tokenArb = fc.oneof(
      hex12Arb.map((hex) => ({
        token: `[hidden HTML removed #${hex}]`,
        key: hex,
      })),
      hex12Arb.map((hex) => ({
        token: `[HTML comment removed #${hex}]`,
        key: hex,
      })),
      lookalikeArb.map((token) => ({ token, key: null })),
    );
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.tuple(asciiFillerArb, tokenArb), {
          minLength: 1,
          maxLength: 4,
        }),
        fc.constantFrom("MultiEdit", "NotebookEdit", "Bash", "mcp__fs__write"),
        fc.boolean(),
        async (parts, tool, keyInOldString) => {
          freshStore();
          const text = parts
            .map(([prose, entry]) => `${prose} ${entry.token}`)
            .join("\n");
          const keys = [
            ...new Set(
              parts.filter(([, e]) => e.key !== null).map(([, e]) => e.key),
            ),
          ];
          const hasSecretLookalike = parts.some(
            ([, entry]) => entry.token === SECRET_LOOKALIKE,
          );
          if (tool === "MultiEdit") {
            const edits = [
              { old_string: "a", new_string: "b" },
              keyInOldString
                ? { old_string: text, new_string: "clean" }
                : { old_string: "clean", new_string: text },
            ];
            const result = rehydrateLayer2(tool, { file_path: "/f", edits });
            if (keys.length === 0) {
              assert.equal(result, null);
              bag.passThroughShapes++;
              return;
            }
            assert.ok(result !== null && "deny" in result);
            assert.ok(result.deny.includes("MultiEdit"));
            assert.ok(result.deny.includes("single Edit"));
            bag.multiEditDenies++;
            return;
          }
          if (tool === "NotebookEdit") {
            const result = rehydrateLayer2(tool, {
              notebook_path: "/n.ipynb",
              new_source: text,
            });
            if (keys.length === 0) {
              assert.equal(result, null);
              bag.passThroughShapes++;
              return;
            }
            assert.ok(result !== null && "deny" in result);
            assert.ok(result.deny.includes("new_source"));
            bag.notebookDenies++;
            return;
          }
          // Bash / MCP: never a verdict, only advisories. rehydrateLayer2
          // itself must pass these shapes straight through.
          assert.equal(rehydrateLayer2(tool, { command: text }), null);
          bag.unrehydratableShapes++;
          const response = await buildPreToolUseResponse(
            { tool_name: tool, tool_input: { command: text } },
            async () => null,
            () => {},
          );
          const context = response?.additionalContext ?? "";
          assert.equal(response?.permissionDecision, undefined);
          assert.equal(response?.updatedInput, undefined);
          // Each advisory fires exactly when its own grammar is present.
          assert.equal(
            context.includes("[hidden HTML removed #…]"),
            keys.length > 0,
          );
          assert.equal(context.includes("[REDACTED…]"), hasSecretLookalike);
          for (const key of keys)
            assert.ok(context.includes(`span-${key}.txt`));
          if (keys.length > 0) bag.layer2Advisories++;
          if (hasSecretLookalike) bag.secretAdvisories++;
        },
      ),
      fcRunOptions({ numRuns: 500 }),
    );
  });

  it("placeholder text is a fixed point of re-sanitization, and lookalikes are never rehydrated", async () => {
    const bag = counters.p4;
    const partArb = fc.oneof(
      hex12Arb.map((hex) => ({ kind: "minted", hex })),
      lookalikeArb.map((token) => ({ kind: "lookalike", token })),
      asciiFillerArb.map((token) => ({ kind: "prose", token })),
    );
    await fc.assert(
      fc.asyncProperty(
        fc.array(partArb, { minLength: 1, maxLength: 6 }),
        // Whether one planted span's stored bytes themselves contain another
        // well-formed placeholder token: restored bytes are never rescanned,
        // so that inner token must survive LITERALLY (one ordered pass).
        fc.boolean(),
        async (parts, nestToken) => {
          const storeDir = freshStore();
          const ledger = new Map();
          const minted = parts.filter((part) => part.kind === "minted");
          // Distinct keys only — two identical draws would make "plant then
          // overwrite" ambiguous.
          const seen = new Set();
          const pieces = [];
          let nestedInner = null;
          for (const part of parts) {
            if (part.kind !== "minted") {
              pieces.push(part.token);
              continue;
            }
            if (seen.has(part.hex)) continue;
            seen.add(part.hex);
            const isNestHost =
              nestToken && minted.length >= 2 && part === minted[0];
            const inner = `[hidden HTML removed #${minted[1]?.hex}]`;
            const content = isNestHost
              ? `pre ${inner} post`
              : `<div hidden>orig ${part.hex}</div>`;
            if (isNestHost) nestedInner = inner;
            writeFileSync(join(storeDir, `span-${part.hex}.txt`), content, {
              mode: 0o600,
            });
            ledger.set(part.hex, content);
            pieces.push(`[hidden HTML removed #${part.hex}]`);
          }
          const doc = pieces.join(" and ");
          // Fixed point: placeholders and lookalikes carry no `<`, so the
          // model's next view of this document is byte-identical.
          assert.equal(await sanitizeRound("WebFetch", "string", doc), doc);
          // Rehydration touches exactly the well-formed ledgered tokens.
          const expected = expectedVerdict(doc, ledger);
          const result = rehydrateLayer2("Write", {
            file_path: "/tmp/rt.md",
            content: doc,
          });
          if (expected.kind === "null") {
            assert.equal(result, null);
          } else {
            assert.equal(expected.kind, "rehydrate");
            assert.equal(result.updatedInput.content, expected.text);
            bag.mintedRehydrations++;
          }
          const surface =
            expected.kind === "rehydrate" ? result.updatedInput.content : doc;
          for (const part of parts)
            if (part.kind === "lookalike") {
              assert.ok(surface.includes(part.token));
              bag.lookalikesPreserved++;
            }
          // The restored span's own placeholder text was NOT re-expanded.
          if (nestedInner !== null && expected.kind === "rehydrate") {
            assert.ok(surface.includes(nestedInner));
            bag.nestedTokenLeftLiteral++;
          }
        },
      ),
      fcRunOptions({ numRuns: 500 }),
    );
  });

  it("a secret-free splice round-trips to a byte-identical document under a stable content-addressed key", async () => {
    const bag = counters.p5;
    await fc.assert(
      fc.asyncProperty(
        benignHiddenArb,
        asciiFillerArb,
        asciiFillerArb,
        async (construct, before_, after_) => {
          freshStore();
          const doc = `${before_} ${construct} ${after_}`;
          // The key rule, recomputed here from sha256 rather than taken from
          // the engine: the placeholder is fully predictable from the bytes.
          const token = `[hidden HTML removed #${keyOf(construct)}]`;
          const sanitized = await sanitizeRound("WebFetch", "string", doc);
          assert.equal(sanitized, `${before_} ${token} ${after_}`);
          // Secret-free, so the stored span is the RAW original and the write
          // restores the document byte-for-byte.
          const result = rehydrateLayer2("Write", {
            file_path: "/tmp/rt.md",
            content: sanitized,
          });
          assert.equal(result.updatedInput.content, doc);
          // Content addressing: re-sanitizing the restored document mints the
          // very same key, which is what makes the round trip idempotent.
          assert.equal(
            await sanitizeRound(
              "WebFetch",
              "string",
              result.updatedInput.content,
            ),
            sanitized,
          );
          bag.stableKeys++;
        },
      ),
      fcRunOptions({ numRuns: 200 }),
    );
  });

  // Non-vacuity: every interesting path must be PROVEN to have executed, per
  // property — a shared counter bag would let one property be deleted while
  // another property's increments kept its checks green.
  describe("non-vacuity", () => {
    for (const [property, bag] of Object.entries(counters))
      for (const name of Object.keys(bag))
        it(`${property} exercised ${name}`, () => {
          assert.ok(bag[name] > 0, `${property}.${name} never incremented`);
        });
  });
});
