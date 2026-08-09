/**
 * Whole-pipeline round-trip fuzz: PostToolUse sanitize → adversarial "model
 * edits" of the sanitized text → PreToolUse rehydration, iterated over multiple
 * rounds against the REAL hook entry points (evaluateToolOutput,
 * rehydrateLayer2, buildPreToolUseResponse). The per-primitive suites
 * (html-property, splice-property, claude-hooks-layer2-*) pin each stage in
 * isolation; this file pins the COMPOSITION — the loop an agent session
 * actually runs, where round n+1's tool output is round n's rehydrated write.
 *
 * The oracle is an independent re-derivation, never a call back into the code
 * under test: placeholders are located with the shared grammar regex, span
 * bytes are read with raw readFileSync (not readSpan), and the expected
 * rehydrated text is spliced by hand. Invariants:
 *
 *   (a) every well-formed placeholder whose span persisted rehydrates to the
 *       stored bytes, byte-exact, at every round;
 *   (b) every byte outside a placeholder survives rehydration untouched
 *       (subsumed by the byte-exact expected-output equality);
 *   (c/g) the planted secret never appears in any model-visible surface or in
 *       any span file, any round;
 *   (d/f) the verdict trichotomy (updatedInput / deny / null) is total and
 *       predicted from key presence alone; a deny never carries updatedInput;
 *   (e) placeholder text is a fixed point of re-sanitization, and re-spliced
 *       secret-free content reproduces the identical content-addressed key.
 *
 * Known-lossy-by-design behavior is asserted POSITIVELY, never flagged:
 * mangled placeholders write through as literal text, fabricated well-formed
 * unknown keys deny naming the key, MultiEdit/NotebookEdit carrying keys deny,
 * and lookalike prose is never treated as a placeholder.
 */
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:net";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import fc from "fast-check";
import { fcRunOptions } from "./test-helpers.mjs";

// Stub redactor socket + project dir BEFORE the hook imports (the redactor
// client resolves its socket path at module load; the invisible-char gate
// hashes CLAUDE_PROJECT_DIR at load). The sanitize budget is pinned high: one
// wall-clock deadline spans every leaf of every round, and an expiry
// mid-property would nondeterministically drop spans.
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

// SUBSTITUTING stub daemon over the real socket protocol (4-byte BE length +
// JSON), copied from claude-hooks-layer2-roundtrip.test.mjs: redaction is
// observable per-text, not a canned reply. Secrets are always planted WITH a
// hint word ("password") so the hint pre-gate provably routes the text to the
// daemon — a hintless secret legitimately bypasses redaction by design and
// asserting on it would flag documented behavior.
const SECRET_VALUE = "hunter2hunter2hunter2";
const REDACTED_MARK = "[REDACTED: password]";
function startStubDaemon() {
  const server = createServer((sock) => {
    const chunks = [];
    sock.on("data", (chunk) => {
      chunks.push(chunk);
      const buf = Buffer.concat(chunks);
      if (buf.length < 4) return;
      const expected = buf.readUInt32BE(0);
      if (buf.length < 4 + expected) return;
      const request = JSON.parse(
        buf.subarray(4, 4 + expected).toString("utf8"),
      );
      const reply = request.text.includes(SECRET_VALUE)
        ? {
            text: request.text.replaceAll(SECRET_VALUE, REDACTED_MARK),
            found: ["StubPassword"],
          }
        : null;
      const body = Buffer.from(JSON.stringify(reply), "utf8");
      const header = Buffer.allocUnsafe(4);
      header.writeUInt32BE(body.length, 0);
      sock.end(Buffer.concat([header, body]));
    });
  });
  return new Promise((resolve) => {
    server.listen(socketPath, () => resolve(server));
  });
}

/** @type {import("node:net").Server} */
let daemon;
before(async () => {
  daemon = await startStubDaemon();
});
after(() => {
  daemon.close();
  for (const dir of [socketDir, projectDir, revealBase])
    rmSync(dir, { recursive: true, force: true });
});

// One fresh span store PER fc ITERATION, shared across the rounds inside it:
// cross-round aliasing (a round-1 span satisfying a round-3 placeholder) and
// first-write-wins dedupe are exactly the content-addressed design under
// test, but a store shared across ITERATIONS would let an earlier draw's span
// satisfy a later draw's key and make shrunk counterexamples irreproducible.
function freshStore() {
  const dir = mkdtempSync(join(revealBase, "store-"));
  process.env._AGENT_SANITIZER_REVEAL_DIR = dir;
  return dir;
}

// ---------------------------------------------------------------------------
// Non-vacuity counters (repo doctrine: every interesting path must be PROVEN
// to have executed; if one is flaky under the unseeded nightly, bias the
// generator — never lower the bar).
const counters = {
  hiddenSplices: 0,
  commentSplices: 0,
  rehydrations: 0,
  denies: 0,
  unknownKeyDenies: 0,
  mangledWrittenThrough: 0,
  roundsAtDepth3Plus: 0,
  mcpStructuredSplices: 0,
  secretSpansRedacted: 0,
  dedupeHits: 0,
  lookalikesPreserved: 0,
};

// ---------------------------------------------------------------------------
// Corpus. Curated subsets duplicated module-local from the existing suites'
// module-local corpora (html-semantic-fuzz STRIP/KEEP tokens,
// html-property's round-trip pieces, rehydrate-property's astral filler) —
// deliberately NOT lifted into test-helpers.mjs, which would churn suites
// this change doesn't own.

// Hiding constructs Layer 2 splices, each wrapping a marker payload.
const hiddenConstructArb = fc
  .tuple(
    fc.constantFrom(
      (inner) => `<div hidden>${inner}</div>`,
      (inner) => `<span style="display:none">${inner}</span>`,
      (inner) => `<p style="visibility: hidden">${inner}</p>`,
      (inner) => `<div style="position:absolute;left:-9999px">${inner}</div>`,
      (inner) => `<span style="opacity: 0">${inner}</span>`,
      (inner) => `<div><div hidden>${inner}</div></div>`,
    ),
    fc.nat(999),
    // Some hidden payloads carry the planted (hinted) secret so the span-persist
    // redaction path runs; the rest are benign markers.
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
    "café naïve",
    "\u{10348}\u{10349} hwair",
  ),
);

// ASCII-only filler for the full-pipeline property, where the confusables and
// authored-content layers must be provable no-ops on the edit material.
const asciiFillerArb = fc.stringMatching(/^[a-zA-Z0-9 .,'!?_-]{1,30}$/);

// Near-miss literals that must NEVER be treated as placeholders.
const lookalikeArb = fc.constantFrom(
  "[hidden HTML removed]",
  "[hidden HTML removed #ABCDEF123456]",
  "[HTML comment removed #abc]",
  "[hidden HTML removed #0123456789abc]",
  "[hidden html removed #0123456789ab]",
  "[REDACTED: token]",
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
});

// ---------------------------------------------------------------------------
// Oracle helpers — grammar-only re-derivations, independent of the hooks.

/** @param {string} text */
function placeholderMatches(text) {
  return [...text.matchAll(LAYER2_PLACEHOLDER_RE)].map((match) => ({
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
function ledgerUpdate(ledger, storeDir, text) {
  for (const { key } of placeholderMatches(text)) {
    let bytes;
    try {
      bytes = readFileSync(join(storeDir, `span-${key}.txt`), "utf8");
    } catch {
      continue;
    }
    if (ledger.has(key)) {
      // First write wins: dedupe must never rewrite an existing span file.
      assert.equal(bytes, ledger.get(key));
      counters.dedupeHits++;
    } else {
      ledger.set(key, bytes);
    }
    // (g) plus the redaction proof: a span that carried the planted secret
    // must hold the daemon's redaction mark instead.
    assert.ok(!bytes.includes(SECRET_VALUE));
    if (bytes.includes(REDACTED_MARK)) counters.secretSpansRedacted++;
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
 * re-derived from the grammar and the ledger alone.
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
  return { kind: "rehydrate", text: out + fieldText.slice(last) };
}

/**
 * True when `token` occurs in `text` at a position disjoint from every
 * grammar match. A mangled token can also occur as a SUBSTRING of a live
 * placeholder (breakBracket damage is a strict prefix of the valid token), and
 * a later op can re-damage the mangled occurrence itself — so only a
 * match-disjoint occurrence proves the literal must survive rehydration.
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
function assertVerdict(actual, expect, edited) {
  if (expect.kind === "null") {
    assert.equal(actual, null);
  } else if (expect.kind === "deny") {
    assert.ok(actual !== null && actual.deny !== undefined);
    // (f): a deny never carries a rewritten input.
    assert.equal(actual.updatedField, undefined);
    for (const key of expect.missing) assert.ok(actual.deny.includes(key));
    assert.ok(!actual.deny.includes(SECRET_VALUE));
    counters.denies++;
    if (edited.fabricated.length > 0) counters.unknownKeyDenies++;
  } else {
    assert.ok(actual !== null && actual.deny === undefined);
    // (a) + (b): byte-exact — every ledgered placeholder becomes exactly the
    // stored bytes, every other byte survives untouched.
    assert.equal(actual.updatedField, expect.text);
    assert.ok(!actual.updatedField.includes(SECRET_VALUE));
    counters.rehydrations++;
    // Mangled tokens are not grammar matches, so they must write through as
    // literal text — the documented lossy case, asserted positively. Only a
    // match-disjoint occurrence counts: breakBracket damage is a prefix of a
    // live placeholder, so bare .includes() would match the live token.
    for (const token of edited.mangled)
      if (occursOutsideMatches(edited.text, token)) {
        assert.ok(actual.updatedField.includes(token));
        counters.mangledWrittenThrough++;
      }
  }
}

/** Compose the round's Write/Edit tool_input around the edited field text. */
function composeInput(tool, fieldText) {
  return tool === "Write"
    ? {
        field: "content",
        input: { file_path: "/tmp/rt.md", content: fieldText },
      }
    : {
        field: "new_string",
        input: {
          file_path: "/tmp/rt.md",
          old_string: "anchor text",
          new_string: fieldText,
        },
      };
}

/**
 * The next round's document: on a successful rehydration the write's content
 * (the loop a real session runs); otherwise the edited text with the
 * fabricated unknown-key tokens stripped, so a deny round doesn't pin every
 * later round to the same deny.
 */
function nextDoc(expect, edited) {
  if (expect.kind === "rehydrate") return expect.text;
  let doc = edited.text;
  for (const token of edited.fabricated) doc = doc.replaceAll(token, "");
  return doc;
}

/** Count splice kinds (and the mcp+structured combination) for non-vacuity. */
function countSplices(text, toolName, shape) {
  const hidden = (text.match(/\[hidden HTML removed #/g) ?? []).length;
  const comments = (text.match(/\[HTML comment removed #/g) ?? []).length;
  counters.hiddenSplices += hidden;
  counters.commentSplices += comments;
  if (toolName.startsWith("mcp__") && shape === "structured")
    counters.mcpStructuredSplices += hidden + comments;
}

// ---------------------------------------------------------------------------

describe("whole-pipeline Layer-2 round-trip fuzz", () => {
  it("sanitize → edit → rehydrateLayer2 over 2–4 rounds matches the byte-exact oracle", async () => {
    await fc.assert(
      fc.asyncProperty(
        docPiecesArb(visibleFillerArb),
        toolShapeArb,
        fc.array(roundArb, { minLength: 2, maxLength: 4 }),
        async (pieces, shape, rounds) => {
          const storeDir = freshStore();
          const ledger = new Map();
          let doc = pieces.join("\n");
          if (rounds.length >= 3) counters.roundsAtDepth3Plus++;
          for (const round of rounds) {
            const sanitized = await sanitizeRound(shape.tool, shape.shape, doc);
            countSplices(sanitized, shape.tool, shape.shape);
            ledgerUpdate(ledger, storeDir, sanitized);
            const edited = applyOps(sanitized, round.ops, ledger);
            const expect = expectedVerdict(edited.text, ledger);
            const { field, input } = composeInput(round.tool, edited.text);
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
              expect,
              edited,
            );
            // A rewrite must not disturb the input's other fields.
            if (result !== null && "updatedInput" in result) {
              assert.equal(result.updatedInput.file_path, input.file_path);
              if (field === "new_string")
                assert.equal(result.updatedInput.old_string, "anchor text");
              assert.ok(result.context.length > 0);
            }
            doc = nextDoc(expect, edited);
          }
        },
      ),
      fcRunOptions({ numRuns: 300 }),
    );
  });

  it("the same loop through buildPreToolUseResponse (real layer pipeline) matches the oracle", async () => {
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
            countSplices(sanitized, shape.tool, shape.shape);
            ledgerUpdate(ledger, storeDir, sanitized);
            const edited = applyOps(sanitized, round.ops, ledger);
            const expect = expectedVerdict(edited.text, ledger);
            const { field, input } = composeInput(round.tool, edited.text);
            const response = await buildPreToolUseResponse(
              { tool_name: round.tool, tool_input: input },
              async () => null,
              () => {},
            );
            if (expect.kind === "deny") {
              assert.equal(
                response.permissionDecision,
                PermissionDecision.DENY,
              );
              assertVerdict(
                {
                  deny: response.permissionDecisionReason,
                  updatedField: response.updatedInput?.[field],
                },
                expect,
                edited,
              );
            } else if (expect.kind === "rehydrate") {
              assert.equal(response.permissionDecision, undefined);
              assertVerdict(
                {
                  deny: undefined,
                  updatedField: response.updatedInput[field],
                },
                expect,
                edited,
              );
              assert.ok(response.additionalContext.includes("restored"));
            } else {
              // No placeholders and ASCII-safe material: the whole pipeline
              // must be a clean no-op.
              assert.equal(response, null);
            }
            for (const text of flattenStrings(response ?? {}))
              assert.ok(!text.includes(SECRET_VALUE));
            doc = nextDoc(expect, edited);
          }
        },
      ),
      fcRunOptions({ numRuns: 300 }),
    );
  });

  it("MultiEdit/NotebookEdit deny on any key; Bash/MCP get a context-only advisory naming the span files", async () => {
    const tokenArb = fc.oneof(
      hex12Arb.map((hex) => ({
        token: `[hidden HTML removed #${hex}]`,
        keyed: true,
        key: hex,
      })),
      hex12Arb.map((hex) => ({
        token: `[HTML comment removed #${hex}]`,
        keyed: true,
        key: hex,
      })),
      lookalikeArb.map((token) => ({ token, keyed: false, key: null })),
    );
    await fc.assert(
      fc.asyncProperty(
        fc.array(fc.tuple(asciiFillerArb, tokenArb), {
          minLength: 1,
          maxLength: 4,
        }),
        fc.constantFrom("MultiEdit", "NotebookEdit", "Bash", "mcp__fs__write"),
        fc.nat(3),
        async (parts, tool, slot) => {
          freshStore();
          const text = parts
            .map(([prose, entry]) => `${prose} ${entry.token}`)
            .join("\n");
          const keys = parts
            .filter(([, entry]) => entry.keyed)
            .map(([, entry]) => entry.key);
          if (tool === "MultiEdit") {
            // The keyed token rides in old_string or new_string of one edit —
            // either position must trip the deny.
            const edits = [
              { old_string: "a", new_string: "b" },
              slot % 2 === 0
                ? { old_string: text, new_string: "clean" }
                : { old_string: "clean", new_string: text },
            ];
            const result = rehydrateLayer2(tool, { file_path: "/f", edits });
            if (keys.length > 0) {
              assert.ok(result !== null && "deny" in result);
              assert.ok(!("updatedInput" in result));
              assert.ok(result.deny.includes("MultiEdit"));
              counters.denies++;
            } else {
              assert.equal(result, null);
            }
          } else if (tool === "NotebookEdit") {
            const result = rehydrateLayer2(tool, {
              notebook_path: "/n.ipynb",
              new_source: text,
            });
            if (keys.length > 0) {
              assert.ok(result !== null && "deny" in result);
              assert.ok(!("updatedInput" in result));
              counters.denies++;
            } else {
              assert.equal(result, null);
            }
          } else {
            // Bash / MCP tools: never a verdict, only the advisory naming the
            // span file for each key (rehydrateLayer2 itself must pass).
            assert.equal(rehydrateLayer2(tool, { command: text }), null);
            const response = await buildPreToolUseResponse(
              { tool_name: tool, tool_input: { command: text } },
              async () => null,
              () => {},
            );
            if (keys.length > 0) {
              assert.equal(response.permissionDecision, undefined);
              assert.equal(response.updatedInput, undefined);
              for (const key of keys)
                assert.ok(
                  response.additionalContext.includes(`span-${key}.txt`),
                );
            } else if (response !== null) {
              assert.equal(
                response.additionalContext?.includes("span-"),
                false,
              );
            }
          }
        },
      ),
      fcRunOptions({ numRuns: 500 }),
    );
  });

  it("placeholder text is a fixed point of re-sanitization, and lookalikes are never rehydrated", async () => {
    const mintedArb = fc.oneof(
      hex12Arb.map((hex) => ({ kind: "minted", hex })),
      lookalikeArb.map((token) => ({ kind: "lookalike", token })),
      asciiFillerArb.map((token) => ({ kind: "prose", token })),
    );
    await fc.assert(
      fc.asyncProperty(
        fc.array(mintedArb, { minLength: 1, maxLength: 6 }),
        async (parts) => {
          const storeDir = freshStore();
          const ledger = new Map();
          const pieces = [];
          for (const part of parts) {
            if (part.kind === "minted") {
              const token = `[hidden HTML removed #${part.hex}]`;
              // Plant the span file directly (0700 mkdtemp dir, plain file) so
              // every minted key is ledgered without a sanitize pass.
              writeFileSync(
                join(storeDir, `span-${part.hex}.txt`),
                `<div hidden>orig ${part.hex}</div>`,
                { mode: 0o600 },
              );
              ledger.set(part.hex, `<div hidden>orig ${part.hex}</div>`);
              pieces.push(token);
            } else {
              pieces.push(part.token);
            }
          }
          const doc = pieces.join(" and ");
          // Fixed point: placeholders carry no `<`, so re-sanitizing the
          // model's view must leave every token (real or lookalike) intact.
          const resanitized = await sanitizeRound("WebFetch", "string", doc);
          for (const piece of pieces) assert.ok(resanitized.includes(piece));
          assert.deepEqual(
            placeholderMatches(resanitized).map((match) => match.token),
            placeholderMatches(doc).map((match) => match.token),
          );
          // Rehydration touches exactly the well-formed ledgered tokens;
          // lookalike bytes survive verbatim.
          const expect = expectedVerdict(doc, ledger);
          const result = rehydrateLayer2("Write", {
            file_path: "/tmp/rt.md",
            content: doc,
          });
          if (expect.kind === "null") {
            assert.equal(result, null);
          } else {
            assert.equal(expect.kind, "rehydrate");
            assert.equal(result.updatedInput.content, expect.text);
          }
          for (const part of parts)
            if (part.kind === "lookalike") {
              const surface =
                expect.kind === "null" ? doc : result.updatedInput.content;
              assert.ok(surface.includes(part.token));
              counters.lookalikesPreserved++;
            }
        },
      ),
      fcRunOptions({ numRuns: 500 }),
    );
  });

  // Non-vacuity: the interesting paths must have actually executed. These run
  // after the properties above (node:test executes `it`s in order).
  describe("non-vacuity", () => {
    for (const name of Object.keys(counters))
      it(`exercised ${name}`, () => {
        assert.ok(counters[name] > 0, `${name} never incremented`);
      });
  });
});
