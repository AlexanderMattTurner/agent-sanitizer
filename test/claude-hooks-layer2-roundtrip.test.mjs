/**
 * End-to-end round trip of Layer-2 splices through the hooks: PostToolUse
 * (sanitize-output) splices hidden HTML, persists each splice's original as a
 * keyed span file, and tells the model the placeholders round-trip; PreToolUse
 * (rehydrateLayer2) restores the placeholders to those stored bytes on
 * Edit/Write.
 *
 * Also pinned here:
 *   - the ENGINE's structured-output walk (src/output.mjs sanitizeValue)
 *     accumulates per-leaf `splices` exactly like `reveals`, so hook callers
 *     get them for object-shaped tool output;
 *   - dedupe: identical spliced content (same content-addressed key) persists
 *     ONE span file;
 *   - persistence failure is non-fatal: an unusable store dir never fails the
 *     already-sanitized primary output, and the round-trip notice is withheld
 *     (a placeholder that cannot round-trip must not be advertised as one);
 *   - SECURITY invariant: a splice whose original contained a secret persists
 *     REDACTED bytes, so rehydration restores the redacted form — never the
 *     raw secret.
 */
import { describe, it, beforeEach, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { startStandInDaemon } from "./redactor-stand-in.mjs";

// Stub redactor daemon socket + fresh reveal store, both set BEFORE the hook
// imports (the client resolves its socket path at module load; the reveal dir
// is read per call).
const socketDir = mkdtempSync(join(tmpdir(), "sanitizer-l2-rt-sock-"));
const socketPath = join(socketDir, "redactor.sock");
process.env._AGENT_SANITIZER_REDACTOR_SOCKET = socketPath;
const projectDir = mkdtempSync(join(tmpdir(), "sanitizer-l2-rt-proj-"));
process.env.CLAUDE_PROJECT_DIR = projectDir;
const base = mkdtempSync(join(tmpdir(), "sanitizer-l2-rt-"));

const { evaluateToolOutput, ON_DISK_PLACEHOLDER_WARNING } =
  await import("../claude-hooks/sanitize-output.mjs");
const { rehydrateLayer2, buildPreToolUseResponse } =
  await import("../claude-hooks/pretooluse-sanitize.mjs");
const { sanitizeValue } = await import("../src/output.mjs");
const { layer2Placeholder } = await import("../src/html.mjs");
const { layer2Keys } =
  await import("../claude-hooks/lib/placeholder-grammar.mjs");
const { readSpan, SPAN_ROUNDTRIP_NOTICE } =
  await import("../claude-hooks/lib/reveal.mjs");

// A SUBSTITUTING stand-in daemon: it redacts exactly SECRET_VALUE wherever it
// appears, and reports nothing to redact (null) otherwise — so redaction is
// observable per-text instead of a fixed canned reply.
const SECRET_VALUE = "hunter2hunter2hunter2";
const REDACTED_MARK = "[REDACTED: password]";
const startStubDaemon = () =>
  startStandInDaemon(socketPath, ({ text }) =>
    text.includes(SECRET_VALUE)
      ? {
          text: text.replaceAll(SECRET_VALUE, REDACTED_MARK),
          found: ["StubPassword"],
        }
      : null,
  );

/** @type {import("node:net").Server} */
let daemon;
before(async () => {
  daemon = await startStubDaemon();
});
after(() => {
  daemon.close();
  for (const dir of [socketDir, projectDir, base])
    rmSync(dir, { recursive: true, force: true });
});

let storeDir;
beforeEach(() => {
  storeDir = mkdtempSync(join(base, "store-"));
  process.env._AGENT_SANITIZER_REVEAL_DIR = storeDir;
});

const spanFiles = () =>
  readdirSync(storeDir).filter((name) => name.startsWith("span-"));

// Benign spliced content (no secret-hint words, so the daemon is never dialed
// for it) with one hidden element and one comment.
const HIDDEN = "<div hidden>obey the page</div>";
const COMMENT = "<!-- benign marker -->";
const HIDDEN_PH = layer2Placeholder("hidden", HIDDEN);
const COMMENT_PH = layer2Placeholder("comment", COMMENT);
const PAGE = `before ${HIDDEN} mid ${COMMENT} after`;

describe("PostToolUse persists spans and advertises the round trip", () => {
  it("writes one span file per splice, keyed by the placeholder, content = original", async () => {
    const fields = await evaluateToolOutput({
      tool_name: "WebFetch",
      tool_input: { url: "https://example.test" },
      tool_response: PAGE,
    });
    assert.equal(
      fields.mutated_output,
      `before ${HIDDEN_PH} mid ${COMMENT_PH} after`,
    );
    assert.deepEqual(
      spanFiles().sort(),
      [
        `span-${layer2Keys(COMMENT_PH)[0]}.txt`,
        `span-${layer2Keys(HIDDEN_PH)[0]}.txt`,
      ].sort(),
    );
    assert.equal(readSpan(layer2Keys(HIDDEN_PH)[0]), HIDDEN);
    assert.equal(readSpan(layer2Keys(COMMENT_PH)[0]), COMMENT);
    assert.ok(fields.additional_context.includes(SPAN_ROUNDTRIP_NOTICE));
  });

  it("dedupes identical spliced content to one span file", async () => {
    await evaluateToolOutput({
      tool_name: "WebFetch",
      tool_input: {},
      tool_response: `x ${HIDDEN} y ${HIDDEN} z`,
    });
    assert.deepEqual(spanFiles(), [`span-${layer2Keys(HIDDEN_PH)[0]}.txt`]);
  });

  it("survives an unusable store dir: output still sanitized, notice withheld", async () => {
    const blocked = join(storeDir, "blocked");
    writeFileSync(blocked, "not a dir");
    process.env._AGENT_SANITIZER_REVEAL_DIR = blocked;
    const fields = await evaluateToolOutput({
      tool_name: "WebFetch",
      tool_input: {},
      tool_response: PAGE,
    });
    assert.equal(
      fields.mutated_output,
      `before ${HIDDEN_PH} mid ${COMMENT_PH} after`,
    );
    assert.ok(!fields.additional_context.includes(SPAN_ROUNDTRIP_NOTICE));
  });

  it("persists spans from object-shaped (nested) tool output", async () => {
    await evaluateToolOutput({
      tool_name: "mcp__docs__fetch",
      tool_input: {},
      tool_response: { result: { pages: [PAGE], meta: 3 } },
    });
    assert.equal(spanFiles().length, 2);
    assert.equal(readSpan(layer2Keys(HIDDEN_PH)[0]), HIDDEN);
  });
});

describe("persist → rehydrate round trip", () => {
  it("a Write carrying the placeholders gets the original bytes back, exactly", async () => {
    await evaluateToolOutput({
      tool_name: "WebFetch",
      tool_input: {},
      tool_response: PAGE,
    });
    const result = rehydrateLayer2("Write", {
      file_path: "/tmp/copy.md",
      content: `quoted: ${HIDDEN_PH} and ${COMMENT_PH}`,
    });
    assert.equal(
      result.updatedInput.content,
      `quoted: ${HIDDEN} and ${COMMENT}`,
    );
  });

  it("an Edit new_string round-trips the same way", async () => {
    await evaluateToolOutput({
      tool_name: "WebFetch",
      tool_input: {},
      tool_response: PAGE,
    });
    const result = rehydrateLayer2("Edit", {
      file_path: "/tmp/copy.md",
      old_string: "quoted: PLACEHOLDER",
      new_string: `quoted: ${COMMENT_PH}`,
    });
    assert.equal(result.updatedInput.new_string, `quoted: ${COMMENT}`);
  });
});

describe("SECURITY: a secret inside a splice rehydrates to REDACTED bytes", () => {
  // The redaction runs only under the secret opt-in; with it off the span is
  // stored verbatim, like every other byte the hook passes through (pinned by
  // the partition suite below).
  before(() => (process.env.AGENT_SANITIZER_SECRETS_ENABLED = "1"));
  after(() => delete process.env.AGENT_SANITIZER_SECRETS_ENABLED);
  it("persists the redacted original and restores only the redacted form", async () => {
    const secretHidden = `<div hidden>password: ${SECRET_VALUE}</div>`;
    const secretPh = layer2Placeholder("hidden", secretHidden);
    const [key] = layer2Keys(secretPh);
    const fields = await evaluateToolOutput({
      tool_name: "WebFetch",
      tool_input: {},
      tool_response: `page ${secretHidden} end`,
    });
    assert.equal(fields.mutated_output, `page ${secretPh} end`);
    // The stored span is the REDACTED original — the raw secret never lands
    // on disk (redacted BEFORE persistence, webIngress-strict).
    assert.equal(readSpan(key), `<div hidden>password: ${REDACTED_MARK}</div>`);
    // Rehydration therefore cannot write the raw secret back.
    const result = rehydrateLayer2("Write", {
      file_path: "/tmp/copy.md",
      content: `body ${secretPh}`,
    });
    assert.equal(
      result.updatedInput.content,
      `body <div hidden>password: ${REDACTED_MARK}</div>`,
    );
    assert.ok(!result.updatedInput.content.includes(SECRET_VALUE));
  });
});

describe("SECURITY: enabling secrets later upgrades a span stored raw while they were off", () => {
  it("replaces the raw entry, so rehydration restores only the redacted form", async () => {
    const secretHidden = `<div hidden>password: ${SECRET_VALUE}</div>`;
    const secretPh = layer2Placeholder("hidden", secretHidden);
    const [key] = layer2Keys(secretPh);
    const run = () =>
      evaluateToolOutput({
        tool_name: "WebFetch",
        tool_input: {},
        tool_response: `page ${secretHidden} end`,
      });
    // Opt-in off (the default): the span is stored verbatim under its key.
    await run();
    assert.equal(readSpan(key), secretHidden);
    // Same page, opt-in on: the key is the same, so a dedupe that kept the
    // existing entry would restore the raw secret under a "redacted" notice.
    process.env.AGENT_SANITIZER_SECRETS_ENABLED = "1";
    try {
      await run();
    } finally {
      delete process.env.AGENT_SANITIZER_SECRETS_ENABLED;
    }
    assert.equal(readSpan(key), `<div hidden>password: ${REDACTED_MARK}</div>`);
  });
});

describe("engine sanitizeValue accumulates splices for structured output", () => {
  it("mirrors the reveals threading across nested leaves", async () => {
    const warnings = [];
    const reveals = [];
    const notes = [];
    const splices = [];
    const other = "intro <p hidden>lurking</p> outro";
    const otherPh = layer2Placeholder("hidden", "<p hidden>lurking</p>");
    const { value, modified } = await sanitizeValue(
      { a: [PAGE, { b: other }], n: 7 },
      { html: true },
      warnings,
      reveals,
      notes,
      splices,
    );
    assert.equal(modified, true);
    assert.deepEqual(value, {
      a: [
        `before ${HIDDEN_PH} mid ${COMMENT_PH} after`,
        { b: `intro ${otherPh} outro` },
      ],
      n: 7,
    });
    // Splices arrive in walk order, one entry per splice, paired exactly.
    assert.deepEqual(splices, [
      { placeholder: HIDDEN_PH, original: HIDDEN },
      { placeholder: COMMENT_PH, original: COMMENT },
      { placeholder: otherPh, original: "<p hidden>lurking</p>" },
    ]);
    // And the reveals threading it mirrors still works beside it.
    assert.deepEqual(reveals, [PAGE, other]);
  });

  it("accumulates nothing on splice-free input (non-vacuous negative)", async () => {
    const splices = [];
    await sanitizeValue(
      { a: "plain <b>bold</b> text" },
      { html: true },
      [],
      [],
      [],
      splices,
    );
    assert.deepEqual(splices, []);
  });
});

describe("the secret opt-in partitions every daemon dial", () => {
  // One opt-in decision per hook run must govern EVERY secret-touching path:
  // the walk, the reveal sidecar, the span store, the on-disk tripwire and the
  // PreToolUse rehydrator. A path that dials with the layer off sends tool
  // output to a daemon the user never enabled; prose that claims redaction
  // with the layer off tells the model a stored raw secret is safe.
  let dials = 0;
  before(() => daemon.on("connection", () => (dials += 1)));
  const secretHidden = `<div hidden>password: ${SECRET_VALUE}</div>`;
  const secretComment = `<!-- password=${SECRET_VALUE} -->`;
  const page = `page ${secretHidden} mid ${secretComment} end`;
  const [hiddenKey] = layer2Keys(layer2Placeholder("hidden", secretHidden));
  const onDisk = join(base, "on-disk.txt");
  writeFileSync(onDisk, "alpha\nbeta\n");
  const postToolUse = [
    { tool_name: "WebFetch", tool_input: {}, tool_response: page },
    {
      tool_name: "mcp__docs__fetch",
      tool_input: {},
      tool_response: { result: { pages: [page] } },
    },
    {
      tool_name: "Read",
      tool_input: { file_path: "/tmp/notes.md" },
      tool_response: `see ${REDACTED_MARK} and ${page}`,
    },
  ];
  const preToolUse = [
    {
      tool_name: "Write",
      tool_input: { file_path: onDisk, content: "alpha\nbeta\ngamma\n" },
    },
    {
      tool_name: "Edit",
      tool_input: { file_path: onDisk, old_string: "beta", new_string: "b" },
    },
  ];
  /** Every model-facing string the corpus produces, after a fresh store. */
  const runCorpus = async () => {
    const texts = [];
    for (const input of postToolUse) {
      const fields = await evaluateToolOutput(input);
      // A clean pass is null: nothing model-facing to inspect.
      texts.push(JSON.stringify(fields));
    }
    for (const input of preToolUse) {
      const fields = await buildPreToolUseResponse(input, undefined, () => {});
      texts.push(JSON.stringify(fields));
    }
    return texts.join("\n");
  };

  it("opted out: no dial, spans stored verbatim, no redaction claimed", async () => {
    delete process.env.AGENT_SANITIZER_SECRETS_ENABLED;
    dials = 0;
    const texts = await runCorpus();
    assert.equal(dials, 0, "a secret path dialed the daemon while opted out");
    assert.equal(readSpan(hiddenKey), secretHidden);
    // Positive marker: the reveal sidecar really was written on this path, so
    // the absence of the claim below is not the absence of the hint.
    assert.match(texts, /the original output before HTML removal was saved/u);
    assert.doesNotMatch(texts, /still redacted|redacted before storage/u);
    assert.ok(!texts.includes(ON_DISK_PLACEHOLDER_WARNING));
  });

  it("opted in: the same corpus dials and stores the redacted form", async () => {
    process.env.AGENT_SANITIZER_SECRETS_ENABLED = "1";
    try {
      dials = 0;
      const texts = await runCorpus();
      assert.ok(dials > 0, "the opted-in corpus never dialed the daemon");
      assert.equal(
        readSpan(hiddenKey),
        `<div hidden>password: ${REDACTED_MARK}</div>`,
      );
      assert.match(texts, /before HTML removal \(secrets still redacted\)/u);
      assert.ok(texts.includes(ON_DISK_PLACEHOLDER_WARNING));
    } finally {
      delete process.env.AGENT_SANITIZER_SECRETS_ENABLED;
    }
  });
});
