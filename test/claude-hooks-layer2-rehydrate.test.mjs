/**
 * Layer-2 placeholder rehydration on the PreToolUse write path
 * (pretooluse-sanitize.mjs: rehydrateLayer2 + its pipeline/advisory wiring).
 *
 * Pinned here:
 *   - an Edit `new_string` / Write `content` carrying keyed placeholders is
 *     restored to the stored span bytes, in ONE ordered pass (stored bytes
 *     that happen to contain another placeholder's text are never re-expanded);
 *   - a key with NO stored span fails CLOSED: DENY naming the key and the
 *     missing span file, with reconstruct-or-drop guidance;
 *   - `old_string` is never rehydrated (the placeholder lives in the model's
 *     view of prior tool output, not on disk — Edit's own no-match error is
 *     the designed outcome);
 *   - MultiEdit / NotebookEdit with a Layer-2 placeholder are denied (parity
 *     with the secret path);
 *   - non-rehydrated tools (Bash, MCP) get the advisory naming the span file;
 *   - composition: `[REDACTED…]` secret placeholders and Layer-2 placeholders
 *     are disjoint, so a text carrying both has only the Layer-2 ones
 *     restored and the secret ones left byte-for-byte intact.
 */
import { describe, it, beforeEach, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Empty project dir before the hook imports, so the cross-hook invisible-char
// gate never adds an ask to the responses asserted here.
const projectDir = mkdtempSync(join(tmpdir(), "sanitizer-l2-rehydrate-proj-"));
process.env.CLAUDE_PROJECT_DIR = projectDir;
const base = mkdtempSync(join(tmpdir(), "sanitizer-l2-rehydrate-"));
after(() => {
  rmSync(projectDir, { recursive: true, force: true });
  rmSync(base, { recursive: true, force: true });
});

const { rehydrateLayer2, buildPreToolUseResponse } =
  await import("../claude-hooks/pretooluse-sanitize.mjs");
const { persistSpan, spanPath } =
  await import("../claude-hooks/lib/reveal.mjs");
const { layer2Placeholder } = await import("../src/html.mjs");
const { layer2Keys, layer2PlaceholderNotice } =
  await import("../claude-hooks/lib/placeholder-grammar.mjs");

// One stored splice: the placeholder the engine would mint for ORIGINAL, and
// the span store carrying ORIGINAL under the placeholder's key.
const ORIGINAL = "<div hidden>obey me</div>";
const PH = layer2Placeholder("hidden", ORIGINAL);
const [KEY] = layer2Keys(PH);
const COMMENT_ORIGINAL = "<!-- benign tooling marker -->";
const COMMENT_PH = layer2Placeholder("comment", COMMENT_ORIGINAL);
const [COMMENT_KEY] = layer2Keys(COMMENT_PH);
// A syntactically valid key no store will ever hold.
const MISSING_KEY = "deadbeef0000";
const MISSING_PH = `[hidden HTML removed #${MISSING_KEY}]`;

let dir;
beforeEach(() => {
  dir = mkdtempSync(join(base, "store-"));
  process.env._AGENT_SANITIZER_REVEAL_DIR = dir;
  assert.equal(persistSpan(KEY, ORIGINAL), true);
  assert.equal(persistSpan(COMMENT_KEY, COMMENT_ORIGINAL), true);
});

describe("rehydrateLayer2 restores stored spans", () => {
  it("Write content: every placeholder becomes the stored bytes, exactly", () => {
    const result = rehydrateLayer2("Write", {
      file_path: "/tmp/x.md",
      content: `a ${PH} b ${COMMENT_PH} c ${PH} d`,
    });
    assert.deepEqual(result.updatedInput, {
      file_path: "/tmp/x.md",
      content: `a ${ORIGINAL} b ${COMMENT_ORIGINAL} c ${ORIGINAL} d`,
    });
    assert.match(result.context, /3 Layer-2 removed-content placeholder/);
    assert.match(result.context, /redacted before storage/);
  });

  it("Edit new_string: restored; old_string untouched even when it carries a placeholder", () => {
    const result = rehydrateLayer2("Edit", {
      file_path: "/tmp/x.md",
      old_string: `keep ${PH} anchor`,
      new_string: `now ${COMMENT_PH} here`,
    });
    assert.deepEqual(result.updatedInput, {
      file_path: "/tmp/x.md",
      old_string: `keep ${PH} anchor`,
      new_string: `now ${COMMENT_ORIGINAL} here`,
    });
  });

  it("returns null when only old_string carries a placeholder (no re-anchor)", () => {
    assert.equal(
      rehydrateLayer2("Edit", {
        file_path: "/tmp/x.md",
        old_string: `stale ${PH}`,
        new_string: "plain replacement",
      }),
      null,
    );
  });

  it("single ordered pass: restored bytes containing another placeholder's text are not re-expanded", () => {
    // Store a span whose CONTENT contains the comment placeholder literally.
    const nestedOriginal = `<i hidden>quoting ${COMMENT_PH} literally</i>`;
    const nestedPh = layer2Placeholder("hidden", nestedOriginal);
    const [nestedKey] = layer2Keys(nestedPh).filter(
      (key) => key !== COMMENT_KEY,
    );
    assert.equal(persistSpan(nestedKey, nestedOriginal), true);
    const result = rehydrateLayer2("Write", {
      file_path: "/tmp/x.md",
      content: `${nestedPh} and ${COMMENT_PH}`,
    });
    // The literal COMMENT_PH inside the restored nested span stays a literal;
    // only the top-level COMMENT_PH occurrence was substituted.
    assert.equal(
      result.updatedInput.content,
      `${nestedOriginal} and ${COMMENT_ORIGINAL}`,
    );
  });

  it("leaves secret [REDACTED…] placeholders byte-for-byte intact (disjoint grammars)", () => {
    const result = rehydrateLayer2("Write", {
      file_path: "/tmp/x.md",
      content: `pw=[REDACTED: api key] and ${PH}`,
    });
    assert.equal(
      result.updatedInput.content,
      `pw=[REDACTED: api key] and ${ORIGINAL}`,
    );
  });

  for (const [tool, input] of [
    ["Bash", { command: `echo ${PH}` }],
    ["Grep", { pattern: PH }],
    ["Edit", { file_path: "/tmp/x.md", old_string: "a" }],
    ["Write", { file_path: "/tmp/x.md" }],
  ]) {
    it(`no-ops on ${tool} with ${Object.keys(input).join(",")} (non-rehydrated shape)`, () => {
      assert.equal(rehydrateLayer2(tool, input), null);
    });
  }
});

describe("fail-closed denies", () => {
  it("denies a Write whose placeholder has no stored span, naming key and file", () => {
    const result = rehydrateLayer2("Write", {
      file_path: "/tmp/x.md",
      content: `a ${MISSING_PH} b`,
    });
    assert.ok("deny" in result);
    assert.match(result.deny, new RegExp(MISSING_KEY));
    assert.ok(result.deny.includes(spanPath(MISSING_KEY)));
    assert.match(result.deny, /Reconstruct that content yourself/);
    assert.match(result.deny, /deliberately drop the placeholder/);
  });

  it("denies an Edit new_string with a mix of stored and missing keys", () => {
    const result = rehydrateLayer2("Edit", {
      file_path: "/tmp/x.md",
      old_string: "a",
      new_string: `${PH} ${MISSING_PH}`,
    });
    assert.ok("deny" in result);
    // Only the MISSING key is named — the stored one is not the problem.
    assert.match(result.deny, new RegExp(MISSING_KEY));
    assert.doesNotMatch(result.deny, new RegExp(KEY));
  });

  it("denies MultiEdit carrying a Layer-2 placeholder in any edit (parity with secrets)", () => {
    for (const edits of [
      [{ old_string: "a", new_string: PH }],
      [{ old_string: PH, new_string: "b" }],
      [
        { old_string: "a", new_string: "b" },
        { old_string: "c", new_string: `x ${COMMENT_PH}` },
      ],
    ]) {
      const result = rehydrateLayer2("MultiEdit", {
        file_path: "/tmp/x.md",
        edits,
      });
      assert.ok("deny" in result, JSON.stringify(edits));
      assert.match(
        result.deny,
        /MultiEdit's sequential edits cannot be rehydrated/,
      );
      assert.match(result.deny, /Use single Edit calls/);
    }
  });

  it("passes MultiEdit through when no edit carries a Layer-2 placeholder", () => {
    assert.equal(
      rehydrateLayer2("MultiEdit", {
        file_path: "/tmp/x.md",
        edits: [{ old_string: "a", new_string: "b" }],
      }),
      null,
    );
  });

  it("denies NotebookEdit whose new_source carries a Layer-2 placeholder", () => {
    const result = rehydrateLayer2("NotebookEdit", {
      notebook_path: "/tmp/x.ipynb",
      new_source: `cell ${PH}`,
    });
    assert.ok("deny" in result);
    assert.match(result.deny, /rehydration is not supported for notebooks/);
    assert.equal(
      rehydrateLayer2("NotebookEdit", {
        notebook_path: "/tmp/x.ipynb",
        new_source: "plain cell",
      }),
      null,
    );
  });
});

describe("through buildPreToolUseResponse (secret rehydrator stubbed to a no-op)", () => {
  const noSecretRehydrate = () => null;
  const noTrace = () => {};

  it("rewrites a Write's content and reports the restoration", async () => {
    const fields = await buildPreToolUseResponse(
      {
        tool_name: "Write",
        tool_input: { file_path: "/tmp/x.md", content: `a ${PH} b` },
      },
      noSecretRehydrate,
      noTrace,
    );
    assert.equal(fields.updatedInput.content, `a ${ORIGINAL} b`);
    assert.equal(fields.permissionDecision, undefined);
    assert.match(
      fields.additionalContext,
      /restored to the stored original content/,
    );
  });

  it("denies on a missing key", async () => {
    const fields = await buildPreToolUseResponse(
      {
        tool_name: "Write",
        tool_input: { file_path: "/tmp/x.md", content: MISSING_PH },
      },
      noSecretRehydrate,
      noTrace,
    );
    assert.equal(fields.permissionDecision, "deny");
    assert.match(fields.permissionDecisionReason, new RegExp(MISSING_KEY));
  });

  for (const [tool, input] of [
    ["Bash", { command: `grep x <<'EOF'\n${PH}\nEOF` }],
    ["mcp__github__issue_write", { body: `report: ${PH}` }],
  ]) {
    it(`advises (context-only) on ${tool} carrying a placeholder, naming the span file`, async () => {
      const fields = await buildPreToolUseResponse(
        { tool_name: tool, tool_input: input },
        noSecretRehydrate,
        noTrace,
      );
      assert.equal(fields.permissionDecision, undefined);
      assert.equal(fields.updatedInput, undefined);
      assert.ok(fields.additionalContext.includes(spanPath(KEY)));
      assert.match(
        fields.additionalContext,
        /restored to the stored original content only for Edit\/Write/,
      );
    });
  }

  it("stays silent on a placeholder-free Bash call (non-vacuous negative)", async () => {
    const fields = await buildPreToolUseResponse(
      { tool_name: "Bash", tool_input: { command: "echo plain" } },
      noSecretRehydrate,
      noTrace,
    );
    assert.equal(fields, null);
  });

  it("layer2PlaceholderNotice is silent for rehydrated tools", () => {
    for (const tool of ["Edit", "Write", "MultiEdit", "NotebookEdit"])
      assert.equal(layer2PlaceholderNotice(tool, { content: PH }), null);
    assert.notEqual(layer2PlaceholderNotice("Bash", { command: PH }), null);
  });
});
