/**
 * The placeholder grammar (PLACEHOLDER_RE), the non-rehydrated-tool advisory
 * (placeholderNotice), and the MultiEdit arm of rehydrateRedacted.
 *
 * The grammar test is the SSOT contract: the JS regex is pinned to the Python
 * producer (python/agent_sanitizer/secrets/placeholders.py) by extracting that
 * file's charset/length literals and rebuilding the regex source from them —
 * an edit to either side that forgets the other fails here, not in the field.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { rehydrateRedacted } from "../src/rehydrate.mjs";
import { layer2Placeholder, UNPARSEABLE_PLACEHOLDER } from "../src/html.mjs";
import {
  placeholderNotice,
  layer2PlaceholderNotice,
  collectPlaceholders,
  PLACEHOLDER_RE,
  PLACEHOLDER_LABEL_CHARS,
  UNPARSEABLE_MARKER,
} from "../claude-hooks/lib/placeholder-grammar.mjs";

// Keyed Layer-2 placeholders, minted by the engine's single producer so these
// carry real keys rather than hand-typed ones.
const HIDDEN_PH = layer2Placeholder("hidden", "<span hidden>x</span>");
const COMMENT_PH = layer2Placeholder("comment", "<!-- do this -->");

// Secrets assembled at runtime so no complete token literal trips push
// protection / gitleaks.
const SECRET_A = ["hunter2hunter2", "hunter2xA"].join("");
const PH = "[REDACTED]";
// Built from a code point so no raw invisible byte sits in this source.
const ZW = String.fromCharCode(0x200b);

/** io over a fixed view (fixtures carry no invisible chars → cleaned ≡ content). */
const fakeIo = (content, view, redact = () => null) => ({
  readFile: () => content,
  redactMap: () => view,
  redact,
});

/** A view redacting every SECRET_A occurrence to PH. */
function secretView(content) {
  const pairs = [];
  let text = "";
  let last = 0;
  for (
    let index = content.indexOf(SECRET_A);
    index !== -1;
    index = content.indexOf(SECRET_A, index + SECRET_A.length)
  ) {
    text += content.slice(last, index);
    pairs.push({ placeholder: PH, original: SECRET_A, start: text.length });
    text += PH;
    last = index + SECRET_A.length;
  }
  text += content.slice(last);
  return { text, pairs };
}

/** @param {string} code */
function fsError(code) {
  const err = new Error(code);
  /** @type {any} */ (err).code = code;
  return err;
}

// ─── PLACEHOLDER_RE: SSOT contract with the Python producer ──────────────────

describe("PLACEHOLDER_RE: contract with placeholders.py", () => {
  const pySource = readFileSync(
    new URL(
      "../python/agent_sanitizer/secrets/placeholders.py",
      import.meta.url,
    ),
    "utf8",
  );

  it("mirrors the Python charset and length literals exactly", () => {
    const charsMatch = pySource.match(
      /^PLACEHOLDER_LABEL_CHARS = r"([^"]+)"$/m,
    );
    const lenMatch = pySource.match(/^PLACEHOLDER_LABEL_MAX_LEN = (\d+)$/m);
    // Positive markers first: if the Python literals move or get reformatted,
    // fail as "extraction broke", never as a vacuous pass.
    assert.ok(
      charsMatch,
      "PLACEHOLDER_LABEL_CHARS not found in placeholders.py",
    );
    assert.ok(
      lenMatch,
      "PLACEHOLDER_LABEL_MAX_LEN not found in placeholders.py",
    );
    assert.equal(PLACEHOLDER_LABEL_CHARS, charsMatch[1]);
    // Rebuild the JS regex source from the PYTHON literals; equality pins the
    // whole grammar (prefix, optional `: label`, charset, length) to one shape.
    assert.equal(
      PLACEHOLDER_RE.source,
      `\\[REDACTED(?:: [${charsMatch[1]}]{1,${lenMatch[1]}})?\\]`,
    );
  });

  it("agrees with the live Python regex on a positive/negative corpus", function () {
    const corpus = [
      "[REDACTED]",
      "[REDACTED: ANTHROPIC_API_KEY]",
      "[REDACTED: Public IP (ipv4)]",
      "[REDACTED: a.b-c_d 9]",
      "x=[REDACTED] embedded in text",
      "[REDACTED…]", // hint-prefixed prose (the ellipsis form the docs use)
      "[REDACTED:missing-space]",
      "[REDACTED: bad:colon]",
      "[REDACTED: line\nbreak]",
      `[REDACTED: ${"a".repeat(65)}]`,
      "REDACTED] alone",
    ];
    let pyVerdicts;
    try {
      pyVerdicts = JSON.parse(
        execFileSync(
          "python3",
          [
            "-c",
            // Load placeholders.py by path: importing the package would drag
            // in the detect-secrets engine, which isn't installed for JS runs.
            "import importlib.util, json, sys\n" +
              "spec = importlib.util.spec_from_file_location('ph', 'python/agent_sanitizer/secrets/placeholders.py')\n" +
              "m = importlib.util.module_from_spec(spec)\n" +
              "spec.loader.exec_module(m)\n" +
              "print(json.dumps([bool(m.PLACEHOLDER_RE.search(c)) for c in json.load(sys.stdin)]))",
          ],
          {
            input: JSON.stringify(corpus),
            cwd: fileURLToPath(new URL("..", import.meta.url)),
          },
        ).toString(),
      );
    } catch {
      // No python3 on this runner: the source-literal contract above still
      // pins the grammar; skip only the live cross-check.
      this.skip();
      return;
    }
    assert.deepEqual(
      corpus.map((c) => PLACEHOLDER_RE.test(c)),
      pyVerdicts,
    );
    // Non-vacuous in both directions.
    assert.ok(pyVerdicts.includes(true) && pyVerdicts.includes(false));
  });

  it("matches only full placeholder shapes, not the bare hint prefix", () => {
    assert.equal(PLACEHOLDER_RE.test("[REDACTED]"), true);
    assert.equal(PLACEHOLDER_RE.test("[REDACTED: X]"), true);
    assert.equal(PLACEHOLDER_RE.test('grep -rn "\\[REDACTED" .'), false);
    assert.equal(PLACEHOLDER_RE.test("[REDACTED…]"), false);
    assert.equal(PLACEHOLDER_RE.test("[REDACTEDish]"), false);
  });
});

// ─── UNPARSEABLE_MARKER: SSOT contract with the splicer ──────────────────────

describe("UNPARSEABLE_MARKER: contract with src/html.mjs", () => {
  it("mirrors the splicer's un-keyed marker exactly", () => {
    // The hooks copy exists because the shipped plugin bundle resolves the
    // engine from a pinned release; this pins the copy to the producer so a
    // reworded marker cannot silently stop being detected. The keyed markers
    // have their own contract test (claude-hooks-layer2-grammar.test.mjs).
    assert.equal(UNPARSEABLE_MARKER, UNPARSEABLE_PLACEHOLDER);
  });
});

// ─── collectPlaceholders ─────────────────────────────────────────────────────

describe("collectPlaceholders", () => {
  it("names each distinct token once, with the field path it sits in", () => {
    const found = collectPlaceholders({
      title: "ok",
      body: `see [REDACTED: SOME_VAR] and ${HIDDEN_PH}`,
      notes: ["[REDACTED: SOME_VAR]", "[REDACTED]"],
    });
    assert.deepEqual(found.secret, [
      { token: "[REDACTED: SOME_VAR]", path: "body" },
      { token: "[REDACTED]", path: "notes[1]" },
    ]);
    assert.deepEqual(found.layer2, [{ token: HIDDEN_PH, path: "body" }]);
  });

  it("finds nothing in clean input", () => {
    assert.deepEqual(collectPlaceholders({ command: "ls -la" }), {
      secret: [],
      layer2: [],
    });
  });
});

// ─── placeholderNotice ───────────────────────────────────────────────────────

describe("placeholderNotice", () => {
  const cmd = `cat > .env <<'EOF'\nKEY=[REDACTED: SOME_VAR]\nEOF`;

  it("notes a placeholder in a Bash command", () => {
    const notice = placeholderNotice("Bash", { command: cmd });
    assert.ok(notice !== null && notice.includes("Edit or Write"));
  });

  it("names the exact token and the field carrying it", () => {
    const notice = placeholderNotice("mcp__github__update_pull_request", {
      pullNumber: 244,
      body: `Fixes the thing. KEY=[REDACTED: SOME_VAR]`,
    });
    assert.ok(notice !== null);
    assert.match(notice, /"\[REDACTED: SOME_VAR\]" \(in body\)/);
    // The outbound-content rule: never reconstruct the secret into a call that
    // publishes it.
    assert.match(notice, /do NOT reconstruct the real secret/);
  });

  it("stays silent on Layer-2-only input (that is the Layer-2 advisory's job)", () => {
    assert.equal(
      placeholderNotice("mcp__github__update_pull_request", {
        body: `## Summary\n\n${COMMENT_PH}\n`,
      }),
      null,
    );
  });

  it("caps the spelled-out token list", () => {
    const command = Array.from(
      { length: 8 },
      (_, index) => `[REDACTED: VAR ${index}]`,
    ).join(" ");
    const notice = placeholderNotice("Bash", { command });
    assert.ok(notice !== null);
    assert.match(notice, /"\[REDACTED: VAR 4\]"/);
    assert.equal(notice.includes("[REDACTED: VAR 5]"), false);
    assert.match(notice, /and 3 more/);
  });

  it("notes a placeholder in nested MCP-tool input", () => {
    const notice = placeholderNotice("mcp__fs__write_file", {
      args: [{ body: { text: "value: [REDACTED]" } }],
    });
    assert.ok(notice !== null);
  });

  for (const tool of ["Edit", "Write", "MultiEdit", "NotebookEdit"]) {
    it(`stays silent on ${tool} (rehydration owns its verdict)`, () => {
      assert.equal(placeholderNotice(tool, { content: "[REDACTED]" }), null);
    });
  }

  it("ignores hint-prefixed prose that is not a placeholder", () => {
    assert.equal(
      placeholderNotice("Bash", { command: 'grep -rn "\\[REDACTED" .' }),
      null,
    );
    assert.equal(
      placeholderNotice("Bash", { command: "echo [REDACTED…]" }),
      null,
    );
  });

  it("ignores clean input, non-string leaves, and null input", () => {
    assert.equal(placeholderNotice("Bash", { command: "ls -la" }), null);
    assert.equal(placeholderNotice("Bash", { count: 3, ok: true }), null);
    assert.equal(placeholderNotice("Bash", null), null);
  });

  it("caps the walk depth (fails open, never throws)", () => {
    /** @type {any} */
    let deep = "[REDACTED]";
    for (let i = 0; i < 40; i++) deep = { nested: deep };
    assert.equal(placeholderNotice("Bash", deep), null);
  });
});

// ─── MultiEdit ───────────────────────────────────────────────────────────────

describe("rehydrate: MultiEdit", () => {
  const edits = (...pairs) =>
    pairs.map(([old_string, new_string]) => ({ old_string, new_string }));

  it("passes through on a clean, secret-free file (fast path)", async () => {
    const content = "alpha\nbeta\n";
    const res = await rehydrateRedacted(
      "MultiEdit",
      { file_path: "/f", edits: edits(["alpha", "gamma"]) },
      fakeIo(content, { text: content, pairs: [] }),
    );
    assert.equal(res, null);
  });

  it("denies on a secret-bearing file with use-single-Edit guidance", async () => {
    const content = `password=${SECRET_A}\nother=x\n`;
    const res = await rehydrateRedacted(
      "MultiEdit",
      { file_path: "/f", edits: edits(["other=x", "other=y"]) },
      fakeIo(content, secretView(content), (text) =>
        text.includes(SECRET_A) ? text.split(SECRET_A).join(PH) : null,
      ),
    );
    assert.ok(res !== null && "deny" in res);
    assert.match(res.deny, /single Edit calls/);
  });

  it("denies on a file with stripped invisible characters", async () => {
    const content = `alpha${ZW}beta\n`;
    const res = await rehydrateRedacted(
      "MultiEdit",
      { file_path: "/f", edits: edits(["alphabeta", "gamma"]) },
      {
        readFile: () => content,
        redactMap: (text) => ({ text, pairs: [] }),
        redact: () => null,
      },
    );
    assert.ok(res !== null && "deny" in res);
    assert.match(res.deny, /single Edit calls/);
  });

  it("denies a hinted MultiEdit even when the view equals disk (foreign placeholder)", async () => {
    // A pristine file has no own placeholder to resolve, so hint-bearing edits
    // would persist a foreign [REDACTED…] verbatim — same deny as the
    // byte-identical Write's cross-file rule.
    const content = "notes\n";
    const res = await rehydrateRedacted(
      "MultiEdit",
      { file_path: "/f", edits: edits(["notes", "KEY=[REDACTED]"]) },
      fakeIo(content, { text: content, pairs: [] }),
    );
    assert.ok(res !== null && "deny" in res);
    assert.match(res.deny, /single Edit calls/);
  });

  it("denies a hint-free MultiEdit on an unmappable view", async () => {
    const content = `password=${SECRET_A}\n`;
    const res = await rehydrateRedacted(
      "MultiEdit",
      { file_path: "/f", edits: edits(["a", "b"]) },
      {
        readFile: () => content,
        redactMap: () => ({ unmappable: "because" }),
        redact: () => "probe says secrets",
      },
    );
    assert.ok(res !== null && "deny" in res);
    assert.match(res.deny, /single Edit calls/);
  });

  it("ENOENT: hint-free passes through, hinted denies (file creation)", async () => {
    const io = {
      readFile: () => {
        throw fsError("ENOENT");
      },
      redactMap: () => ({ text: "", pairs: [] }),
      redact: () => null,
    };
    assert.equal(
      await rehydrateRedacted(
        "MultiEdit",
        { file_path: "/missing", edits: edits(["a", "b"]) },
        io,
      ),
      null,
    );
    const res = await rehydrateRedacted(
      "MultiEdit",
      { file_path: "/missing", edits: edits(["", "KEY=[REDACTED]"]) },
      io,
    );
    assert.ok(res !== null && "deny" in res);
    assert.match(res.deny, /does not exist/);
  });

  it("ignores malformed MultiEdit shapes (not a candidate)", async () => {
    const io = fakeIo("x", { text: "x", pairs: [] });
    for (const ti of [
      { file_path: "/f" },
      { file_path: "/f", edits: [] },
      { file_path: "/f", edits: [{ old_string: "a" }] },
      { file_path: "/f", edits: "nope" },
      { edits: [{ old_string: "a", new_string: "b" }] },
    ])
      assert.equal(await rehydrateRedacted("MultiEdit", ti, io), null);
  });
});

// ─── layer2PlaceholderNotice ─────────────────────────────────────────────────

describe("layer2PlaceholderNotice", () => {
  it("names the keyed marker, the field carrying it, and its span file", () => {
    const notice = layer2PlaceholderNotice("mcp__github__update_pull_request", {
      body: `## Summary\n\n${COMMENT_PH}\n`,
    });
    assert.ok(notice !== null);
    assert.match(
      notice,
      new RegExp(`"${COMMENT_PH.replace(/[[\]]/g, "\\$&")}" \\(in body\\)`),
    );
    assert.match(
      notice,
      /The stored original\(s\) live at: .*span-[0-9a-f]{12}\.txt/,
    );
    // A keyed marker is round-trippable, so the advisory must not send the
    // model to the whole-output reveal sidecar instead.
    assert.equal(/reveal file under/.test(notice), false);
  });

  it("points the un-keyed unparseable marker at the reveal sidecar", () => {
    const notice = layer2PlaceholderNotice("Bash", {
      command: `echo '${UNPARSEABLE_MARKER}' >> out.md`,
    });
    assert.ok(notice !== null);
    assert.match(notice, /reveal file under .*layer2-reveal/);
    assert.equal(/span-/.test(notice), false);
  });

  it("names both recovery routes when keyed and un-keyed markers mix", () => {
    const notice = layer2PlaceholderNotice("Bash", {
      command: `echo '${HIDDEN_PH} ${UNPARSEABLE_MARKER}'`,
    });
    assert.ok(notice !== null);
    assert.match(notice, /span-[0-9a-f]{12}\.txt/);
    assert.match(notice, /reveal file under .*layer2-reveal/);
  });

  it("says nothing about secrets on Layer-2-only input", () => {
    const notice = layer2PlaceholderNotice("Bash", {
      command: `echo '${HIDDEN_PH}'`,
    });
    assert.ok(notice !== null);
    assert.equal(/secret-redaction placeholder/.test(notice), false);
  });

  it("ignores a truncated or mis-keyed splice marker", () => {
    for (const command of [
      "echo '[hidden HTML remove'",
      "echo '[hidden HTML removed]'",
      "echo '[hidden HTML removed #NOTHEX123456]'",
    ])
      assert.equal(layer2PlaceholderNotice("Bash", { command }), null);
  });

  for (const tool of ["Edit", "Write", "MultiEdit", "NotebookEdit"]) {
    it(`stays silent on ${tool} (rehydration owns its verdict)`, () => {
      assert.equal(layer2PlaceholderNotice(tool, { content: HIDDEN_PH }), null);
    });
  }

  it("ignores clean input, non-string leaves, and null input", () => {
    assert.equal(layer2PlaceholderNotice("Bash", { command: "ls -la" }), null);
    assert.equal(layer2PlaceholderNotice("Bash", { count: 3 }), null);
    assert.equal(layer2PlaceholderNotice("Bash", null), null);
  });
});
