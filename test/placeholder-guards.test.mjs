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
import {
  placeholderNotice,
  PLACEHOLDER_RE,
  PLACEHOLDER_LABEL_CHARS,
} from "../claude-hooks/lib/placeholder-grammar.mjs";

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

// ─── placeholderNotice ───────────────────────────────────────────────────────

describe("placeholderNotice", () => {
  const cmd = `cat > .env <<'EOF'\nKEY=[REDACTED: SOME_VAR]\nEOF`;

  it("notes a placeholder in a Bash command", () => {
    const notice = placeholderNotice("Bash", { command: cmd });
    assert.ok(notice !== null && notice.includes("Edit or Write"));
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

  it("passes through a hinted MultiEdit when the view equals disk (literal text)", async () => {
    const content = "notes about [REDACTED] as prose\n";
    const res = await rehydrateRedacted(
      "MultiEdit",
      { file_path: "/f", edits: edits(["[REDACTED] as prose", "reworded"]) },
      fakeIo(content, { text: content, pairs: [] }),
    );
    assert.equal(res, null);
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
