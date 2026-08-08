import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { rehydrateRedacted, DEFAULT_HINT } from "../src/rehydrate.mjs";
import { alignDeletions, occurrences } from "../src/view-map.mjs";

// Secrets assembled at runtime so no complete token literal trips push
// protection / gitleaks.
const SECRET_A = ["hunter2hunter2", "hunter2xA"].join("");
const SECRET_B = ["hunter2hunter2", "hunter2xB"].join("");
const SECRET_C = ["hunter2hunter2", "hunter2xC"].join("");
const PH = "[REDACTED]";
const PH_PEM = "[REDACTED: Private Key]";
// Built from code points so no raw invisible/control byte sits in this source.
const ZW = String.fromCharCode(0x200b); // zero-width space (Layer 1 strips)
const ESC = String.fromCharCode(0x1b);
const GREEN = `${ESC}[32m`;
const RESET = `${ESC}[0m`;

/**
 * Build a redactMap view from already-Layer-1-cleaned text: replace each
 * secret occurrence with its placeholder, emitting ordered (placeholder,
 * original, start) pairs at the view offsets.
 * @param {string} cleaned
 * @param {{value: string, placeholder: string}[]} secrets
 * @returns {{text: string, pairs: {placeholder: string, original: string, start: number}[]}}
 */
function mkView(cleaned, secrets) {
  // Collect every secret occurrence in the cleaned text, ordered by position.
  const hits = [];
  for (const { value, placeholder } of secrets)
    for (const index of occurrences(cleaned, value))
      hits.push({ index, value, placeholder });
  hits.sort((a, b) => a.index - b.index);

  let text = "";
  let last = 0;
  const pairs = [];
  for (const { index, value, placeholder } of hits) {
    text += cleaned.slice(last, index);
    pairs.push({ placeholder, original: value, start: text.length });
    text += placeholder;
    last = index + value.length;
  }
  text += cleaned.slice(last);
  return { text, pairs };
}

/**
 * Fake io over a hand-built view. `redact` is what io.redact returns for the
 * exposure re-scan (null = the redactor's "nothing redacted" signal). The
 * `redactMap` ignores its (cleaned) argument: these fixtures carry no
 * invisible characters, so cleaned ≡ content.
 */
const fakeIo = (content, view, redact = () => null) => ({
  readFile: () => content,
  redactMap: () => view,
  redact,
});

/**
 * Fake io for invisible-char fixtures: derives the view from whatever cleaned
 * text the layer hands it, replacing each secret occurrence.
 */
const liveIo = (content, secrets = [], redact = () => null) => ({
  readFile: () => content,
  redactMap: (text) => mkView(text, secrets),
  redact,
});

// An exposure re-scan in which every known secret stays redacted.
const reRedact = (text) =>
  text.split(SECRET_A).join(PH).split(SECRET_B).join(PH);

// ─── Gating: which calls the layer even looks at ─────────────────────────────

/**
 * An error shaped like Node's real `fs` failures: a `.code` property, not
 * just a message string that happens to say "ENOENT".
 * @param {string} code
 */
function fsError(code) {
  const err = new Error(code);
  err.code = code;
  return err;
}

describe("rehydrate: gating", () => {
  const unreadableIo = {
    readFile: () => {
      throw fsError("ENOENT");
    },
    redactMap: () => {
      throw new Error("redactMap must not be reached");
    },
    redact: () => null,
  };

  it("exports the default hint", () => {
    assert.equal(DEFAULT_HINT, "[REDACTED");
  });

  it("ignores tools without rehydratable fields", async () => {
    assert.equal(
      await rehydrateRedacted("Bash", { command: `echo ${PH}` }, unreadableIo),
      null,
    );
  });

  it("ignores malformed inputs (missing path or non-string fields)", async () => {
    assert.equal(
      await rehydrateRedacted(
        "Edit",
        { old_string: PH, new_string: "b" },
        unreadableIo,
      ),
      null,
    );
    assert.equal(
      await rehydrateRedacted(
        "Edit",
        { file_path: "/f", old_string: PH, new_string: 7 },
        unreadableIo,
      ),
      null,
    );
    assert.equal(
      await rehydrateRedacted(
        "Write",
        { file_path: "/f", content: 7 },
        unreadableIo,
      ),
      null,
    );
  });

  it("ignores Write content without placeholder text", async () => {
    assert.equal(
      await rehydrateRedacted(
        "Write",
        { file_path: "/f", content: "x" },
        unreadableIo,
      ),
      null,
    );
  });

  it("treats a null tool_input as a non-candidate without dereferencing it", async () => {
    assert.equal(await rehydrateRedacted("Edit", null, unreadableIo), null);
    assert.equal(
      await rehydrateRedacted("NotebookEdit", null, unreadableIo),
      null,
    );
  });

  it("passes through when the target file is missing (ENOENT)", async () => {
    assert.equal(
      await rehydrateRedacted(
        "Edit",
        { file_path: "/missing", old_string: PH, new_string: "x" },
        unreadableIo,
      ),
      null,
    );
  });

  it("denies a hinted call on a non-ENOENT read failure instead of passing the placeholder through", async () => {
    // EACCES (or any other read failure) means the file almost certainly still
    // EXISTS with real bytes on disk — unlike ENOENT. Silently passing this
    // through would let a hinted Write persist literal "[REDACTED…]" text over
    // whatever real secret is actually there.
    const eaccesIo = {
      readFile: () => {
        throw fsError("EACCES");
      },
      redactMap: () => {
        throw new Error("redactMap must not be reached");
      },
      redact: () => null,
    };
    const out = await rehydrateRedacted(
      "Write",
      { file_path: "/locked", content: `secret: ${PH}` },
      eaccesIo,
    );
    assert.match(out.deny, /could not read \/locked/);
    assert.match(out.deny, /EACCES/);
    assert.equal(out.updatedInput, undefined);
  });

  it("falls back to the error message when a non-ENOENT failure carries no .code", async () => {
    const noCodeIo = {
      readFile: () => {
        throw new Error("disk gremlins");
      },
      redactMap: () => {
        throw new Error("redactMap must not be reached");
      },
      redact: () => null,
    };
    const out = await rehydrateRedacted(
      "Write",
      { file_path: "/weird", content: `secret: ${PH}` },
      noCodeIo,
    );
    assert.match(out.deny, /disk gremlins/);
  });

  it("rethrows a non-ENOENT read failure for a non-hinted call instead of swallowing it", async () => {
    const eaccesIo = {
      readFile: () => {
        throw fsError("EACCES");
      },
      redactMap: () => {
        throw new Error("redactMap must not be reached");
      },
      redact: () => null,
    };
    await assert.rejects(
      rehydrateRedacted(
        "Edit",
        { file_path: "/locked", old_string: "a", new_string: "b" },
        eaccesIo,
      ),
      /EACCES/,
    );
  });

  it("short-circuits a hint-free Edit whose old_string matches disk", async () => {
    const io = {
      readFile: () => "plain content\n",
      redactMap: () => {
        throw new Error("redactMap must not be reached");
      },
      redact: () => null,
    };
    assert.equal(
      await rehydrateRedacted(
        "Edit",
        { file_path: "/f", old_string: "plain", new_string: "simple" },
        io,
      ),
      null,
    );
  });

  it("short-circuits a hint-free mismatch against a Layer-1-clean file", async () => {
    const io = {
      readFile: () => "plain content\n",
      redactMap: () => {
        throw new Error("redactMap must not be reached");
      },
      redact: () => null,
    };
    assert.equal(
      await rehydrateRedacted(
        "Edit",
        { file_path: "/f", old_string: "absent", new_string: "x" },
        io,
      ),
      null,
    );
  });

  it("denies an unmappable file for a placeholder-bearing input", async () => {
    const io = fakeIo("c", {
      unmappable: "input contains reserved sentinel characters",
    });
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: PH, new_string: "x" },
      io,
    );
    assert.match(out.deny, /cannot resolve redaction placeholders/);
  });

  it("passes through an unmappable file for a hint-free Edit", async () => {
    const content = `${ZW}weird\n`;
    const io = {
      readFile: () => content,
      redactMap: () => ({
        unmappable: "input contains reserved sentinel characters",
      }),
      redact: () => null,
    };
    assert.equal(
      await rehydrateRedacted(
        "Edit",
        { file_path: "/f", old_string: "weird stuff", new_string: "x" },
        io,
      ),
      null,
    );
  });

  it("passes through when nothing in the file is redacted or stripped", async () => {
    const content = `doc says ${PH} here`;
    const io = fakeIo(content, mkView(content, []));
    assert.equal(
      await rehydrateRedacted(
        "Edit",
        {
          file_path: "/f",
          old_string: `says ${PH}`,
          new_string: `says ${PH}!`,
        },
        io,
      ),
      null,
    );
  });

  it("passes through a hinted Edit on a clean file when old_string is absent", async () => {
    const content = "plain\n";
    const io = fakeIo(content, mkView(content, []));
    assert.equal(
      await rehydrateRedacted(
        "Edit",
        { file_path: "/f", old_string: `gone ${PH}`, new_string: "x" },
        io,
      ),
      null,
    );
  });

  it("denies NotebookEdit carrying a placeholder, ignores one without", async () => {
    const out = await rehydrateRedacted(
      "NotebookEdit",
      { notebook_path: "/n.ipynb", new_source: `x = "${PH}"` },
      // io is never reached on the notebook deny path.
      { readFile: () => "x", redactMap: () => mkView("x", []) },
    );
    assert.match(out.deny, /not supported for notebooks/);
    assert.match(out.deny, /stands for a secret/);
    assert.match(out.deny, /Keep[\s\S]*the secret-bearing cell unchanged/);
    assert.equal(
      await rehydrateRedacted(
        "NotebookEdit",
        { notebook_path: "/n.ipynb", new_source: "x = 1" },
        { readFile: () => "x", redactMap: () => mkView("x", []) },
      ),
      null,
    );
  });

  // The candidate gate must reject before any file/redactor work.
  const mapThrowsIo = {
    readFile: () => `secret K=${SECRET_A}\n`,
    redactMap: () => {
      throw new Error("redactMap must not be reached");
    },
    redact: () => null,
  };

  it("rejects an Edit with a non-string field before touching the redactor", async () => {
    assert.equal(
      await rehydrateRedacted(
        "Edit",
        { file_path: "/f", old_string: PH, new_string: 7 },
        mapThrowsIo,
      ),
      null,
    );
    assert.equal(
      await rehydrateRedacted(
        "Edit",
        { file_path: "/f", old_string: 7, new_string: `x ${PH}` },
        mapThrowsIo,
      ),
      null,
    );
  });

  it("rejects a hint-free Write before touching the redactor", async () => {
    assert.equal(
      await rehydrateRedacted(
        "Write",
        { file_path: "/f", content: "plain content" },
        mapThrowsIo,
      ),
      null,
    );
  });

  it("does not treat a non-Edit, non-Write tool as a Write candidate", async () => {
    assert.equal(
      await rehydrateRedacted(
        "Glob",
        { file_path: "/f", content: `doc ${PH}` },
        mapThrowsIo,
      ),
      null,
    );
  });

  it("applies the notebook guard only to NotebookEdit, not other tools", async () => {
    assert.equal(
      await rehydrateRedacted(
        "Edit",
        {
          file_path: "/f",
          old_string: "plain",
          new_string: "x",
          new_source: `v=${PH}`,
        },
        {
          readFile: () => "plain\n",
          redactMap: () => mkView("plain\n", []),
          // Hint-free Edit on a Layer-1-clean file: the R1 secrets-present probe
          // (io.redact) runs before the redactor's map mode; no secrets here.
          redact: () => null,
        },
      ),
      null,
    );
  });

  it("honors a custom hint", async () => {
    // With a custom hint "<SECRET", DEFAULT_HINT "[REDACTED" is no longer a
    // placeholder marker, so an old_string carrying only "[REDACTED]" is
    // hint-free; the custom-hinted placeholder drives the deny.
    const HINT = "<SECRET";
    const content = `plain\n`;
    const io = fakeIo(content, mkView(content, []));
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: `gone <SECRET:k>`, new_string: "x" },
      io,
      { hint: HINT },
    );
    // No match on the clean file → hinted absent → pass-through (null).
    assert.equal(out, null);

    // A custom-hinted NotebookEdit is denied with the custom hint in the text.
    const nb = await rehydrateRedacted(
      "NotebookEdit",
      { notebook_path: "/n.ipynb", new_source: `x = "<SECRET:k>"` },
      io,
      { hint: HINT },
    );
    assert.match(nb.deny, /<SECRET…\] placeholder/);
  });
});

// ─── Edit resolution across redaction placeholders ───────────────────────────

describe("rehydrate: Edit", () => {
  const content = `# config\nPASSWORD=${SECRET_A}\nDEBUG=1\n`;
  const view = mkView(content, [{ value: SECRET_A, placeholder: PH }]);
  const edit = (old_string, new_string, extra = {}) =>
    rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string, new_string, ...extra },
      fakeIo(content, view, reRedact),
    );

  it("passes through old_string that matches disk verbatim", async () => {
    const src = `x ${PH} y\nPASSWORD=${SECRET_A}\n`;
    const io = fakeIo(src, mkView(src, [{ value: SECRET_A, placeholder: PH }]));
    assert.equal(
      await rehydrateRedacted(
        "Edit",
        { file_path: "/f", old_string: `x ${PH} y`, new_string: "z" },
        io,
      ),
      null,
    );
  });

  it("keeps a literal placeholder in new_string when old_string matched it verbatim", async () => {
    const src = `x ${PH} y\nPASSWORD=${SECRET_A}\n`;
    const io = fakeIo(src, mkView(src, [{ value: SECRET_A, placeholder: PH }]));
    assert.equal(
      await rehydrateRedacted(
        "Edit",
        { file_path: "/f", old_string: `x ${PH} y`, new_string: `x ${PH} z` },
        io,
      ),
      null,
    );
  });

  it("denies a verbatim-matching edit that inserts a placeholder for another secret", async () => {
    const out = await edit("DEBUG=1", `DEBUG=1\nPASSWORD_COPY=${PH}`);
    assert.match(out.deny, /outside the matched old_string/);
  });

  it("rehydrates old_string and new_string around a kept secret", async () => {
    const out = await edit(
      `PASSWORD=${PH}\nDEBUG=1`,
      `PASSWORD=${PH}\nDEBUG=0`,
    );
    assert.equal(out.updatedInput.old_string, `PASSWORD=${SECRET_A}\nDEBUG=1`);
    assert.equal(out.updatedInput.new_string, `PASSWORD=${SECRET_A}\nDEBUG=0`);
    assert.match(out.context, /placeholders were resolved/);
    assert.doesNotMatch(out.context, /invisible\/control/);
  });

  it("rehydrates a deletion of the secret line (no placeholder in new_string)", async () => {
    const out = await edit(`PASSWORD=${PH}\n`, "");
    assert.equal(out.updatedInput.old_string, `PASSWORD=${SECRET_A}\n`);
    assert.equal(out.updatedInput.new_string, "");
  });

  it("denies an old_string that matches nowhere in the view", async () => {
    const out = await edit(`PASSWORD=${PH}x`, "y");
    assert.match(out.deny, /does not match the sanitized\s+view/);
  });

  it("denies an ambiguous old_string without replace_all", async () => {
    const src = `A_PASSWORD=${SECRET_A}\nB_PASSWORD=${SECRET_B}\n`;
    const vw = mkView(src, [
      { value: SECRET_A, placeholder: PH },
      { value: SECRET_B, placeholder: PH },
    ]);
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: `PASSWORD=${PH}`, new_string: "x" },
      fakeIo(src, vw, reRedact),
    );
    assert.match(out.deny, /matches 2 locations/);
    assert.match(out.deny, /the view can differ from disk at each \(redacted/);
    assert.match(out.deny, /add surrounding context to make it unique/);
  });

  it("denies replace_all over spans hiding differing secrets", async () => {
    const src = `PASSWORD=${SECRET_A}\nPASSWORD=${SECRET_B}\n`;
    const vw = mkView(src, [
      { value: SECRET_A, placeholder: PH },
      { value: SECRET_B, placeholder: PH },
    ]);
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `PASSWORD=${PH}`,
        new_string: `PASS=${PH}`,
        replace_all: true,
      },
      fakeIo(src, vw, reRedact),
    );
    assert.match(out.deny, /on-disk bytes differ/);
    assert.match(out.deny, /edit each occurrence separately/);
    assert.match(out.deny, /with unique context/);
  });

  it("applies replace_all when every span hides the same secret", async () => {
    const src = `PASSWORD=${SECRET_A}\nPASSWORD=${SECRET_A}\n`;
    const vw = mkView(src, [{ value: SECRET_A, placeholder: PH }]);
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `PASSWORD=${PH}`,
        new_string: `PASSWD=${PH}`,
        replace_all: true,
      },
      fakeIo(src, vw, reRedact),
    );
    assert.equal(out.updatedInput.old_string, `PASSWORD=${SECRET_A}`);
    assert.equal(out.updatedInput.new_string, `PASSWD=${SECRET_A}`);
    assert.equal(out.updatedInput.replace_all, true);
  });

  it("denies an old_string cut mid-placeholder", async () => {
    const out = await edit(`PASSWORD=${PH.slice(0, 9)}`, "x");
    assert.match(out.deny, /include each placeholder whole/);
  });

  it("skips the exposure simulation when the disk old_string is not unique", async () => {
    const src = `K=${SECRET_A}\nK=${SECRET_A}\n`;
    const vw = {
      text: `K=${PH}\nK=${SECRET_A}\n`,
      pairs: [{ placeholder: PH, original: SECRET_A, start: 2 }],
    };
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: `K=${PH}`, new_string: "K=x" },
      fakeIo(src, vw, () => {
        throw new Error("exposure check must not run");
      }),
    );
    assert.equal(out.updatedInput.old_string, `K=${SECRET_A}`);
  });
});

// ─── Edit re-anchoring across stripped invisible/ANSI bytes ──────────────────

describe("rehydrate: stripped-character re-anchoring", () => {
  it("re-anchors a hint-free edit across an interior zero-width char", async () => {
    const content = `add(a, b)${ZW};\nDEBUG=1\n`;
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: "add(a, b);\nDEBUG=1",
        new_string: "add(a, b, c);\nDEBUG=1",
      },
      liveIo(content),
    );
    assert.equal(out.updatedInput.old_string, `add(a, b)${ZW};\nDEBUG=1`);
    assert.equal(out.updatedInput.new_string, "add(a, b, c);\nDEBUG=1");
    assert.match(out.context, /invisible\/control\s+character/);
    assert.doesNotMatch(out.context, /placeholders were resolved/);
  });

  it("re-anchors across stripped ANSI sequences, preserving boundary runs", async () => {
    const content = `${GREEN}green${RESET} text\n`;
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: "green text", new_string: "blue text" },
      liveIo(content),
    );
    assert.equal(out.updatedInput.old_string, `green${RESET} text`);
  });

  it("preserves a boundary run while replacing an interior one", async () => {
    const content = `${ZW}AAA${ZW}BBB\n`;
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: "AAABBB", new_string: "CCC" },
      liveIo(content),
    );
    assert.equal(out.updatedInput.old_string, `AAA${ZW}BBB`);
  });

  it("handles a file with both a secret and stripped characters", async () => {
    const content = `PASSWORD=${SECRET_A}${ZW}\nDEBUG=1\n`;
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `PASSWORD=${PH}\nDEBUG=1`,
        new_string: `PASSWORD=${PH}\nDEBUG=0`,
      },
      liveIo(content, [{ value: SECRET_A, placeholder: PH }], reRedact),
    );
    assert.equal(
      out.updatedInput.old_string,
      `PASSWORD=${SECRET_A}${ZW}\nDEBUG=1`,
    );
    assert.equal(out.updatedInput.new_string, `PASSWORD=${SECRET_A}\nDEBUG=0`);
    assert.equal(
      out.context,
      `Edit input was translated to the file's actual on-disk bytes: ` +
        `${PH.slice(0, 9)}…] placeholders were resolved to the file's real secret ` +
        `values (still hidden from you); the matched region carries 1 ` +
        `invisible/control character(s) stripped from your view; they are ` +
        `replaced along with it.`,
    );
  });

  it("fails closed (null, no throw) on an empty old_string against a divergent-view file", async () => {
    // A stripped ANSI run makes the Layer-1 view diverge from disk, so this
    // Edit reaches rehydrateEdit. An empty old_string would otherwise hit
    // occurrences(view.text, "") — which used to loop until a RangeError.
    // Edit's own create/anchor handling owns the empty case, so pass through.
    const content = `${GREEN}green${RESET} text\n`;
    let out;
    await assert.doesNotReject(async () => {
      out = await rehydrateRedacted(
        "Edit",
        { file_path: "/f", old_string: "", new_string: "inserted" },
        liveIo(content),
      );
    });
    assert.equal(out, null);
  });

  it("returns null (not a misleading deny) for an empty old_string whose new_string carries a placeholder", async () => {
    // Without the empty-old_string guard, occurrences("") returns [] and the
    // call falls into the literal/empty-span resolver, which — because
    // new_string names a redacted secret outside the (empty) span — emits the
    // "extend old_string to cover that secret" deny. That guidance is nonsense
    // for an empty old_string (Edit's create case), so the guard must short
    // out to null first. This case fails (deny, not null) if the guard is
    // removed, so it pins the guard's behavior, not just the no-throw fix.
    const content = `${GREEN}green${RESET}\nPASSWORD=${SECRET_A}\n`;
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: "", new_string: `X=${PH}` },
      liveIo(content, [{ value: SECRET_A, placeholder: PH }], reRedact),
    );
    assert.equal(out, null);
  });

  it("fails closed (null) on an empty old_string against a zero-width-divergent file", async () => {
    // Second divergence flavor (stripped invisible char) to prove the guard is
    // not specific to ANSI.
    const content = `note${ZW}here\n`;
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: "", new_string: "x" },
      liveIo(content),
    );
    assert.equal(out, null);
  });

  it("passes through a hint-free stale old_string on a divergent file", async () => {
    const content = `${ZW}note\n`;
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: "missing", new_string: "x" },
      liveIo(content),
    );
    assert.equal(out, null);
  });

  it("passes through a raw-byte match the view does not contain", async () => {
    const content = `${ZW}note\nPASSWORD=${SECRET_A}\n`;
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `PASSWORD=${SECRET_A}`,
        new_string: "PASSWORD=rotated",
      },
      liveIo(content, [{ value: SECRET_A, placeholder: PH }], reRedact),
    );
    assert.equal(out, null);
  });

  it("denies a raw-byte match whose new_string references a redacted secret", async () => {
    const content = `${ZW}note\nPASSWORD=${SECRET_A}\n`;
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `PASSWORD=${SECRET_A}`,
        new_string: `PASSWORD_COPY=${PH}`,
      },
      liveIo(content, [{ value: SECRET_A, placeholder: PH }], reRedact),
    );
    assert.match(out.deny, /outside the matched old_string/);
  });

  it("denies when greedy alignment cannot re-anchor unambiguously", async () => {
    const content = `m${GREEN}mm\n`;
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: "mmm", new_string: "nnn" },
      liveIo(content),
    );
    assert.match(out.deny, /cannot be\s+re-anchored unambiguously/);
    assert.match(out.deny, /edit a smaller region away/);
    assert.match(out.deny, /ask the user to make this change/);
  });

  it("denies a purely-invisible alignment collision the re-clean check misses", async () => {
    // A complete, real "[32m" SGR sequence is fully stripped (its raw bytes
    // still contain the literal "[32m" substring), while a second, ZW-spliced
    // "[3<ZW>2m" as plain text re-cleans to the sole view occurrence of
    // "[32m" — the disk collision is invisible to the re-clean check (a).
    const content = `${ESC}[32mX [3${ZW}2m\n`;
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: "[32m", new_string: "[32m\nEXTRA=1" },
      liveIo(content),
    );
    assert.match(out.deny, /cannot be\s+re-anchored unambiguously/);
  });
});

// ─── new_string placeholder resolution ───────────────────────────────────────

describe("rehydrate: new_string resolution", () => {
  const content = `PASSWORD=${SECRET_A}\nAPI_KEY=${SECRET_B}\nEND\n`;
  const view = mkView(content, [
    { value: SECRET_A, placeholder: PH },
    { value: SECRET_B, placeholder: PH },
  ]);
  const edit = (old_string, new_string) =>
    rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string, new_string },
      fakeIo(content, view, reRedact),
    );

  it("maps same-text placeholders 1:1 by position when the sequence is preserved", async () => {
    const out = await edit(
      `PASSWORD=${PH}\nAPI_KEY=${PH}\nEND`,
      `PASSWORD=${PH}\nEXTRA=1\nAPI_KEY=${PH}\nEND`,
    );
    assert.equal(
      out.updatedInput.new_string,
      `PASSWORD=${SECRET_A}\nEXTRA=1\nAPI_KEY=${SECRET_B}\nEND`,
    );
  });

  it("denies when same-text placeholders change count and hide distinct secrets", async () => {
    const out = await edit(
      `PASSWORD=${PH}\nAPI_KEY=${PH}\nEND`,
      `MERGED=${PH}\nEND`,
    );
    assert.match(out.deny, /changes their count or order/);
    assert.match(
      out.deny,
      /multiple distinct secrets in the matched text share the placeholder/,
    );
    assert.match(
      out.deny,
      /edit them one at a time with unique surrounding context/,
    );
  });

  it("resolves a duplicated placeholder per-text when it names one secret", async () => {
    const src = `PASSWORD=${SECRET_A}\nEND\n`;
    const vw = mkView(src, [{ value: SECRET_A, placeholder: PH }]);
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `PASSWORD=${PH}\nEND`,
        new_string: `PASSWORD=${PH}\nPASSWORD_COPY=${PH}\nEND`,
      },
      fakeIo(src, vw, reRedact),
    );
    assert.equal(
      out.updatedInput.new_string,
      `PASSWORD=${SECRET_A}\nPASSWORD_COPY=${SECRET_A}\nEND`,
    );
  });

  it("denies a placeholder text only produced outside the span", async () => {
    const src = `PASSWORD=${SECRET_A}\ncert: x\nKEY ${SECRET_B} END\n`;
    const vw = mkView(src, [
      { value: SECRET_A, placeholder: PH },
      { value: SECRET_B, placeholder: PH_PEM },
    ]);
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `PASSWORD=${PH}\ncert: x`,
        new_string: `PASSWORD=${PH}\ncert: ${PH_PEM}`,
      },
      fakeIo(src, vw, reRedact),
    );
    assert.match(out.deny, /outside\s+the matched old_string/);
  });

  it("leaves literal placeholder text alone when the model matched it verbatim", async () => {
    const src = `note ${PH_PEM} here\nPASSWORD=${SECRET_A}\nKEY ${SECRET_B} END\n`;
    const vw = mkView(src, [
      { value: SECRET_A, placeholder: PH },
      { value: SECRET_B, placeholder: PH_PEM },
    ]);
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `note ${PH_PEM} here\nPASSWORD=${PH}`,
        new_string: `note ${PH_PEM} kept\nPASSWORD=${PH}`,
      },
      fakeIo(src, vw, reRedact),
    );
    assert.equal(
      out.updatedInput.new_string,
      `note ${PH_PEM} kept\nPASSWORD=${SECRET_A}`,
    );
  });

  it("denies when the span mixes literal and redacted occurrences of one placeholder", async () => {
    const src = `say ${PH}\nPASSWORD=${SECRET_A}\n`;
    const vw = mkView(src, [{ value: SECRET_A, placeholder: PH }]);
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `say ${PH}\nPASSWORD=${PH}`,
        new_string: `say ${PH}\nPASSWORD=${PH}x`,
      },
      fakeIo(src, vw, reRedact),
    );
    assert.match(out.deny, /mixes literal/);
    assert.match(
      out.deny,
      /cannot tell which occurrences in new_string are which/,
    );
    assert.match(
      out.deny,
      /edit the literal text and the secret's line separately/,
    );
  });
});

// ─── Exposure check ──────────────────────────────────────────────────────────

describe("rehydrate: exposure check", () => {
  const content = `PASSWORD=${SECRET_A}\n`;
  const view = mkView(content, [{ value: SECRET_A, placeholder: PH }]);

  it("denies an edit that re-labels the secret out of redaction", async () => {
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `PASSWORD=${PH}`,
        new_string: `nextPageToken=${PH}`,
      },
      fakeIo(content, view, (text) => text),
    );
    assert.match(out.deny, /would reveal them/);
    assert.match(out.deny, /this change would move 1 secret value/);
    assert.match(
      out.deny,
      /keep each secret under its recognizable field name/,
    );
  });

  it("denies when the re-scan finds nothing at all (redact returns null)", async () => {
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `PASSWORD=${PH}`,
        new_string: `note ${PH}`,
      },
      fakeIo(content, view, () => null),
    );
    assert.match(out.deny, /would reveal them/);
  });

  it("does not deny a secret the prior view already exposed", async () => {
    const src = `PASSWORD=${SECRET_A}\nweird ${SECRET_A}\n`;
    const vw = {
      text: `PASSWORD=${PH}\nweird ${SECRET_A}\n`,
      pairs: [{ placeholder: PH, original: SECRET_A, start: 9 }],
    };
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: `PASSWORD=${PH}`, new_string: `pw ${PH}` },
      fakeIo(src, vw, () => {
        throw new Error("exposure re-scan must not run with no new secret");
      }),
    );
    assert.equal(out.updatedInput.new_string, `pw ${SECRET_A}`);
  });

  it("runs the exposure check on a replace_all edit and denies a leak", async () => {
    const src = `PASSWORD=${SECRET_A}\nPASSWORD=${SECRET_A}\n`;
    const vw = mkView(src, [{ value: SECRET_A, placeholder: PH }]);
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `PASSWORD=${PH}`,
        new_string: `nextPageToken=${PH}`,
        replace_all: true,
      },
      fakeIo(src, vw, (text) => text),
    );
    assert.match(out.deny, /would reveal them/);
  });
});

// ─── Write resolution ────────────────────────────────────────────────────────

describe("rehydrate: Write", () => {
  const content = `# config\nPASSWORD=${SECRET_A}\nDEBUG=1\n`;
  const view = mkView(content, [{ value: SECRET_A, placeholder: PH }]);
  const write = (newContent, io = fakeIo(content, view, reRedact)) =>
    rehydrateRedacted("Write", { file_path: "/f", content: newContent }, io);

  it("rehydrates a whole-file rewrite that keeps the secret", async () => {
    const out = await write(`# rewritten\nPASSWORD=${PH}\nDEBUG=0\n`);
    assert.equal(
      out.updatedInput.content,
      `# rewritten\nPASSWORD=${SECRET_A}\nDEBUG=0\n`,
    );
    assert.match(out.context, /resolved to the\s+file's real secret values/);
    assert.match(out.context, /are preserved in the written file/);
  });

  it("denies content whose placeholder does not match any of the file's (cross-file/stale placeholder)", async () => {
    // PH_PEM starts with the default hint ("[REDACTED") but this file's own
    // view only produced PH ("[REDACTED]") — PH_PEM names a secret from
    // elsewhere (or a stale/mistyped placeholder), not literal prose. Writing
    // it verbatim would silently persist "[REDACTED: Private Key]" into a file
    // where the model likely intended a real secret value.
    const out = await write(`docs about ${PH_PEM} markers\n`);
    assert.match(
      out.deny,
      /\[REDACTED…\] placeholder in the new content does not match any secret/,
    );
    assert.match(
      out.deny,
      /cannot copy a placeholder from another file or context/,
    );
    assert.equal(out.updatedInput, undefined);
  });

  it("denies when distinct secrets share one placeholder text", async () => {
    const src = `PASSWORD=${SECRET_A}\nAPI_KEY=${SECRET_B}\n`;
    const vw = mkView(src, [
      { value: SECRET_A, placeholder: PH },
      { value: SECRET_B, placeholder: PH },
    ]);
    const out = await write(`PASSWORD=${PH}\n`, fakeIo(src, vw, reRedact));
    assert.match(out.deny, /use Edit with unique\s+surrounding context/);
    assert.match(
      out.deny,
      /multiple distinct secrets in .* share the placeholder/,
    );
  });

  it("denies when the file mixes literal and redacted occurrences", async () => {
    const src = `say ${PH}\nPASSWORD=${SECRET_A}\n`;
    const vw = mkView(src, [{ value: SECRET_A, placeholder: PH }]);
    const out = await write(`PASSWORD=${PH}\n`, fakeIo(src, vw, reRedact));
    assert.match(out.deny, /mixes literal/);
  });

  it("filters the produced count to the placeholder when a second secret shares the file", async () => {
    const src = `say ${PH}\nPASSWORD=${SECRET_A}\ncert ${SECRET_B}\n`;
    const vw = mkView(src, [
      { value: SECRET_A, placeholder: PH },
      { value: SECRET_B, placeholder: PH_PEM },
    ]);
    const out = await write(
      `say ${PH}\nPASSWORD=${PH}\ncert ${PH_PEM}\n`,
      fakeIo(src, vw, reRedact),
    );
    assert.match(out.deny, /mixes literal/);
    assert.match(
      out.deny,
      /cannot tell which occurrences in the new content are/,
    );
    assert.match(out.deny, /use Edit with unique surrounding context instead/);
  });

  it("denies a rewrite that would expose the secret", async () => {
    const out = await write(
      `note ${PH}\n`,
      fakeIo(content, view, () => null),
    );
    assert.match(out.deny, /would reveal them/);
  });

  it("uses a custom hint in the Write success context", async () => {
    // hint only affects the context string here; "<SECRET" must appear.
    const src = `PASSWORD=${SECRET_A}\n`;
    const vw = mkView(src, [{ value: SECRET_A, placeholder: PH }]);
    const out = await rehydrateRedacted(
      "Write",
      { file_path: "/f", content: `PASSWORD=${PH}\n` },
      fakeIo(src, vw, reRedact),
      { hint: "[REDACTED" },
    );
    assert.match(out.context, /\[REDACTED…\] placeholders/);
  });
});

// ─── Hidden-span safety: no edit may read/split bytes inside a redacted span ──
//
// Core invariant (R1/R2/R5): for a file holding a redacted secret, no Edit or
// Write — hinted or not, replace_all or not, self-overlapping or not — may
// read, split, or mutate a byte INSIDE the secret's on-disk span unless the
// model supplied the whole secret itself. Every such attempt must DENY, never
// pass through to a raw disk edit (a char-by-char extraction oracle) or rewrite
// that splices hidden bytes.

describe("rehydrate: hidden-span safety", () => {
  // SECRET_A === "hunter2hunter2hunter2xA": "hunter" appears 3× inside it and
  // "2xA" appears only there — perfect probes for bytes the view hides as PH.
  const FRAGMENT_ONLY_IN_SECRET = "2xA";
  const FRAGMENT_VISIBLE_AND_IN_SECRET = "hunter";

  it("R1: denies a hint-free Edit whose old_string matches ONLY inside a redacted secret", async () => {
    const content = `PASSWORD=${SECRET_A}\nDEBUG=1\n`;
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: FRAGMENT_ONLY_IN_SECRET,
        new_string: `${FRAGMENT_ONLY_IN_SECRET}\nEXTRA=1`,
      },
      liveIo(content, [{ value: SECRET_A, placeholder: PH }], reRedact),
    );
    assert.match(out.deny, /inside a \[REDACTED…\] redacted secret/);
    assert.match(out.deny, /hidden from your view/);
    assert.equal(out.updatedInput, undefined);
  });

  it("R1: the deny reports the disk byte range of both the match and the secret", async () => {
    // The refusal is conservative, so the caller needs the two ranges to tell a
    // real overlap from a redaction whose recorded span is too wide.
    const content = `PASSWORD=${SECRET_A}\nDEBUG=1\n`;
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: FRAGMENT_ONLY_IN_SECRET,
        new_string: "Z",
      },
      liveIo(content, [{ value: SECRET_A, placeholder: PH }], reRedact),
    );
    const matchStart = content.indexOf(FRAGMENT_ONLY_IN_SECRET);
    const secretStart = content.indexOf(SECRET_A);
    assert.match(
      out.deny,
      new RegExp(
        `matches bytes ${matchStart}-${matchStart + FRAGMENT_ONLY_IN_SECRET.length},`,
      ),
    );
    assert.match(
      out.deny,
      new RegExp(`at bytes ${secretStart}-${secretStart + SECRET_A.length} `),
    );
  });

  it("R1: denies a hint-free replace_all fragment that would splice inside the secret", async () => {
    // "2xA" is hint-free, invisible in the view, but on disk sits inside the
    // secret. replace_all would splice it there; deny (viewOcc===0 branch).
    const content = `PASSWORD=${SECRET_A}\n`;
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: FRAGMENT_ONLY_IN_SECRET,
        new_string: "Z",
        replace_all: true,
      },
      liveIo(content, [{ value: SECRET_A, placeholder: PH }], reRedact),
    );
    assert.match(out.deny, /hidden from your view/);
  });

  it("R1: does NOT deny a hint-free Edit whose old_string wholly contains the secret (rotation)", async () => {
    // The model supplied the secret's own bytes (e.g. a rotation): it extracts
    // nothing, so this is left to pass through (null), not falsely denied.
    const content = `PASSWORD=${SECRET_A}\n`;
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `PASSWORD=${SECRET_A}`,
        new_string: "PASSWORD=rotated",
      },
      liveIo(content, [{ value: SECRET_A, placeholder: PH }], reRedact),
    );
    assert.equal(out, null);
  });

  it("R2: denies a replace_all whose resolved bytes occur more often on disk than in the view", async () => {
    const content = `note ${FRAGMENT_VISIBLE_AND_IN_SECRET} x\nPASSWORD=${SECRET_A}\n`;
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: FRAGMENT_VISIBLE_AND_IN_SECRET,
        new_string: "HUNTER",
        replace_all: true,
      },
      liveIo(content, [{ value: SECRET_A, placeholder: PH }], reRedact),
    );
    assert.match(out.deny, /replace_all would rewrite \d+ on-disk occurrence/);
    assert.match(out.deny, /hidden inside redacted secrets or stripped/);
    assert.equal(out.updatedInput, undefined);
  });

  it("R2: allows a replace_all when every disk occurrence is visible in the view", async () => {
    // "PASSWORD=[REDACTED]" resolves to the same disk bytes at both spots and
    // the resolved bytes occur exactly twice on disk — no hidden occurrence.
    const src = `PASSWORD=${SECRET_A}\nPASSWORD=${SECRET_A}\n`;
    const vw = mkView(src, [{ value: SECRET_A, placeholder: PH }]);
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `PASSWORD=${PH}`,
        new_string: `PASSWD=${PH}`,
        replace_all: true,
      },
      fakeIo(src, vw, reRedact),
    );
    assert.equal(out.updatedInput.old_string, `PASSWORD=${SECRET_A}`);
  });

  it("R5: denies a self-overlapping hint-free old_string the >1 gate would miss", async () => {
    // A trailing ZW makes the view diverge from disk so the edit reaches the
    // resolver; "aa" in "aaa" is one non-overlapping match but two overlapping
    // anchors — ambiguous, so deny.
    const content = `aaa${ZW}\n`;
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: "aa", new_string: "bb" },
      liveIo(content),
    );
    assert.match(out.deny, /matches 2 locations/);
    assert.match(out.deny, /add surrounding context to make it unique/);
  });

  it("R4: denies a hinted Write to a MISSING file instead of persisting the placeholder literally", async () => {
    const enoentIo = {
      readFile: () => {
        throw fsError("ENOENT");
      },
      redactMap: () => {
        throw new Error("redactMap must not be reached");
      },
      redact: () => null,
    };
    const out = await rehydrateRedacted(
      "Write",
      { file_path: "/new", content: `secret: ${PH}\n` },
      enoentIo,
    );
    assert.match(out.deny, /\/new does not exist/);
    assert.match(
      out.deny,
      /cannot copy a placeholder from another file or context/,
    );
    assert.equal(out.updatedInput, undefined);
  });

  it("R4: still passes an Edit through on a missing file (Edit fails on its own)", async () => {
    const enoentIo = {
      readFile: () => {
        throw fsError("ENOENT");
      },
      redactMap: () => {
        throw new Error("redactMap must not be reached");
      },
      redact: () => null,
    };
    assert.equal(
      await rehydrateRedacted(
        "Edit",
        { file_path: "/missing", old_string: `x ${PH}`, new_string: "y" },
        enoentIo,
      ),
      null,
    );
  });
});

// ─── Write: cross-file / re-substitution safety (R3, R6) ─────────────────────

describe("rehydrate: Write cross-file and re-substitution safety", () => {
  it("R3: denies a Write that mixes a valid same-file placeholder with a FOREIGN one", async () => {
    // The file's own secret is under PH; PH_PEM shares the hint prefix but names
    // no secret here (pasted from another file). The valid PH is substituted,
    // but PH_PEM would survive verbatim — deny rather than persist it.
    const src = `PASSWORD=${SECRET_A}\n`;
    const vw = mkView(src, [{ value: SECRET_A, placeholder: PH }]);
    const out = await rehydrateRedacted(
      "Write",
      { file_path: "/f", content: `PASSWORD=${PH}\nKEY=${PH_PEM}\n` },
      fakeIo(src, vw, reRedact),
    );
    assert.match(out.deny, /still carries a \[REDACTED…\] placeholder/);
    assert.match(
      out.deny,
      /cannot copy a placeholder from another file or context/,
    );
    assert.equal(out.updatedInput, undefined);
  });

  it("R3: allows a Write whose only leftover hint-prefixed text is genuine prose the file already had", async () => {
    // The file documents "[REDACTEDXYZ]" as prose — it shares the hint prefix
    // "[REDACTED" but is NOT any placeholder (no "]" right after "REDACTED"), so
    // it is not a redaction pair and does not collide with PH. Substituting the
    // real secret leaves that prose token; R3 must count it as a pre-existing
    // literal and NOT raise a cross-file deny.
    const prose = "[REDACTEDXYZ]";
    const src = `see ${prose} docs\nPW=${SECRET_A}\n`;
    const vw = {
      text: `see ${prose} docs\nPW=${PH}\n`,
      pairs: [
        {
          placeholder: PH,
          original: SECRET_A,
          start: `see ${prose} docs\nPW=`.length,
        },
      ],
    };
    const out = await rehydrateRedacted(
      "Write",
      { file_path: "/f", content: `see ${prose} docs\nPW=${PH}\n` },
      fakeIo(src, vw, reRedact),
    );
    assert.equal(
      out.updatedInput.content,
      `see ${prose} docs\nPW=${SECRET_A}\n`,
    );
  });

  it("P2: denies a foreign-placeholder Write onto a PRISTINE (secret-free) target", async () => {
    // The target holds no secrets, so its view is byte-identical to disk
    // (view.pairs empty, cleaned === content) and the early "view identical to
    // disk" return would fire. A Write whose content carries a foreign
    // [REDACTED…] placeholder must NOT sail through that fast path — it is
    // denied exactly like a Write onto a secret-bearing or absent target,
    // rather than persisting the placeholder verbatim over pristine bytes.
    const src = "plain config, no secrets here\n";
    const vw = mkView(src, []); // no pairs
    const out = await rehydrateRedacted(
      "Write",
      { file_path: "/f", content: `KEY=${PH_PEM}\n` },
      fakeIo(src, vw),
    );
    assert.match(out.deny, /does not match any secret/);
    assert.match(
      out.deny,
      /cannot copy a placeholder from another file or context/,
    );
    assert.equal(out.updatedInput, undefined);
  });

  it("P3: denies a count-offsetting foreign-placeholder Write (drop one literal hint, add one foreign)", async () => {
    // The file documents literal "[REDACTEDXYZ]" prose (one hint occurrence that
    // is NOT a placeholder) and holds a real secret under PH. A Write that DROPS
    // the prose and ADDS a foreign PH_PEM leaves the raw hint COUNT unchanged, so
    // the old scalar `>` gate passed it — persisting the foreign placeholder.
    // Comparing the actual placeholder STRINGS must still deny it.
    const prose = "[REDACTEDXYZ]";
    const src = `see ${prose} docs\nPW=${SECRET_A}\n`;
    const vw = {
      text: `see ${prose} docs\nPW=${PH}\n`,
      pairs: [
        {
          placeholder: PH,
          original: SECRET_A,
          start: `see ${prose} docs\nPW=`.length,
        },
      ],
    };
    const out = await rehydrateRedacted(
      "Write",
      // prose dropped, foreign PH_PEM added, valid PH kept
      { file_path: "/f", content: `PW=${PH}\nKEY=${PH_PEM}\n` },
      fakeIo(src, vw, reRedact),
    );
    assert.match(out.deny, /still carries a \[REDACTED…\] placeholder/);
    assert.equal(out.updatedInput, undefined);
  });

  it("P3: denies a Write carrying an UNCLOSED foreign hint (no trailing ']')", async () => {
    // A valid same-file PH is substituted (so the foreign scan runs), but the
    // content also pastes a hint-prefixed token with NO closing bracket. The
    // token extends to end-of-string; absent from the file's own view, it is a
    // foreign placeholder and must be denied (fail closed on the malformed run).
    const src = `PASSWORD=${SECRET_A}\n`;
    const vw = mkView(src, [{ value: SECRET_A, placeholder: PH }]);
    const out = await rehydrateRedacted(
      "Write",
      {
        file_path: "/f",
        content: `PASSWORD=${PH}\nnote ${DEFAULT_HINT}-oops\n`,
      },
      fakeIo(src, vw, reRedact),
    );
    assert.match(out.deny, /still carries a \[REDACTED…\] placeholder/);
    assert.equal(out.updatedInput, undefined);
  });

  it("R6: a Write substitutes in one pass, never re-touching an inserted secret's bytes", async () => {
    // SECRET_A's bytes literally contain PH_PEM's placeholder text. A chained
    // split(PH).join(secret) then split(PH_PEM).join(secretB) would clobber the
    // PH_PEM substring inside the just-inserted secret; one pass must not.
    const SECRET_WITH_PH = `pre${PH_PEM}post`;
    const src = `A=${SECRET_WITH_PH}\nB=${SECRET_C}\n`;
    const vw = {
      text: `A=${PH}\nB=${PH_PEM}\n`,
      pairs: [
        { placeholder: PH, original: SECRET_WITH_PH, start: 2 },
        {
          placeholder: PH_PEM,
          original: SECRET_C,
          start: `A=${PH}\nB=`.length,
        },
      ],
    };
    const reRedactMix = (text) =>
      text.split(SECRET_WITH_PH).join(PH).split(SECRET_C).join(PH_PEM);
    const out = await rehydrateRedacted(
      "Write",
      { file_path: "/f", content: `A=${PH}\nB=${PH_PEM}\n` },
      fakeIo(src, vw, reRedactMix),
    );
    assert.equal(
      out.updatedInput.content,
      `A=${SECRET_WITH_PH}\nB=${SECRET_C}\n`,
    );
    // The PH_PEM text survives verbatim inside the inserted secret (not clobbered).
    assert.ok(out.updatedInput.content.includes(SECRET_WITH_PH));
  });
});

// ─── Placeholder-boundary and multi-secret resolution edge cases ─────────────

describe("view-map: occurrences", () => {
  it("steps by needle length, not 1 — no overlapping matches", () => {
    assert.deepEqual(occurrences("aaaa", "aa"), [0, 2]);
    assert.deepEqual(occurrences("ababab", "ab"), [0, 2, 4]);
    assert.deepEqual(occurrences("xyz", "q"), []);
  });
});

describe("rehydrate: placeholder-boundary resolution", () => {
  it("rehydrates an old_string that begins exactly at a placeholder", async () => {
    const src = `${SECRET_A}\nDEBUG=1\n`;
    const vw = mkView(src, [{ value: SECRET_A, placeholder: PH }]);
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `${PH}\nDEBUG=1`,
        new_string: `${PH}\nDEBUG=0`,
      },
      fakeIo(src, vw, reRedact),
    );
    assert.equal(out.updatedInput.old_string, `${SECRET_A}\nDEBUG=1`);
    assert.equal(out.updatedInput.new_string, `${SECRET_A}\nDEBUG=0`);
  });

  it("denies an old_string that begins inside a placeholder", async () => {
    const src = `${SECRET_A} mid ${SECRET_B}\n`;
    const vw = mkView(src, [
      { value: SECRET_A, placeholder: PH },
      { value: SECRET_B, placeholder: PH },
    ]);
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `${PH.slice(3)} mid ${PH}`,
        new_string: "x",
      },
      fakeIo(src, vw, reRedact),
    );
    assert.match(out.deny, /include each placeholder whole/);
  });

  it("counts only interior stripped characters when the span starts after offset 0", async () => {
    const content = `KEEP ${ZW}AB${ZW}CD\n`;
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: "ABCD", new_string: "WXYZ" },
      liveIo(content),
    );
    assert.equal(out.updatedInput.old_string, `AB${ZW}CD`);
    assert.match(out.context, /carries 1 invisible/);
  });
});

describe("rehydrate: interleaved distinct placeholders", () => {
  const reRedact3 = (text) =>
    text
      .split(SECRET_A)
      .join(PH)
      .split(SECRET_C)
      .join(PH)
      .split(SECRET_B)
      .join(PH_PEM);

  it("resolves an interleaved PH / PH_PEM / PH sequence in position order", async () => {
    const src = `A=${SECRET_A}\nB=${SECRET_B}\nC=${SECRET_C}\n`;
    const vw = mkView(src, [
      { value: SECRET_A, placeholder: PH },
      { value: SECRET_B, placeholder: PH_PEM },
      { value: SECRET_C, placeholder: PH },
    ]);
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `A=${PH}\nB=${PH_PEM}\nC=${PH}`,
        new_string: `A=${PH}\nB=${PH_PEM}\nC=${PH}`,
      },
      fakeIo(src, vw, reRedact3),
    );
    assert.equal(
      out.updatedInput.new_string,
      `A=${SECRET_A}\nB=${SECRET_B}\nC=${SECRET_C}`,
    );
  });

  it("collects only the placeholder's own secret when a second distinct one shares the span", async () => {
    const src = `X=${SECRET_A}\nY=${SECRET_B}\n`;
    const vw = mkView(src, [
      { value: SECRET_A, placeholder: PH },
      { value: SECRET_B, placeholder: PH_PEM },
    ]);
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `X=${PH}\nY=${PH_PEM}`,
        new_string: `X=${PH}\nZ=${PH}`,
      },
      fakeIo(src, vw, reRedact),
    );
    assert.equal(out.updatedInput.new_string, `X=${SECRET_A}\nZ=${SECRET_A}`);
  });

  it("denies a literal/redacted placeholder mix even when the span holds another secret", async () => {
    const src = `say ${PH}\nPASSWORD=${SECRET_A}\ncert ${SECRET_B}\n`;
    const vw = mkView(src, [
      { value: SECRET_A, placeholder: PH },
      { value: SECRET_B, placeholder: PH_PEM },
    ]);
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `say ${PH}\nPASSWORD=${PH}\ncert ${PH_PEM}`,
        new_string: `say ${PH}\nPASSWORD=${PH}x\ncert ${PH_PEM}`,
      },
      fakeIo(src, vw, reRedact),
    );
    assert.match(out.deny, /mixes literal/);
  });
});

// ─── alignDeletions (pure engine) ────────────────────────────────────────────

describe("view-map: alignDeletions", () => {
  it("locates interior and trailing deleted runs", () => {
    assert.deepEqual(alignDeletions(`a${ZW}b`, "ab"), [
      { start: 1, deleted: ZW },
    ]);
    assert.deepEqual(alignDeletions(`ab${ZW}${ZW}`, "ab"), [
      { start: 2, deleted: `${ZW}${ZW}` },
    ]);
    assert.deepEqual(alignDeletions("ab", "ab"), []);
  });

  it("throws when the cleaned text is not a subsequence (fail closed)", () => {
    assert.throws(() => alignDeletions("abc", "xyz"), /not a subsequence/);
  });
});

// ─── Astral-char offset normalization (code-point → UTF-16) ──────────────────

// Like mkView, but emits CODE-POINT start offsets — exactly what the Python
// redactor's map mode produces (Python indexes strings by code point). The
// rehydrate layer must normalize these to UTF-16 before the offset machinery
// runs, or an astral char before a placeholder mis-anchors the edit.
function mkViewCodePoints(cleaned, secrets) {
  const hits = [];
  for (const { value, placeholder } of secrets)
    for (const index of occurrences(cleaned, value))
      hits.push({ index, value, placeholder });
  hits.sort((a, b) => a.index - b.index);
  let text = "";
  let last = 0;
  const pairs = [];
  for (const { index, value, placeholder } of hits) {
    text += cleaned.slice(last, index);
    pairs.push({
      placeholder,
      original: value,
      start: Array.from(text).length,
    });
    text += placeholder;
    last = index + value.length;
  }
  text += cleaned.slice(last);
  return { text, pairs };
}

describe("rehydrate: astral chars before a placeholder", () => {
  // An emoji (astral: 1 code point, 2 UTF-16 units) sits immediately before the
  // secret, so the redactor's code-point start for the placeholder is one less
  // than its UTF-16 offset. The old_string begins AT the placeholder, so its
  // span boundary lands exactly on that offset — the one case where the
  // code-point/UTF-16 divergence flips a comparison in mapViewOffset and, absent
  // the conversion, makes resolveSpan reject the edit as cutting a placeholder.
  const content = `KEY=🔑${SECRET_A}\nDEBUG=1\n`;
  const view = mkViewCodePoints(content, [
    { value: SECRET_A, placeholder: PH },
  ]);

  it("the fixture actually exercises the divergence (code-point start < UTF-16)", () => {
    // Guard against a vacuous test: if this fixture were BMP-only, the two
    // offsets would coincide and the conversion would be untested.
    const cp = view.pairs[0].start;
    const utf16 = view.text.indexOf(PH);
    assert.ok(
      utf16 > cp,
      "fixture must place an astral char before the placeholder",
    );
  });

  it("rehydrates an Edit whose old_string starts at the astral-shifted placeholder", async () => {
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `${PH}\nDEBUG=1`,
        new_string: `${PH}\nDEBUG=0`,
      },
      fakeIo(content, view, reRedact),
    );
    assert.equal(out.updatedInput.old_string, `${SECRET_A}\nDEBUG=1`);
    assert.equal(out.updatedInput.new_string, `${SECRET_A}\nDEBUG=0`);
  });
});

// ─── Lone-surrogate normalization matches the model's real view ──────────────

// output.mjs normalizes lone UTF-16 surrogates to U+FFFD right after Layer 1,
// BEFORE redaction runs — so that is what the model actually sees. rehydrate
// must re-derive that exact same text (Layer 1, then the same normalization)
// before matching old_string/handing text to the redactor, or the model's
// faithfully-copied old_string can never match and every edit near a lone
// surrogate is permanently, unfixably denied (re-reading the file reproduces
// the same mismatch every time).
describe("rehydrate: lone-surrogate normalization", () => {
  const LONE_HIGH = String.fromCharCode(0xd800); // unpaired high surrogate
  const FFFD = String.fromCharCode(0xfffd);

  it("rehydrates a hinted edit whose old_string copies the model's U+FFFD-normalized view across a lone surrogate", async () => {
    const content = `PASSWORD=${SECRET_A}${LONE_HIGH}\nDEBUG=1\n`;
    const io = liveIo(
      content,
      [{ value: SECRET_A, placeholder: PH }],
      reRedact,
    );
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `PASSWORD=${PH}${FFFD}\nDEBUG=1`,
        new_string: `PASSWORD=${PH}${FFFD}\nDEBUG=0`,
      },
      io,
    );
    // old_string is re-anchored to the real disk bytes (the raw surrogate).
    assert.equal(
      out.updatedInput.old_string,
      `PASSWORD=${SECRET_A}${LONE_HIGH}\nDEBUG=1`,
    );
    // new_string only has its PLACEHOLDER substituted; the model-authored
    // U+FFFD elsewhere in it is not a placeholder, so it is carried through
    // verbatim rather than reverted to the raw surrogate.
    assert.equal(
      out.updatedInput.new_string,
      `PASSWORD=${SECRET_A}${FFFD}\nDEBUG=0`,
    );
  });

  it("re-anchors a hint-free edit across a lone surrogate with nothing else divergent", async () => {
    // No secrets, no Layer-1-stripped bytes anywhere in the file — the ONLY
    // divergence between disk and the model's view is the surrogate
    // normalization. Before the fix this hit the "view identical to disk"
    // early exit and passed through, so the edit (built from the model's
    // actual U+FFFD view) would never match raw disk bytes.
    const content = `add(a, b)${LONE_HIGH};\nDEBUG=1\n`;
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `add(a, b)${FFFD};\nDEBUG=1`,
        new_string: `add(a, b, c)${FFFD};\nDEBUG=1`,
      },
      liveIo(content),
    );
    // old_string is re-anchored to the real disk bytes (the raw surrogate).
    assert.equal(
      out.updatedInput.old_string,
      `add(a, b)${LONE_HIGH};\nDEBUG=1`,
    );
    // new_string carries no placeholder here, so nothing is translated: it is
    // the model-authored text verbatim (still U+FFFD, not the raw surrogate).
    assert.equal(out.updatedInput.new_string, `add(a, b, c)${FFFD};\nDEBUG=1`);
  });

  it("does not spuriously deny as an ambiguous anchor when a lone surrogate sits inside the matched span", async () => {
    // Regression guard for the anchor-ambiguity re-clean check: comparing a
    // freshly re-cleaned disk span against a normalized view span must ALSO
    // normalize the re-clean, or every lone-surrogate-crossing edit would be
    // misdiagnosed as an unsound anchor and denied instead of rewritten.
    const content = `A${LONE_HIGH}B\n`;
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: `A${FFFD}B`, new_string: "X" },
      liveIo(content),
    );
    assert.equal(out.updatedInput.old_string, `A${LONE_HIGH}B`);
    assert.equal(out.updatedInput.new_string, "X");
  });
});

// ─── MultiEdit gating ────────────────────────────────────────────────────────

describe("rehydrate: MultiEdit gating", () => {
  const EDITS = [
    { old_string: "alpha", new_string: "beta" },
    { old_string: "gamma", new_string: "delta" },
  ];
  const HINTED_EDITS = [{ old_string: "alpha", new_string: `x=${PH}` }];

  it("passes through when the view equals disk and no edit carries a placeholder", async () => {
    const content = "alpha\ngamma\n";
    assert.equal(
      await rehydrateRedacted(
        "MultiEdit",
        { file_path: "/f", edits: EDITS },
        fakeIo(content, { text: content, pairs: [] }),
      ),
      null,
    );
  });

  it("ignores malformed inputs (missing, empty, or non-string edits)", async () => {
    const unreachable = {
      readFile: () => {
        throw new Error("must not read");
      },
      redactMap: () => {
        throw new Error("must not map");
      },
      redact: () => null,
    };
    for (const ti of [
      { file_path: "/f" },
      { file_path: "/f", edits: [] },
      { file_path: "/f", edits: [{ old_string: "a" }] },
      { file_path: "/f", edits: "nope" },
      { edits: EDITS },
    ])
      assert.equal(await rehydrateRedacted("MultiEdit", ti, unreachable), null);
  });

  it("denies when the file holds a redacted secret, hinted or not", async () => {
    const content = `alpha\nkey=${SECRET_A}\n`;
    const io = fakeIo(
      content,
      mkView(content, [{ value: SECRET_A, placeholder: PH }]),
      (text) => text.split(SECRET_A).join(PH),
    );
    for (const edits of [EDITS, HINTED_EDITS]) {
      const out = await rehydrateRedacted(
        "MultiEdit",
        { file_path: "/f", edits },
        io,
      );
      assert.match(out.deny, /differs from its on-disk bytes/);
      assert.match(out.deny, /single Edit calls/);
    }
  });

  it("denies when the view diverges only via stripped invisible characters", async () => {
    const content = `alpha${ZW}\ngamma\n`;
    const out = await rehydrateRedacted(
      "MultiEdit",
      { file_path: "/f", edits: EDITS },
      liveIo(content),
    );
    assert.match(out.deny, /differs from its on-disk bytes/);
  });

  it("denies when the map is unmappable, hinted or not", async () => {
    const content = `key=${SECRET_A}\n`;
    const io = fakeIo(content, { unmappable: "two keys collide" }, (text) =>
      text.split(SECRET_A).join(PH),
    );
    for (const edits of [EDITS, HINTED_EDITS]) {
      const out = await rehydrateRedacted(
        "MultiEdit",
        { file_path: "/f", edits },
        io,
      );
      // The single MultiEdit refusal is deliberately generic: it names the
      // resolution path, not the engine's internal reason.
      assert.match(out.deny, /single Edit calls/);
    }
  });

  it("denies placeholder text over a pristine file (foreign placeholder)", async () => {
    const content = "alpha\ngamma\n";
    const out = await rehydrateRedacted(
      "MultiEdit",
      { file_path: "/f", edits: HINTED_EDITS },
      fakeIo(content, { text: content, pairs: [] }),
    );
    assert.match(out.deny, /placeholder text/);
    assert.match(out.deny, /single Edit calls/);
  });

  it("passes literal [REDACTED prose the pristine file itself contains", async () => {
    // Precision over recall: this repo's own docs carry literal placeholder
    // text. A hint token already present verbatim in a secret-free file is
    // prose, not a placeholder — denying the edit would mangle documentation
    // work (old_string may carry it too: a non-matching old_string persists
    // nothing on its own).
    const content = `alpha\nsee ${PH} in docs\n`;
    assert.equal(
      await rehydrateRedacted(
        "MultiEdit",
        {
          file_path: "/f",
          edits: [
            { old_string: `see ${PH} in docs`, new_string: `see ${PH} above` },
          ],
        },
        fakeIo(content, { text: content, pairs: [] }),
      ),
      null,
    );
  });

  it("ENOENT: denies only the hinted CREATE form", async () => {
    const missingIo = {
      readFile: () => {
        throw fsError("ENOENT");
      },
      redactMap: () => {
        throw new Error("must not map");
      },
      redact: () => null,
    };
    // First edit's empty old_string is the create form: a placeholder in any
    // edit would be persisted verbatim as the new file's content.
    const denied = await rehydrateRedacted(
      "MultiEdit",
      {
        file_path: "/new",
        edits: [{ old_string: "", new_string: `key=${PH}\n` }],
      },
      missingIo,
    );
    assert.match(denied.deny, /does not exist/);
    // A non-create MultiEdit errors not-found in the real tool and persists
    // nothing, hinted or not; an unhinted create has no placeholder to write.
    for (const edits of [HINTED_EDITS, EDITS])
      assert.equal(
        await rehydrateRedacted(
          "MultiEdit",
          { file_path: "/new", edits },
          missingIo,
        ),
        null,
      );
  });

  it("EACCES: denies hinted, propagates unhinted", async () => {
    const brokenIo = {
      readFile: () => {
        throw fsError("EACCES");
      },
      redactMap: () => {
        throw new Error("must not map");
      },
      redact: () => null,
    };
    const denied = await rehydrateRedacted(
      "MultiEdit",
      { file_path: "/f", edits: HINTED_EDITS },
      brokenIo,
    );
    assert.match(denied.deny, /could not read/);
    await assert.rejects(
      rehydrateRedacted(
        "MultiEdit",
        { file_path: "/f", edits: EDITS },
        brokenIo,
      ),
      /EACCES/,
    );
  });
});

describe("rehydrate: Edit-create onto a missing file", () => {
  const missingIo = {
    readFile: () => {
      throw fsError("ENOENT");
    },
    redactMap: () => {
      throw new Error("must not map");
    },
    redact: () => null,
  };

  it("denies a hinted create (empty old_string, placeholder in new_string)", async () => {
    // The Edit create form writes new_string verbatim into a NEW file — the
    // same R4 cross-file/stale-placeholder mistake a Write onto a missing
    // path is denied for.
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/new", old_string: "", new_string: `key=${PH}\n` },
      missingIo,
    );
    assert.match(out.deny, /does not exist/);
  });

  it("still passes a hinted NON-create Edit through (Edit reports not-found itself)", async () => {
    assert.equal(
      await rehydrateRedacted(
        "Edit",
        { file_path: "/new", old_string: `key=${PH}`, new_string: "x" },
        missingIo,
      ),
      null,
    );
  });
});

// ─── Redactor-map validation ─────────────────────────────────────────────────

describe("rehydrate: a defective redactor map is never spliced", () => {
  const content = `key=${SECRET_A}\n`;
  const viewText = `key=${PH}\n`;
  const hintedEdit = {
    file_path: "/f",
    old_string: `key=${PH}`,
    new_string: `token=${PH}`,
  };
  const probe = (text) => text.split(SECRET_A).join(PH);
  /** io returning a hand-built (possibly defective) map for `content`. */
  const mapIo = (pairs) => fakeIo(content, { text: viewText, pairs }, probe);

  it("non-vacuity: the same fixture with a SOUND map rehydrates", async () => {
    const out = await rehydrateRedacted(
      "Edit",
      hintedEdit,
      mapIo([{ placeholder: PH, original: SECRET_A, start: 4 }]),
    );
    assert.equal(out.updatedInput.old_string, `key=${SECRET_A}`);
  });

  it("denies a placeholder that is not at its stated offset", async () => {
    const out = await rehydrateRedacted(
      "Edit",
      hintedEdit,
      mapIo([{ placeholder: PH, original: SECRET_A, start: 2 }]),
    );
    assert.match(out.deny, /map is inconsistent/);
    assert.match(out.deny, /offset 2/);
  });

  it("denies originals that do not splice back to the file's bytes", async () => {
    const out = await rehydrateRedacted(
      "Edit",
      hintedEdit,
      mapIo([{ placeholder: PH, original: SECRET_B, start: 4 }]),
    );
    assert.match(out.deny, /does not reconstruct/);
    // The deny reason must never carry a secret byte.
    assert.ok(!out.deny.includes(SECRET_A) && !out.deny.includes(SECRET_B));
  });

  it("denies overlapping pairs (map-contract violation) instead of throwing", async () => {
    const out = await rehydrateRedacted(
      "Edit",
      hintedEdit,
      mapIo([
        { placeholder: PH, original: SECRET_A, start: 4 },
        { placeholder: PH, original: SECRET_B, start: 5 },
      ]),
    );
    assert.match(out.deny, /violates its contract/);
  });

  it("denies an out-of-range pair start instead of throwing", async () => {
    const out = await rehydrateRedacted(
      "Edit",
      hintedEdit,
      mapIo([{ placeholder: PH, original: SECRET_A, start: 999 }]),
    );
    assert.match(out.deny, /violates its contract/);
  });

  it("denies even an unhinted Edit on a defective map (stricter than unmappable)", async () => {
    // Unmappable keeps the unhinted pass-through (an honest "cannot map");
    // a map that FAILED VALIDATION is proof the engine is wrong about where
    // this file's secrets sit, so a pass-through would hand the real Edit
    // bytes inside spans nothing can vet — the R1 hidden-span oracle.
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: "key=", new_string: "k=" },
      mapIo([{ placeholder: PH, original: SECRET_A, start: 2 }]),
    );
    assert.match(out.deny, /cannot safely edit/);
  });

  it("denies a MultiEdit on a defective map", async () => {
    const out = await rehydrateRedacted(
      "MultiEdit",
      { file_path: "/f", edits: [{ old_string: "key=", new_string: "k=" }] },
      mapIo([{ placeholder: PH, original: SECRET_A, start: 2 }]),
    );
    assert.match(out.deny, /single Edit calls/);
  });
});
