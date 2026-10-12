import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { rehydrateRedacted, DEFAULT_HINT } from "../src/rehydrate.mjs";
import { mkView } from "./helpers/redact-view.mjs";

// Placeholder shapes. PH2 shares the hint prefix but is a distinct placeholder.
const PH = "[REDACTED]";
const PH2 = "[REDACTED: Private Key]";
const HINT = DEFAULT_HINT; // "[REDACTED"
const ZW = String.fromCharCode(0x200b); // zero-width space (Layer 1 strips)

// A redactor probe that reports "secrets present" (non-null) — needed so the
// hint-free short-circuit in rehydrateRedacted does NOT pass the call through.
const present = () => "redacted";

const fakeIo = (content, view, redact = () => null) => ({
  readFile: () => content,
  redactMap: () => view,
  redact,
});

const liveIo = (content, secrets = [], redact = () => null) => ({
  readFile: () => content,
  redactMap: (text) => mkView(text, secrets),
  redact,
});

function fsError(code) {
  const err = new Error(code);
  err.code = code;
  return err;
}

// ─── R1 hidden-span intrusion arithmetic/logic (rehydrateEdit, lines 186-192) ─
//
// These all exercise the viewOcc.length===0 branch: a hint-free old_string that
// is invisible in the model's view yet matches disk. Whether the match
// "intrudes" into a redacted secret's on-disk span (partial overlap → deny) vs.
// wholly contains it or sits adjacent (→ pass through) is decided by the exact
// boundary comparisons the mutants flip.

describe("rehydrate mutation kill: R1 intrusion boundaries", () => {
  it("L187: matchEnd = matchStart + oldS.length (leading fragment of a secret)", async () => {
    // old_string is the secret's LEADING substring: a partial overlap that must
    // deny. Under matchEnd = matchStart - oldS.length the B-term
    // (secret.start < matchEnd) goes false, dropping the intrusion → no deny.
    const content = `k=omegabody\n`;
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: "omega", new_string: "omegaX" },
      liveIo(content, [{ value: "omegabody", placeholder: PH }], present),
    );
    assert.match(out.deny, /inside a \[REDACTED…\] redacted secret/); // L198
    assert.match(out.deny, /hidden from your view/); // L199
    assert.match(out.deny, /include each placeholder whole/); // L200
    assert.equal(out.updatedInput, undefined);
  });

  it("L188: diskSpans.some (fragment intrudes ONE of two secrets)", async () => {
    // "MID" lives only inside secret1; secret2 is elsewhere and untouched.
    // `.some` → intrusion via secret1 → deny. `.every` would require secret2 to
    // also match (it does not) → no deny.
    const content = `A=xxMIDyy\nB=other\n`;
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: "MID", new_string: "MIDX" },
      liveIo(
        content,
        [
          { value: "xxMIDyy", placeholder: PH },
          { value: "other", placeholder: PH2 },
        ],
        present,
      ),
    );
    assert.match(out.deny, /inside a \[REDACTED…\] redacted secret/);
    assert.equal(out.updatedInput, undefined);
  });

  it("L186: occurrences(...).some (one disk match intrudes, one wholly covers a secret)", async () => {
    // "PQ" occurs twice on disk: interior to secret1 "xxPQyy" (intrude) and as
    // the whole of secret2 "PQ" (rotation — not an intrusion). Both are hidden
    // in the view. The OUTER `.some` denies on the intruding match; `.every`
    // would let the pair pass because the second match does not intrude.
    const content = `s1=xxPQyy\ns2=PQ\n`;
    const view = {
      text: "s1=" + PH + "\ns2=" + PH2 + "\n",
      pairs: [
        { placeholder: PH, original: "xxPQyy", start: 3 },
        { placeholder: PH2, original: "PQ", start: 3 + PH.length + 1 + 3 },
      ],
    };
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: "PQ", new_string: "PQZ" },
      fakeIo(content, view, present),
    );
    assert.match(out.deny, /inside a \[REDACTED…\] redacted secret/);
    assert.equal(out.updatedInput, undefined);
  });

  it("L190: matchStart < secret.end AND the && (adjacent secret to the LEFT of a rotation)", async () => {
    // old_string == secret "omega" (a whole-secret rotation → no intrusion).
    // secret2 "delta" ends exactly where the match starts (adjacent, no
    // overlap). Correct: null. But `<`→`<=` makes A true at the boundary, and
    // `&&`→`||` / cond→true each independently turn the adjacent secret into a
    // spurious intrusion → deny.
    const content = `xdeltaomegay\n`;
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: "omega", new_string: "OMEGA" },
      liveIo(
        content,
        [
          { value: "delta", placeholder: PH2 },
          { value: "omega", placeholder: PH },
        ],
        present,
      ),
    );
    assert.equal(out, null);
  });

  it("L191: secret.start < matchEnd AND its cond (adjacent secret to the RIGHT of a rotation)", async () => {
    // Mirror of the previous: secret2 "delta" starts exactly where the rotation
    // match ends. Correct: the B-term is false → null. `<`→`<=` or cond→true
    // makes the adjacent secret a spurious intrusion → deny.
    const content = `xomegadeltay\n`;
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: "omega", new_string: "OMEGA" },
      liveIo(
        content,
        [
          { value: "omega", placeholder: PH },
          { value: "delta", placeholder: PH2 },
        ],
        present,
      ),
    );
    assert.equal(out, null);
  });

  it("L192: !(matchStart <= secret.start && ...) and its cond (exact-secret rotation)", async () => {
    // old_string == the secret exactly: matchStart === secret.start and
    // matchEnd === secret.end, so the match WHOLLY contains the secret → not an
    // intrusion → null. `<=`→`<` breaks the wholly-contains test at the equal
    // boundary, and cond→true drops the guard entirely → spurious deny.
    const content = `k=omega\n`;
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: "omega", new_string: "rotated" },
      liveIo(content, [{ value: "omega", placeholder: PH }], present),
    );
    assert.equal(out, null);
  });
});

// ─── Exposure-simulation gating (rehydrateEdit, lines 310-323) ────────────────

describe("rehydrate mutation kill: exposure-sim gating", () => {
  it("L310: span.diskText === oldS && newRes.text === new_string (rehydrate around a kept secret)", async () => {
    // The span holds a real secret (diskText != oldS which carries a
    // placeholder), so the condition is false and the call must proceed to
    // produce updatedInput. cond→true would early-return null.
    const secret = ["red", "apple", "seed"].join("");
    const content = `PASSWORD=${secret}\nDEBUG=1\n`;
    const view = mkView(content, [{ value: secret, placeholder: PH }]);
    const reRedact = (t) => t.split(secret).join(PH);
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `PASSWORD=${PH}\nDEBUG=1`,
        new_string: `PASSWORD=${PH}\nDEBUG=0`,
      },
      fakeIo(content, view, reRedact),
    );
    assert.equal(out.updatedInput.old_string, `PASSWORD=${secret}\nDEBUG=1`);
    assert.equal(out.updatedInput.new_string, `PASSWORD=${secret}\nDEBUG=0`);
  });

  it("L317/L318/L323: the replace_all / diskOcc===1 / updated!==null gates (hidden duplicate)", async () => {
    // The resolved disk bytes "K=aabbcc" occur twice on disk: once at the edit
    // target and once hidden INSIDE a second, differently-placeholdered secret.
    // With replace_all off and diskMatchCount !== viewOcc, `updated` stays null
    // and the exposure simulation is correctly SKIPPED — so the call succeeds.
    // Each mutant forces the exposure sim to run over a wrongly-computed (or
    // null) `updated`, and with an identity redactor the freshly-substituted
    // secret is seen as exposed → deny (or a throw on null), not this success.
    const content = `K=aabbcc\nbig=K=aabbccTL\n`;
    const view = {
      text: "K=" + PH + "\nbig=" + PH2 + "\n",
      pairs: [
        { placeholder: PH, original: "aabbcc", start: 2 },
        { placeholder: PH2, original: "K=aabbccTL", start: 17 },
      ],
    };
    const out = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: `K=${PH}`, new_string: `K2=${PH}` },
      fakeIo(content, view, (t) => t), // identity: exposes any secret in `updated`
    );
    assert.equal(out.updatedInput.old_string, "K=aabbcc");
    assert.equal(out.updatedInput.new_string, "K2=aabbcc");
  });

  it("L270/L272/L273: replace_all hidden-count deny text (same hidden duplicate, replace_all)", async () => {
    const content = `K=aabbcc\nbig=K=aabbccTL\n`;
    const view = {
      text: "K=" + PH + "\nbig=" + PH2 + "\n",
      pairs: [
        { placeholder: PH, original: "aabbcc", start: 2 },
        { placeholder: PH2, original: "K=aabbccTL", start: 17 },
      ],
    };
    const out = await rehydrateRedacted(
      "Edit",
      {
        file_path: "/f",
        old_string: `K=${PH}`,
        new_string: `K2=${PH}`,
        replace_all: true,
      },
      fakeIo(content, view, (t) => t),
    );
    assert.match(
      out.deny,
      /replace_all would rewrite 2 on-disk occurrence\(s\) of the matched/,
    );
    assert.match(out.deny, /hidden inside redacted secrets or stripped/);
    assert.match(
      out.deny,
      /Edit each visible occurrence separately with unique context/,
    );
  });

  it("L333: notes .filter(Boolean) drops the false placeholder-note (invisible-only edit)", async () => {
    // No placeholder in the span (span.pairs empty) but an interior zero-width
    // char (a non-empty strip count). Without .filter(Boolean) the notes array keeps a
    // boolean `false`, which join()s into the context as the literal "false".
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
    assert.match(out.context, /invisible\/control character/);
    assert.ok(!out.context.includes("false"));
  });
});

// ─── foreignPlaceholders (rehydrateWrite helper, lines 365-372) ──────────────

describe("rehydrate mutation kill: foreignPlaceholders", () => {
  const secretHint = HINT + "abc_secret_A"; // pathological: value CONTAINS the hint
  const secretB = ["blue", "berry", "value"].join("");

  it("L365 skip-condition (secret bytes contain the hint prefix → not foreign)", async () => {
    // One substituted secret's own bytes begin with "[REDACTED"; that hint
    // occurrence sits at span.start and must be SKIPPED (some/<=/>= all decide
    // this). A second secret is present so `.some` vs `.every` diverge. The
    // Write is legitimate and must succeed.
    const src = `A=${secretHint}\nB=${secretB}\n`;
    const view = mkView(src, [
      { value: secretHint, placeholder: PH },
      { value: secretB, placeholder: PH2 },
    ]);
    const reRedact = (t) =>
      t.split(secretHint).join(PH).split(secretB).join(PH2);
    const out = await rehydrateRedacted(
      "Write",
      { file_path: "/f", content: `A=${PH}\nB=${PH2}\n` },
      fakeIo(src, view, reRedact),
    );
    assert.equal(out.updatedInput.content, `A=${secretHint}\nB=${secretB}\n`);
  });

  it("L365 cond→true (a genuine foreign placeholder must still be caught)", async () => {
    const secret = ["green", "olive", "value"].join("");
    const src = `PW=${secret}\n`;
    const view = mkView(src, [{ value: secret, placeholder: PH }]);
    const reRedact = (t) => t.split(secret).join(PH);
    const out = await rehydrateRedacted(
      "Write",
      { file_path: "/f", content: `PW=${PH}\nK=${PH2}\n` },
      fakeIo(src, view, reRedact),
    );
    assert.match(out.deny, /still carries a \[REDACTED…\] placeholder/); // L461
    assert.match(
      out.deny,
      /Edit instead, or write the secret's real value directly/,
    ); // L464
    assert.equal(out.updatedInput, undefined);
  });

  it("L365 start < span.end (foreign placeholder abuts a substituted secret's end)", async () => {
    // The foreign PH2 begins exactly at the substituted secret's on-disk end.
    // start === span.end must NOT be treated as "inside" the secret (`<`, not
    // `<=`), so the foreign placeholder is detected → deny.
    const secret = ["amber", "cocoa", "value"].join("");
    const src = `A=${secret}\n`;
    const view = mkView(src, [{ value: secret, placeholder: PH }]);
    const reRedact = (t) => t.split(secret).join(PH);
    const out = await rehydrateRedacted(
      "Write",
      { file_path: "/f", content: `A=${PH}${PH2}\n` },
      fakeIo(src, view, reRedact),
    );
    assert.match(out.deny, /still carries a \[REDACTED…\] placeholder/);
    assert.equal(out.updatedInput, undefined);
  });

  it("L372: token = out.slice(start, close+1) (same-file prose token is kept whole)", async () => {
    // "[REDACTEDXYZ]" is prose the file documents (hint prefix, not a
    // placeholder). The token must be sliced to its own "]" so viewText.includes
    // recognizes it; replacing the slice with the whole `out` makes the include
    // fail → spurious foreign deny.
    const prose = "[REDACTEDXYZ]";
    const secret = ["cocoa", "maple", "value"].join("");
    const src = `see ${prose} docs\nPW=${secret}\n`;
    const view = {
      text: `see ${prose} docs\nPW=${PH}\n`,
      pairs: [
        {
          placeholder: PH,
          original: secret,
          start: `see ${prose} docs\nPW=`.length,
        },
      ],
    };
    const reRedact = (t) => t.split(secret).join(PH);
    const out = await rehydrateRedacted(
      "Write",
      { file_path: "/f", content: `see ${prose} docs\nPW=${PH}\n` },
      fakeIo(src, view, reRedact),
    );
    assert.equal(out.updatedInput.content, `see ${prose} docs\nPW=${secret}\n`);
  });
});

// ─── Read-failure narrowing (rehydrateRedacted catch, lines 557-582) ─────────

describe("rehydrate mutation kill: read-failure handling", () => {
  it("L557/L580: optional chaining on the (possibly value-less) error (throws null)", async () => {
    // io.readFile throws a non-object (null). `nodeErr?.code` and the deny's
    // `nodeErr?.code ?? nodeErr?.message` must tolerate it and still return a
    // deny; dropping the `?.` throws a TypeError instead.
    const io = {
      readFile: () => {
        throw null;
      },
      redactMap: () => {
        throw new Error("redactMap must not be reached");
      },
      redact: () => null,
    };
    const out = await rehydrateRedacted(
      "Write",
      { file_path: "/f", content: `secret: ${PH}\n` },
      io,
    );
    assert.match(out.deny, /could not read \/f/);
  });

  it("L581/L582: non-ENOENT deny prose (EACCES on a hinted Write)", async () => {
    const io = {
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
      { file_path: "/locked", content: `secret: ${PH}\n` },
      io,
    );
    assert.match(out.deny, /EACCES/);
    assert.match(out.deny, /the file likely still exists, so writing/); // L581
    assert.match(out.deny, /risks overwriting a real secret/); // L582
  });

  it("L564: ENOENT Write deny prose", async () => {
    const io = {
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
      io,
    );
    assert.match(out.deny, /\/new does not exist/);
    assert.match(out.deny, /Write the secret's real value directly, or ask/); // L564
  });
});

// ─── Cross-file Write (rehydrateWrite texts-empty deny, lines 398-404) ───────

describe("rehydrate mutation kill: cross-file Write deny", () => {
  it("L404: content placeholder matches no file placeholder", async () => {
    const secret = ["coral", "mango", "value"].join("");
    const src = `PW=${secret}\n`;
    const view = mkView(src, [{ value: secret, placeholder: PH }]);
    const out = await rehydrateRedacted(
      "Write",
      { file_path: "/f", content: `docs ${PH2} here\n` },
      fakeIo(src, view, (t) => t.split(secret).join(PH)),
    );
    assert.match(out.deny, /does not match any secret/);
    assert.match(
      out.deny,
      /request the source file's content and rehydrate a same-file/,
    ); // L403-404
    assert.equal(out.updatedInput, undefined);
  });
});
