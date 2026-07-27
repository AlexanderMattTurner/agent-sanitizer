/**
 * Property/fuzz tests for the Edit re-anchoring layer (rehydrate.mjs +
 * view-map.mjs). Example tests pin specific shapes; these pin the INVARIANTS
 * that must hold across fuzzed file contents — secrets, invisible chars, and
 * ANSI sequences interleaved at arbitrary positions:
 *
 *   1. NO MIS-ANCHOR: when the layer rewrites an Edit, the rewritten
 *      old_string exists verbatim on disk AND its sanitized view equals the
 *      old_string the model supplied.
 *   2. ROUND-TRIP: applying the rewritten edit to the disk bytes and
 *      re-sanitizing yields exactly the view-level edit the model intended.
 *   3. NO CORRUPTION otherwise: every other outcome is a pass-through (null)
 *      or an instructive deny — never a rewrite that violates 1-2.
 *   4. NEVER THROWS for arbitrary string inputs given a well-formed io.
 *   5. NO EXPOSURE: a successful rewrite never puts a candidate secret into a
 *      form the next view would reveal.
 *   6. A deny always carries a non-empty reason and no updatedInput.
 *
 * The redactor is NOT re-implemented here. `io.redactMap`/`io.redact` are driven
 * by the REAL Python engine (`agent_sanitizer.secrets.redact_map`) over a
 * long-lived worker — the single source of truth — so the view these invariants
 * anchor against is exactly what production redaction produces, offsets and all.
 */
import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import { rehydrateRedacted } from "../src/rehydrate.mjs";
import { applyLayer1 } from "../src/layer1.mjs";
import { occurrences as occ } from "../src/view-map.mjs";
import { fcRunOptions } from "./test-helpers.mjs";
import {
  realRedactMap,
  realRedact,
  stopRealRedactor,
} from "./real-redactor.mjs";

// Secrets the corpus plants after named fields (PASSWORD=/API_KEY=/TOKEN=). The
// real engine flags each as a "named secret field" and redacts it to an
// identical [REDACTED], so the test never re-implements redaction.
const SECRET_A = ["hunter2hunter2", "hunter2xA"].join("");
const SECRET_B = ["hunter2hunter2", "hunter2xB"].join("");
const SECRET_VALUES = [SECRET_A, SECRET_B];
const ZW = String.fromCharCode(0x200b);
const ESC = String.fromCharCode(0x1b);

// Tear the shared redactor worker down once the file's tests finish.
after(stopRealRedactor);

// io backed by the real Python redactor — the single source of truth. redactMap
// runs the engine's map mode; redact is the plain "any secrets?" probe (null
// when clean). readFile returns the planted disk bytes.
const realIo = (content) => ({
  readFile: () => content,
  redactMap: (text) => realRedactMap(text),
  redact: (text) => realRedact(text),
});

/** Sanitized view of `disk` exactly as the model would read it: Layer 1 (JS),
 * then the real redactor. Async — it awaits the engine. */
async function modelView(disk) {
  const { cleaned } = applyLayer1(disk);
  const view = await realRedactMap(cleaned);
  return view.text;
}

/** The planted secret values the next view of `disk` would reveal. */
async function exposedInView(disk) {
  const view = await modelView(disk);
  return SECRET_VALUES.filter((v) => view.includes(v));
}

// Counterexamples this property has caught, pinned so they replay on EVERY run.
const REGRESSION_EXAMPLES = [[`${ESC}${ESC}[3${ZW}2m[32m\n`, 0, 0, "append"]];

const runOptions = fcRunOptions({
  numRuns: 300,
  examples: REGRESSION_EXAMPLES,
});

const KEY = String.fromCodePoint(0x1f511); // 🔑 astral (2 UTF-16 units)
const lineArb = fc.constantFrom(
  "alpha beta gamma",
  "x = compute(y)",
  "",
  "mm 32m",
  `PASSWORD=${SECRET_A}`,
  `API_KEY=${SECRET_B}`,
  `TOKEN=${SECRET_A}`,
  // Astral chars before a secret make the placeholder's code-point offset
  // diverge from its UTF-16 offset, exercising rehydrate's pairsToUtf16
  // normalization (a BMP-only corpus never reaches that shift).
  `${KEY} PASSWORD=${SECRET_A}`,
  `${KEY}${KEY} TOKEN=${SECRET_B}`,
);
const strippableArb = fc.constantFrom(ZW, `${ESC}[32m`, `${ESC}[0m`, ZW + ZW);

const contentArb = fc
  .record({
    lines: fc.array(lineArb, { minLength: 1, maxLength: 6 }),
    inserts: fc.array(fc.record({ chunk: strippableArb, pos: fc.nat() }), {
      maxLength: 4,
    }),
  })
  .map(({ lines, inserts }) => {
    let content = `${lines.join("\n")}\n`;
    for (const { chunk, pos } of inserts) {
      const at = pos % (content.length + 1);
      content = content.slice(0, at) + chunk + content.slice(at);
    }
    return content;
  });

/** Pick a whole-line span of the view as old_string. */
function pickSpan(view, startSeed, lenSeed) {
  const lines = view.split("\n");
  const start = startSeed % lines.length;
  const len = 1 + (lenSeed % (lines.length - start));
  return lines.slice(start, start + len).join("\n");
}

describe("rehydrate: properties", () => {
  it("never mis-anchors and round-trips the model's intended edit", async () => {
    // T4: invariants 2 + 5 (round-trip and no-exposure) only run inside the
    // unambiguous single-match precondition below. Count how often that branch
    // is actually taken so a fixture/generator change that stops reaching it can
    // never let the property pass vacuously.
    let sawRoundTrip = 0;
    await fc.assert(
      fc.asyncProperty(
        contentArb,
        fc.nat(),
        fc.nat(),
        fc.constantFrom("delete", "append", "replace"),
        async (content, startSeed, lenSeed, mode) => {
          const view = await modelView(content);
          const oldS = pickSpan(view, startSeed, lenSeed);
          if (oldS.length === 0) return;
          const replacements = {
            delete: "",
            append: `${oldS}\nEXTRA=1`,
            replace: "replaced line",
          };
          const newS = replacements[mode];

          const result = await rehydrateRedacted(
            "Edit",
            { file_path: "/f", old_string: oldS, new_string: newS },
            realIo(content),
          );

          if (result === null) {
            assert.ok(
              content.includes(oldS),
              `null pass-through for a non-matching old_string\n` +
                `content=${JSON.stringify(content)}\nold=${JSON.stringify(oldS)}`,
            );
            return;
          }
          if ("deny" in result) {
            // Invariant 6: a deny is a non-empty reason and carries no rewrite.
            assert.equal(typeof result.deny, "string");
            assert.ok(result.deny.length > 0, "empty deny reason");
            assert.equal(result.updatedInput, undefined);
            return;
          }

          const updatedOld = result.updatedInput.old_string;
          // Invariant 1: anchored to real disk bytes whose view is the input.
          assert.ok(content.includes(updatedOld), "old_string not on disk");
          assert.equal(
            await modelView(updatedOld),
            oldS,
            "rewritten old_string does not sanitize back to the model's input",
          );

          // Invariant 2 + 5: round-trip and no-exposure on the unambiguous
          // single-match case.
          if (
            occ(content, updatedOld).length === 1 &&
            occ(view, oldS).length === 1
          ) {
            sawRoundTrip++;
            const newDisk = content.replace(
              updatedOld,
              result.updatedInput.new_string,
            );
            assert.equal(
              await modelView(newDisk),
              await modelView(view.replace(oldS, newS)),
              "post-edit view differs from the model's intended edit",
            );
            // No secret newly revealed by the rewrite.
            const before = new Set(await exposedInView(content));
            for (const v of await exposedInView(newDisk))
              assert.ok(
                before.has(v),
                "a secret became visible after the rewrite",
              );
          }
        },
      ),
      runOptions,
    );
    assert.ok(
      sawRoundTrip > 0,
      "round-trip/no-exposure precondition never held — property passed vacuously",
    );
  });

  it("re-anchors across an astral char before the secret (pairsToUtf16 integration)", async () => {
    // Deterministic companion to the fuzz corpus: the placeholder sits after an
    // astral char, so its code-point offset (what the redactor emits) is one
    // less than its UTF-16 offset. A missing pairsToUtf16 normalization would
    // mis-anchor the rewrite onto the wrong disk bytes. Proves the integration
    // path the property test only reaches stochastically.
    const content = `${KEY} PASSWORD=${SECRET_A}\nDEBUG=1\n`;
    const view = await modelView(content);
    const oldS = view.split("\n")[0]; // "🔑 PASSWORD=[REDACTED]"
    assert.ok(oldS.startsWith(KEY), "fixture must place the astral char first");

    const result = await rehydrateRedacted(
      "Edit",
      { file_path: "/f", old_string: oldS, new_string: "REMOVED" },
      realIo(content),
    );

    assert.ok(
      result && result.updatedInput,
      "expected a rewrite, not null/deny",
    );
    const updatedOld = result.updatedInput.old_string;
    assert.ok(content.includes(updatedOld), "rewritten old_string not on disk");
    assert.ok(
      updatedOld.startsWith(KEY),
      "rewrite anchored past the astral char — pairsToUtf16 shift was dropped",
    );
    assert.equal(
      await modelView(updatedOld),
      oldS,
      "rewritten old_string does not sanitize back to the model's input",
    );
  });

  it("never throws for arbitrary string inputs given a well-formed io", async () => {
    // Robustness of rehydrate over arbitrary TOOL INPUTS — not a redaction test.
    // fast-check feeds lone surrogates here, which have no meaning to redaction;
    // a minimal well-formed io (no secrets) is the right double, and it keeps the
    // real engine's JSON bridge out of the lone-surrogate path.
    const inertIo = (content) => ({
      readFile: () => content,
      redactMap: (text) => ({ text, pairs: [] }),
      redact: () => null,
    });
    await fc.assert(
      fc.asyncProperty(
        fc.string(),
        fc.string(),
        fc.string(),
        fc.constantFrom("Edit", "Write", "NotebookEdit", "Bash"),
        async (content, oldOrContent, newS, tool) => {
          const io = inertIo(content);
          const inputs = {
            Edit: {
              file_path: "/f",
              old_string: oldOrContent,
              new_string: newS,
            },
            Write: { file_path: "/f", content: oldOrContent },
            NotebookEdit: { notebook_path: "/n", new_source: oldOrContent },
            Bash: { command: oldOrContent },
          };
          const result = await rehydrateRedacted(tool, inputs[tool], io);
          // Invariant 4: the result is one of the three legal shapes.
          assert.ok(
            result === null ||
              typeof result.deny === "string" ||
              typeof result.updatedInput === "object",
          );
          // Invariant 6: a deny carries a reason and no rewrite.
          if (result && "deny" in result) {
            assert.ok(result.deny.length > 0);
            assert.equal(result.updatedInput, undefined);
          }
        },
      ),
      runOptions,
    );
  });

  it("never splices a byte inside a redacted secret's on-disk span (deny, never guess)", async () => {
    // A file with a secret at a KNOWN disk span. We fuzz old_string over a pool
    // that includes fragments living only inside the secret, boundary-crossing
    // slices, visible text, whole-secret rotations, and self-overlapping runs —
    // with and without replace_all. INVARIANT: whenever the layer returns a
    // rewrite, applying it must leave the secret's on-disk bytes intact UNLESS
    // the model's old_string wholly contained them. Any edit that would read or
    // split bytes inside the span must deny, never pass through to a raw edit.
    const secret = SECRET_A;
    const prefix = "PASSWORD=";
    const content = `${prefix}${secret}\nDEBUG=1\nEND\n`;
    const secretStart = content.indexOf(secret);
    const secretEnd = secretStart + secret.length;

    // A pool of adversarial and benign old_strings.
    const oldPool = [
      secret.slice(0, 3), // fragment: only inside the secret
      secret.slice(-3), // tail fragment: only inside the secret
      secret[0], // single char inside the secret
      `${prefix}${secret.slice(0, 4)}`, // crosses the secret's start boundary
      `${prefix}${secret}`, // wholly contains the secret (rotation)
      `${prefix}[REDACTED]`, // hinted: resolves to a rewrite covering the secret
      "DEBUG=1", // visible, disjoint from the secret
      "END", // visible, disjoint
      secret.slice(0, 2).repeat(1) + secret[0], // self-overlap-ish
    ];

    let sawRewrite = 0;
    let sawDeny = 0;
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom(...oldPool),
        fc.constantFrom("", "X", "\n-", "replaced"),
        fc.boolean(),
        async (oldS, newS, replaceAll) => {
          if (oldS.length === 0) return;
          const result = await rehydrateRedacted(
            "Edit",
            {
              file_path: "/f",
              old_string: oldS,
              new_string: newS,
              replace_all: replaceAll,
            },
            realIo(content),
          );
          if (result === null) return;
          if ("deny" in result) {
            sawDeny++;
            return;
          }
          sawRewrite++;
          const updatedOld = result.updatedInput.old_string;
          // The model's old_string must wholly cover any part of the secret the
          // rewrite touches — otherwise it would splice hidden bytes.
          for (const at of occ(content, updatedOld)) {
            const end = at + updatedOld.length;
            const overlaps = at < secretEnd && secretStart < end;
            if (overlaps)
              assert.ok(
                at <= secretStart && secretEnd <= end,
                `rewrite splices partially inside the secret span: ` +
                  `old=${JSON.stringify(oldS)} disk=${JSON.stringify(updatedOld)}`,
              );
          }
          // And re-sanitizing the applied edit must not newly reveal the secret.
          if (!replaceAll && occ(content, updatedOld).length === 1) {
            const newDisk = content.replace(
              updatedOld,
              result.updatedInput.new_string,
            );
            const before = new Set(await exposedInView(content));
            for (const v of await exposedInView(newDisk))
              assert.ok(before.has(v), "secret exposed by the rewrite");
          }
        },
      ),
      runOptions,
    );
    // Both branches must actually be exercised or the invariant is vacuous.
    assert.ok(sawDeny > 0, "no deny ever exercised — invariant vacuous");
    assert.ok(sawRewrite > 0, "no rewrite ever exercised — invariant vacuous");
  });
});
