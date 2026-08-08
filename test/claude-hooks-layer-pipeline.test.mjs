/**
 * The PreToolUse layer chain's ordering invariant, asserted on what the hook
 * actually EMITS.
 *
 * The confusable fold is skip-based by design: a token still holding an unmapped
 * non-ASCII glyph is left alone, because folding it could only mangle real
 * foreign-language text — it could never come out byte-equal to an ASCII deny-rule
 * target. That argument is sound only while nothing later erases code points from
 * the same field. The authored-content strip does exactly that, and it ran after
 * the fold, so zero-width padding inside a token suppressed the fold and the strip
 * then removed the padding: the emitted command carried the homoglyph AND no
 * longer carried the reason for keeping it.
 *
 * The invariant that closes it, and the one asserted here: the EMITTED tool input
 * is a fixed point of every skip-based layer. Running the fold on the hook's own
 * output must report nothing left to fold; likewise the strip. A pipeline that
 * leaves either with work to do has taken a decision on text it did not emit.
 */
import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";
import fc from "fast-check";

// An empty project dir, set before the hook imports: the PreToolUse gate reads
// its cross-hook alert from a path keyed to CLAUDE_PROJECT_DIR (resolved at
// module load), and a stray alert from another suite would add an ask to every
// response here.
const projectDir = mkdtempSync(join(tmpdir(), "sanitizer-pipeline-proj-"));
process.env.CLAUDE_PROJECT_DIR = projectDir;
// Other suites point the SessionStart scanner's project dir at $TMPDIR, where it
// globs **/CLAUDE.md — so a fixture dir left behind here becomes their problem.
after(() => rmSync(projectDir, { recursive: true, force: true }));

const { buildPreToolUseResponse, preToolUseLayers } =
  await import("../claude-hooks/pretooluse-sanitize.mjs");
const { runLayerPipeline, needsFixedPoint } =
  await import("../claude-hooks/lib/layer-pipeline.mjs");
const { normalizeConfusables } = await import("../src/confusables.mjs");
const { sanitizeAuthoredContent } =
  await import("../claude-hooks/lib/authored-content.mjs");

// The REAL vision map the hook injects, not a stub: the gate this test is about
// is decided by which glyphs that engine flags, so a hand-rolled scanner would
// be testing the test's own idea of a confusable.
const { scan } = createRequire(import.meta.url)("namespace-guard");

const ZWSP = "​";
const CYRILLIC_A = "а";

/** The command the hook emits for `command`, or the original on a clean pass. */
async function emittedCommand(command) {
  const fields = await buildPreToolUseResponse(
    { tool_name: "Bash", tool_input: { command } },
    // Layer 4 stubbed to a no-op: it reaches the redactor daemon and the
    // filesystem, neither of which this invariant is about, and it is terminal
    // so it cannot affect the fixed point of the layers above it.
    () => null,
    () => {},
  );
  const updated = /** @type {any} */ (fields)?.updatedInput;
  return updated === undefined ? command : updated.command;
}

/** Every skip-based layer's verdict on `command`; all null means a fixed point. */
function residualWork(command) {
  return {
    fold: normalizeConfusables("Bash", { command }, { scan }),
    strip: sanitizeAuthoredContent("Bash", { command }),
  };
}

describe("the emitted tool input is a fixed point of every skip-based layer", () => {
  it("folds the homoglyph that zero-width padding used to hide", async () => {
    // The concrete bypass: 12 ZWSPs inside the token push it past the strip's
    // payload-capable floor while making the token unfoldable, so the pre-fix
    // chain emitted "cat /etc/p<CYRILLIC A>sswd".
    const command = `cat /etc/p${CYRILLIC_A}${ZWSP.repeat(12)}sswd`;
    assert.equal(await emittedCommand(command), "cat /etc/passwd");
  });

  it("leaves a lone padded glyph alone (the gate is not weakened)", async () => {
    // One code point between boundaries is a one-letter foreign word as readily
    // as a disguised argument, and no deny rule targets a single character. The
    // strip still fires on the padding; the fold still declines.
    const command = `echo ${CYRILLIC_A}${ZWSP.repeat(12)} done`;
    assert.equal(await emittedCommand(command), `echo ${CYRILLIC_A} done`);
  });

  it("holds for arbitrary mixes of ASCII, confusables and zero-width runs", async () => {
    const piece = fc.oneof(
      fc.stringMatching(/^[a-z/._-]{1,6}$/u),
      fc.constantFrom(CYRILLIC_A, "е", "о", "р", "с"),
      fc.integer({ min: 1, max: 14 }).map((n) => ZWSP.repeat(n)),
      fc.constantFrom(" ", "/", "-"),
    );
    let everModified = 0;
    await fc.assert(
      fc.asyncProperty(
        fc.array(piece, { minLength: 1, maxLength: 12 }),
        async (pieces) => {
          const command = pieces.join("");
          const emitted = await emittedCommand(command);
          if (emitted !== command) everModified += 1;
          const { fold, strip } = residualWork(emitted);
          assert.equal(
            fold,
            null,
            `emitted command is not a fixed point of the confusable fold: ${JSON.stringify(emitted)}`,
          );
          assert.equal(
            strip,
            null,
            `emitted command is not a fixed point of the authored strip: ${JSON.stringify(emitted)}`,
          );
        },
      ),
      { numRuns: 300 },
    );
    // Non-vacuity: a generator that never produced a payload would satisfy the
    // property by producing nothing to sanitize.
    assert.ok(
      everModified > 0,
      "no generated command was ever rewritten — the property held vacuously",
    );
  });
});

describe("the pipeline driver enforces the ordering precondition", () => {
  /** A layer that appends `mark` once, then reports nothing further to do. */
  const appender = (name, mark, flags) => ({
    name,
    ...flags,
    run: (_tool, input) =>
      input.command.includes(mark)
        ? null
        : { updatedInput: { command: input.command + mark }, context: name },
  });

  it("recognizes an erasing layer placed after a skip-based one", () => {
    const skip = { name: "s", erases: false, skipBased: true, run: () => null };
    const erase = {
      name: "e",
      erases: true,
      skipBased: false,
      run: () => null,
    };
    assert.equal(needsFixedPoint([skip, erase]), true);
    assert.equal(needsFixedPoint([erase, skip]), false);
  });

  it("re-runs a skip-based layer that only fires after the erasure", async () => {
    // "erase" removes the padding; only then does the skip-based layer act — the
    // shape of the real bug, in miniature.
    const erase = {
      name: "erase",
      erases: true,
      skipBased: false,
      run: (_tool, input) =>
        input.command.includes("#")
          ? {
              updatedInput: { command: input.command.replace(/#/gu, "") },
              context: "erase",
            }
          : null,
    };
    const skip = {
      name: "fold",
      erases: false,
      skipBased: true,
      run: (_tool, input) =>
        input.command.includes("#") || !input.command.includes("a")
          ? null
          : {
              updatedInput: { command: input.command.replace(/a/gu, "A") },
              context: "fold",
            },
    };
    const out = await runLayerPipeline("Bash", { command: "a#" }, [
      skip,
      erase,
    ]);
    assert.equal(out.updatedInput.command, "A");
    assert.deepEqual(out.contexts, ["erase", "fold"]);
  });

  it("runs a single pass when the table needs no fixed point", async () => {
    let passes = 0;
    const counted = {
      name: "count",
      erases: true,
      skipBased: false,
      run: (_tool, input) => {
        passes += 1;
        return passes === 1
          ? { updatedInput: { command: input.command + "!" }, context: "count" }
          : null;
      },
    };
    const out = await runLayerPipeline("Bash", { command: "x" }, [counted]);
    assert.equal(passes, 1);
    assert.equal(out.updatedInput.command, "x!");
  });

  it("throws rather than looping when two layers undo each other", async () => {
    const up = {
      name: "up",
      erases: true,
      skipBased: true,
      run: (_tool, input) =>
        input.command === "a"
          ? { updatedInput: { command: "b" }, context: "up" }
          : null,
    };
    const down = {
      name: "down",
      erases: true,
      skipBased: true,
      run: (_tool, input) =>
        input.command === "b"
          ? { updatedInput: { command: "a" }, context: "down" }
          : null,
    };
    await assert.rejects(
      () => runLayerPipeline("Bash", { command: "a" }, [up, down]),
      /did not reach a fixed point/u,
    );
  });

  it("runs a terminal layer exactly once, after the fixed point", async () => {
    const runs = [];
    const body = appender("body", "B", { erases: true, skipBased: true });
    const terminal = {
      name: "terminal",
      erases: true,
      skipBased: false,
      terminal: true,
      run: (_tool, input) => {
        runs.push(input.command);
        return { updatedInput: { command: input.command + "T" }, context: "t" };
      },
    };
    const out = await runLayerPipeline("Bash", { command: "x" }, [
      body,
      terminal,
    ]);
    assert.deepEqual(runs, ["xB"]);
    assert.equal(out.updatedInput.command, "xBT");
  });

  it("rejects a table with a non-terminal layer after a terminal one", async () => {
    const terminal = {
      name: "t",
      erases: false,
      skipBased: false,
      terminal: true,
      run: () => null,
    };
    const body = {
      name: "b",
      erases: false,
      skipBased: false,
      run: () => null,
    };
    await assert.rejects(
      () => runLayerPipeline("Bash", {}, [terminal, body, terminal]),
      /terminal layers must come last/u,
    );
  });

  it("stops at a deny verdict without running later layers", async () => {
    let ran = false;
    const deny = {
      name: "deny",
      erases: false,
      skipBased: false,
      run: () => ({ deny: "nope" }),
    };
    const after = {
      name: "after",
      erases: false,
      skipBased: false,
      run: () => {
        ran = true;
        return null;
      },
    };
    const out = await runLayerPipeline("Bash", {}, [deny, after]);
    assert.equal(out.deny, "nope");
    assert.equal(ran, false);
  });
});

describe("the shipped layer table declares the hazard it has to handle", () => {
  it("orders the erasing strip after the skip-based fold, and says so", () => {
    const layers = preToolUseLayers(() => null, {});
    assert.deepEqual(
      layers.map((l) => l.name),
      ["confusables", "authored-content", "rehydrate", "layer2-rehydrate"],
    );
    assert.equal(
      needsFixedPoint(layers.filter((l) => l.terminal !== true)),
      true,
    );
  });

  it("drops the strip — and the fixed-point cost — when it is disabled", () => {
    const layers = preToolUseLayers(() => null, {
      AGENT_SANITIZER_OUTPUT_DISABLED: "1",
    });
    assert.deepEqual(
      layers.map((l) => l.name),
      ["confusables", "rehydrate", "layer2-rehydrate"],
    );
    assert.equal(
      needsFixedPoint(layers.filter((l) => l.terminal !== true)),
      false,
    );
  });
});
