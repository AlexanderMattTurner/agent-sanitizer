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
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
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
const {
  runLayerPipeline,
  needsFixedPoint,
  nonConvergenceReason,
  MAX_PIPELINE_PASSES,
} = await import("../claude-hooks/lib/layer-pipeline.mjs");
const { normalizeConfusables } = await import("../src/confusables.mjs");
const { sanitizeAuthoredContent } =
  await import("../claude-hooks/lib/authored-content.mjs");
const { rehydrateRedacted } = await import("../src/rehydrate.mjs");

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
    // The rehydrate stage stubbed to a no-op: it reaches the redactor daemon and the
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

  /** Two body stages that undo each other forever: a -> b -> a -> ... */
  const oscillating = () => [
    {
      name: "up",
      erases: true,
      skipBased: true,
      run: (_tool, input) =>
        input.command === "a"
          ? { updatedInput: { command: "b" }, context: "up" }
          : null,
    },
    {
      name: "down",
      erases: true,
      skipBased: true,
      run: (_tool, input) =>
        input.command === "b"
          ? { updatedInput: { command: "a" }, context: "down" }
          : null,
    },
  ];

  it("reports a fault — never throws — when two layers undo each other", async () => {
    // A throw lands in the hook's fault posture with no sanitized value to
    // carry, so by default the RAW input passes through. The driver instead
    // returns the last pass's sanitized value plus the reason, naming the
    // stages that never settled, and leaves the verdict to the caller.
    const out = await runLayerPipeline("Bash", { command: "a" }, oscillating());
    assert.equal(out.fault, nonConvergenceReason(["up", "down"]));
    assert.match(out.fault, /did not settle: the up, down stage/u);
    assert.match(
      out.fault,
      new RegExp(`after ${MAX_PIPELINE_PASSES} passes`, "u"),
    );
    assert.equal(out.deny, undefined);
    assert.equal(out.ask, undefined);
    // Even passes: the last pass's value, which is not the raw input's twin by
    // identity but is what every stage has actually rewritten.
    assert.equal(out.changed, true);
    assert.equal(out.updatedInput.command, "a");
  });

  it("still runs the terminal stages under a non-convergence fault", async () => {
    // A call that proceeds must carry the same rehydration a settled one would.
    const runs = [];
    const terminal = {
      name: "terminal",
      erases: false,
      skipBased: false,
      terminal: true,
      run: (_tool, input) => {
        runs.push(input.command);
        return { updatedInput: { command: `${input.command}T` }, context: "t" };
      },
    };
    const out = await runLayerPipeline("Bash", { command: "a" }, [
      ...oscillating(),
      terminal,
    ]);
    assert.equal(runs.length, 1);
    assert.equal(out.updatedInput.command, `${runs[0]}T`);
    assert.equal(typeof out.fault, "string");
  });

  it("lets a terminal deny win over a non-convergence fault", async () => {
    const out = await runLayerPipeline("Bash", { command: "a" }, [
      ...oscillating(),
      {
        name: "deny",
        erases: false,
        skipBased: false,
        terminal: true,
        run: () => ({ deny: "nope" }),
      },
    ]);
    assert.equal(out.deny, "nope");
    assert.equal(out.fault, undefined);
  });

  it("decides 'changed' by value: a stage that always reports a rewrite of an equal value converges", async () => {
    // The family-emoji bug in miniature: a stage whose self-report says
    // "changed" while its output equals its input used to keep the loop from
    // ever settling, and the throw that followed passed the input through
    // unsanitized. The driver must ignore the report and read the value.
    let calls = 0;
    const liar = {
      name: "liar",
      erases: true,
      skipBased: true,
      run: (_tool, input) => {
        calls += 1;
        return { updatedInput: { ...input }, context: "liar" };
      },
    };
    const fold = appender("fold", "F", { erases: false, skipBased: true });
    const out = await runLayerPipeline("Bash", { command: "x" }, [fold, liar]);
    assert.equal(out.fault, undefined);
    assert.equal(out.updatedInput.command, "xF");
    // The liar's note never reaches the model: it changed nothing.
    assert.deepEqual(out.contexts, ["fold"]);
    assert.equal(out.changed, true);
    // Positive marker: the table needed a fixed point and the liar ran on
    // every pass until the real change settled — two passes, not eight.
    assert.equal(calls, 2);
  });

  it("reports unchanged when every rewrite was a no-op", async () => {
    const liar = {
      name: "liar",
      erases: true,
      skipBased: false,
      run: (_tool, input) => ({
        updatedInput: structuredClone(input),
        context: "liar",
      }),
    };
    const out = await runLayerPipeline("Bash", { command: "x" }, [liar]);
    assert.deepEqual(out, {
      updatedInput: { command: "x" },
      changed: false,
      contexts: [],
    });
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

describe("authored-content strips vs terminal rehydrate restoration on an unchanged Write", () => {
  // Built via fromCharCode so no raw invisible byte sits in this source. 12
  // consecutive ZWSPs crosses both floors at once: Layer 1's read-view strip
  // and authored-content's payload-capable gate (LONG_RUN_THRESHOLD = 10).
  const ZW = String.fromCharCode(0x200b);
  const FILE = "/proj/payload.txt";
  const DISK = `alpha${ZW.repeat(12)}omega\n`;
  const VIEW = "alphaomega\n";
  // The REAL rehydrateRedacted, with only the fs/redactor seams faked: the
  // file holds no secrets, so the map view is the cleaned text itself.
  const io = {
    readFile: (path) => {
      assert.equal(path, FILE);
      return DISK;
    },
    redact: () => null,
    redactMap: (text) => ({ text, pairs: [] }),
  };

  it("restores the disk bytes authored-content stripped from a faithful echo", async () => {
    // Positive marker first: the fixture really crosses authored-content's floor on its
    // own — without this, a raised threshold would make the pipeline assertion
    // below pass vacuously (nothing stripped, nothing to restore).
    const stripped = sanitizeAuthoredContent("Write", {
      file_path: FILE,
      content: DISK,
    });
    assert.ok(
      stripped !== null,
      "fixture no longer crosses the authored strip's payload-capable floor",
    );
    assert.equal(stripped.updatedInput.content, VIEW);

    const fields = await buildPreToolUseResponse(
      { tool_name: "Write", tool_input: { file_path: FILE, content: DISK } },
      (tool, toolInput) => rehydrateRedacted(tool, toolInput, io),
      () => {},
    );
    assert.ok(fields !== null);
    // authored-content stripped the run (content became the sanitized view),
    // then the terminal rehydrate stage saw a faithful whole-file echo of that
    // view and restored the exact on-disk bytes — and, being terminal, its
    // restored invisibles were NOT re-stripped by another authored-content pass.
    assert.equal(fields.updatedInput.content, DISK);
    assert.equal(fields.updatedInput.file_path, FILE);
    assert.equal("permissionDecision" in fields, false);
    // Both layers really fired, in that order: the authored strip announced
    // itself AND the rehydrator reported the restored count.
    const context = String(fields.additionalContext);
    assert.match(context, /Sanitized model-authored content in: content/u);
    assert.match(
      context,
      /12 invisible\/control character\(s\) stripped from your view .* restored from disk/u,
    );
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

describe("a stage's spurious change report never unsanitizes the hook's output", () => {
  // The executed repro: ten family emoji (each a ZWJ sequence) push the
  // authored-content stage to REPORT a rewrite whose value equals its input.
  // The driver used to trust the report, never settle, and throw — and the
  // hook's default open posture then passed the command through with its ANSI
  // escapes intact. Built from code points so no raw ZWJ/ESC sits in source.
  const ZWJ = String.fromCodePoint(0x200d);
  const ESC = String.fromCodePoint(0x1b);
  const FAMILY = [0x1f468, 0x1f469, 0x1f467, 0x1f466]
    .map((cp) => String.fromCodePoint(cp))
    .join(ZWJ);
  const PROSE = "This is a perfectly ordinary sentence of prose. ";
  const COVER =
    PROSE.repeat(5) +
    Array.from({ length: 10 }, () => `${PROSE}${FAMILY} `).join("");
  const COMMAND = `echo '${ESC}[2J${ESC}[Hspoofed' # ${COVER}`;
  const CLEAN = `echo 'spoofed' # ${COVER}`;
  const familyCount = (text) => text.split(FAMILY).length - 1;

  it("strips the escapes and keeps every emoji, in-process", async () => {
    assert.equal(familyCount(COMMAND), 10);
    const fields = await buildPreToolUseResponse(
      { tool_name: "Bash", tool_input: { command: COMMAND } },
      () => null,
      () => {},
    );
    assert.equal(fields?.permissionDecision, undefined);
    assert.equal(fields?.updatedInput?.command, CLEAN);
  });

  it("emits the sanitized command from the CLI under the default posture", () => {
    const env = { ...process.env, CLAUDE_PROJECT_DIR: projectDir };
    delete env.AGENT_SANITIZER_FAIL_OPEN;
    const run = spawnSync(
      process.execPath,
      [
        fileURLToPath(
          new URL("../claude-hooks/pretooluse-sanitize.mjs", import.meta.url),
        ),
      ],
      {
        input: JSON.stringify({
          hook_event_name: "PreToolUse",
          session_id: "pipeline-family-emoji",
          tool_name: "Bash",
          tool_input: { command: COMMAND },
        }),
        env,
        encoding: "utf8",
      },
    );
    assert.equal(run.status, 0, run.stderr);
    // No error output. The slow-hook notice is the one stderr line a loaded
    // machine legitimately adds to a correct run (the hook crossed its 1s
    // budget), so it is carved out here and nothing else is.
    assert.equal(
      run.stderr.replace(/^agent-sanitizer PERFORMANCE: .*\n/gmu, ""),
      "",
    );
    const out = JSON.parse(run.stdout).hookSpecificOutput;
    assert.equal(out.updatedInput.command, CLEAN);
    assert.equal(out.permissionDecision, undefined);
    assert.doesNotMatch(out.additionalContext, /UNSANITIZED/u);
  });

  describe("a stage that never settles goes through the hook's fault posture", () => {
    // `grow` rewrites its input on every pass, so no pass count settles it, and
    // its output is distinguishable from the raw input — the open path must
    // carry THAT, not the raw value.
    const grow = {
      name: "grow",
      erases: false,
      skipBased: true,
      run: (_tool, input) => ({
        updatedInput: { command: `${input.command}x` },
        context: "grow",
      }),
    };
    const eraseNothing = {
      name: "erase",
      erases: true,
      skipBased: false,
      run: () => null,
    };
    const respond = async (env) => {
      const saved = process.env.AGENT_SANITIZER_FAIL_OPEN;
      if (env === undefined) delete process.env.AGENT_SANITIZER_FAIL_OPEN;
      else process.env.AGENT_SANITIZER_FAIL_OPEN = env;
      try {
        return await buildPreToolUseResponse(
          { tool_name: "Bash", tool_input: { command: "a" } },
          undefined,
          () => {},
          [grow, eraseNothing],
        );
      } finally {
        if (saved === undefined) delete process.env.AGENT_SANITIZER_FAIL_OPEN;
        else process.env.AGENT_SANITIZER_FAIL_OPEN = saved;
      }
    };
    const reason = nonConvergenceReason(["grow"]);

    it("OPEN (the default): proceeds with the last pass's sanitized input and warns", async () => {
      const fields = await respond(undefined);
      // No verdict: the call proceeds.
      assert.equal(fields?.permissionDecision, undefined);
      assert.equal(fields?.permissionDecisionReason, undefined);
      // The sanitized value of the last pass, never the raw "a".
      assert.equal(
        fields?.updatedInput.command,
        `a${"x".repeat(MAX_PIPELINE_PASSES)}`,
      );
      assert.match(
        fields?.additionalContext,
        /WARNING: the pretooluse-sanitize hook failed/u,
      );
      assert.ok(fields?.additionalContext.includes(reason));
    });

    it("CLOSED (AGENT_SANITIZER_FAIL_OPEN=0): the policy's closed verdict, naming the reason", async () => {
      const fields = await respond("0");
      assert.equal(fields?.permissionDecision, "ask");
      assert.ok(fields?.permissionDecisionReason.includes(reason));
      // Still the sanitized value, never the raw input, if the user approves.
      assert.equal(
        fields?.updatedInput.command,
        `a${"x".repeat(MAX_PIPELINE_PASSES)}`,
      );
    });
  });
});

describe("the secret rehydrator stage follows the run's opt-in", () => {
  it("is dropped from the table when no rehydrator is bound", () => {
    assert.deepEqual(
      preToolUseLayers(null, {}).map((l) => l.name),
      ["confusables", "authored-content", "layer2-rehydrate"],
    );
  });
});

describe("THREAT-MODEL.md's declared stage orders are the executed ones", () => {
  // The ordering claims are data in THREAT-MODEL.md, asserted here against what
  // runs: an order the docs state but the code does not follow — the false
  // "Layer 4 runs before sanitizeAuthoredContent" claim — fails this suite.
  const threatModel = readFileSync(
    new URL("../THREAT-MODEL.md", import.meta.url),
    "utf8",
  ).replace(/\s+/gu, " ");
  /** The `→`-separated list THREAT-MODEL.md declares after `label`. */
  const declared = (label) => {
    const at = threatModel.indexOf(label);
    assert.notEqual(at, -1, `THREAT-MODEL.md lost its "${label}" line`);
    const rest = threatModel.slice(at + label.length);
    return rest
      .slice(0, rest.search(/[.,]/u))
      .split("→")
      .map((step) => step.trim().replaceAll("`", ""));
  };

  it("PreToolUse: the declared stage table, in order", () => {
    assert.deepEqual(
      declared("PreToolUse stage order:"),
      preToolUseLayers(async () => null, {}).map((layer) => layer.name),
    );
  });

  it("PostToolUse: every adjacent pair of the declared layer order is observed", async () => {
    const { sanitizeText: engineSanitizeText } =
      await import("../src/output.mjs");
    // A comment opener split by a zero-width space is HTML only once Layer 1
    // has removed it; the secret and the span exist to be seen by the seams.
    const ZW = String.fromCharCode(0x200b);
    const input = `keep <!-${ZW}- hidden note --> TOKEN123 tail DELETE-ME`;
    const redactSaw = [];
    const filterSaw = [];
    await engineSanitizeText(input, {
      html: true,
      exfilScan: true,
      redact: (text) => {
        redactSaw.push(text);
        return text.includes("TOKEN123")
          ? { text: text.replace("TOKEN123", "[REDACTED: t]"), found: ["T"] }
          : null;
      },
      filterInjection: (text) => {
        filterSaw.push(text);
        return { removeSpans: ["DELETE-ME"] };
      },
    });
    const [firstRedact, rescan] = redactSaw;
    /** One observation per ordered pair the pipeline can be asked about. */
    const observed = {
      // The spliced comment was only recognizable after Layer 1 removed the
      // zero-width space inside its opener.
      "1→2–3": !firstRedact.includes(ZW) && !firstRedact.includes("hidden"),
      // Layer 4 saw Layer 2's placeholder, not the comment.
      "2–3→4": firstRedact.includes("[HTML comment removed #"),
      // Layer 5 saw Layer 4's redaction, never the raw secret.
      "4→5":
        filterSaw.length === 1 &&
        filterSaw[0].includes("[REDACTED: t]") &&
        !filterSaw[0].includes("TOKEN123"),
      // Layer 4 re-scanned what Layer 5's deletion left.
      "5→4": rescan !== undefined && !rescan.includes("DELETE-ME"),
    };
    const order = declared("Layer order:");
    const pairs = order.slice(1).map((step, i) => `${order[i]}→${step}`);
    assert.deepEqual(pairs, Object.keys(observed));
    for (const pair of pairs)
      assert.ok(observed[pair], `not observed: ${pair}`);
  });
});
