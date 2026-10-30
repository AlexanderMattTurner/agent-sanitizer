/**
 * Model-based fault fuzzing of the four Claude Code hook entry points, driven
 * in-process through their real CLIs (stdin swapped, stdout captured) across one
 * simulated session per run. fast-check interleaves ordinary calls with injected
 * sanitizer faults — a dead redactor, an unusable confirm / ack / span store, a
 * deleted span, an unreadable target or CLAUDE.md, a malformed payload — and a
 * model of the session predicts which calls fault. Checked after EVERY command:
 *
 *   - DEFAULT posture: nothing asks but the gate's one-time ask on a genuine
 *     instruction-file finding; nothing denies, blocks, suppresses or exits 2
 *     except a releasable refusal of a predicted fault; a faulting call that
 *     proceeds carries a warning; an exact re-issue of a refused call is never
 *     refused again for the same reason, a refusal chain is bounded by the
 *     refusing stages, and nothing is refused while the confirm store is unusable.
 *   - AGENT_SANITIZER_FAIL_OPEN=0: every predicted fault IS refused, never with
 *     the re-issue escape — the marker that keeps the default property from
 *     passing on a fault injector that injects nothing.
 *   - both: the fault prediction is exact (an unpredicted fault fails the run),
 *     and every entry point settles instead of rejecting.
 * Root-proof faults only (CI runs as root): a path under a regular FILE, or a
 * directory where a file belongs, never a chmod.
 */
import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { Readable, Writable } from "node:stream";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import fc from "fast-check";
import { fcRunOptions } from "./test-helpers.mjs";

// Fixture layout, set before the hooks import: the project dir, the state root
// (via CLAUDE_PLUGIN_DATA) and the redactor socket are all resolved at load.
const root = mkdtempSync(join(tmpdir(), "sanitizer-fault-model-"));
const projectDir = join(root, "proj");
mkdirSync(projectDir);
const pluginData = join(root, "data");
mkdirSync(pluginData, { mode: 0o700 });
const BLOCKER = join(root, "blocker");
writeFileSync(BLOCKER, "");
/** A directory path no uid can create or list: its parent is a regular file. */
const UNUSABLE_DIR = join(BLOCKER, "dir");
const SOCKET = join(root, "redactor.sock");
/** An ancestor of the project: scanned at launch, never auto-cleaned. */
const ANCESTOR_CLAUDE_MD = join(root, "CLAUDE.md");
const PROJECT_CLAUDE_MD = join(projectDir, "CLAUDE.md");
Object.assign(process.env, {
  CLAUDE_PROJECT_DIR: projectDir,
  CLAUDE_PLUGIN_DATA: pluginData,
  // The DEAD_REDACTOR shape of plugin/test/plugin-bundle.test.mjs: no socket, a
  // daemon binary that does not exist, and short waits.
  _AGENT_SANITIZER_REDACTOR_SOCKET: SOCKET,
  _AGENT_SANITIZER_REDACTOR_DAEMON: join(root, "no-such-redactor-daemon"),
  _AGENT_SANITIZER_REDACTOR_WAIT_MS: "1",
  _AGENT_SANITIZER_REDACTOR_REQUEST_MS: "300",
});
delete process.env.AGENT_SANITIZER_FAIL_OPEN;
delete process.env.AGENT_SANITIZER_SECRETS_ENABLED;
after(() => rmSync(root, { recursive: true, force: true }));

const preToolUse = await import("../claude-hooks/pretooluse-sanitize.mjs");
const sanitizeOutput = await import("../claude-hooks/sanitize-output.mjs");
const userPrompt = await import("../claude-hooks/sanitize-user-prompt.mjs");
const scanInvisible = await import("../claude-hooks/scan-invisible-chars.mjs");
const { invisibleCharAlert, alertAckFile } =
  await import("../claude-hooks/lib/invisible-alert.mjs");
const { LAYER2_PLACEHOLDER_RE } =
  await import("../claude-hooks/lib/placeholder-grammar.mjs");

const REDACTED = "[REDACTED: Secret]";
/** A well-formed Layer-2 placeholder whose key no store ever holds. */
const MISSING_PH = "[hidden HTML removed #deadbeef0000]";
const AWS_EXAMPLE_KEY = ["AKIA", "IOSFODNN7EXAMPLE"].join("");
const TAG_RUN = String.fromCodePoint(0xe0041).repeat(40);
const REISSUE_NOTE = /re-issue this exact call/u;
const GATE_ASK =
  /^agent-sanitizer: the session-start scan of this project's instruction files did not finish clean\./u;
const GATE_ACK_WARNING =
  /could not record that its instruction-file alert was shown/u;
/** A sanitizer fault the call proceeded past: the hook's or a stage's warning. */
const FAULT_WARNING = /UNSANITIZED|proceed unchanged \(fail-open\)/u;
const SUPPRESSED = /SANITIZATION FAILED/u;
/** hook-fault, rehydrate and layer2-rehydrate: the sites that refuse once. */
const MAX_REFUSALS_PER_CALL = 3;
const HIDDEN_TEXTS = [
  "footnote seven",
  "draft margin note",
  "aside for editors",
];

/**
 * Run one hook entry point with `stdinText` as its stdin and its stdout, stderr
 * and exit code captured — the `process.stdout` PROPERTY is swapped, as in
 * helpers/capture-stdout.mjs, so the TAP stream is never touched.
 * @param {() => Promise<unknown>} fn
 * @param {string} [stdinText]
 */
async function drive(fn, stdinText = "") {
  const out = [];
  const realStdout = Object.getOwnPropertyDescriptor(process, "stdout");
  const realStdin = Object.getOwnPropertyDescriptor(process, "stdin");
  const realStderrWrite = process.stderr.write;
  Object.defineProperty(process, "stdout", {
    configurable: true,
    value: new Writable({
      write(chunk, _encoding, done) {
        out.push(String(chunk));
        done();
      },
    }),
  });
  Object.defineProperty(process, "stdin", {
    configurable: true,
    value: Readable.from([Buffer.from(stdinText)]),
  });
  process.stderr.write = () => true;
  process.exitCode = undefined;
  let threw;
  let exitCode;
  try {
    await fn();
    exitCode = process.exitCode;
  } catch (err) {
    threw = err;
  } finally {
    Object.defineProperty(process, "stdout", realStdout);
    Object.defineProperty(process, "stdin", realStdin);
    process.stderr.write = realStderrWrite;
    process.exitCode = undefined;
  }
  assert.equal(threw, undefined, `the hook entry point rejected: ${threw}`);
  assert.notEqual(exitCode, 2, "a hook exited 2 (blocking)");
  const stdout = out.join("");
  return { stdout, json: stdout === "" ? null : JSON.parse(stdout) };
}

const HOOKS = {
  pre: (/** @type {string} */ raw) => drive(() => preToolUse.cliMain(), raw),
  post: (/** @type {string} */ raw) =>
    drive(() => sanitizeOutput.cliMain(), raw),
  prompt: (/** @type {string} */ raw) =>
    drive(() =>
      userPrompt.main(
        async () => JSON.parse(raw),
        (chunk) => process.stdout.write(chunk),
      ),
    ),
  sessionStart: (/** @type {string} */ sessionId) =>
    drive(() => scanInvisible.cliMain({ sessionId })),
};

let sessionCount = 0;

/**
 * A fresh simulated session: its own session id, confirm store ($TMPDIR), span
 * store and target file, so no confirmation or span leaks between runs.
 * @param {"open" | "closed"} posture
 * @param {Record<string, number>} stats  outcome counters, shared per property
 */
function openSession(posture, stats) {
  const runDir = mkdtempSync(join(root, "run-"));
  const sessionId = `fault-model-${++sessionCount}`;
  const paths = {
    tmp: join(runDir, "tmp"),
    reveal: join(runDir, "reveal"),
    target: join(runDir, "target.txt"),
    ack: alertAckFile(sessionId),
  };
  mkdirSync(paths.tmp);
  writeFileSync(paths.target, "alpha\nbeta\n");
  const saved = { TMPDIR: process.env.TMPDIR };
  process.env.TMPDIR = paths.tmp;
  process.env._AGENT_SANITIZER_REVEAL_DIR = paths.reveal;
  if (posture === "closed") process.env.AGENT_SANITIZER_FAIL_OPEN = "0";
  const model = {
    posture,
    stats,
    sessionId,
    paths,
    secretsOn: false,
    confirmStoreBroken: false,
    spanStoreBroken: false,
    targetUnreadable: false,
    redactorSquatted: false,
    claudeMdUnreadable: false,
    ackStoreBroken: false,
    ancestorContaminated: false,
    alertArmed: false,
    ackRecorded: false,
    /** Layer-2 placeholders the session has seen, in first-seen order. */
    learned: /** @type {string[]} */ ([]),
    /** Placeholders whose span the healthy store holds. */
    stored: new Set(),
    /** @type {null | { raw: string, faults: () => boolean, refusals: string[] }} */
    lastPre: null,
  };
  const close = () => {
    for (const path of [runDir, ANCESTOR_CLAUDE_MD, PROJECT_CLAUDE_MD, SOCKET])
      rmSync(path, { recursive: true, force: true });
    rmSync(paths.ack, { recursive: true, force: true });
    if (saved.TMPDIR === undefined) delete process.env.TMPDIR;
    else process.env.TMPDIR = saved.TMPDIR;
    delete process.env._AGENT_SANITIZER_REVEAL_DIR;
    delete process.env.AGENT_SANITIZER_FAIL_OPEN;
    delete process.env.AGENT_SANITIZER_SECRETS_ENABLED;
  };
  return { model, close };
}

/** @param {string} name @param {{ check?: (m: any) => boolean, run: (m: any) => Promise<void> | void }} body */
const command = (name, { check = () => true, run }) => ({
  check,
  run,
  toString: () => name,
});

const bump = (/** @type {any} */ model, /** @type {string} */ key) => {
  model.stats[key] = (model.stats[key] ?? 0) + 1;
};

const spanAvailable = (/** @type {any} */ model, /** @type {string} */ ph) =>
  !model.spanStoreBroken && model.stored.has(ph);

/**
 * Judge one PreToolUse response against the model. `faults` is the model's
 * prediction that the sanitizer cannot do its job on this call.
 * @param {any} model
 * @param {string} raw  the exact stdin, identity of the call for re-issue
 * @param {() => boolean} faultsNow
 */
async function preToolUseStep(model, raw, faultsNow) {
  const faults = faultsNow();
  const { json } = await HOOKS.pre(raw);
  const out = json?.hookSpecificOutput ?? {};
  const decision = out.permissionDecision;
  const reason = String(out.permissionDecisionReason ?? "");
  const context = String(out.additionalContext ?? "");
  const reissue = model.lastPre?.raw === raw;
  const priorRefusals = reissue ? model.lastPre.refusals : [];
  const gateIsAsk = (decision === "ask" && GATE_ASK.test(reason)) || false;
  if (gateIsAsk) bump(model, "gateAsks");

  if (model.posture === "open") {
    // (1) No ask but the gate's one-time ask on a genuine finding.
    if (decision === "ask") {
      assert.ok(gateIsAsk, `an ask that is not the gate's: ${reason}`);
      assert.ok(
        model.alertArmed && !model.ackRecorded && !model.ackStoreBroken,
        "the gate asked again after its ask was recorded, or with no ack store",
      );
    }
    if (decision === "deny") {
      // (1) A deny is only ever the releasable refusal of a real fault.
      assert.ok(faults, `a deny with no fault the model knows of: ${reason}`);
      assert.match(reason, REISSUE_NOTE, "a deny with no re-issue escape");
      // (3) With nowhere to record the confirmation, nothing is refused.
      assert.ok(!model.confirmStoreBroken, "refused with no confirm store");
      // (2) No stuck loop: a re-issue is never refused for the same reason.
      assert.ok(
        !priorRefusals.includes(reason),
        `the exact re-issue was refused again for the same reason: ${reason}`,
      );
      assert.ok(
        priorRefusals.length < MAX_REFUSALS_PER_CALL,
        `refused ${priorRefusals.length + 1} times in a row`,
      );
      bump(model, priorRefusals.length > 0 ? "chainedRefusals" : "refusals");
    }
    if (faults && decision !== "deny") {
      assert.match(context, FAULT_WARNING, "a fault proceeded without warning");
      bump(model, "faultWarnings");
      if (/confirmed re-issue/u.test(context)) bump(model, "releasedReissues");
      if (/could not be recorded/u.test(context)) bump(model, "unrecordable");
    }
  } else {
    // A predicted fault IS refused, with no release offered.
    if (faults) {
      assert.ok(
        decision === "deny" || decision === "ask",
        `a fault was let through under FAIL_OPEN=0: ${JSON.stringify(out)}`,
      );
      assert.doesNotMatch(reason, REISSUE_NOTE);
      bump(
        model,
        reissue && priorRefusals.length > 0 ? "reRefused" : "refusals",
      );
    } else if (decision !== undefined) {
      assert.ok(gateIsAsk, `a refusal with no fault: ${reason}`);
    }
  }

  if (!faults) {
    // The prediction is exact: an unpredicted fault is a fault class the model
    // (and so this suite's coverage claim) does not know about.
    assert.equal(decision === "deny", false, `unpredicted deny: ${reason}`);
    assert.doesNotMatch(context, FAULT_WARNING, "an unpredicted fault");
    if (model.alertArmed) checkGate(model, decision, gateIsAsk, context);
  }
  if (gateIsAsk && !model.ackStoreBroken) model.ackRecorded = true;
  model.lastPre = {
    raw,
    faults: faultsNow,
    refusals:
      decision === "deny" || (decision === "ask" && !gateIsAsk)
        ? [...priorRefusals, reason]
        : [],
  };
}

/**
 * The gate on a call nothing else refused: it asks exactly while no ack is
 * recorded, and with no ack store it warns (open) or asks every time (closed).
 */
function checkGate(model, decision, gateIsAsk, context) {
  if (model.ackStoreBroken) {
    if (model.posture === "open") {
      assert.match(context, GATE_ACK_WARNING);
      bump(model, "gateAckWarnings");
    } else assert.ok(gateIsAsk, "the closed gate stopped asking");
    return;
  }
  if (!model.ackRecorded) {
    assert.ok(gateIsAsk, "the armed gate never asked");
    return;
  }
  assert.notEqual(decision, "ask", "the gate asked twice");
  assert.match(context, /Reminder: this project's instruction files/u);
}

/** PreToolUse Edit/Write/Bash carrying plain text, a Layer-2 placeholder, a `[REDACTED`, or both. */
const preCommand = (tool, variant, pick = 0) =>
  command(`Pre(${tool},${variant},${pick})`, {
    run: (model) => {
      const ph =
        model.learned.length > 0
          ? model.learned[pick % model.learned.length]
          : MISSING_PH;
      const body = {
        plain: "gamma",
        layer2: `see ${ph}`,
        redacted: `key=${REDACTED}`,
        both: `key=${REDACTED} ${ph}`,
      }[variant];
      const toolInput = {
        Edit: {
          file_path: model.paths.target,
          old_string: "alpha",
          new_string: body,
        },
        Write: { file_path: model.paths.target, content: `${body}\n` },
        Bash: { command: `printf '%s\\n' '${body}'` },
      }[tool];
      const raw = JSON.stringify({
        hook_event_name: "PreToolUse",
        session_id: model.sessionId,
        tool_name: tool,
        tool_input: toolInput,
      });
      const hasLayer2 = variant === "layer2" || variant === "both";
      // Faults: Layer 4 always does with secrets on (the redactor is dead,
      // or the target is unreadable); Layer 2 does on an unstored span.
      const faults = () =>
        tool !== "Bash" &&
        (model.secretsOn || (hasLayer2 && !spanAvailable(model, ph)));
      return preToolUseStep(model, raw, faults);
    },
  });
const preToolUseCall = fc
  .record({
    tool: fc.constantFrom("Edit", "Write", "Bash"),
    variant: fc.constantFrom("plain", "layer2", "redacted", "both"),
    pick: fc.nat(7),
  })
  .map(({ tool, variant, pick }) => preCommand(tool, variant, pick));

/** The exact re-issue of the previous PreToolUse call. */
const REISSUE = command("Reissue", {
  check: (model) => model.lastPre !== null,
  run: (model) =>
    preToolUseStep(model, model.lastPre.raw, model.lastPre.faults),
});

const malformedCommand = (hook) =>
  command(`Malformed(${hook})`, {
    run: async (model) => {
      if (hook === "pre" || hook === "pre-unknown") {
        const raw =
          hook === "pre"
            ? "{not json"
            : JSON.stringify({
                session_id: model.sessionId,
                tool_name: "Bash",
                tool_input: { command: "ls" },
              });
        await preToolUseStep(model, raw, () => true);
        return;
      }
      const { json } = await HOOKS[hook]("{not json");
      if (model.posture === "open") {
        assert.equal(json.decision, undefined);
        assert.equal(json.hookSpecificOutput.updatedToolOutput, undefined);
        assert.match(json.hookSpecificOutput.additionalContext, /UNSANITIZED/u);
        bump(model, "faultWarnings");
      } else {
        if (hook === "prompt") assert.equal(json.decision, "block");
        else
          assert.match(json.hookSpecificOutput.updatedToolOutput, SUPPRESSED);
        bump(model, "refusals");
      }
    },
  });

const postCommand = (kind, pick = 0) =>
  command(`Post(${kind},${pick})`, {
    run: async (model) => {
      const [tool, response] = {
        plain: ["Bash", "build finished in 3s"],
        secret: ["Bash", `aws_key=${AWS_EXAMPLE_KEY}`],
        web: ["WebFetch", `page <div hidden>${HIDDEN_TEXTS[pick]}</div> end`],
      }[kind];
      const { json } = await HOOKS.post(
        JSON.stringify({
          hook_event_name: "PostToolUse",
          session_id: model.sessionId,
          tool_name: tool,
          tool_input: {},
          tool_response: response,
        }),
      );
      const out = json?.hookSpecificOutput ?? {};
      assert.equal(json?.decision, undefined, "PostToolUse blocked");
      const updated = out.updatedToolOutput;
      if (kind === "secret" && model.secretsOn) {
        if (model.posture === "open") {
          assert.equal(updated, undefined, "a fault suppressed the output");
          assert.match(String(out.additionalContext), /UNSANITIZED/u);
          bump(model, "faultWarnings");
        } else {
          assert.match(String(updated), SUPPRESSED);
          bump(model, "refusals");
        }
        return;
      }
      assert.doesNotMatch(String(out.additionalContext ?? ""), /UNSANITIZED/u);
      if (kind !== "web") {
        assert.equal(updated, undefined, `rewrote ${kind} output`);
        return;
      }
      // Positive marker: web ingress really went through Layer 2.
      const found = [...String(updated).matchAll(LAYER2_PLACEHOLDER_RE)];
      assert.equal(found.length, 1, `no Layer-2 placeholder in ${updated}`);
      const [ph] = found[0];
      if (!model.learned.includes(ph)) model.learned.push(ph);
      if (!model.spanStoreBroken) model.stored.add(ph);
    },
  });

const prompt = fc
  .constantFrom("hello", "please summarize the file")
  .map((text) =>
    command(`Prompt(${text})`, {
      run: async (model) => {
        const { json } = await HOOKS.prompt(
          JSON.stringify({
            hook_event_name: "UserPromptSubmit",
            session_id: model.sessionId,
            prompt: text,
          }),
        );
        assert.equal(json?.decision, undefined, "the prompt was blocked");
        assert.doesNotMatch(JSON.stringify(json ?? {}), /UNSANITIZED/u);
      },
    }),
  );

const SESSION_START = command("SessionStart", {
  run: async (model) => {
    const { stdout } = await HOOKS.sessionStart(model.sessionId);
    model.alertArmed ||=
      model.ancestorContaminated ||
      (model.posture === "closed" && model.claudeMdUnreadable);
    assert.equal(
      invisibleCharAlert(model.sessionId) !== null,
      model.alertArmed,
    );
    if (model.posture === "open" && model.claudeMdUnreadable) {
      assert.match(stdout, /failing open — nothing is blocked/u);
      bump(model, "faultWarnings");
    }
  },
});

/** How each fault (or content) flag is applied on disk or in the env. */
const TOGGLE_APPLY = {
  secretsOn: (_m, on) => {
    if (on) process.env.AGENT_SANITIZER_SECRETS_ENABLED = "1";
    else delete process.env.AGENT_SANITIZER_SECRETS_ENABLED;
  },
  confirmStoreBroken: (m, on) => {
    process.env.TMPDIR = on ? UNUSABLE_DIR : m.paths.tmp;
  },
  spanStoreBroken: (m, on) => {
    process.env._AGENT_SANITIZER_REVEAL_DIR = on
      ? UNUSABLE_DIR
      : m.paths.reveal;
  },
  targetUnreadable: (m, on) => {
    rmSync(m.paths.target, { recursive: true, force: true });
    if (on) mkdirSync(m.paths.target);
    else writeFileSync(m.paths.target, "alpha\nbeta\n");
  },
  // Two dead-redactor shapes: no socket (the daemon spawn fails), or a squatted
  // socket path the client refuses to dial.
  redactorSquatted: (_m, on) => {
    if (on) writeFileSync(SOCKET, "");
    else rmSync(SOCKET, { force: true });
  },
  claudeMdUnreadable: (_m, on) => {
    if (on) mkdirSync(PROJECT_CLAUDE_MD);
    else rmSync(PROJECT_CLAUDE_MD, { recursive: true });
  },
  ackStoreBroken: (m, on) => {
    rmSync(m.paths.ack, { recursive: true, force: true });
    if (on) mkdirSync(m.paths.ack);
    m.ackRecorded = false;
  },
  ancestorContaminated: (_m, on) => {
    if (on) writeFileSync(ANCESTOR_CLAUDE_MD, `notes ${TAG_RUN}\n`);
    else rmSync(ANCESTOR_CLAUDE_MD);
  },
};

/** Flip `flag` in the model and apply it. */
const toggle = (flag) =>
  command(`Toggle(${flag})`, {
    run: (model) => {
      model[flag] = !model[flag];
      TOGGLE_APPLY[flag](model, model[flag]);
    },
  });

const DELETE_SPANS = command("DeleteSpans", {
  run: (model) => {
    rmSync(model.paths.reveal, { recursive: true, force: true });
    model.stored.clear();
  },
});

const COMMANDS = [
  preToolUseCall,
  preToolUseCall,
  preToolUseCall,
  fc.constant(REISSUE),
  fc.constant(REISSUE),
  fc
    .record({
      kind: fc.constantFrom("plain", "secret", "web"),
      pick: fc.nat(2),
    })
    .map(({ kind, pick }) => postCommand(kind, pick)),
  fc.constantFrom("pre", "pre-unknown", "post", "prompt").map(malformedCommand),
  prompt,
  fc.constant(SESSION_START),
  fc.constant(DELETE_SPANS),
  // Two shares for all the toggles together, so faults interleave with calls
  // rather than crowding them out.
  ...Array.from({ length: 2 }, () =>
    fc.constantFrom(...Object.keys(TOGGLE_APPLY)).map(toggle),
  ),
];

/** Hand-written sequences that reach each counted outcome on every run. */
const EXAMPLES = [
  // A hook-fault refusal, then its release.
  [toggle("secretsOn"), preCommand("Write", "redacted"), REISSUE, REISSUE],
  // Two refusing stages on one call (rehydrate, then Layer 2), then release.
  [
    postCommand("web"),
    DELETE_SPANS,
    toggle("secretsOn"),
    toggle("targetUnreadable"),
    preCommand("Edit", "both"),
    REISSUE,
    REISSUE,
  ],
  // Nowhere to record the confirmation: the first call proceeds.
  [
    toggle("confirmStoreBroken"),
    toggle("secretsOn"),
    preCommand("Write", "redacted"),
    preCommand("Edit", "layer2"),
  ],
  // The gate: one ask, a reminder, then an unrecordable ack.
  [
    toggle("ancestorContaminated"),
    SESSION_START,
    preCommand("Bash", "plain"),
    preCommand("Bash", "plain"),
    toggle("ackStoreBroken"),
    preCommand("Bash", "plain"),
    REISSUE,
  ],
  // An unreadable CLAUDE.md, a malformed payload, a secret the dead redactor
  // cannot vet.
  [
    toggle("claudeMdUnreadable"),
    SESSION_START,
    preCommand("Bash", "plain"),
    malformedCommand("pre"),
    malformedCommand("post"),
    toggle("secretsOn"),
    postCommand("secret"),
  ],
].map((cmds) => [cmds]);

/**
 * Check the model-based property under one posture and return its counters.
 * @param {"open" | "closed"} posture
 * @param {number} numRuns
 */
async function checkPosture(posture, numRuns) {
  /** @type {Record<string, number>} */
  const stats = {};
  const property = fc.asyncProperty(
    fc.commands(COMMANDS, { maxCommands: 24, size: "medium" }),
    async (cmds) => {
      const session = openSession(posture, stats);
      try {
        await fc.asyncModelRun(
          () => ({ model: session.model, real: {} }),
          cmds,
        );
      } finally {
        session.close();
      }
    },
  );
  await fc.assert(
    property,
    fcRunOptions({ numRuns, examples: EXAMPLES, includeErrorInReport: true }),
  );
  return stats;
}

describe("hook fault model", () => {
  it("fails open by default: no fault blocks, and no refusal loops", async () => {
    const stats = await checkPosture("open", 150);
    // Non-vacuity: every outcome the invariants judge was actually reached.
    for (const key of [
      "refusals",
      "chainedRefusals",
      "releasedReissues",
      "unrecordable",
      "faultWarnings",
      "gateAsks",
      "gateAckWarnings",
    ])
      assert.ok(
        (stats[key] ?? 0) > 0,
        `never reached ${key}: ${JSON.stringify(stats)}`,
      );
  });

  it("refuses the same faults under AGENT_SANITIZER_FAIL_OPEN=0", async () => {
    const stats = await checkPosture("closed", 80);
    for (const key of ["refusals", "reRefused", "gateAsks"])
      assert.ok(
        (stats[key] ?? 0) > 0,
        `never reached ${key}: ${JSON.stringify(stats)}`,
      );
  });

  // The minimized counterexample the model found, kept as a fixed case:
  // [Toggle(claudeMdUnreadable), Toggle(confirmStoreBroken), SessionStart].
  it("SessionStart still scans when $TMPDIR is unusable", async () => {
    for (const posture of /** @type {const} */ (["open", "closed"])) {
      const session = openSession(posture, {});
      try {
        toggle("claudeMdUnreadable").run(session.model);
        toggle("confirmStoreBroken").run(session.model);
        await SESSION_START.run(session.model);
      } finally {
        session.close();
      }
    }
  });
});
