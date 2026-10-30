/**
 * A hook run writes at most ONE JSON document to stdout.
 *
 * Claude Code parses a hook's stdout as a single document. The two SessionStart /
 * InstructionsLoaded scans each wrote their own envelope (a fault, the
 * unreadable-file notice, a finding) and then the timing wrapper's `finally`
 * wrote a SECOND one for a slow run; two concatenated objects are invalid hook
 * output, the host drops the response, and the model never learns that
 * instructions were not checked. These cases drive each `cliMain` through a run
 * that is both partial/finding AND over the slow-hook budget, and assert that
 * stdout parses as exactly one object carrying BOTH notices.
 */
import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { Readable } from "node:stream";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { withCapturedStdout } from "./helpers/capture-stdout.mjs";

const projectDir = mkdtempSync(join(tmpdir(), "sanitizer-envelope-proj-"));
process.env.CLAUDE_PROJECT_DIR = projectDir;
delete process.env._AGENT_SANITIZER_TRACE;
delete process.env.AGENT_SANITIZER_FAIL_OPEN;

const { SLOW_HOOK_THRESHOLD_MS } =
  await import("../claude-hooks/lib/hook-timing.mjs");
const { createEnvelopeBuffer } =
  await import("../claude-hooks/lib/hook-io.mjs");
const scanInvisible = await import("../claude-hooks/scan-invisible-chars.mjs");
const scanLoaded = await import("../claude-hooks/scan-loaded-instructions.mjs");
const { alertDir } = scanInvisible;

after(() => {
  rmSync(projectDir, { recursive: true, force: true });
  rmSync(alertDir(), { recursive: true, force: true });
});

// A trace sink that WAITS without computing: the host-extension window is what
// the slow-hook notice attributes it to, and it clears the budget by itself.
const block = (ms) =>
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
const slowSink = () => block(SLOW_HOOK_THRESHOLD_MS + 100);

const SLOW = /PERFORMANCE: the [\w-]+ hook took/u;

/** Silence stderr for `fn`; the hooks narrate there and the runner owns stdout. */
async function quietStderr(fn) {
  const real = process.stderr.write;
  // @ts-expect-error -- narrower than the overloaded write signature.
  process.stderr.write = () => true;
  const exitCode = process.exitCode;
  try {
    return await fn();
  } finally {
    process.stderr.write = real;
    process.exitCode = exitCode;
  }
}

/** Parse stdout as exactly one JSON document (JSON.parse rejects `{}{}`). */
const single = (stdout) => JSON.parse(stdout);

describe("createEnvelopeBuffer", () => {
  it("writes nothing when nothing was added", () => {
    const writes = [];
    createEnvelopeBuffer((chunk) => writes.push(chunk)).flush();
    assert.deepEqual(writes, []);
  });

  it("folds every added envelope into one write, joining the message slots", () => {
    const writes = [];
    const out = createEnvelopeBuffer((chunk) => writes.push(chunk));
    out.add({
      systemMessage: "gap",
      hookSpecificOutput: {
        hookEventName: "SessionStart",
        additionalContext: "gap",
      },
    });
    out.emit("SessionStart", { additionalContext: "slow" });
    out.flush();
    out.flush();
    assert.equal(writes.length, 1);
    assert.deepEqual(JSON.parse(writes[0]), {
      systemMessage: "gap",
      hookSpecificOutput: {
        hookEventName: "SessionStart",
        additionalContext: "gap\nslow",
      },
    });
  });
});

describe("scan-invisible-chars: unreadable file + slow run", () => {
  const partial = {
    targets: ["CLAUDE.md"],
    scanned: 0,
    findings: [],
    skipped: [{ file: "CLAUDE.md", reason: "EACCES: permission denied" }],
    absent: [],
  };

  it("emits one envelope carrying the gap notice AND the slow-hook notice", async () => {
    const { stdout } = await quietStderr(() =>
      withCapturedStdout(() =>
        scanInvisible.cliMain({ trace: slowSink, scan: () => partial }),
      ),
    );
    const envelope = single(stdout);
    const context = envelope.hookSpecificOutput.additionalContext;
    assert.equal(envelope.hookSpecificOutput.hookEventName, "SessionStart");
    assert.match(context, /INSTRUCTION FILES NOT SCANNED/u);
    assert.match(context, /CLAUDE\.md: EACCES/u);
    assert.match(context, SLOW);
    assert.match(envelope.systemMessage, /INSTRUCTION FILES NOT SCANNED/u);
  });

  it("still emits the gap notice alone when the run is fast", async () => {
    const { stdout } = await quietStderr(() =>
      withCapturedStdout(() => scanInvisible.cliMain({ scan: () => partial })),
    );
    const context = single(stdout).hookSpecificOutput.additionalContext;
    assert.match(context, /INSTRUCTION FILES NOT SCANNED/u);
    assert.doesNotMatch(context, SLOW);
  });

  it("emits the slow-hook notice alone when the scan is clean", async () => {
    const { stdout } = await quietStderr(() =>
      withCapturedStdout(() =>
        scanInvisible.cliMain({
          trace: slowSink,
          scan: () => ({ ...partial, skipped: [], scanned: 1 }),
        }),
      ),
    );
    const context = single(stdout).hookSpecificOutput.additionalContext;
    assert.match(context, SLOW);
    assert.doesNotMatch(context, /NOT SCANNED/u);
  });
});

describe("scan-loaded-instructions: finding + slow run", () => {
  const loadedFile = join(projectDir, "packages", "foo", "CLAUDE.md");
  mkdirSync(join(loadedFile, ".."), { recursive: true });

  it("emits one envelope carrying the finding AND the slow-hook notice", async () => {
    // Tag characters: a run long enough to clear the finding threshold.
    const payload = Array.from({ length: 40 }, (_, i) =>
      String.fromCodePoint(0xe0041 + (i % 26)),
    ).join("");
    writeFileSync(loadedFile, `# Foo\n\nhello${payload}world\n`);
    const stdin = Object.getOwnPropertyDescriptor(process, "stdin");
    Object.defineProperty(process, "stdin", {
      value: Readable.from([
        Buffer.from(
          JSON.stringify({
            hook_event_name: "InstructionsLoaded",
            session_id: "single-envelope",
            file_path: loadedFile,
            load_reason: "nested_traversal",
          }),
        ),
      ]),
      configurable: true,
    });
    let stdout;
    try {
      ({ stdout } = await quietStderr(() =>
        withCapturedStdout(() => scanLoaded.cliMain({ trace: slowSink })),
      ));
    } finally {
      if (stdin) Object.defineProperty(process, "stdin", stdin);
    }
    const envelope = single(stdout);
    const context = envelope.hookSpecificOutput.additionalContext;
    assert.equal(
      envelope.hookSpecificOutput.hookEventName,
      "InstructionsLoaded",
    );
    assert.match(context, /hidden|invisible|Unicode/iu);
    assert.match(context, SLOW);
    assert.equal(typeof envelope.systemMessage, "string");
  });
});
