/**
 * The injectable trace sink on every hook.
 *
 * Every hook announces that it ENGAGED on the trace channel, so a missing
 * announcement is loud — that is the point of the channel. But the default sink
 * is keyed to `_AGENT_SANITIZER_TRACE` / `_AGENT_SANITIZER_TRACE_FILE`, and a
 * host that already runs a trace channel under ITS OWN variables, with a
 * detector that reds when a defense layer stops announcing itself, would be
 * adopting a hook whose announcement lands on a channel nothing reads: the layer
 * looks disengaged while working fine. So each hook's entry point takes a sink.
 *
 * Two properties per hook, and the second is the load-bearing one:
 *
 *   - INERT BY DEFAULT. No sink supplied → the announcement still lands on the
 *     package's own channel, byte-identically to before the seam existed.
 *   - IT MOVES, IT DOES NOT COPY. A supplied sink receives the announcement and
 *     the package channel receives NOTHING. A seam that merely forked the event
 *     onto a second channel would leave the host's detector satisfied while the
 *     package kept writing to a file the host never configured.
 *
 * Both are asserted for every hook member-by-member rather than for a
 * representative one: the threading is hand-written per hook (an options bag
 * here, an extension bag there), so a hook that drops the sink is exactly the
 * regression this file exists to catch. A third case per hook covers the sink
 * THROWING, which host code is free to do and the announcement sites were written
 * assuming it never would.
 */
import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { Readable } from "node:stream";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { withCapturedStdout } from "./helpers/capture-stdout.mjs";

// An empty project dir: the SessionStart scanner walks CLAUDE_PROJECT_DIR and
// REWRITES contaminated instruction files, so pointing it at this repo would let
// the test edit the tree. Set before the hook imports — invisible-alert.mjs
// resolves the project dir at module load.
const projectDir = mkdtempSync(join(tmpdir(), "sanitizer-trace-proj-"));
process.env.CLAUDE_PROJECT_DIR = projectDir;
process.env._AGENT_SANITIZER_TRACE = "info";

const { TraceEvent, hookTrace, trace } =
  await import("../claude-hooks/lib/trace.mjs");
const { SLOW_HOOK_THRESHOLD_MS } =
  await import("../claude-hooks/lib/hook-timing.mjs");
const preToolUse = await import("../claude-hooks/pretooluse-sanitize.mjs");
const sanitizeOutput = await import("../claude-hooks/sanitize-output.mjs");
const userPrompt = await import("../claude-hooks/sanitize-user-prompt.mjs");
const scanInvisible = await import("../claude-hooks/scan-invisible-chars.mjs");
const scanLoaded = await import("../claude-hooks/scan-loaded-instructions.mjs");
const { instructionsLoadedFile } =
  await import("../claude-hooks/lib/invisible-alert.mjs");

// The InstructionsLoaded event names a file and carries none of its bytes, so
// the hook reads the path; an absent one would run its fault posture rather than
// the clean path these cases assert the announcement for.
const loadedFile = join(projectDir, "packages", "foo", "CLAUDE.md");
mkdirSync(join(loadedFile, ".."), { recursive: true });
writeFileSync(loadedFile, "# Foo\n\nordinary, clean prose\n");

const traceDir = mkdtempSync(join(tmpdir(), "sanitizer-trace-"));
let traceFileSeq = 0;

/**
 * Point the package's default sink at a fresh file and return its path, so each
 * case reads only its own run's lines.
 */
function freshTraceFile() {
  traceFileSeq += 1;
  const path = join(traceDir, `trace-${traceFileSeq}.jsonl`);
  process.env._AGENT_SANITIZER_TRACE_FILE = path;
  return path;
}

/** The JSON lines the package's default sink wrote to `path`. */
function packageChannel(path) {
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

/**
 * Run `fn` with `payload` as the process's stdin — the stdin hooks read the real
 * stream. Stdout is `quietly`'s job, for every hook alike.
 * @param {unknown} payload
 * @param {() => Promise<void>} fn
 */
async function withStdin(payload, fn) {
  const stdin = Object.getOwnPropertyDescriptor(process, "stdin");
  Object.defineProperty(process, "stdin", {
    value: Readable.from([Buffer.from(JSON.stringify(payload))]),
    configurable: true,
  });
  try {
    await fn();
  } finally {
    if (stdin) Object.defineProperty(process, "stdin", stdin);
  }
}

/**
 * One entry per hook: how to run it with and without a host sink, and what its
 * announcement looks like.
 * `envelopeOnly` marks a hook with no verdict to fold a timing notice into, so
 * its response envelope is the only route its attribution takes to the model.
 * @type {Array<{
 *   name: string,
 *   event: string,
 *   envelopeOnly?: boolean,
 *   run: (sink?: import("../claude-hooks/lib/trace.mjs").TraceFn) => Promise<void>,
 * }>}
 */
const HOOKS = [
  {
    name: "pretooluse-sanitize",
    event: TraceEvent.HOOK_RAN,
    run: (sink) =>
      withStdin(
        {
          hook_event_name: "PreToolUse",
          tool_name: "Bash",
          tool_input: { command: "echo hi" },
        },
        () =>
          sink ? preToolUse.cliMain({ trace: sink }) : preToolUse.cliMain(),
      ),
  },
  {
    name: "sanitize-output",
    event: TraceEvent.HOOK_RAN,
    run: (sink) =>
      withStdin(
        {
          hook_event_name: "PostToolUse",
          tool_name: "Bash",
          tool_input: {},
          tool_response: "plain output",
        },
        () =>
          sink
            ? sanitizeOutput.cliMain({ trace: sink })
            : sanitizeOutput.cliMain(),
      ),
  },
  {
    name: "sanitize-user-prompt",
    event: TraceEvent.HOOK_RAN,
    run: (sink) => {
      const read = () => ({
        hook_event_name: "UserPromptSubmit",
        prompt: "hello",
      });
      const write = () => {};
      return sink
        ? userPrompt.main(read, write, { trace: sink })
        : userPrompt.main(read, write);
    },
  },
  {
    name: "scan-invisible-chars",
    event: TraceEvent.SCAN_INVISIBLE_CHARS_RAN,
    envelopeOnly: true,
    run: (sink) =>
      sink ? scanInvisible.cliMain({ trace: sink }) : scanInvisible.cliMain(),
  },
  {
    name: "scan-loaded-instructions",
    event: TraceEvent.SCAN_LOADED_INSTRUCTIONS_RAN,
    envelopeOnly: true,
    run: (sink) =>
      withStdin(
        {
          hook_event_name: "InstructionsLoaded",
          file_path: loadedFile,
          load_reason: "nested_traversal",
        },
        () =>
          sink ? scanLoaded.cliMain({ trace: sink }) : scanLoaded.cliMain(),
      ),
  },
];

// Every hook run goes through here, so a new HOOKS entry cannot arrive with its
// stdout unguarded: a hook writes its response envelope to stdout, which under
// `--test-reporter=tap` is the stream this suite's own result is parsed from.
/** @param {(sink?: import("../claude-hooks/lib/trace.mjs").TraceFn) => Promise<void>} run
 *  @param {import("../claude-hooks/lib/trace.mjs").TraceFn} [sink] */
const quietly = (run, sink) => withCapturedStdout(() => run(sink));

for (const hook of HOOKS) {
  describe(hook.name, () => {
    it("announces on the package channel when no sink is supplied", async () => {
      const file = freshTraceFile();
      await quietly(hook.run);
      const events = packageChannel(file);
      assert.equal(events.length, 1);
      assert.equal(events[0].event, hook.event);
    });

    it("announces on an injected sink and NOT on the package channel", async () => {
      const file = freshTraceFile();
      /** @type {Array<[string, Record<string, unknown> | undefined]>} */
      const host = [];
      await quietly(hook.run, (event, fields) => host.push([event, fields]));
      // The host sees the same event name the default emits, so a detector can
      // key on TraceEvent rather than on this package's file format.
      assert.deepEqual(
        host.map(([event]) => event),
        [hook.event],
      );
      assert.deepEqual(packageChannel(file), []);
    });

    it("survives a host sink that throws", async () => {
      freshTraceFile();
      // Host code carries no never-throws contract, and the announcement sites
      // were placed under one — see bestEffortTrace, which is what makes this
      // hold. scan-invisible-chars gets the assertion with teeth below.
      await assert.doesNotReject(() =>
        quietly(hook.run, () => {
          throw new Error("host channel down");
        }),
      );
    });
  });
}

// A host sink that WAITS without computing, which is the shape the slow-hook
// notice's host window exists to name: `Atomics.wait` blocks this thread and
// burns no CPU, exactly as a sink writing to an unanswered socket does. Past the
// budget, so the run it is injected into reports.
const HOST_SINK_WAIT_MS = SLOW_HOOK_THRESHOLD_MS + 100;
const block = (ms) =>
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

/**
 * A sink that records the events it is handed and then waits.
 * @param {string[]} seen  filled with each event name as it arrives
 */
const waitingSink = (seen) => (event) => {
  seen.push(event);
  block(HOST_SINK_WAIT_MS);
};

/**
 * Run `fn` with `process.stderr` collected. Every hook writes the slow-hook
 * notice there whatever verdict channel it also rides, so it is the one place a
 * case below can read it for all five hooks alike. The `write` PROPERTY is safe
 * to patch here (see
 * capture-stdout.mjs for why stdout is not): node:test reports on stdout.
 * @template T
 * @param {() => Promise<T>} fn
 * @returns {Promise<{ result: T, stderr: string }>}
 */
async function withCapturedStderr(fn, slowLines = () => false) {
  /** @type {string[]} */
  const chunks = [];
  const real = process.stderr.write;
  // @ts-expect-error -- narrower than the overloaded write signature.
  process.stderr.write = (chunk) => {
    const line = String(chunk);
    chunks.push(line);
    if (slowLines(line)) block(HOST_SINK_WAIT_MS);
    return true;
  };
  try {
    return { result: await fn(), stderr: chunks.join("") };
  } finally {
    process.stderr.write = real;
  }
}

/** A trace line from the package's own sink, which writes one JSON object. */
const isTraceLine = (line) => line.includes(`"event":"`);

// Threaded by hand per hook, like the sink itself, so every hook is asserted
// rather than one standing in for the rest.
describe("a host sink's wait is charged to the host window", () => {
  for (const hook of HOOKS)
    it(`${hook.name} names the host extension, not itself`, async () => {
      freshTraceFile();
      /** @type {string[]} */
      const seen = [];
      const {
        result: { stdout },
        stderr,
      } = await withCapturedStderr(() => quietly(hook.run, waitingSink(seen)));
      // The announcement reached the sink, so the wait asserted below is the
      // sink's and the hook ran its clean path. A hook that faulted before
      // announcing waits for nothing, and its notice — which this case would
      // otherwise read as the finding — names no window at all.
      assert.deepEqual(seen, [hook.event]);
      // The number, then the verdict: an uncharged host window reads 0.0s and
      // hands the same wait to the "blocked on a loaded machine" arm, which
      // sends the reader to their own machine for a cost their sink spent —
      // and bills the sink's own in-process CPU to the sanitizer.
      assert.match(stderr, /[1-9]\d*\.\ds was inside host extensions/);
      assert.match(
        stderr,
        /The largest share was spent inside a host extension/,
      );
      if (!hook.envelopeOnly) return;
      // One envelope: these hooks fold the notice INTO their own response
      // rather than emitting a second, so a parse that throws here is a real
      // regression in that merge and not a loose assertion.
      const { additionalContext } = JSON.parse(stdout).hookSpecificOutput;
      // Every window MEASURED, so the notice rules the empty ones out rather
      // than listing them as candidates it cannot separate.
      assert.match(additionalContext, /0\.0s was inside redactor round trips/);
      assert.match(additionalContext, /hook name and all four timings/);
    });

  // One hook, unlike the cases above: the wrap order lives inside hookTrace,
  // which all five share, so a second hook would re-assert the same binder.
  it("charges a host sink that waits and then THROWS", async () => {
    freshTraceFile();
    /** @type {string[]} */
    const seen = [];
    // The charge is booked in chargeHostExtensionSync's `finally`, so a sink
    // that spends its wait and THEN throws is measured before best-effort
    // swallows the throw. Booked on the success path instead, the sink that
    // spent the most is the one sink the notice cannot see.
    const { stderr } = await withCapturedStderr(() =>
      quietly(HOOKS[0].run, (event, fields, level) => {
        waitingSink(seen)(event, fields, level);
        throw new Error("host channel down");
      }),
    );
    assert.deepEqual(seen, [HOOKS[0].event]);
    assert.match(stderr, /[1-9]\d*\.\ds was inside host extensions/);
  });
});

// The other half of the same claim, and the one a wrapper that RESOLVES the
// default sink before the binding breaks: this package's own trace write is the
// sanitizer's own work, so charging it would blame a composer for a cost no
// composer paid.
describe("the package's own sink is never charged as a host extension", () => {
  it("hands the default back unwrapped, so nothing can charge it", () => {
    assert.equal(hookTrace(undefined), trace);
  });

  for (const hook of HOOKS)
    it(`${hook.name} leaves the host window empty with no sink`, async () => {
      // No trace FILE, so the package sink writes its line to stderr — where
      // this case makes that one write block past the budget. Any hook that
      // charged its own sink would report the wait as a host extension.
      delete process.env._AGENT_SANITIZER_TRACE_FILE;
      const { stderr } = await withCapturedStderr(
        () => quietly(hook.run),
        isTraceLine,
      );
      // The line that blocked, so the budget was spent inside the package's own
      // sink and not somewhere a faulting hook stopped short of.
      assert.match(stderr, new RegExp(`"event":"${hook.event}"`));
      assert.match(stderr, /0\.0s was inside host extensions/);
      assert.doesNotMatch(
        stderr,
        /The largest share was spent inside a host extension/,
      );
    });
});

// The one hook where a throwing sink costs more than an announcement: its
// announcement runs BEFORE the auto-clean and the alert write, with no catch
// above it, so an abort here leaves the payload on disk and the PreToolUse gate
// un-armed — and says so on no channel at all. Asserted on the work, not on the
// absence of a throw. Runs last: it contaminates the shared project dir the
// cases above rely on being clean.
describe("scan-invisible-chars with a throwing sink", () => {
  it("still cleans the contaminated instruction file", async () => {
    // Tag characters (U+E0041…) — a long enough run to clear the finding
    // threshold, and the file is auto-cleanable, so the scan reaches the write.
    const payload = Array.from({ length: 40 }, (_, i) =>
      String.fromCodePoint(0xe0041 + (i % 26)),
    ).join("");
    const file = join(projectDir, "CLAUDE.md");
    writeFileSync(file, `# Project\n\nhello${payload}world\n`);

    const stderr = process.stderr.write;
    // @ts-expect-error -- narrower than the overloaded write signature.
    process.stderr.write = () => true;
    try {
      await quietly(
        (sink) => scanInvisible.cliMain({ trace: sink }),
        () => {
          throw new Error("host channel down");
        },
      );
    } finally {
      process.stderr.write = stderr;
    }

    assert.equal(readFileSync(file, "utf8").includes(payload), false);
  });
});

after(() => {
  for (const dir of [traceDir, projectDir])
    rmSync(dir, { recursive: true, force: true });
  // The InstructionsLoaded run writes its support marker under $TMPDIR, outside
  // both dirs above; left behind it answers "does this host emit the event" for
  // a later run keyed to the same project hash.
  rmSync(instructionsLoadedFile(), { force: true });
});
