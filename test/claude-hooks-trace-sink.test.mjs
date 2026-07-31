/**
 * The injectable trace sink on all four hooks.
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
 * Both are asserted for all four hooks member-by-member rather than for a
 * representative one: the threading is hand-written per hook (an options bag
 * here, an extension bag there, a positional parameter in the prompt gate), so a
 * hook that drops the sink is exactly the regression this file exists to catch.
 */
import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { Readable } from "node:stream";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// An empty project dir: the SessionStart scanner walks CLAUDE_PROJECT_DIR and
// REWRITES contaminated instruction files, so pointing it at this repo would let
// the test edit the tree. Set before the hook imports — invisible-alert.mjs
// resolves the project dir at module load.
const projectDir = mkdtempSync(join(tmpdir(), "sanitizer-trace-proj-"));
process.env.CLAUDE_PROJECT_DIR = projectDir;
process.env._AGENT_SANITIZER_TRACE = "info";

const { TraceEvent } = await import("../claude-hooks/lib/trace.mjs");
const preToolUse = await import("../claude-hooks/pretooluse-sanitize.mjs");
const sanitizeOutput = await import("../claude-hooks/sanitize-output.mjs");
const userPrompt = await import("../claude-hooks/sanitize-user-prompt.mjs");
const scanInvisible = await import("../claude-hooks/scan-invisible-chars.mjs");

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
 * Run `fn` with `payload` as the process's stdin and stdout swallowed — the
 * stdin hooks read the real streams, and their rendered response would otherwise
 * be interleaved into this runner's TAP output.
 * @param {unknown} payload
 * @param {() => Promise<void>} fn
 */
async function withStdio(payload, fn) {
  const stdin = Object.getOwnPropertyDescriptor(process, "stdin");
  const stdout = process.stdout.write;
  Object.defineProperty(process, "stdin", {
    value: Readable.from([Buffer.from(JSON.stringify(payload))]),
    configurable: true,
  });
  // @ts-expect-error -- narrower than the overloaded write signature.
  process.stdout.write = () => true;
  try {
    await fn();
  } finally {
    process.stdout.write = stdout;
    if (stdin) Object.defineProperty(process, "stdin", stdin);
  }
}

/**
 * One entry per hook: how to run it with and without a host sink, and what its
 * announcement looks like.
 * @type {Array<{
 *   name: string,
 *   event: string,
 *   run: (sink?: import("../claude-hooks/lib/trace.mjs").TraceFn) => Promise<void>,
 * }>}
 */
const HOOKS = [
  {
    name: "pretooluse-sanitize",
    event: TraceEvent.HOOK_RAN,
    run: (sink) =>
      withStdio(
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
      withStdio(
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
        ? userPrompt.main(read, write, undefined, undefined, sink)
        : userPrompt.main(read, write);
    },
  },
  {
    name: "scan-invisible-chars",
    event: TraceEvent.SCAN_INVISIBLE_CHARS_RAN,
    run: (sink) =>
      sink ? scanInvisible.cliMain({ trace: sink }) : scanInvisible.cliMain(),
  },
];

for (const hook of HOOKS) {
  describe(hook.name, () => {
    it("announces on the package channel when no sink is supplied", async () => {
      const file = freshTraceFile();
      await hook.run();
      const events = packageChannel(file);
      assert.equal(events.length, 1);
      assert.equal(events[0].event, hook.event);
    });

    it("announces on an injected sink and NOT on the package channel", async () => {
      const file = freshTraceFile();
      /** @type {Array<[string, Record<string, unknown> | undefined]>} */
      const host = [];
      await hook.run((event, fields) => host.push([event, fields]));
      // The host sees the same event name the default emits, so a detector can
      // key on TraceEvent rather than on this package's file format.
      assert.deepEqual(
        host.map(([event]) => event),
        [hook.event],
      );
      assert.deepEqual(packageChannel(file), []);
    });
  });
}

after(() => {
  for (const dir of [traceDir, projectDir])
    rmSync(dir, { recursive: true, force: true });
});
