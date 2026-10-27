/**
 * PreToolUse Edit/Write rehydration through the REAL redactor client and the
 * REAL Python daemon — no stubbed rehydrator, no stub socket.
 *
 * Every other buildPreToolUseResponse test injects the rehydrate stage or a
 * fake daemon, so none of them proves the shipped composition — the
 * redactor-client wire protocol, the daemon's map response, rehydrateRedacted
 * and the drop guard — restores a secret the model only ever saw as a
 * placeholder. This suite starts the daemon from the working tree exactly as
 * the pytest suite imports the engine, and composes each write from the view
 * the daemon itself returns.
 *
 * Skips, naming the failed probe, only when the Python engine cannot be
 * imported (no `uv`, or no detect-secrets in the dev environment).
 */
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { repoRoot } from "./helpers/repo-root.mjs";
import { skipUnless } from "./helpers/skip.mjs";

const pythonDir = join(repoRoot, "python");
const UV_PYTHON = ["run", "--extra", "dev", "--frozen", "python", "-c"];

const probe = spawnSync("uv", [...UV_PYTHON, "import detect_secrets"], {
  cwd: repoRoot,
  encoding: "utf8",
});
const skip = skipUnless(
  !probe.error && probe.status === 0,
  `the Python engine is unavailable: \`uv ${UV_PYTHON.join(" ")} "import detect_secrets"\` ` +
    `failed (${probe.error?.message ?? `exit ${probe.status}: ${probe.stderr?.trim()}`})`,
);

// The client reads its socket path at module load, so it is set before the
// hook is imported; an empty project dir keeps the invisible-char gate quiet.
const socketDir = mkdtempSync(join(tmpdir(), "sanitizer-real-daemon-"));
const socketPath = join(socketDir, "sock", "redactor.sock");
process.env._AGENT_SANITIZER_REDACTOR_SOCKET = socketPath;
// A dead daemon command: the suite starts the daemon itself, so a respawn
// means the client never reached it — that must fail, not start a second one.
process.env._AGENT_SANITIZER_REDACTOR_DAEMON = join(socketDir, "no-daemon");
process.env.CLAUDE_PROJECT_DIR = mkdtempSync(join(socketDir, "proj-"));
process.env.AGENT_SANITIZER_SECRETS_ENABLED = "1";

const { buildPreToolUseResponse } =
  await import("../claude-hooks/pretooluse-sanitize.mjs");
const { redactViaDaemon, waitForSocket } =
  await import("../claude-hooks/lib/redactor-client.mjs");

// Assembled at runtime so no complete key literal trips push protection.
const AWS_KEY = ["AKIA", "Z7Q3", "M2XK", "P9RT", "W4HN"].join("");
const DISK = `region = "eu-west-1"\naws_access_key_id = "${AWS_KEY}"\ntimeout = 30\n`;

describe("PreToolUse rehydration against the real daemon", { skip }, () => {
  /** @type {import("node:child_process").ChildProcess} */
  let daemon;
  const file = join(socketDir, "settings.toml");
  /** The file as the model saw it: the daemon's own redacted view. */
  let view = "";

  before(async () => {
    daemon = spawn(
      "uv",
      [
        ...UV_PYTHON,
        "import sys; sys.path.insert(0, sys.argv[1]); " +
          "from agent_sanitizer.secrets.daemon import main; main([sys.argv[2]])",
        pythonDir,
        socketPath,
      ],
      // Own process group, so `after` reaps uv AND the interpreter it runs.
      { cwd: repoRoot, detached: true, stdio: "ignore" },
    );
    assert.ok(
      await waitForSocket(socketPath, { deadlineMs: 30_000 }),
      "the real daemon never bound its socket",
    );
    writeFileSync(file, DISK);
    const redacted = await redactViaDaemon(DISK, {
      map: true,
      webIngress: false,
    });
    view = /** @type {string} */ (redacted?.text);
    // Positive marker: the daemon really redacted the key, so the
    // restorations asserted below are the rehydrator's work, not a pass-through.
    assert.equal(typeof view, "string");
    assert.ok(!view.includes(AWS_KEY), `the daemon left the key in: ${view}`);
    assert.match(view, /\[REDACTED/u);
  });

  after(() => {
    if (daemon?.pid !== undefined) process.kill(-daemon.pid, "SIGTERM");
    rmSync(socketDir, { recursive: true, force: true });
  });

  it("restores the secret in a Write composed from the redacted view", async () => {
    const fields = await buildPreToolUseResponse(
      {
        tool_name: "Write",
        tool_input: { file_path: file, content: `${view}retries = 3\n` },
      },
      undefined,
      () => {},
    );
    assert.equal(fields?.permissionDecision, undefined);
    assert.equal(fields?.updatedInput?.content, `${DISK}retries = 3\n`);
  });

  it("re-anchors an Edit whose old_string carries the placeholder", async () => {
    const line = view.split("\n")[1];
    assert.match(line, /^aws_access_key_id = "\[REDACTED/u);
    const fields = await buildPreToolUseResponse(
      {
        tool_name: "Edit",
        tool_input: {
          file_path: file,
          old_string: line,
          new_string: `# rotated quarterly\n${line}`,
        },
      },
      undefined,
      () => {},
    );
    const realLine = `aws_access_key_id = "${AWS_KEY}"`;
    assert.equal(fields?.permissionDecision, undefined);
    assert.equal(fields?.updatedInput?.old_string, realLine);
    assert.equal(
      fields?.updatedInput?.new_string,
      `# rotated quarterly\n${realLine}`,
    );
  });
});
