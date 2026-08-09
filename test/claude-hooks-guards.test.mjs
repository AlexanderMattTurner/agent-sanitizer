/**
 * Host-side placeholder-clobber guards:
 *
 *   - the on-disk placeholder tripwire in sanitize-output (a Read whose RAW
 *     bytes already carry placeholder text warns; other tools and the bare
 *     hint prefix stay silent);
 *   - the Bash/MCP placeholder advisory wired through buildPreToolUseResponse;
 *   - lib/secret-drop-guard: a Write dropping a redacted secret from an
 *     untracked file is denied once and confirmed by an identical retry.
 *
 * All daemon-touching seams are injected; no live redactor is needed.
 */
import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, unlinkSync, utimesSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// An empty project dir, set before the hooks import: the PreToolUse gate reads
// the invisible-char alert path derived from it at module load.
const projectDir = mkdtempSync(join(tmpdir(), "sanitizer-guards-"));
process.env.CLAUDE_PROJECT_DIR = projectDir;
after(() => rmSync(projectDir, { recursive: true, force: true }));

// Every guard under test lives inside the secret layer, which is opt-in
// (AGENT_SANITIZER_SECRETS_ENABLED, read per call). Enable it for this file;
// the knob-off arms are asserted explicitly below.
process.env.AGENT_SANITIZER_SECRETS_ENABLED = "1";
after(() => delete process.env.AGENT_SANITIZER_SECRETS_ENABLED);

/**
 * Run `fn` with the secret opt-in cleared, restoring it afterwards — the
 * knob-off negative arm of each guard.
 * @param {() => Promise<void>} fn
 */
async function withSecretsOff(fn) {
  delete process.env.AGENT_SANITIZER_SECRETS_ENABLED;
  try {
    await fn();
  } finally {
    process.env.AGENT_SANITIZER_SECRETS_ENABLED = "1";
  }
}

const { evaluateToolOutput, ON_DISK_PLACEHOLDER_WARNING } =
  await import("../claude-hooks/sanitize-output.mjs");
const { buildPreToolUseResponse } =
  await import("../claude-hooks/pretooluse-sanitize.mjs");
const {
  secretDropGuard,
  withSecretDropGuard,
  gitTracked,
  dropFingerprint,
  confirmMarkerPath,
  CONFIRM_TTL_MS,
} = await import("../claude-hooks/lib/secret-drop-guard.mjs");
const { rehydrateRedacted } = await import("../src/rehydrate.mjs");

// Secret assembled at runtime so no complete token literal trips push
// protection / gitleaks. The label avoids every SECRET_HINT keyword so the
// fixtures never wake the (absent) daemon.
const SECRET_A = ["hunter2hunter2", "hunter2xA"].join("");
const PH = "[REDACTED: Public IP (ipv4)]";

// ─── on-disk placeholder tripwire (sanitize-output) ──────────────────────────

describe("sanitize-output: on-disk placeholder tripwire", () => {
  it("warns on a Read whose raw bytes carry placeholder text", async () => {
    const fields = await evaluateToolOutput({
      tool_name: "Read",
      tool_input: { file_path: "/tmp/notes.md" },
      tool_response: `config was ${PH} on disk\n`,
    });
    assert.ok(fields !== null);
    // Containment, not equality: composeContext wraps the warning in its
    // envelope. The constant is the single source of truth for the prose.
    assert.ok(
      String(fields.additional_context).includes(ON_DISK_PLACEHOLDER_WARNING),
    );
    // Warning only — the bytes are untouched.
    assert.equal("mutated_output" in fields, false);
  });

  it("walks structured Read responses", async () => {
    const fields = await evaluateToolOutput({
      tool_name: "Read",
      tool_input: { file_path: "/tmp/notes.md" },
      tool_response: { file: { content: `x ${PH} y`, numLines: 1 } },
    });
    assert.ok(
      String(fields?.additional_context).includes(ON_DISK_PLACEHOLDER_WARNING),
    );
  });

  it("stays silent on the bare hint prefix and the ellipsis prose form", async () => {
    for (const text of ['grep -rn "\\[REDACTED" .', "docs say [REDACTED…]"]) {
      const fields = await evaluateToolOutput({
        tool_name: "Read",
        tool_input: { file_path: "/tmp/notes.md" },
        tool_response: text,
      });
      assert.equal(fields, null);
    }
  });

  it("stays silent for non-Read tools (grep output quotes placeholders routinely)", async () => {
    const fields = await evaluateToolOutput({
      tool_name: "Grep",
      tool_input: {},
      tool_response: `match: ${PH}`,
    });
    assert.equal(fields, null);
  });

  it("stays silent without the secret opt-in (placeholders are plain text)", async () =>
    withSecretsOff(async () => {
      const fields = await evaluateToolOutput({
        tool_name: "Read",
        tool_input: { file_path: "/tmp/notes.md" },
        tool_response: `config was ${PH} on disk\n`,
      });
      assert.equal(fields, null);
    }));
});

// ─── placeholder advisory through buildPreToolUseResponse ────────────────────

describe("pretooluse: placeholder advisory for non-rehydrated tools", () => {
  const noopRehydrate = () => null;

  it("attaches context for a Bash command carrying a placeholder", async () => {
    const fields = await buildPreToolUseResponse(
      {
        tool_name: "Bash",
        tool_input: { command: `printf 'K=${PH}\\n' > /tmp/.env` },
      },
      noopRehydrate,
    );
    assert.ok(fields !== null);
    assert.match(
      String(fields.additionalContext),
      /rehydrated to the real secret only for Edit\/Write/,
    );
    // Advisory only: no verdict, no rewrite.
    assert.equal("permissionDecision" in fields, false);
    assert.equal("updatedInput" in fields, false);
  });

  it("stays a clean no-op without the secret opt-in", async () =>
    withSecretsOff(async () => {
      const fields = await buildPreToolUseResponse(
        {
          tool_name: "Bash",
          tool_input: { command: `printf 'K=${PH}\\n' > /tmp/.env` },
        },
        noopRehydrate,
      );
      assert.equal(fields, null);
    }));

  it("stays a clean no-op for a Bash command without a full placeholder", async () => {
    const fields = await buildPreToolUseResponse(
      {
        tool_name: "Bash",
        tool_input: { command: 'grep -rn "\\[REDACTED" .' },
      },
      noopRehydrate,
    );
    assert.equal(fields, null);
  });

  it("leaves Edit to the rehydration layer (no doubled note)", async () => {
    const fields = await buildPreToolUseResponse(
      {
        tool_name: "Edit",
        tool_input: {
          file_path: "/f",
          old_string: "[REDACTED]",
          new_string: "x",
        },
      },
      noopRehydrate,
    );
    assert.equal(fields, null);
  });
});

// ─── secret-drop-guard ───────────────────────────────────────────────────────

/** io over one fixed file whose only secret is SECRET_A. */
const dropIo = (disk) => ({
  readFile: () => disk,
  redact: (text) =>
    text.includes(SECRET_A) ? text.split(SECRET_A).join(PH) : null,
  redactMap: (text) => {
    const start = text.indexOf(SECRET_A);
    if (start === -1) return { text, pairs: [] };
    return {
      text: text.split(SECRET_A).join(PH),
      pairs: [{ placeholder: PH, original: SECRET_A, start }],
    };
  },
});

const DISK = `host=1.2.3.4\nvalue=${SECRET_A}\n`;
const untracked = { isTracked: () => false };

describe("secret-drop-guard", () => {
  it("denies a first Write that drops the secret, then passes the identical retry", async () => {
    const ti = {
      file_path: "/w/.env",
      content: "host=1.2.3.4\nvalue=<fill>\n",
    };
    const seen = new Set();
    const seams = {
      ...untracked,
      confirmSeen: (fp) => seen.delete(fp),
      recordConfirm: (fp) => seen.add(fp),
    };
    const first = await secretDropGuard(ti, dropIo(DISK), seams);
    assert.ok(first !== null);
    assert.match(first.deny, /re-issue this exact Write to confirm/);
    assert.match(first.deny, /not tracked by git/);
    const retry = await secretDropGuard(ti, dropIo(DISK), seams);
    assert.equal(retry, null);
    // The confirmation was consumed: a third identical Write re-asks.
    const third = await secretDropGuard(ti, dropIo(DISK), seams);
    assert.ok(third !== null && "deny" in third);
  });

  it("passes when the content preserves the secret's value (rehydrated Write)", async () => {
    const res = await secretDropGuard(
      { file_path: "/w/.env", content: `renamed=${SECRET_A}\n` },
      dropIo(DISK),
      untracked,
    );
    assert.equal(res, null);
  });

  it("skips tracked files entirely (git is the recovery path)", async () => {
    let probed = 0;
    const res = await secretDropGuard(
      { file_path: "/w/.env", content: "gone\n" },
      {
        ...dropIo(DISK),
        redact: () => {
          probed++;
          throw new Error("must not probe a tracked file");
        },
      },
      { isTracked: () => true },
    );
    assert.equal(res, null);
    // Tracked check runs before any daemon probe.
    assert.equal(probed, 0);
  });

  it("skips secret-free files after one cheap probe (no map call)", async () => {
    let mapped = 0;
    const res = await secretDropGuard(
      { file_path: "/w/notes.md", content: "anything\n" },
      {
        ...dropIo("no secrets here\n"),
        redactMap: () => {
          mapped++;
          throw new Error("must not map a secret-free file");
        },
      },
      untracked,
    );
    assert.equal(res, null);
    assert.equal(mapped, 0);
  });

  it("re-denies a retry when the drop set changed between deny and retry", async () => {
    const ti = { file_path: "/w/.env", content: "value=<fill>\n" };
    const seen = new Set();
    const seams = {
      ...untracked,
      confirmSeen: (fp) => seen.delete(fp),
      recordConfirm: (fp) => seen.add(fp),
    };
    const first = await secretDropGuard(ti, dropIo(DISK), seams);
    assert.ok(first !== null && "deny" in first);
    // The file's secret changed on disk: the recorded confirmation no longer
    // covers what THIS retry would drop.
    const OTHER = ["hunter2hunter2", "hunter2xB"].join("");
    const otherIo = {
      readFile: () => `value=${OTHER}\n`,
      redact: (text) =>
        text.includes(OTHER) ? text.split(OTHER).join(PH) : null,
      redactMap: (text) => ({
        text: text.split(OTHER).join(PH),
        pairs: [
          { placeholder: PH, original: OTHER, start: text.indexOf(OTHER) },
        ],
      }),
    };
    const retry = await secretDropGuard(ti, otherIo, seams);
    assert.ok(retry !== null && "deny" in retry);
  });

  it("skips an unmappable view (cannot know the drop set)", async () => {
    const res = await secretDropGuard(
      { file_path: "/w/.env", content: "gone\n" },
      {
        readFile: () => DISK,
        redact: () => "probe says secrets",
        redactMap: () => ({ unmappable: "because" }),
      },
      untracked,
    );
    assert.equal(res, null);
  });

  it("passes file creation (ENOENT) and rethrows other read failures", async () => {
    const enoent = Object.assign(new Error("gone"), { code: "ENOENT" });
    assert.equal(
      await secretDropGuard(
        { file_path: "/w/new", content: "x" },
        {
          ...dropIo(DISK),
          readFile: () => {
            throw enoent;
          },
        },
        untracked,
      ),
      null,
    );
    const eacces = Object.assign(new Error("denied"), { code: "EACCES" });
    await assert.rejects(
      secretDropGuard(
        { file_path: "/w/locked", content: "x" },
        {
          ...dropIo(DISK),
          readFile: () => {
            throw eacces;
          },
        },
        untracked,
      ),
      /denied/,
    );
  });

  it("ignores malformed inputs", async () => {
    for (const ti of [null, {}, { file_path: "/f" }, { content: "x" }])
      assert.equal(await secretDropGuard(ti, dropIo(DISK), untracked), null);
  });

  it("round-trips the default sentinel state (deny once, retry passes)", async () => {
    const ti = { file_path: "/w/.env", content: "sentinel-roundtrip\n" };
    const marker = confirmMarkerPath(
      dropFingerprint(ti.file_path, ti.content, [SECRET_A]),
    );
    try {
      const first = await secretDropGuard(ti, dropIo(DISK), untracked);
      assert.ok(first !== null && "deny" in first);
      const retry = await secretDropGuard(ti, dropIo(DISK), untracked);
      assert.equal(retry, null);
    } finally {
      try {
        unlinkSync(marker);
      } catch {
        // Already consumed — the retry unlinks it.
      }
    }
  });

  it("expires a stale sentinel instead of honoring it (no standing approval)", async () => {
    const ti = { file_path: "/w/.env", content: "sentinel-ttl\n" };
    const marker = confirmMarkerPath(
      dropFingerprint(ti.file_path, ti.content, [SECRET_A]),
    );
    try {
      const first = await secretDropGuard(ti, dropIo(DISK), untracked);
      assert.ok(first !== null && "deny" in first);
      // Backdate the sentinel past the TTL: the retry must re-deny, and the
      // stale marker is consumed rather than left behind.
      const stale = new Date(Date.now() - CONFIRM_TTL_MS - 60_000);
      utimesSync(marker, stale, stale);
      const retry = await secretDropGuard(ti, dropIo(DISK), untracked);
      assert.ok(retry !== null && "deny" in retry);
      // The re-deny re-armed a fresh sentinel, so the next retry passes.
      const third = await secretDropGuard(ti, dropIo(DISK), untracked);
      assert.equal(third, null);
    } finally {
      try {
        unlinkSync(marker);
      } catch {
        // Already consumed.
      }
    }
  });

  it("gitTracked maps exit codes and spawn failure to the fail-open side", () => {
    const spawnWith = (result) => () => result;
    assert.equal(gitTracked("/f/x", spawnWith({ status: 0 })), true);
    assert.equal(gitTracked("/f/x", spawnWith({ status: 1 })), false);
    assert.equal(gitTracked("/f/x", spawnWith({ status: 128 })), false);
    assert.equal(
      gitTracked("/f/x", spawnWith({ error: new Error("ENOENT") })),
      true,
    );
  });

  it("fingerprints distinguish path, content, and the dropped values", () => {
    assert.notEqual(dropFingerprint("/a", "x"), dropFingerprint("/a", "y"));
    assert.notEqual(dropFingerprint("/a", "x"), dropFingerprint("/b", "x"));
    assert.notEqual(
      dropFingerprint("/a", "x", ["s1"]),
      dropFingerprint("/a", "x", ["s2"]),
    );
    assert.notEqual(
      dropFingerprint("/a", "x", ["s1"]),
      dropFingerprint("/a", "x", ["s1", "s2"]),
    );
    assert.equal(
      dropFingerprint("/a", "x", ["s1"]),
      dropFingerprint("/a", "x", ["s1"]),
    );
  });
});

// ─── withSecretDropGuard (the production composition) ────────────────────────

describe("withSecretDropGuard", () => {
  const guardDeny = { deny: "guard says no" };

  it("runs the guard on the POST-substitution content for a rehydrated Write", async () => {
    /** @type {any[]} */
    const guardCalls = [];
    const rehydrated = {
      updatedInput: { file_path: "/w/.env", content: `k=${SECRET_A}\n` },
      context: "substituted",
    };
    const composed = withSecretDropGuard(
      async () => rehydrated,
      dropIo(DISK),
      async (finalInput) => {
        guardCalls.push(finalInput);
        return null;
      },
    );
    const res = await composed("Write", {
      file_path: "/w/.env",
      content: "k=[REDACTED]\n",
    });
    assert.equal(res, rehydrated);
    assert.deepEqual(guardCalls, [rehydrated.updatedInput]);
  });

  it("propagates a guard deny over a null rehydration (hint-free Write fallback)", async () => {
    const ti = { file_path: "/w/.env", content: "gone\n" };
    /** @type {any[]} */
    const guardCalls = [];
    const composed = withSecretDropGuard(
      async () => null,
      dropIo(DISK),
      async (finalInput) => {
        guardCalls.push(finalInput);
        return guardDeny;
      },
    );
    assert.equal(await composed("Write", ti), guardDeny);
    // The guard saw the ORIGINAL toolInput — nothing was substituted.
    assert.deepEqual(guardCalls, [ti]);
  });

  it("skips the guard for non-Write tools", async () => {
    let guarded = 0;
    const composed = withSecretDropGuard(
      async () => null,
      dropIo(DISK),
      async () => {
        guarded++;
        return guardDeny;
      },
    );
    for (const tool of ["Edit", "MultiEdit", "Bash", "Read"])
      assert.equal(await composed(tool, { file_path: "/f" }), null);
    assert.equal(guarded, 0);
  });

  it("does not deny a faithfully-restored secret through the hook pipeline (real rehydrate + real guard)", async () => {
    // Production Layer-4 shape — the REAL rehydrateRedacted composed with the
    // REAL secretDropGuard via withSecretDropGuard — driven end-to-end through
    // buildPreToolUseResponse. Only the fs/daemon/git/sentinel seams are
    // injected (no fake rehydrate, no fake guard).
    const layer4 = (io) =>
      withSecretDropGuard(
        (tool, toolInput) => rehydrateRedacted(tool, toolInput, io),
        io,
        (finalInput, guardIo) =>
          secretDropGuard(finalInput, guardIo, {
            isTracked: () => false,
            confirmSeen: () => false,
            recordConfirm: () => {},
          }),
      );

    // Placeholder-carrying faithful echo: Layer 4 rehydrates the view back to
    // the disk bytes, and the guard — running on the POST-substitution
    // content — sees the secret preserved, not dropped.
    const view = `host=1.2.3.4\nvalue=${PH}\n`;
    const fields = await buildPreToolUseResponse(
      {
        tool_name: "Write",
        tool_input: { file_path: "/w/.env", content: view },
      },
      layer4(dropIo(DISK)),
    );
    assert.ok(fields !== null);
    assert.equal(fields.updatedInput.content, DISK);
    assert.ok(fields.updatedInput.content.includes(SECRET_A));
    assert.equal("permissionDecision" in fields, false);
    assert.match(
      String(fields.additionalContext),
      /resolved to the file's real secret values/u,
    );

    // Hint-free restoration (the new every-well-formed-Write path): no
    // placeholder anywhere in the content, yet Layer 4 restores the stripped
    // invisible run from disk, and the restored content carries the file's
    // secret bytes. The guard must count that secret as preserved.
    const ZW = String.fromCharCode(0x200b);
    const diskInvis = `${ZW.repeat(12)}\nvalue=${SECRET_A}\n`;
    const hintFree = `\nvalue=${SECRET_A}\n`;
    assert.equal(hintFree.includes("[REDACTED"), false);
    const restored = await buildPreToolUseResponse(
      {
        tool_name: "Write",
        tool_input: { file_path: "/w/.env", content: hintFree },
      },
      layer4(dropIo(diskInvis)),
    );
    assert.ok(restored !== null);
    // Restoration really happened (the invisible run is back)...
    assert.equal(restored.updatedInput.content, diskInvis);
    assert.ok(restored.updatedInput.content.includes(SECRET_A));
    // ...and the guard did not read it as a drop.
    assert.equal("permissionDecision" in restored, false);
    assert.match(
      String(restored.additionalContext),
      /12 invisible\/control character\(s\) .* restored from disk/u,
    );

    // Non-vacuity control: the same composition DOES deny when the Write
    // genuinely drops the secret — proving the guard is live on this path
    // and the two passes above were its verdicts, not its absence.
    const dropping = await buildPreToolUseResponse(
      {
        tool_name: "Write",
        tool_input: { file_path: "/w/.env", content: "\nvalue=<rotated>\n" },
      },
      layer4(dropIo(diskInvis)),
    );
    assert.equal(dropping?.permissionDecision, "deny");
    assert.match(
      String(dropping?.permissionDecisionReason),
      /removes 1 redacted secret value\(s\)/u,
    );
    assert.match(
      String(dropping?.permissionDecisionReason),
      /re-issue this exact Write to confirm/u,
    );
  });

  it("short-circuits on a rehydration deny (guard never runs)", async () => {
    let guarded = 0;
    const rehydrateDeny = { deny: "rehydrate says no" };
    const composed = withSecretDropGuard(
      async () => rehydrateDeny,
      dropIo(DISK),
      async () => {
        guarded++;
        return null;
      },
    );
    assert.equal(
      await composed("Write", { file_path: "/w/.env", content: "x" }),
      rehydrateDeny,
    );
    assert.equal(guarded, 0);
  });
});
