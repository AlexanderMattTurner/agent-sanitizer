/**
 * The InstructionsLoaded scan: what happens to an instruction file at the moment
 * Claude Code loads it.
 *
 * This hook is the lazy half of the instruction-file scan — the SessionStart
 * scan covers what loads at launch, and everything a subdirectory, a rule glob
 * or a compaction reload pulls in later arrives here. It cannot block (the event
 * ignores its exit code) and the bytes are already in context when it runs, so
 * the three things it CAN do are the contract: strip the payload from disk, say
 * so on both the user and model channels, and arm the PreToolUse gate when the
 * strip did not happen.
 */
import { describe, it, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { repoRoot } from "./helpers/repo-root.mjs";

// Set before the hook imports: it REWRITES contaminated instruction files under
// CLAUDE_PROJECT_DIR, so pointing it at this repo would let the test edit the
// tree.
const projectDir = mkdtempSync(join(tmpdir(), "sanitizer-loaded-proj-"));
process.env.CLAUDE_PROJECT_DIR = projectDir;

const { readLoadedFile, scanLoadedFile, loadedFileMessage, scopeNotice } =
  await import("../claude-hooks/scan-loaded-instructions.mjs");
const { LONG_RUN_THRESHOLD } = await import("../src/invisible.mjs");
const {
  alertDir,
  appendAlert,
  instructionsLoadedFile,
  instructionsLoadedGapNotice,
  instructionsLoadedNoticeFile,
  instructionsLoadedSeen,
  invisibleCharAlert,
  recordInstructionsLoaded,
  recordInstructionsLoadedNotice,
} = await import("../claude-hooks/lib/invisible-alert.mjs");

/** The session id the CLI cases send, so their markers are this session's. */
const SESSION = "sess-loaded-1";

/** A payload long enough for the scanner's long-run threshold to flag it. */
const PAYLOAD = "\u{e0001}".repeat(LONG_RUN_THRESHOLD + 2);
const PROSE = "real prose the strip must keep\n";

const markers = [
  instructionsLoadedFile(),
  instructionsLoadedNoticeFile(),
  instructionsLoadedFile(SESSION),
  instructionsLoadedNoticeFile(SESSION),
  // The "nothing loads at launch" cache instructionsLoadedGapNotice writes
  // itself — see the "no InstructionsLoaded scan" describe block below.
  `${instructionsLoadedFile()}.launch-empty`,
  `${instructionsLoadedFile(SESSION)}.launch-empty`,
];

/** Every alert store these cases touch: the shared fallback and SESSION's. */
const alertDirs = [alertDir(), alertDir(SESSION)];

beforeEach(() => {
  for (const path of markers) rmSync(path, { force: true });
  for (const path of alertDirs) rmSync(path, { recursive: true, force: true });
});

after(() => {
  rmSync(projectDir, { recursive: true, force: true });
  for (const path of markers) rmSync(path, { force: true });
  for (const path of alertDirs) rmSync(path, { recursive: true, force: true });
});

/** Write `content` to `name` under the project and return its absolute path. */
function project(name, content) {
  const abs = join(projectDir, name);
  mkdirSync(join(abs, ".."), { recursive: true });
  writeFileSync(abs, content);
  return abs;
}

describe("the loaded-file payload is validated, never assumed", () => {
  it("reads the file path and the load reason", () => {
    assert.deepEqual(
      readLoadedFile({
        file_path: "/p/CLAUDE.md",
        load_reason: "nested_traversal",
      }),
      { filePath: "/p/CLAUDE.md", loadReason: "nested_traversal" },
    );
  });

  it("labels a missing load reason rather than skipping the scan", () => {
    // The reason decides the scope notice, never the scan: treating its absence
    // as a reason not to scan would let a harness change disable the scan. The
    // "unknown" label is what the notice then reads as "not host-chosen".
    assert.equal(
      readLoadedFile({ file_path: "/p/CLAUDE.md" }).loadReason,
      "unknown",
    );
  });

  it("ignores fields the event carries that this hook does not read", () => {
    // The live payload carries cwd, memory_type, prompt_id, trigger_file_path
    // and more. Reading only what it needs is what keeps a host that adds a
    // field from routing a real event into the fault posture.
    assert.deepEqual(
      readLoadedFile({
        file_path: "/p/CLAUDE.md",
        load_reason: "session_start",
        memory_type: "project",
        trigger_file_path: "/p/packages/foo/main.js",
        prompt_id: "p-1",
      }),
      { filePath: "/p/CLAUDE.md", loadReason: "session_start" },
    );
  });

  for (const [name, payload] of [
    ["no file_path", { load_reason: "session_start" }],
    ["an empty file_path", { file_path: "" }],
    ["a non-string file_path", { file_path: 7 }],
    ["nothing at all", undefined],
  ])
    it(`throws on ${name}, rather than reporting a clean file`, () => {
      // The one answer that must be unreachable: "no findings" for a file the
      // hook never identified. The throw routes to the declared fault posture.
      assert.throws(() => readLoadedFile(payload), /file_path/u);
    });
});

describe("a loaded file inside the project is cleaned on disk", () => {
  it("strips the payload and reports it cleaned", () => {
    const filePath = project(
      "packages/foo/CLAUDE.md",
      `${PROSE}hidden:${PAYLOAD}\n`,
    );

    const result = scanLoadedFile(filePath);
    assert.equal(result.cleaned, true);
    assert.equal(result.reason, null);

    const after = readFileSync(filePath, "utf8");
    assert.ok(after.includes(PROSE), "the strip took real prose with it");
    assert.ok(!after.includes("\u{e0001}"), "the payload is still on disk");
  });

  it("scans the file the event names, taking no bytes from the payload", () => {
    // The live event carries file_path and no file_content, so the path is the
    // only source of bytes there is. A scan that waited for payload bytes
    // reports nothing on every real event.
    const filePath = project("CLAUDE.md", `${PROSE}hidden:${PAYLOAD}\n`);
    const result = scanLoadedFile(filePath);
    assert.notEqual(result, null);
    assert.match(result.report, /INVISIBLE CHARACTER INJECTION DETECTED/u);
  });

  it("says nothing about a clean file", () => {
    assert.equal(scanLoadedFile(project("CLAUDE.md", PROSE)), null);
  });

  it("propagates an unreadable file instead of calling it clean", () => {
    // The bytes are in context and could not be checked. Returning null here
    // would announce "clean" for a file nothing scanned; the throw is what
    // routes it to the hook's fault posture.
    assert.throws(
      () => scanLoadedFile(join(projectDir, "no-such-CLAUDE.md")),
      /ENOENT/u,
    );
  });

  it("reports a symlinked instruction file rather than rewriting through it", () => {
    // The read follows links and the clean refuses them, and that split is the
    // behavior: an in-project path pointed at a contaminated file elsewhere is
    // SCANNED (the bytes did reach the model) but never rewritten (the target
    // belongs to someone else). Pinned because a later realpath or
    // follow-refusing open in the read would move it with nothing to notice.
    const outside = mkdtempSync(join(tmpdir(), "sanitizer-loaded-link-"));
    const target = join(outside, "target.md");
    const content = `${PROSE}hidden:${PAYLOAD}\n`;
    writeFileSync(target, content);
    const linkPath = join(projectDir, "linked-CLAUDE.md");
    rmSync(linkPath, { force: true });
    symlinkSync(target, linkPath);

    const result = scanLoadedFile(linkPath);
    assert.match(result.report, /INVISIBLE CHARACTER INJECTION DETECTED/u);
    assert.equal(result.cleaned, false);
    assert.match(result.reason, /symlink/u);
    assert.equal(
      readFileSync(target, "utf8"),
      content,
      "the symlink's target was rewritten",
    );
    rmSync(outside, { recursive: true, force: true });
    rmSync(linkPath, { force: true });
  });

  it("reports NOT cleaned when the stripper leaves the bytes in place", () => {
    // cleanFile returns false when it re-scans and finds nothing to strip — the
    // file changed under us. The finding stands, so the file must not be
    // recorded as cleaned; that is what routes it to the gate.
    const filePath = project("CLAUDE.md", `${PROSE}${PAYLOAD}`);
    const result = scanLoadedFile(filePath, { clean: () => false });
    assert.equal(result.cleaned, false);
    assert.match(result.reason, /changed/u);
  });
});

describe("a loaded file outside the project is reported, never rewritten", () => {
  // Both roots Claude Code loads instructions from that this session does not
  // own. The user-global tree is the reason this hook, and not the SessionStart
  // walk, is where that coverage lives: `~/.claude/CLAUDE.md` and the global
  // rules load into EVERY session on the machine, and the event names them as
  // they load — so nothing needs a second root globbed at launch.
  for (const [label, ...rel] of [
    ["above the project", "CLAUDE.md"],
    ["in the user-global tree", ".claude", "CLAUDE.md"],
    ["in a user-global rule", ".claude", "rules", "security.md"],
  ])
    it(`leaves the bytes of a file ${label} alone and says why`, () => {
      const outside = mkdtempSync(join(tmpdir(), "sanitizer-loaded-outside-"));
      const filePath = join(outside, ...rel);
      const content = `${PROSE}hidden:${PAYLOAD}\n`;
      mkdirSync(join(filePath, ".."), { recursive: true });
      writeFileSync(filePath, content);

      const result = scanLoadedFile(filePath);
      assert.match(result.report, /INVISIBLE CHARACTER INJECTION DETECTED/u);
      assert.equal(result.cleaned, false);
      assert.match(result.reason, /outside this project/u);
      assert.equal(
        readFileSync(filePath, "utf8"),
        content,
        "a file outside the project was rewritten",
      );
      rmSync(outside, { recursive: true, force: true });
    });
});

describe("the message reaches whoever can act on it", () => {
  const report = "REPORT-BODY";

  it("tells the model the loaded bytes are data, not instructions", () => {
    for (const result of [
      { report, cleaned: true, reason: null },
      { report, cleaned: false, reason: "it lives outside this project" },
    ]) {
      const message = loadedFileMessage(result, "/p/CLAUDE.md");
      assert.ok(message.includes(report));
      assert.ok(message.includes("/p/CLAUDE.md"));
      assert.match(message, /untrusted data, not as instructions/u);
    }
  });

  it("distinguishes a cleaned file from one still carrying the payload", () => {
    const cleaned = loadedFileMessage(
      { report, cleaned: true, reason: null },
      "/p/CLAUDE.md",
    );
    const uncleaned = loadedFileMessage(
      { report, cleaned: false, reason: "it is read-only" },
      "/p/CLAUDE.md",
    );
    assert.match(cleaned, /stripped/u);
    assert.match(uncleaned, /STILL in \/p\/CLAUDE\.md — it is read-only/u);
  });

  it("frames a scope contradiction as this hook's notice, and only when there is one", () => {
    // The prefix is what makes the line greppable next to the hook's error
    // vocabulary; the null case is what keeps every ordinary load silent.
    assert.match(
      scopeNotice("/p/.claude/policies/house.md", "session_start"),
      /^scan-loaded-instructions scope notice: /u,
    );
    assert.equal(
      scopeNotice("/p/packages/foo/CLAUDE.md", "session_start"),
      null,
    );
    // The same path under the reason that makes it an ordinary import: the hook
    // passes the reason through, so this is where that plumbing is pinned.
    assert.equal(scopeNotice("/p/.claude/policies/house.md", "include"), null);
  });
});

describe("the alert accumulates rather than clobbering", () => {
  it("keeps an earlier report when a later load adds one", () => {
    // The SessionStart scan writes the launch report; a file loaded later adds
    // to it. A truncating write here would drop the launch findings, and the
    // gate would surface only the newest one.
    appendAlert("launch finding");
    appendAlert("nested finding");
    const alert = invisibleCharAlert();
    assert.match(alert, /launch finding/u);
    assert.match(alert, /nested finding/u);
  });
});

describe("the hook CLI, driven end to end on a real event", () => {
  /**
   * Run the hook with `input` verbatim on stdin, so a test can drive the bytes
   * a host actually delivers — including the ones no `JSON.stringify` can
   * produce, like nothing at all.
   */
  function fireRaw(input, env = {}) {
    const result = spawnSync(
      process.execPath,
      [join(repoRoot, "claude-hooks", "scan-loaded-instructions.mjs")],
      {
        input,
        encoding: "utf8",
        env: { ...process.env, CLAUDE_PROJECT_DIR: projectDir, ...env },
      },
    );
    return {
      ...result,
      json: result.stdout ? JSON.parse(result.stdout) : null,
    };
  }

  /** Run the hook as Claude Code does: one JSON event on stdin. */
  function fire(payload) {
    return fireRaw(JSON.stringify(payload));
  }

  it("cleans the file and answers on both channels", () => {
    const filePath = project("nested/CLAUDE.md", `${PROSE}${PAYLOAD}\n`);
    // The live payload, field for field, as a real host emits it: no
    // file_content anywhere in it. A hook that requires those bytes faults on
    // this event instead of scanning, and does so on every event it ever sees.
    const { json, stderr } = fire({
      hook_event_name: "InstructionsLoaded",
      session_id: SESSION,
      cwd: projectDir,
      file_path: filePath,
      load_reason: "nested_traversal",
      memory_type: "project",
      trigger_file_path: join(projectDir, "nested", "main.js"),
      prompt_id: "prompt-1",
      transcript_path: join(projectDir, "transcript.jsonl"),
    });

    assert.ok(!readFileSync(filePath, "utf8").includes("\u{e0001}"));
    // systemMessage reaches the user, additionalContext the model: the file is
    // already in context, so both parties need telling.
    assert.match(json.systemMessage, /INVISIBLE CHARACTER INJECTION DETECTED/u);
    assert.equal(json.hookSpecificOutput.hookEventName, "InstructionsLoaded");
    assert.match(json.hookSpecificOutput.additionalContext, /untrusted data/u);
    assert.match(stderr, /INVISIBLE CHARACTER INJECTION DETECTED/u);
    // Cleaned, so nothing is left for the gate to ask about.
    assert.equal(invisibleCharAlert(SESSION), null);
    assert.ok(existsSync(instructionsLoadedFile(SESSION)));
  });

  it("arms the gate when the payload is still on disk", () => {
    const outside = mkdtempSync(join(tmpdir(), "sanitizer-loaded-cli-"));
    const filePath = join(outside, "CLAUDE.md");
    writeFileSync(filePath, `${PROSE}${PAYLOAD}\n`);

    fire({
      hook_event_name: "InstructionsLoaded",
      session_id: SESSION,
      file_path: filePath,
      load_reason: "include",
    });

    assert.match(
      invisibleCharAlert(SESSION) ?? "",
      /CLAUDE\.md/u,
      "the PreToolUse gate was not armed",
    );
    rmSync(outside, { recursive: true, force: true });
  });

  it("reports a `.claude/` directory the scope table does not carry", () => {
    // The event is the only thing that can prove the SessionStart scan's scope
    // stale, and this is the proof: context loading out of a directory that
    // scan prunes. The file itself is clean, so the notice is the only output —
    // it is a maintenance signal about this package, not a verdict on the file.
    const filePath = project(".claude/policies/house.md", PROSE);
    const { stdout, stderr } = fire({
      hook_event_name: "InstructionsLoaded",
      session_id: SESSION,
      file_path: filePath,
      load_reason: "session_start",
    });
    assert.match(stderr, /scope notice/u);
    assert.match(stderr, /\.claude\/policies\//u);
    // Not a finding: no model/user channel, and nothing for the gate to ask.
    assert.equal(stdout, "");
    assert.equal(invisibleCharAlert(SESSION), null);
  });

  it("stays silent on a clean file, and still records that it ran", () => {
    const filePath = project("CLAUDE.md", PROSE);
    const { stdout, stderr } = fire({
      hook_event_name: "InstructionsLoaded",
      session_id: SESSION,
      file_path: filePath,
      load_reason: "session_start",
    });
    assert.equal(stdout, "");
    assert.equal(stderr, "");
    assert.equal(invisibleCharAlert(SESSION), null);
    // The marker is what tells the PreToolUse gate this host emits the event at
    // all; a clean file must still leave it.
    assert.ok(existsSync(instructionsLoadedFile(SESSION)));
  });

  it("reports a malformed event instead of passing it as clean", () => {
    const { stderr, status } = fire({
      hook_event_name: "InstructionsLoaded",
      load_reason: "session_start",
    });
    assert.match(stderr, /scan-loaded-instructions/u);
    assert.match(stderr, /file_path/u);
    assert.notEqual(status, 0);
  });

  // An empty stdin is a hook that was handed no event at all — a different
  // fault from a file it could not scan, with a different fix. Reported as
  // itself, or the operator is sent to the gate's remedies (a symlink on the
  // path, a permission bit, `pnpm install`) for a file that was never read.
  it("names an empty payload as its own fault, not an unscanned file", () => {
    const { stderr, stdout, status } = fireRaw("");
    assert.match(stderr, /scan-loaded-instructions hook error/u);
    assert.match(stderr, /received no payload/u);
    // The two claims that are false here: no file went unscanned, and nothing
    // was malformed — `JSON.parse` never saw the empty buffer.
    assert.doesNotMatch(stderr, /NOT scanned/u);
    assert.doesNotMatch(stderr, /Unexpected end of JSON input/u);
    assert.equal(stdout, "");
    assert.notEqual(status, 0);
  });

  it("does not arm the tool-call gate on an empty payload, even fail-closed", () => {
    const { stderr } = fireRaw("", { AGENT_SANITIZER_FAIL_OPEN: "0" });
    assert.match(stderr, /received no payload/u);
    // Both stores: with no payload there is no session id, so the fallback is
    // where such a finding would land if one were (wrongly) recorded.
    assert.equal(invisibleCharAlert(SESSION), null);
    assert.equal(invisibleCharAlert(), null);
  });

  // The other half of that distinction, and what keeps the assertions above
  // from passing vacuously: a non-empty payload that is malformed still reads
  // as an unscanned file and still arms the gate under the strict posture.
  it("still reports a non-empty malformed payload as an unscanned file", () => {
    const { stderr, status } = fireRaw("{not json", {
      AGENT_SANITIZER_FAIL_OPEN: "0",
    });
    assert.match(stderr, /NOT scanned/u);
    assert.doesNotMatch(stderr, /received no payload/u);
    assert.notEqual(status, 0);
    // The payload never parsed, so the hook had no session id to key by: the
    // finding lands in the shared fallback store, and the gate reads that store
    // alongside its own so the report still reaches a tool call.
    assert.notEqual(
      invisibleCharAlert(SESSION),
      null,
      "the PreToolUse gate was not armed",
    );
  });
});

describe("a session with no InstructionsLoaded scan is named, once", () => {
  // The notice is only a real gap when something at launch could have fired
  // the event — see the "stays silent when nothing loads at launch" block
  // below for the empty case. Written explicitly here rather than relying on
  // an earlier describe block's fixture: it must survive whichever order the
  // suite runs in.
  beforeEach(() => project("CLAUDE.md", PROSE));

  it("warns while no scan has been seen, naming every cause", () => {
    const notice = instructionsLoadedGapNotice();
    assert.match(notice, /InstructionsLoaded/u);
    assert.match(notice, /unscanned/u);
    // The marker cannot distinguish the three causes, so the notice must assert
    // none of them — a reader sent to the wrong fix stops trusting the next
    // notice. One marker each, so dropping a cause reds here:
    // the host never wired the event (the self-wiring host's case, and the one
    // cause the reader can repair in this session)...
    assert.match(notice, /wired/u);
    assert.match(notice, /`\/hooks` command/u);
    // ...a Claude Code below the floor, quoted so "upgrade" names a number the
    // reader can compare `claude --version` against...
    assert.match(notice, /upgrading/u);
    assert.match(notice, /2\.1\.69/u);
    assert.match(notice, /claude --version/u);
    // ...and the hook switched off by the operator.
    assert.match(notice, /AGENT_SANITIZER_DISABLED_HOOKS/u);
    assert.match(notice, /echo \$AGENT_SANITIZER_DISABLED_HOOKS/u);
  });

  it("stays silent when nothing loads at launch, even with no scan seen", () => {
    // Reported bug: launching in a directory whose ancestor chain has no
    // NON-EMPTY CLAUDE.md/rules file (e.g. an empty ~/.claude/CLAUDE.md) gives
    // Claude Code nothing to fire InstructionsLoaded over, so the missing
    // event is expected there, not evidence the scanner is unwired.
    const emptyDir = mkdtempSync(join(tmpdir(), "sanitizer-empty-launch-"));
    const emptySession = "sess-empty-launch";
    try {
      mkdirSync(join(emptyDir, ".claude"));
      writeFileSync(join(emptyDir, ".claude", "CLAUDE.md"), "");
      assert.equal(instructionsLoadedSeen(emptySession), false);
      assert.equal(instructionsLoadedGapNotice(emptySession, emptyDir), null);
      // Cached, not just silent this once: the launch set cannot change
      // mid-session, so a second ask must not re-glob to find the same answer.
      assert.equal(instructionsLoadedGapNotice(emptySession, emptyDir), null);
    } finally {
      rmSync(emptyDir, { recursive: true, force: true });
      rmSync(`${instructionsLoadedFile(emptySession)}.launch-empty`, {
        force: true,
      });
    }
  });

  it("still warns once the launch set actually has content", () => {
    const withContentDir = mkdtempSync(
      join(tmpdir(), "sanitizer-nonempty-launch-"),
    );
    const contentSession = "sess-nonempty-launch";
    try {
      writeFileSync(join(withContentDir, "CLAUDE.md"), PROSE);
      assert.match(
        instructionsLoadedGapNotice(contentSession, withContentDir),
        /unscanned/u,
      );
    } finally {
      rmSync(withContentDir, { recursive: true, force: true });
      rmSync(instructionsLoadedNoticeFile(contentSession), { force: true });
    }
  });

  it("does not repeat the warning once it has been surfaced", () => {
    // The notice itself is a pure read: nothing is recorded until the caller
    // confirms the notice actually landed in a response, so a call that ends in
    // a deny leaves the session's one report still to come.
    assert.notEqual(instructionsLoadedGapNotice(), null);
    assert.notEqual(instructionsLoadedGapNotice(), null);
    recordInstructionsLoadedNotice();
    assert.equal(instructionsLoadedGapNotice(), null);
  });

  it("stays silent once the hook has run", () => {
    assert.equal(instructionsLoadedSeen(), false);
    recordInstructionsLoaded();
    assert.ok(existsSync(instructionsLoadedFile()));
    assert.equal(instructionsLoadedSeen(), true);
    assert.equal(instructionsLoadedGapNotice(), null);
  });

  it("does not let one session's marker answer for another", () => {
    // The markers outlive the session that wrote them — nothing clears them at
    // SessionStart, because SessionStart is not ordered against the
    // InstructionsLoaded events fired for the files loaded at launch. Keying
    // them by session is what keeps a previous session's coverage from
    // silencing this session's gap.
    recordInstructionsLoaded("sess-earlier");
    assert.equal(instructionsLoadedSeen("sess-earlier"), true);
    assert.equal(instructionsLoadedSeen(SESSION), false);
    assert.match(instructionsLoadedGapNotice(SESSION), /unscanned/u);
    rmSync(instructionsLoadedFile("sess-earlier"), { force: true });
  });

  it("sweeps a past session's alert store, not only its markers", () => {
    // The store is a DIRECTORY per session; a sweep that only unlinked files
    // would leave every past session's directory behind forever.
    const stale = alertDir("sess-ancient-store");
    appendAlert("a past session's finding", "sess-ancient-store");
    const eightDaysAgo = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000);
    utimesSync(stale, eightDaysAgo, eightDaysAgo);

    recordInstructionsLoaded(SESSION);

    assert.equal(
      existsSync(stale),
      false,
      "a stale alert store was left behind",
    );
  });

  it("sweeps a past session's markers, keeping this session's and recent ones", () => {
    // One marker pair per session, never cleared while the session could still
    // ask — so the only thing keeping $TMPDIR from growing without bound is this
    // sweep on the first fire of a later session.
    const old = instructionsLoadedFile("sess-ancient");
    const recent = instructionsLoadedFile("sess-yesterday");
    for (const path of [old, recent]) writeFileSync(path, "");
    const eightDaysAgo = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000);
    utimesSync(old, eightDaysAgo, eightDaysAgo);

    recordInstructionsLoaded(SESSION);

    assert.equal(existsSync(old), false, "a stale marker was left behind");
    assert.ok(existsSync(recent), "a marker inside the TTL was swept");
    assert.ok(
      existsSync(instructionsLoadedFile(SESSION)),
      "the sweep took the marker it had just written",
    );
    rmSync(recent, { force: true });
  });

  it("folds a path separator out of a hostile session id", () => {
    // The id becomes a path component. A `/` in it would put the marker
    // somewhere other than $TMPDIR — or at a path an attacker chose.
    assert.equal(
      instructionsLoadedFile("../../etc/x"),
      instructionsLoadedFile(".._.._etc_x"),
    );
  });
});
