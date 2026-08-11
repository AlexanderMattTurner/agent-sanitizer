/**
 * SessionStart: scan the instruction files that load AT LAUNCH — the project's
 * own CLAUDE.md / AGENTS.md, its `.claude/` context markdown, and the CLAUDE.md
 * chain above it — for runs of invisible Unicode that may encode hidden
 * instructions. Pasted markdown can embed invisible sequences (tag chars,
 * zero-width encodings) that hijack the model's behavior — invisible in an
 * editor but read by the LLM. These files load as project instructions at
 * session start, bypassing the PostToolUse sanitizer.
 *
 * A SUBDIRECTORY's instruction file is not this hook's job: Claude Code loads it
 * only when a tool reads that subdirectory, and scan-loaded-instructions.mjs
 * scans it there, at the moment it loads. Globbing for those here is what made a
 * session launched in a home directory wait ~100 seconds (see findInstructionFiles).
 *
 * The scan/decode/clean LOGIC lives in `agent-sanitizer/instructions` — this
 * hook is glue (target discovery, accounting, alert persistence, fault
 * posture) over that SSOT. A hand-written twin used to live here and drifted
 * three ways at once: its report re-emitted the decoded payload with no
 * `untrusted data` framing or escaping (re-injecting the very instruction the
 * scan exists to catch), its scattered counter re-grew the linguistic-joiner
 * false positive the SSOT had already fixed, and its clean path was a bare
 * `writeFileSync` with none of cleanFile's symlink/UTF-8/TOCTOU guards.
 */
import { existsSync, readFileSync, globSync, unlinkSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import {
  awaitLazyDependency,
  emitHookResponse,
  safeErrMessage,
  hookgateMarkerPath,
  HookEvent,
  isMain,
  lazyImport,
  markerIsTrusted,
  probeSetupAlive,
  writeFileNoFollow,
} from "./lib/hook-io.mjs";
import {
  registerFaultPolicy,
  hookFaultOutcome,
  writeFaultOutcome,
} from "./lib/hook-fault.mjs";
import {
  ALERT_FILE,
  ALERT_ACK_FILE,
  PROJECT_DIR,
} from "./lib/invisible-alert.mjs";
import { formatReport } from "./lib/invisible-report.mjs";
import { bestEffortTrace, trace, TraceEvent } from "./lib/trace.mjs";
import { reportSlowHook, startHookTimer } from "./lib/hook-timing.mjs";
// Relative, not the `agent-sanitizer` specifier every other engine import uses:
// this is the scan's SCOPE, which is hook policy, and package.json's exports map
// deliberately does not publish it — routing it through the specifier would fail
// to resolve. The module is dependency-free data (see src/claude-context.mjs),
// so importing it statically carries none of the fail-open hazard lazyImport
// exists to cover.
import {
  ancestorInstructionFiles,
  CLAUDE_CONTEXT_SUBDIRS,
  CLAUDE_INSTRUCTION_GLOBS,
  CLAUDE_LAUNCH_GLOBS,
  excludeFromContextScan,
  isInsideDir,
} from "../src/claude-context.mjs";

// Layer-1 primitives + the instruction-scanner SSOT, bound via lazyImport (see
// its doc for the fail-OPEN hazard of a bare static npm import — here the
// instruction files would load UNSCANNED). A failed load leaves the bindings
// undefined; on a cold container (node deps not yet installed) cliMain's guard
// below waits out session-setup before giving up, and fails loud rather than
// silently passing.
// `let`, not `const`: the cold-start poll re-binds these once the package loads.
let {
  LONG_RUN_RE,
  LONG_RUN_THRESHOLD,
  SCATTERED_THRESHOLD: TOTAL_INVISIBLE_THRESHOLD,
} = /** @type {typeof import("agent-sanitizer/invisible")} */ (
  await lazyImport("agent-sanitizer/invisible")
);
let {
  decodeRun: instrDecodeRun,
  scanText,
  cleanFile,
} = /** @type {typeof import("agent-sanitizer/instructions")} */ (
  await lazyImport("agent-sanitizer/instructions")
);

/**
 * Re-attempt the sanitizer imports, waiting out an in-flight session-setup
 * before giving up. On a cold container the node deps this hook needs are still
 * being installed when SessionStart fires; without this wait `scanText` is
 * undefined, the scan is skipped, and the instruction files load UNSCANNED for
 * the whole session (fail open) — silently. Reuses the control-plane poll
 * (marker + PID liveness) so the wait bound matches every other
 * cold-start-aware gate.
 * @returns {Promise<boolean>} whether the sanitizer is now bound
 */
async function ensureSanitizerLoaded() {
  if (typeof scanText === "function" && typeof cleanFile === "function")
    return true;
  /* c8 ignore start -- cold-start reload: only runs when the top-level
     agent-sanitizer imports above failed (node deps not yet installed), which
     can't be simulated in-process or in the spawned-subprocess CLI run the tests
     observe (the test env always has the deps, so the guard above early-returns).
     The reload reuses awaitLazyDependency / markerIsTrusted /
     probeSetupAlive, each unit-tested directly. */
  const marker = hookgateMarkerPath();
  const reloaded = await awaitLazyDependency({
    tryImport: async () => {
      const invisible = await lazyImport("agent-sanitizer/invisible");
      const instructions = await lazyImport("agent-sanitizer/instructions");
      return typeof instructions.scanText === "function" &&
        typeof instructions.cleanFile === "function" &&
        invisible.LONG_RUN_RE !== undefined
        ? { invisible, instructions }
        : null;
    },
    markerPresent: () => markerIsTrusted(marker),
    setupAlive: () => probeSetupAlive(marker),
  });
  if (!reloaded) return false;
  const bound = /** @type {{
    invisible: typeof import("agent-sanitizer/invisible"),
    instructions: typeof import("agent-sanitizer/instructions"),
  }} */ (reloaded);
  ({
    LONG_RUN_RE,
    LONG_RUN_THRESHOLD,
    SCATTERED_THRESHOLD: TOTAL_INVISIBLE_THRESHOLD,
  } = bound.invisible);
  ({ decodeRun: instrDecodeRun, scanText, cleanFile } = bound.instructions);
  return true;
  /* c8 ignore stop */
}

const HOOK_NAME = "scan-invisible-chars";

/**
 * The stderr line both posture arms share: what broke, and what it cost.
 * @param {{ message: string }} ctx
 * @returns {string}
 */
function faultLine(ctx) {
  return (
    `${HOOK_NAME}: ${ctx.message}. Instruction files were NOT fully scanned ` +
    "for hidden Unicode, so any payload in them reaches the model unvetted."
  );
}

// This hook's entry in the one posture table (lib/hook-fault.mjs). It has no
// stdout verdict channel — SessionStart cannot deny — so BOTH arms are stated
// explicitly rather than taking the shared additionalContext default: the only
// enforcement a SessionStart hook can reach is the cross-hook alert, which makes
// the PreToolUse gate ask once on the next tool call.
registerFaultPolicy(HOOK_NAME, {
  event: HookEvent.SESSION_START,
  guarded: "instruction files",
  open: (ctx) => ({
    stderr: `${faultLine(ctx)} Passing through unguarded; set AGENT_SANITIZER_FAIL_OPEN=0 to arm the tool-call gate instead.\n`,
    exitCode: 1,
  }),
  closed: (ctx) => ({
    stderr: `${faultLine(ctx)} Arming the tool-call gate (AGENT_SANITIZER_FAIL_OPEN=0).\n`,
    exitCode: 1,
    armAlert: true,
  }),
});

/**
 * Render this hook's fault under the declared posture, and return the text (if
 * any) that must ride in the cross-hook alert so a later gate carries the
 * posture this hook cannot express itself.
 * @param {unknown} err
 * @returns {string[]}
 */
function reportFault(err) {
  const outcome = hookFaultOutcome(HOOK_NAME, err);
  process.exitCode = writeFaultOutcome(outcome);
  return outcome.armAlert ? [/** @type {string} */ (outcome.stderr)] : [];
}

/**
 * Persist the accumulated alert text for the PreToolUse gate, or leave the alert
 * absent when there is nothing to surface.
 *
 * ALERT_FILE sits at a predictable, world-visible $TMPDIR path, so a plain
 * writeFileSync would follow a co-tenant-planted symlink and overwrite an
 * arbitrary file this uid owns. Create it symlink-refusingly (see
 * writeFileNoFollow); the gate treats an absent alert as "nothing to surface",
 * so a lost race degrades safely rather than to a hijacked write.
 * @param {string[]} parts
 * @returns {void}
 */
function persistAlert(parts) {
  if (parts.length === 0) return;
  writeFileNoFollow(ALERT_FILE, parts.join("\n") + "\n");
}

// Decoder

/**
 * The SSOT decoder, re-exported through a lazy-bound wrapper (the binding is
 * `let` and may be re-bound by the cold-start reload, so the export must read
 * it at call time). A hand-written twin used to live here; it decoded tag
 * characters to RAW bytes — including actual C0 controls for U+E0001–U+E001F —
 * with no `untrusted data, not instructions:` framing or escaping, so the
 * hook's own report re-injected the hidden payload it had just caught.
 * @param {string} run
 * @returns {{ method: string, decoded: string }}
 */
function decodeRun(run) {
  return instrDecodeRun(run);
}

// Target discovery stays hook-local glue, NOT a copy of the SSOT's
// containment-checked `findInstructionFiles`: the two have different contracts.
// The SSOT finder drops every target it cannot resolve, which is right for a
// pure scan API; this hook must instead bucket it (see classifyReadFailure).
// The write-side symlink hazard the SSOT finder guards against is covered here
// by cleanFile's own O_NOFOLLOW open.

/**
 * Every file Claude Code loads as model context AT LAUNCH: `dir`'s own
 * instruction files and its `.claude/` context tree, plus the CLAUDE.md /
 * CLAUDE.local.md of every directory above it (loaded in full at launch, and
 * until now never scanned by anything). These load before the session's first
 * tool call — a path that bypasses the PostToolUse sanitizer — so a payload in
 * one of them reaches the model uncleaned unless it is scanned here.
 *
 * Bounded on purpose: one shallow glob plus a walk up the parent chain. The
 * `**`-rooted scope ({@link CLAUDE_INSTRUCTION_GLOBS}) walks the entire tree
 * below `dir`, which for a session launched in a home directory is ~100 seconds
 * of blocked startup spent on files Claude Code does not load at launch. Those
 * files load when a tool reads their directory, and scan-loaded-instructions
 * scans each one at that moment.
 *
 * The scope itself — which globs, and which directories the walk must prune — is
 * the library's (see src/claude-context.mjs for why it is imported relatively
 * rather than through the `agent-sanitizer` specifier the plugin bundle pins).
 * @param {string} dir
 * @returns {string[]}
 */
function findInstructionFiles(dir) {
  return [
    ...globSync([...CLAUDE_LAUNCH_GLOBS], {
      cwd: dir,
      exclude: excludeFromContextScan,
    }).map((name) => join(dir, name)),
    // Filtered, unlike the glob's matches: almost every parent directory holds
    // neither memory file, so the unfiltered chain would file ~10 phantom
    // targets per session into the `absent` bucket and bury the one thing that
    // bucket reports — a target that existed when the scan listed it and was
    // gone by the read. A file that appears after this check was not loaded at
    // launch either, so nothing is lost by not listing it.
    ...ancestorInstructionFiles(dir).filter((file) => existsSync(file)),
  ];
}

// Scanner

/**
 * Read one file and run the SSOT scan over it. The scan logic itself (long-run
 * decode + scattered threshold-evasion counting) is `scanText`'s — a local
 * mirror used to re-count scatter from the raw STRIP match count, silently
 * re-growing the linguistic-joiner/VS15 false positive `scanText`'s carve-out
 * counter had already fixed.
 * @param {string} filePath
 * @returns {ReturnType<typeof import("agent-sanitizer/instructions").scanText>}
 *   `line` is 1-based, or `null` for the whole-file scattered-chars finding.
 */
function scanFile(filePath) {
  return scanText(readFileSync(filePath, "utf-8"));
}

export {
  // Re-exported, never redefined: the scope this hook walks is the library's
  // (src/claude-context.mjs), and a consumer that reads it off this hook must
  // get that same list rather than a second copy that can drift.
  CLAUDE_CONTEXT_SUBDIRS,
  CLAUDE_INSTRUCTION_GLOBS,
  CLAUDE_LAUNCH_GLOBS,
  decodeRun,
  findInstructionFiles,
  scanFile,
  ALERT_FILE,
  ALERT_ACK_FILE,
  LONG_RUN_RE,
  LONG_RUN_THRESHOLD,
  TOTAL_INVISIBLE_THRESHOLD,
};

// Main (skip when imported for testing)

/**
 * PROBLEM CLASS — how a failed instruction-file read is classified. Every
 * consumer reads this one bucketing; nothing re-derives it from an errno.
 *
 * The scan is the only thing between a poisoned `CLAUDE.md` and a session that
 * loads it as instructions, and its caller announces "clean" on the trace
 * channel, whose whole purpose is that a MISSING announcement is loud. So a
 * read failure is never swallowed into an empty findings list — that turns "we
 * could not read this file" into "this file is fine". Three buckets:
 *
 *   - SKIPPED — the file exists and this uid cannot read it (EACCES, EISDIR,
 *     ELOOP…). Unvetted context: reported to the operator and it arms the gate.
 *   - ABSENT — ENOENT. The path resolves to nothing, and Claude Code loads
 *     instruction files through the same open, so no bytes can reach the model.
 *     Announced on the trace channel only; naming a risk that does not exist
 *     teaches the operator to dismiss the gate.
 *   - THROWN — no errno at all, i.e. a bug (a TypeError from an unloaded
 *     binding). Nothing here can be trusted, so it goes to the caller's
 *     declared failure posture. Same errno-vs-bug split {@link
 *     autoCleanFindings} uses.
 * @param {unknown} err
 * @returns {"absent" | "skipped"}  never returns for a non-errno throw
 */
function classifyReadFailure(err) {
  const code = /** @type {NodeJS.ErrnoException} */ (err).code;
  if (code === undefined) throw err;
  return code === "ENOENT" ? "absent" : "skipped";
}

/**
 * Scan every instruction file under the project, bucketing each unreadable
 * target through {@link classifyReadFailure}. `scanned` is DERIVED from the two
 * failure buckets, so the accounting invariant — every target is scanned,
 * skipped or absent — holds by construction and needs no comment restating it.
 * A target lost from that accounting is an instruction file that reaches the
 * model while the caller announces "clean".
 * @param {string} [dir]  project root to scan (injectable for tests)
 * @returns {{
 *   targets: string[],
 *   scanned: number,
 *   findings: Array<{file: string, findings: ReturnType<typeof scanFile>}>,
 *   skipped: Array<{file: string, reason: string}>,
 *   absent: string[],
 * }}
 */
export function scanProject(dir = PROJECT_DIR) {
  const targets = [...new Set(findInstructionFiles(dir))];
  const report = (/** @type {string} */ file) =>
    isInsideDir(dir, file) ? relative(dir, file) : file;
  const findings = [];
  const skipped = [];
  const absent = [];
  for (const file of targets) {
    let fileFindings;
    try {
      fileFindings = scanFile(file);
    } catch (err) {
      if (classifyReadFailure(err) === "absent") {
        absent.push(report(file));
        continue;
      }
      // safeErrMessage, not errMessage: this reason is rendered into stderr and
      // into ALERT_FILE, and an errno message embeds the absolute path globbed
      // out of a possibly-hostile repo — a filename carrying ANSI or invisible
      // bytes would otherwise reach the operator's terminal raw.
      skipped.push({ file: report(file), reason: safeErrMessage(err) });
      continue;
    }
    if (fileFindings.length > 0)
      findings.push({ file: report(file), findings: fileFindings });
  }
  const scanned = targets.length - skipped.length - absent.length;
  return { targets, scanned, findings, skipped, absent };
}

/**
 * The report for targets the scan could not read. Rendered into the alert the
 * PreToolUse gate surfaces, so an incomplete scan reaches the operator as a
 * checkpoint rather than as silence.
 * @param {Array<{file: string, reason: string}>} skipped
 * @returns {string}
 */
export function formatSkipped(skipped) {
  return [
    "",
    "━━━ INSTRUCTION FILES NOT SCANNED ━━━",
    "",
    "These files exist and load as project instructions, but this user could",
    "not read them, so they were never checked for hidden Unicode. Treat their",
    "content as unvetted.",
    "",
    ...skipped.map(({ file, reason }) => `  ${file}: ${reason}`),
    "",
  ].join("\n");
}

// Stryker disable all: CLI-entry body. It runs only as a spawned subprocess,
// which in-process tests can't observe, so every mutant here is unkillable by
// construction (same boundary as the c8-ignored regions below). The exported
// scanFile / decodeRun / scanProject above carry the real, tested logic.
/**
 * The hook's CLI: scan the instruction files, auto-clean what it can, persist
 * the alert for the PreToolUse gate otherwise. Exported so a bundle entry
 * (which must claim the CLI slot before this module loads) can run the exact
 * same scan instead of duplicating it.
 * @param {{
 *   trace?: import("./lib/trace.mjs").TraceFn,
 *   scan?: () => ReturnType<typeof scanProject>,
 * }} [opts]  `trace` is where this scan announces engagement; a host with its
 *   own trace channel passes its sink so the announcement lands where its
 *   detector reads (see lib/trace.mjs). `scan` is the scanner, injectable so the
 *   FAULT path below — a scanner that throws something other than an errno, i.e.
 *   a bug — is drivable end to end; no filesystem state can force it, and an
 *   untested fault path is how a posture goes missing in the first place.
 * @returns {Promise<void>}
 */
export async function cliMain(opts = {}) {
  // The scan blocks session startup, and a slow one is invisible from the
  // inside — it reads as "Claude is slow to start". Timing the whole body and
  // reporting an overrun in band is what turned a 30-second scan from a rumor
  // into a bug report (see lib/hook-timing.mjs).
  const elapsed = startHookTimer();
  try {
    await runScanCli(opts);
  } finally {
    reportSlowHook(
      HOOK_NAME,
      elapsed(),
      HookEvent.SESSION_START,
      emitHookResponse,
    );
  }
}

/**
 * The scan itself. Split from {@link cliMain} only so the timing wrapper above
 * has a single call to bracket — every early return here is an exit the wrapper
 * must still measure.
 * @param {{
 *   trace?: import("./lib/trace.mjs").TraceFn,
 *   scan?: () => ReturnType<typeof scanProject>,
 * }} opts  see {@link cliMain}
 * @returns {Promise<void>}
 */
async function runScanCli({ trace: sink = trace, scan: runScan }) {
  // Bound best-effort: the announcements below run BEFORE the auto-clean and
  // the alert write, with no catch above them, so a throwing host sink would
  // abort the scan silently (see bestEffortTrace).
  const emitTrace = bestEffortTrace(sink);
  // Everything the PreToolUse gate must surface this session, written once at
  // the end: an incomplete scan and an uncleanable file are independent reasons
  // to arm the gate, and two separate writes would have the second clobber the
  // first.
  /** @type {string[]} */
  const alertParts = [];
  /* c8 ignore start -- fail-closed module-load guard: only reachable when the
     agent-sanitizer import above failed, which can't be simulated in the
     spawned-subprocess CLI run the tests observe. */
  if (!(await ensureSanitizerLoaded())) {
    // Emit the engagement event with a "skipped" outcome so the loss is LOUD on
    // the trace channel — a scan that never ran is otherwise invisible, and the
    // downstream PreToolUse sanitize gate then passes cleanly all session.
    emitTrace(TraceEvent.SCAN_INVISIBLE_CHARS_RAN, { outcome: "skipped" });
    // Through the shared posture table, NOT a bare exit(1): this hook took an
    // advisory posture unconditionally, so an operator who pinned
    // AGENT_SANITIZER_FAIL_OPEN=0 got only a warning on the one hook guarding
    // session-start ingress, and the PreToolUse gate then passed cleanly for
    // the rest of the session. The closed arm arms the cross-hook alert, which
    // is the only channel a SessionStart hook has to make a later gate ask.
    alertParts.push(
      ...reportFault(
        new Error(
          "agent-sanitizer failed to load (node deps not installed and " +
            "session-setup did not finish in time); run `pnpm install`",
        ),
      ),
    );
    persistAlert(alertParts);
    process.exit(1);
  }
  /* c8 ignore stop */

  // Clean up stale alert + its ack marker from a previous session so this
  // session re-surfaces the gate once if injection is still present.
  for (const stale of [ALERT_FILE, ALERT_ACK_FILE]) {
    try {
      unlinkSync(stale);
    } catch {
      // Doesn't exist or not writable
    }
  }

  // Only a non-errno throw reaches here — a bug in the scanner, not a file it
  // could not read (those are accounted for in `skipped`). It is a fault of THIS
  // hook, so it renders through the same posture table as every other hook's
  // fault instead of aborting with no announcement at all.
  let scan;
  try {
    scan = (runScan ?? scanProject)();
  } catch (err) {
    emitTrace(TraceEvent.SCAN_INVISIBLE_CHARS_RAN, { outcome: "skipped" });
    alertParts.push(...reportFault(err));
    persistAlert(alertParts);
    return;
  }
  const { findings: allFindings, skipped, absent, scanned } = scan;

  // The three buckets of classifyReadFailure, rendered: only `skipped` may
  // withhold "clean" and arm the gate.
  if (skipped.length > 0) {
    emitTrace(TraceEvent.SCAN_INVISIBLE_CHARS_RAN, {
      outcome: "partial",
      scanned,
      skipped: skipped.length,
      absent: absent.length,
      files: allFindings.length,
    });
    const notice = formatSkipped(skipped);
    process.stderr.write(notice + "\n");
    alertParts.push(notice);
  } else if (allFindings.length === 0) {
    emitTrace(TraceEvent.SCAN_INVISIBLE_CHARS_RAN, {
      outcome: "clean",
      absent: absent.length,
    });
    return;
  } else {
    emitTrace(TraceEvent.SCAN_INVISIBLE_CHARS_RAN, {
      outcome: "found",
      absent: absent.length,
      files: allFindings.length,
    });
  }

  if (allFindings.length > 0)
    alertParts.push(...autoCleanFindings(allFindings, PROJECT_DIR));
  persistAlert(alertParts);
}

/**
 * Auto-clean the contaminated files so the session proceeds without blocking
 * every tool call, and return the alert text for whatever could not be cleaned
 * (empty when everything was). The gate hook is the fallback for the rest.
 * @param {Array<{file: string, findings: ReturnType<typeof scanFile>}>} allFindings
 * @param {string} dir  the root the finding paths are relative to
 * @returns {string[]}
 */
function autoCleanFindings(allFindings, dir) {
  let cleaned = 0;
  for (const { file } of allFindings) {
    // `resolve`, not `join`: an ancestor target is reported as an ABSOLUTE path
    // (it has no honest path relative to the project), which join would prefix.
    const absPath = resolve(dir, file);
    // A contaminated file ABOVE the project is real context and is reported, but
    // this hook does not rewrite it: it was pointed at a project, and silently
    // editing a parent directory's file — shared with every other project under
    // it — is a wider blast radius than an auto-clean has any claim to. Leaving
    // it uncleaned is what routes it to the alert below, whose remedy names the
    // cleanFile CLI to run against it deliberately.
    if (!isInsideDir(dir, absPath)) continue;
    try {
      // The SSOT clean: O_NOFOLLOW open, UTF-8 round-trip check, TOCTOU
      // recheck, atomic rename + fsync, mode preservation. The bare
      // readFileSync/writeFileSync pair that lived here had none of those
      // guards — on the one hook that REWRITES instruction files.
      //
      // Counted ONLY on `true` (bytes changed), matching the old
      // `stripped !== original` gate. `false` means cleanFile re-scanned and
      // found nothing to strip in a file this run flagged — the file was
      // changed under us, or the flagged run is one the stripper PRESERVES —
      // so it is not a file we cleaned, and leaving `cleaned` short is what
      // routes it to the alert below instead of an "all clean" report.
      if (cleanFile(absPath)) cleaned++;
      /* c8 ignore start -- only fires on a file cleanFile refuses (symlink,
         non-UTF-8, concurrent write) or cannot rewrite, which the test run
         does not create */
    } catch (err) {
      // The reason is REPORTED rather than swallowed: a refusal or an
      // unwritable file legitimately falls through to the alert path below. A
      // TypeError is the one throw that still propagates — an unbound lazy
      // import, i.e. a bug in THIS hook, which must not be laundered into
      // "this file resisted cleaning". (The scan phase has already exercised
      // the same bindings, so this is a belt-and-braces rethrow.)
      if (err instanceof TypeError) throw err;
      process.stderr.write(
        `scan-invisible-chars: could not clean ${file}: ${safeErrMessage(err)}\n`,
      );
    }
    /* c8 ignore stop */
  }

  const report = formatReport(allFindings);
  if (cleaned === allFindings.length) {
    process.stderr.write(
      report +
        `\nAll ${cleaned} file(s) above were cleaned on disk automatically — ` +
        "the payload is gone from them, and nothing is blocked.\n" +
        "Check what was removed: run `git diff` in the project.\n" +
        "Claude Code loads instruction files at session start, so THIS " +
        "session may have read the pre-clean bytes before the hook ran. Treat " +
        "any odd instruction from these files with suspicion; a new session " +
        "loads only the cleaned text.\n",
    );
    return [];
  }
  process.stderr.write(report + "\n");
  return [report];
}

if (isMain(import.meta.url)) {
  await cliMain();
}
