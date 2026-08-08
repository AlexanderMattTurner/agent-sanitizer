/**
 * SessionStart: scan CLAUDE.md and .claude/ markdown for runs of invisible
 * Unicode that may encode hidden instructions. Pasted markdown can embed
 * invisible sequences (tag chars, zero-width encodings) that hijack the model's
 * behavior — invisible in an editor but read by the LLM. These files load as
 * project instructions at session start, bypassing the PostToolUse sanitizer.
 */
import { readFileSync, globSync, writeFileSync, unlinkSync } from "node:fs";
import { join, relative } from "node:path";
import {
  awaitLazyDependency,
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
import { bestEffortTrace, trace, TraceEvent } from "./lib/trace.mjs";
import { reportSlowHook, startHookTimer } from "./lib/hook-timing.mjs";

// Layer-1 primitives, bound via lazyImport (see its doc for the fail-OPEN
// hazard of a bare static npm import — here the instruction files would load
// UNSCANNED). A failed load leaves the bindings undefined; on a cold container
// (node deps not yet installed) cliMain's guard below waits out session-setup
// before giving up, and fails loud rather than silently passing.
// `let`, not `const`: the cold-start poll re-binds these once the package loads.
let {
  LONG_RUN_RE,
  LONG_RUN_THRESHOLD,
  SCATTERED_THRESHOLD: TOTAL_INVISIBLE_THRESHOLD,
  STRIP,
  stripInvisible,
} = /** @type {typeof import("agent-sanitizer/invisible")} */ (
  await lazyImport("agent-sanitizer/invisible")
);

/**
 * Re-attempt the sanitizer import, waiting out an in-flight session-setup before
 * giving up. On a cold container the node deps this hook needs are still being
 * installed when SessionStart fires; without this wait `stripInvisible` is
 * undefined, the scan is skipped, and the instruction files load UNSCANNED for the
 * whole session (fail open) — silently. Reuses the control-plane poll (marker +
 * PID liveness) so the wait bound matches every other cold-start-aware gate.
 * @returns {Promise<boolean>} whether the sanitizer is now bound
 */
async function ensureSanitizerLoaded() {
  if (typeof stripInvisible === "function") return true;
  /* c8 ignore start -- cold-start reload: only runs when the top-level
     agent-sanitizer import above failed (node deps not yet installed), which
     can't be simulated in-process or in the spawned-subprocess CLI run the tests
     observe (the test env always has the deps, so the guard above early-returns).
     The reload reuses awaitLazyDependency / markerIsTrusted /
     probeSetupAlive, each unit-tested directly. */
  const marker = hookgateMarkerPath();
  const reloaded = await awaitLazyDependency({
    tryImport: async () => {
      const mod = await lazyImport("agent-sanitizer/invisible");
      return typeof mod.stripInvisible === "function" ? mod : null;
    },
    markerPresent: () => markerIsTrusted(marker),
    setupAlive: () => probeSetupAlive(marker),
  });
  if (!reloaded) return false;
  ({
    LONG_RUN_RE,
    LONG_RUN_THRESHOLD,
    SCATTERED_THRESHOLD: TOTAL_INVISIBLE_THRESHOLD,
    STRIP,
    stripInvisible,
  } = /** @type {typeof import("agent-sanitizer/invisible")} */ (reloaded));
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
 * @param {string} run
 * @returns {{ method: string, decoded: string }}
 */
function decodeRun(run) {
  const cps = [...run].map((ch) => /** @type {number} */ (ch.codePointAt(0)));

  // Tag characters U+E0001-U+E007F map directly to ASCII
  const tagAscii = cps
    .filter((cp) => cp >= 0xe0001 && cp <= 0xe007f)
    // Stryker disable next-line ArithmeticOperator: cp - 0xe0000 → cp + 0xe0000 is equivalent — 0xe0000 is a multiple of 2^16 and String.fromCharCode truncates to 16 bits, so both yield the same character.
    .map((cp) => String.fromCharCode(cp - 0xe0000))
    .join("");

  if (tagAscii.length > 0) {
    return { method: "Unicode tag characters → ASCII", decoded: tagAscii };
  }

  // Zero-width binary encoding: ZWSP=0, ZWNJ=1, ZWJ=group separator.
  const ZW_BIT = new Map([
    [0x200b, "0"],
    [0x200c, "1"],
    [0x200d, "|"],
  ]);
  if (cps.every((cp) => ZW_BIT.has(cp))) {
    const bits = cps.map((cp) => ZW_BIT.get(cp)).join("");
    return {
      method: "zero-width binary encoding",
      decoded: `[${cps.length} zero-width chars: ${bits.slice(0, 80)}]`,
    };
  }

  // Mixed/unknown
  return {
    method: "invisible Unicode sequence",
    decoded: cps
      .map((cp) => `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`)
      .join(" "),
  };
}

/**
 * The `.claude/` subdirectories whose markdown Claude Code loads as model
 * context. This is a WHITELIST, and that is the point: `.claude/` is also where
 * tooling parks bulk data that is never loaded as context — `worktrees/`
 * (entire checked-out copies of the repo), plus caches, transcripts and
 * snapshots — and globbing `.claude/**` swept all of it in. On a repo with a few
 * populated worktrees that is thousands of files READ at every session start:
 * one report put it at 30 seconds of blocked startup, paid for scanning files
 * that cannot reach the model.
 *
 * A whitelist, not a `worktrees` denylist, because the failure modes are not
 * symmetric: an unlisted context directory costs a scan this hook was never
 * asked for anyway (the PostToolUse sanitizer still cleans those bytes when a
 * tool reads them), while an unlisted BULK directory silently costs every future
 * session its startup. Add an entry here when Claude Code starts loading a new
 * `.claude/` subdirectory as context.
 */
export const CLAUDE_CONTEXT_SUBDIRS = Object.freeze([
  "agents",
  "commands",
  "output-styles",
  "skills",
]);

// The glob patterns for one `.claude` tree at `prefix` (empty for the project
// root, a doubled-star segment for nested ones): its top-level markdown, plus the
// whitelisted context subdirectories. Built once, from the one list above.
/** @param {string} prefix @returns {string[]} */
function claudeDirPatterns(prefix) {
  return [
    `${prefix}.claude/*.md`,
    ...CLAUDE_CONTEXT_SUBDIRS.map((sub) => `${prefix}.claude/${sub}/**/*.md`),
  ];
}

/**
 * Entries the walk must not descend into or return: `node_modules`, and every
 * child of a `.claude` directory that is not whitelisted context.
 *
 * The patterns alone would already refuse to MATCH those files, but globSync
 * calls this on directories as it walks and prunes the ones it rejects — which
 * is where the cost actually is. Without the prune, a `.claude/worktrees/`
 * holding a few repo checkouts is walked in full on every session start (and,
 * because a doubled-star segment does cross into a dot directory when the
 * pattern names one, a `.claude` NESTED inside a worktree was matched and
 * scanned as if it were this session's context).
 *
 * globSync calls this with both bare names and repo-relative paths, so it must
 * answer for either; a bare name carries no `.claude` context and is judged only
 * against `node_modules`.
 * @param {string} entry  a bare entry name or a path relative to the scan root
 * @returns {boolean}
 */
function excludeFromScan(entry) {
  if (entry === "node_modules") return true;
  const parts = entry.split(/[/\\]/);
  const claudeIndex = parts.indexOf(".claude");
  const tail = parts.slice(claudeIndex + 1);
  if (claudeIndex === -1 || tail.length === 0) return false;
  // `.claude/<file>.md` is context (a top-level note); anything else directly
  // under `.claude` must be a whitelisted subdirectory to be walked at all.
  if (tail.length === 1 && tail[0].endsWith(".md")) return false;
  return !CLAUDE_CONTEXT_SUBDIRS.includes(tail[0]);
}

/**
 * Every file under `dir` that Claude Code loads as model context: the
 * subdirectory instruction files (CLAUDE.md, CLAUDE.local.md, AGENTS.md) and the
 * whitelisted `.claude/` markdown (see {@link CLAUDE_CONTEXT_SUBDIRS}). Claude
 * Code loads these on entry to their containing directory — a load path that
 * bypasses the PostToolUse sanitizer — so a payload planted in e.g.
 * `packages/foo/CLAUDE.md` reaches the model uncleaned unless it is scanned
 * here. Skips node_modules.
 *
 * `**` does not descend into dot directories, so NESTED `.claude/` trees need
 * their own doubled-star-prefixed patterns: without them a directory-scoped skill at
 * `packages/foo/.claude/skills/x/SKILL.md` — model context by the same load
 * path — is never scanned. That same rule is why the root `.claude` needs no
 * separate walk: a leading doubled star matches zero segments, so the nested
 * patterns cover the root tree too.
 * @param {string} dir
 * @returns {string[]}
 */
function findInstructionFiles(dir) {
  return globSync(
    [
      "**/CLAUDE.md",
      "**/CLAUDE.local.md",
      "**/AGENTS.md",
      ...claudeDirPatterns("**/"),
    ],
    { cwd: dir, exclude: excludeFromScan },
  ).map((name) => join(dir, name));
}

// Scanner

/**
 * @param {string} filePath
 * @returns {Array<{ line: number, charCount: number, method: string, decoded: string }>}
 */
function scanFile(filePath) {
  const content = readFileSync(filePath, "utf-8");
  const findings = [];
  LONG_RUN_RE.lastIndex = 0;
  let match;
  let runChars = 0;
  while ((match = LONG_RUN_RE.exec(content)) !== null) {
    const lineNum = content.slice(0, match.index).split("\n").length;
    const charCount = [...match[0]].length;
    runChars += charCount;
    findings.push({ line: lineNum, charCount, ...decodeRun(match[0]) });
  }

  // Threshold-evasion: scattered invisible chars not in a long run can still be
  // a payload. Always evaluated; chars already in a run are excluded so they
  // aren't double-counted.
  const allInvisible = content.match(STRIP);
  const scattered = (allInvisible ? allInvisible.length : 0) - runChars;
  if (scattered >= TOTAL_INVISIBLE_THRESHOLD) {
    findings.push({
      line: 0,
      charCount: scattered,
      method: "scattered invisible chars (possible threshold evasion)",
      decoded: `[${scattered} invisible chars distributed across file]`,
    });
  }

  return findings;
}

export {
  decodeRun,
  findInstructionFiles,
  scanFile,
  ALERT_FILE,
  ALERT_ACK_FILE,
  LONG_RUN_RE,
  LONG_RUN_THRESHOLD,
  TOTAL_INVISIBLE_THRESHOLD,
};

/**
 * @param {Array<{
 *   file: string,
 *   findings: Array<{ line: number, charCount: number, method: string, decoded: string }>,
 * }>} allFindings
 * @returns {string}
 */
function formatReport(allFindings) {
  const BAR = "━".repeat(52);
  const lines = [
    "",
    `━━━ INVISIBLE CHARACTER INJECTION DETECTED ${BAR.slice(0, 11)}`,
    "",
    "Invisible Unicode in instruction files can hijack the model’s behavior",
    "(skill invocation, tool use, instruction override). This commonly",
    "happens when copy-pasting content from the internet.",
    "",
    "These files are loaded directly as context, bypassing PostToolUse",
    "sanitization, so the invisible characters reach the model raw.",
    "",
  ];

  for (const { file, findings } of allFindings) {
    lines.push(`  ${file}:`);
    for (const finding of findings) {
      lines.push(
        `    Line ${finding.line}: ${finding.charCount} invisible chars (${finding.method})`,
      );
      lines.push(`    Decodes to: ${JSON.stringify(finding.decoded)}`);
    }
    lines.push("");
  }

  lines.push(BAR);
  return lines.join("\n");
}

export { formatReport };

// Main (skip when imported for testing)

/**
 * Scan every instruction file under the project, ACCOUNTING for every target
 * the finder returned: `scanned + skipped.length === targets.length`, always.
 *
 * The accounting is the point. This scan is the only thing standing between a
 * poisoned `CLAUDE.md` and a session that loads it as instructions, and its
 * caller announces "clean" on the trace channel — the channel that exists so a
 * MISSING announcement is loud. A per-file failure swallowed into an empty
 * findings list turns "we could not read this file" into "this file is fine",
 * which is the one lie this hook must never tell. So a file that cannot be read
 * is REPORTED as unscanned, not dropped.
 *
 * ANY errno is a skip; only a non-filesystem throw propagates. The split is
 * between "this file could not be read" (report it and keep scanning) and "this
 * code is broken" (a TypeError from an unloaded binding — nothing here can be
 * trusted, so it goes to the caller's declared failure posture). Catching only
 * ENOENT would invert the enforcement: one EACCES target would discard the
 * result for EVERY other instruction file, leaving them unscanned and
 * un-auto-cleaned, and under the shipped OPEN posture the hook fault arms
 * nothing — so the SUSPICIOUS failure would get weaker enforcement than the
 * benign glob race, which reaches `partial` and arms the gate. Same errno-vs-bug
 * split {@link autoCleanFindings} uses.
 * @param {string} [dir]  project root to scan (injectable for tests)
 * @returns {{
 *   targets: string[],
 *   scanned: number,
 *   findings: Array<{file: string, findings: ReturnType<typeof scanFile>}>,
 *   skipped: Array<{file: string, reason: string}>,
 * }}
 */
export function scanProject(dir = PROJECT_DIR) {
  const targets = [...new Set(findInstructionFiles(dir))];
  const findings = [];
  const skipped = [];
  let scanned = 0;
  for (const file of targets) {
    let fileFindings;
    try {
      fileFindings = scanFile(file);
    } catch (err) {
      if (/** @type {NodeJS.ErrnoException} */ (err).code === undefined)
        throw err;
      // safeErrMessage, not errMessage: this reason is rendered into stderr and
      // into ALERT_FILE, and an errno message embeds the absolute path globbed
      // out of a possibly-hostile repo — a filename carrying ANSI or invisible
      // bytes would otherwise reach the operator's terminal raw.
      skipped.push({ file: relative(dir, file), reason: safeErrMessage(err) });
      continue;
    }
    scanned++;
    if (fileFindings.length > 0)
      findings.push({ file: relative(dir, file), findings: fileFindings });
  }
  return { targets, scanned, findings, skipped };
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
    "These files load as project instructions but could NOT be read, so they",
    "were never checked for hidden Unicode. Treat their content as unvetted.",
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
    reportSlowHook(HOOK_NAME, elapsed(), HookEvent.SESSION_START);
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
  const { findings: allFindings, skipped, scanned } = scan;

  // "clean" is a claim about EVERY target, so it may only be made when every
  // target was read. A scan that could not read one says "partial" and arms the
  // gate: an unread instruction file is UNVETTED context, not absent findings.
  if (skipped.length > 0) {
    emitTrace(TraceEvent.SCAN_INVISIBLE_CHARS_RAN, {
      outcome: "partial",
      scanned,
      skipped: skipped.length,
      files: allFindings.length,
    });
    const notice = formatSkipped(skipped);
    process.stderr.write(notice + "\n");
    alertParts.push(notice);
  } else if (allFindings.length === 0) {
    emitTrace(TraceEvent.SCAN_INVISIBLE_CHARS_RAN, { outcome: "clean" });
    return;
  } else {
    emitTrace(TraceEvent.SCAN_INVISIBLE_CHARS_RAN, {
      outcome: "found",
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
    const absPath = join(dir, file);
    try {
      const original = readFileSync(absPath, "utf-8");
      const stripped = stripInvisible(original);
      if (stripped !== original) {
        writeFileSync(absPath, stripped);
        cleaned++;
      }
      /* c8 ignore start -- only fires on a file this uid cannot rewrite, which the test run cannot create */
    } catch (err) {
      // Narrowed to filesystem errnos, and the reason is REPORTED rather than
      // swallowed: an unwritable file legitimately falls through to the alert
      // path below, but a throw from stripInvisible is a bug in the sanitizer
      // and must not be laundered into "this file resisted cleaning".
      if (/** @type {NodeJS.ErrnoException} */ (err).code === undefined)
        throw err;
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
        `\nAll ${cleaned} file(s) cleaned on disk automatically. ` +
        "NOTE: these files load as project instructions at session start, so " +
        "THIS session may have already ingested the pre-clean bytes before the " +
        "hook ran — treat any injected-looking instruction from them with " +
        "suspicion, and restart the session if in doubt. Future sessions load " +
        "the cleaned files.\n",
    );
    return [];
  }
  /* c8 ignore start -- only reachable when the write catch above fires */
  process.stderr.write(report + "\n");
  return [report];
  /* c8 ignore stop */
}

if (isMain(import.meta.url)) {
  await cliMain();
}
