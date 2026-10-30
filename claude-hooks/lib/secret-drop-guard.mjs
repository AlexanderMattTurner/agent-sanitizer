/**
 * Clobber-by-omission guard for whole-file Writes, and the confirm-by-exact-
 * re-issue sentinel it shares with every other releasable PreToolUse refusal.
 *
 * Rehydration (agent-sanitizer/rehydrate) only engages when a Write's content
 * carries a placeholder; a Write that REGENERATES a secret-bearing file and
 * simply drops the secret line (reworded to `API_KEY=<your-key-here>`, or
 * omitted) never enters that layer, and the real secret is silently destroyed.
 * "Tracked by git" is used as an approximation of "recoverable": a tracked
 * file's committed content survives the Write, so the guard stays out of the
 * way — even though an uncommitted secret line on a tracked file is still
 * lost (accepted: precision over recall). For an UNTRACKED file — `.env` and
 * its kin are gitignored precisely because they hold secrets, and files
 * outside any repository count too — there is no git recovery, so the first
 * such Write is denied with an instructive reason and the model confirms by
 * re-issuing the exact same call: a deliberate retry, never a human
 * permission prompt.
 *
 * The confirm state is a presence sentinel keyed to a fingerprint of
 * (file_path, content, dropped secret values) under $TMPDIR, written and read
 * with the same squat-resistant helpers the invisible-char gate uses
 * (markerIsTrusted / writeSentinelFile), consumed on use, and expired after
 * {@link CONFIRM_TTL_MS}, so one confirmation approves exactly one prompt
 * Write — never a stale or standing auto-approval.
 *
 * Skip-on-ambiguity (per the package's precision-over-recall doctrine): a
 * failed git probe, an unmappable redaction view, or a secret-free file all
 * skip the guard — a false denial here blocks legitimate work, while a false
 * pass costs only what the call would do without this guard. This is a
 * guard-local precision choice, not the hook fault posture: an unexpected
 * throw still propagates to the hook's registered policy (lib/hook-fault.mjs).
 */
import { createHash } from "node:crypto";
import { lstatSync, readdirSync, unlinkSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import {
  lazyImport,
  markerIsTrusted,
  PROJECT_HASH,
  writeSentinelFile,
} from "./hook-io.mjs";

// Layer-1 view primitives, bound via lazyImport (see its doc for the fail-OPEN
// hazard of a bare static npm import): a load failure leaves these undefined,
// so the guard's use throws into the hook's posture-managed catch.
const { applyLayer1, LONE_SURROGATE_RE } =
  /** @type {typeof import("agent-sanitizer")} */ (
    await lazyImport("agent-sanitizer")
  );

/** A confirm sentinel older than this is stale, not a confirmation. */
export const CONFIRM_TTL_MS = 10 * 60_000;

/**
 * Fingerprint of one exact drop: same path, same new bytes, same set of
 * secret values being removed. The model confirms by re-issuing the identical
 * call, so the sentinel must match nothing broader — including the dropped
 * values themselves: if the file's secrets change between the deny and the
 * retry, the retry is dropping something the model was never warned about,
 * and must be re-denied.
 * @param {string} filePath
 * @param {string} content
 * @param {string[]} [dropped] the secret values the Write would remove
 * @returns {string}
 */
export function dropFingerprint(filePath, content, dropped = []) {
  const digest = createHash("sha256").update("drop\0").update(filePath);
  digest.update("\0");
  digest.update(content);
  for (const secret of dropped) digest.update("\0").update(secret);
  return digest.digest("hex").slice(0, 32);
}

/**
 * Fingerprint of one refusal of one exact tool call — same refusing site, same
 * tool, same input — released by re-issuing that call. Keyed on the site too, so
 * a call refused by two sites in turn needs a confirmation for each and one
 * re-issue never releases a refusal the model was not shown. The input is
 * hashed in canonical key order, so a re-issue whose keys arrive reordered is
 * still the same call. Distinct domain tags keep it disjoint from
 * {@link dropFingerprint}.
 * @param {string} site
 * @param {unknown} tool
 * @param {unknown} toolInput
 * @returns {string}
 */
export function reissueFingerprint(site, tool, toolInput) {
  return createHash("sha256")
    .update("reissue\0")
    .update(canonicalJson([site, tool ?? null, toolInput ?? null]))
    .digest("hex")
    .slice(0, 32);
}

/**
 * JSON with every object's keys sorted, so two encodings of one value agree.
 * @param {unknown} value
 * @returns {string}
 */
function canonicalJson(value) {
  return JSON.stringify(value, (_key, v) =>
    v !== null && typeof v === "object" && !Array.isArray(v)
      ? Object.fromEntries(
          Object.keys(v)
            .sort()
            .map((k) => [k, v[k]]),
        )
      : v,
  );
}

/**
 * Record a confirm sentinel for `fingerprint`, so the identical re-issue is
 * approved by {@link consumeConfirm}. False when it could not be recorded: the
 * caller then must not refuse, because nothing could ever release the refusal.
 * @param {string} fingerprint
 * @returns {boolean}
 */
export function recordConfirm(fingerprint) {
  return writeSentinelFile(confirmMarkerPath(fingerprint));
}

/**
 * The confirm sentinel's path for one fingerprint. Predictable and
 * world-visible like the alert markers, hence the markerIsTrusted read.
 * @param {string} fingerprint
 * @returns {string}
 */
export function confirmMarkerPath(fingerprint) {
  return join(tmpdir(), `.claude-secret-drop-${PROJECT_HASH}-${fingerprint}`);
}

/**
 * Delete this project's confirm sentinels older than {@link CONFIRM_TTL_MS}.
 *
 * consumeConfirm removes the sentinel it honors, but an abandoned confirmation —
 * denied, never retried — is removed by nothing, so the store grows for the life
 * of the machine. Called from SessionStart, the one touchpoint that runs once per
 * session rather than once per tool call. A sentinel past the TTL is already inert
 * (consumeConfirm refuses it), so this reclaims space without changing a verdict.
 * @returns {void}
 */
export function sweepStaleConfirms() {
  const dir = tmpdir();
  const prefix = `.claude-secret-drop-${PROJECT_HASH}-`;
  const cutoff = Date.now() - CONFIRM_TTL_MS;
  for (const name of readdirSync(dir)) {
    if (!name.startsWith(prefix)) continue;
    const path = join(dir, name);
    try {
      // lstat, not stat: a squatted symlink at a predictable path is judged on
      // ITSELF, and unlink removes the link rather than its target.
      if (lstatSync(path).mtimeMs < cutoff) unlinkSync(path);
    } catch (err) {
      // ENOENT: a parallel session swept this entry between readdir and lstat.
      // EPERM/EACCES: a co-tenant's entry, which is not ours to remove. Anything
      // else is a bug in this sweep and propagates.
      const code = /** @type {NodeJS.ErrnoException} */ (err).code;
      if (code !== "ENOENT" && code !== "EPERM" && code !== "EACCES") throw err;
    }
  }
}

/**
 * Whether git tracks `filePath`, with every probe failure on the skip side the
 * module doc declares. Exit 0 is tracked and exit 1 untracked. Exit 128 is
 * either "not a repository" — no git recovery exists, so the guard applies — or
 * a repository git could not read (a corrupt index, a permission error), which
 * says nothing about the file; a second probe asks git which, reading its
 * printed answer (`false` inside a bare repository or a `.git` directory is
 * also exit 0, and also has no recovery path). A spawn-level
 * failure (no git binary) or any other status also means we cannot tell —
 * report tracked so the guard skips rather than denying on broken tooling.
 * @param {string} filePath
 * @param {typeof spawnSync} [spawn]
 * @returns {boolean}
 */
export function gitTracked(filePath, spawn = spawnSync) {
  const cwd = dirname(filePath);
  const res = spawn("git", ["ls-files", "--error-unmatch", "--", filePath], {
    cwd,
    stdio: "ignore",
  });
  if (res.error) return true;
  if (res.status === 0 || res.status === 1) return res.status === 0;
  if (res.status !== 128) return true;
  const repo = spawn("git", ["rev-parse", "--is-inside-work-tree"], {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });
  if (repo.error) return true;
  // Exit 0 does not mean "in a work tree": inside a bare repository or a
  // repository's own `.git` directory it prints `false`. Such a path has no
  // work-tree/index recovery, so only the printed `true` skips the guard.
  return repo.status === 0 && String(repo.stdout).trim() === "true";
}

/**
 * @param {number} count
 * @param {string} filePath
 * @param {boolean} [confirmable] false when no confirmation could be recorded,
 *   so the reason must not offer a re-issue that would only be refused again
 * @returns {string}
 */
function dropDeny(count, filePath, confirmable = true) {
  const head =
    `this Write removes ${count} redacted secret value(s) from ${filePath}, and the ` +
    `file is not tracked by git, so the secrets may be unrecoverable. `;
  const placeholders = `[REDACTED…] placeholder (or its secret's line) in the new content`;
  return confirmable
    ? `${head}If removing them is intended, re-issue this exact Write to confirm; ` +
        `otherwise keep each ${placeholders}`
    : `${head}Keep each ${placeholders}, or ask the user to remove them`;
}

/**
 * The `fault` a drop deny carries when its confirmation could not be recorded:
 * the deny could then never be released by a re-issue, so it is a sanitizer
 * fault rather than a verdict, and the hook's fault posture decides it.
 * @param {number} count
 * @param {string} filePath
 * @returns {string}
 */
function dropUnconfirmable(count, filePath) {
  return (
    `the secret-drop confirmation could not be recorded under ${tmpdir()}, so ` +
    `this Write removes ${count} redacted secret value(s) from untracked ` +
    `${filePath} without a confirmed re-issue`
  );
}

/**
 * Deny a first-time Write that would drop a redacted secret from an untracked
 * file, or null to let it pass. `toolInput` is the FINAL Write input — after
 * rehydration substituted any placeholders — so a preserved secret shows up as
 * its real value in `content`. `io` is the rehydrate-shaped I/O bag (readFile /
 * redact / redactMap). Injectable seams: `isTracked` (the git probe),
 * `confirmSeen`/`recordConfirm` (the sentinel state). A deny whose confirmation
 * could not be recorded carries `fault` (see {@link dropUnconfirmable}).
 * @param {{file_path?: unknown, content?: unknown}} toolInput
 * @param {import("agent-sanitizer/rehydrate").RehydrateIo} io
 * @param {{
 *   isTracked?: (filePath: string) => boolean,
 *   confirmSeen?: (fingerprint: string) => boolean,
 *   recordConfirm?: (fingerprint: string) => boolean,
 * }} [opts]
 * @returns {Promise<{deny: string, fault?: string} | null>}
 */
export async function secretDropGuard(toolInput, io, opts = {}) {
  const {
    isTracked = gitTracked,
    confirmSeen = consumeConfirm,
    recordConfirm: record = recordConfirm,
  } = opts;
  const { file_path: filePath, content } = toolInput ?? {};
  if (typeof filePath !== "string" || typeof content !== "string") return null;

  let disk;
  try {
    disk = io.readFile(filePath);
  } catch (err) {
    // ENOENT: the Write CREATES the file — nothing on disk to drop, and the
    // hinted-creation case is already rehydration's deny. Any other read
    // failure propagates: the Write itself will hit the same error, and this
    // guard must not convert an unexpected failure into a silent pass.
    if (/** @type {NodeJS.ErrnoException} */ (err)?.code === "ENOENT")
      return null;
    throw err;
  }
  if (isTracked(filePath)) return null;
  const cleaned = applyLayer1(disk).cleaned.replace(
    LONE_SURROGATE_RE,
    "\uFFFD",
  );
  // Cheap secrets-present probe: null exactly when the file holds no secrets —
  // the overwhelmingly common case pays one daemon round-trip and no map.
  if ((await io.redact(cleaned)) === null) return null;
  const view = await io.redactMap(cleaned);
  // Unmappable: cannot resolve WHICH values the file holds, so the drop set is
  // unknowable — skip rather than deny on ambiguity (rehydration already
  // denies the hinted calls this state actually endangers).
  if ("unmappable" in view) return null;
  const dropped = [...new Set(view.pairs.map((pair) => pair.original))].filter(
    (secret) => !content.includes(secret),
  );
  if (dropped.length === 0) return null;

  const fingerprint = dropFingerprint(filePath, content, dropped);
  // THE INVARIANT THIS ENFORCES: a confirmation approves exactly one drop —
  // the identical (path, bytes, drop-set) — and only for CONFIRM_TTL_MS. The
  // window must outlive a model retry (the confirmation IS the retry, so a
  // shorter one would deny forever) and must not outlive the session's working
  // context, or a marker left by an abandoned attempt becomes a standing
  // auto-approval for a Write the user never saw.
  if (confirmSeen(fingerprint)) return null;
  if (record(fingerprint)) return { deny: dropDeny(dropped.length, filePath) };
  return {
    deny: dropDeny(dropped.length, filePath, false),
    fault: dropUnconfirmable(dropped.length, filePath),
  };
}

/**
 * Compose a Layer-4 rehydrator with this guard: for a Write the rehydrator
 * did not deny, run the guard on the FINAL content — after any placeholder
 * substitution — so a rehydrated secret counts as preserved and only a
 * genuinely dropped one can trip it. A rehydrate deny short-circuits (the
 * guard never runs), non-Write tools skip the guard entirely, and a guard
 * deny wins over a pass/rewrite result.
 * @typedef {{updatedInput: any, context: string} | {deny: string, fault?: string} | null} RehydrateResult
 * @param {(tool: string, toolInput: any) => Promise<RehydrateResult>} rehydrate
 * @param {import("agent-sanitizer/rehydrate").RehydrateIo} io
 * @param {typeof secretDropGuard} [guard]
 * @returns {(tool: string, toolInput: any) => Promise<RehydrateResult>}
 */
export function withSecretDropGuard(rehydrate, io, guard = secretDropGuard) {
  return async (tool, toolInput) => {
    const rehydrated = await rehydrate(tool, toolInput);
    if (tool !== "Write" || (rehydrated !== null && "deny" in rehydrated))
      return rehydrated;
    const finalInput =
      rehydrated === null ? toolInput : rehydrated.updatedInput;
    const drop = await guard(finalInput, io);
    return drop ?? rehydrated;
  };
}

/**
 * True when a trusted, fresh confirm sentinel exists for `fingerprint`,
 * consuming it so one confirmation approves exactly one call. A sentinel
 * older than {@link CONFIRM_TTL_MS} is stale — an abandoned deny from a
 * previous session, not a live confirmation — so it is removed and NOT
 * honored, preventing a leftover marker from acting as a standing
 * auto-approval. Removal is best-effort: a fresh marker we could not unlink
 * still counted as consumed for THIS call, and a leftover empty sentinel only
 * ever re-approves the identical fingerprinted call the model already
 * confirmed — and only within the TTL.
 * @param {string} fingerprint
 * @returns {boolean}
 */
export function consumeConfirm(fingerprint) {
  const marker = confirmMarkerPath(fingerprint);
  if (!markerIsTrusted(marker)) return false;
  const fresh = confirmFresh(fingerprint);
  try {
    unlinkSync(marker);
  } catch {
    // Best-effort consume — see doc.
  }
  return fresh;
}

/**
 * True when a trusted confirm sentinel younger than {@link CONFIRM_TTL_MS}
 * exists for `fingerprint`, WITHOUT consuming it — for a caller that learns
 * only later whether the call it confirms actually proceeds, and consumes it
 * then.
 * @param {string} fingerprint
 * @returns {boolean}
 */
export function confirmFresh(fingerprint) {
  const marker = confirmMarkerPath(fingerprint);
  if (!markerIsTrusted(marker)) return false;
  try {
    return Date.now() - lstatSync(marker).mtimeMs <= CONFIRM_TTL_MS;
  } catch {
    // Raced away between the trust check and the stat: no sentinel, no confirm.
    return false;
  }
}
