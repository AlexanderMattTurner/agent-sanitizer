/**
 * Clobber-by-omission guard for whole-file Writes.
 *
 * Rehydration (agent-sanitizer/rehydrate) only engages when a Write's content
 * carries a placeholder; a Write that REGENERATES a secret-bearing file and
 * simply drops the secret line (reworded to `API_KEY=<your-key-here>`, or
 * omitted) never enters that layer, and the real secret is silently destroyed.
 * For a git-tracked file that loss is one checkout away from recovery, so the
 * guard stays out of the way. For an UNTRACKED file — `.env` and its kin are
 * gitignored precisely because they hold secrets — there is no recovery, so
 * the first such Write is denied with an instructive reason and the model
 * confirms by re-issuing the exact same call: a deliberate retry, never a
 * human permission prompt.
 *
 * The confirm state is a presence sentinel keyed to a fingerprint of
 * (file_path, content) under $TMPDIR, written and read with the same
 * squat-resistant helpers the invisible-char gate uses (markerIsTrusted /
 * writeSentinelFile) and consumed on use, so one confirmation approves exactly
 * one Write.
 *
 * Fail-open posture (per the package's precision-over-recall doctrine): a
 * failed git probe, an unmappable redaction view, or a secret-free file all
 * skip the guard — a false denial here blocks legitimate work, while a false
 * pass costs only what today's behavior already allows.
 */
import { createHash } from "node:crypto";
import { unlinkSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { lazyImport, markerIsTrusted, writeSentinelFile } from "./hook-io.mjs";
import { PROJECT_DIR } from "./invisible-alert.mjs";

// Layer-1 view primitives, bound via lazyImport (see its doc for the fail-OPEN
// hazard of a bare static npm import): a load failure leaves these undefined,
// so the guard's use throws into the hook's posture-managed catch.
const { applyLayer1, LONE_SURROGATE_RE } =
  /** @type {typeof import("agent-sanitizer")} */ (
    await lazyImport("agent-sanitizer")
  );

const PROJECT_HASH = createHash("sha256")
  .update(PROJECT_DIR)
  .digest("hex")
  .slice(0, 8);

/**
 * Fingerprint of one exact Write: same path, same bytes. The model confirms by
 * re-issuing the identical call, so the sentinel must match nothing broader.
 * @param {string} filePath
 * @param {string} content
 * @returns {string}
 */
export function dropFingerprint(filePath, content) {
  return createHash("sha256")
    .update(filePath)
    .update("\0")
    .update(content)
    .digest("hex")
    .slice(0, 32);
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
 * Whether git tracks `filePath`. Exit 0 is tracked; exit 1 (untracked) and 128
 * (not a repository) both mean "no git recovery exists", which is what the
 * guard actually cares about. A spawn-level failure (no git binary) means we
 * cannot tell — report tracked so the guard skips (fail open) rather than
 * denying on missing tooling.
 * @param {string} filePath
 * @param {typeof spawnSync} [spawn]
 * @returns {boolean}
 */
export function gitTracked(filePath, spawn = spawnSync) {
  const res = spawn("git", ["ls-files", "--error-unmatch", "--", filePath], {
    cwd: dirname(filePath),
    stdio: "ignore",
  });
  if (res.error) return true;
  return res.status === 0;
}

/**
 * @param {number} count
 * @param {string} filePath
 * @param {string} hint
 * @returns {string}
 */
function dropDeny(count, filePath, hint) {
  return (
    `this Write removes ${count} redacted secret value(s) from ${filePath}, and the ` +
    `file is not tracked by git, so the secrets may be unrecoverable. If removing ` +
    `them is intended, re-issue this exact Write to confirm; otherwise keep each ` +
    `${hint}…] placeholder (or its secret's line) in the new content`
  );
}

/**
 * Deny a first-time Write that would drop a redacted secret from an untracked
 * file, or null to let it pass. `toolInput` is the FINAL Write input — after
 * rehydration substituted any placeholders — so a preserved secret shows up as
 * its real value in `content`. `io` is the rehydrate-shaped I/O bag (readFile /
 * redact / redactMap). Injectable seams: `isTracked` (the git probe),
 * `confirmSeen`/`recordConfirm` (the sentinel state).
 * @param {{file_path?: unknown, content?: unknown}} toolInput
 * @param {import("agent-sanitizer/rehydrate").RehydrateIo} io
 * @param {{
 *   isTracked?: (filePath: string) => boolean,
 *   confirmSeen?: (fingerprint: string) => boolean,
 *   recordConfirm?: (fingerprint: string) => void,
 *   hint?: string,
 * }} [opts]
 * @returns {Promise<{deny: string} | null>}
 */
export async function secretDropGuard(toolInput, io, opts = {}) {
  const {
    isTracked = gitTracked,
    confirmSeen = consumeConfirm,
    recordConfirm = (fingerprint) =>
      writeSentinelFile(confirmMarkerPath(fingerprint)),
    hint = "[REDACTED",
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

  const fingerprint = dropFingerprint(filePath, content);
  if (confirmSeen(fingerprint)) return null;
  recordConfirm(fingerprint);
  return { deny: dropDeny(dropped.length, filePath, hint) };
}

/**
 * True when a trusted confirm sentinel exists for `fingerprint`, consuming it
 * so one confirmation approves exactly one Write. Removal is best-effort: a
 * marker we could not unlink still counted as consumed for THIS call, and a
 * leftover empty sentinel only ever re-approves the identical (path, bytes)
 * Write the model already confirmed.
 * @param {string} fingerprint
 * @returns {boolean}
 */
function consumeConfirm(fingerprint) {
  const marker = confirmMarkerPath(fingerprint);
  if (!markerIsTrusted(marker)) return false;
  try {
    unlinkSync(marker);
  } catch {
    // Best-effort consume — see doc.
  }
  return true;
}
