/**
 * The one primitive that rewrites an instruction file on disk, private to the
 * package: it is not in the `exports` map, and `cleanFile` (./instructions.mjs)
 * is its only caller. It writes the path as given, so the realpath containment
 * that keeps a rewrite inside the project lives in cleanFile, and any second
 * caller would be a write door without it — `test/instruction-paths.test.mjs`
 * partitions every fs write in the package to hold that.
 */
import { randomBytes } from "node:crypto";
import {
  closeSync,
  constants,
  fchmodSync,
  fsyncSync,
  openSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";

/**
 * Atomically replace `absPath`'s contents with `data`, preserving `mode`.
 *
 * Writes to a sibling temp in the same directory, then `rename`s it over the
 * original (same dir => same filesystem => the rename is atomic, not a
 * cross-device copy). The temp name is UNPREDICTABLE (`tmpName()` defaults to
 * crypto-random) and the temp is created exclusively (O_CREAT|O_EXCL): if the
 * path already exists — including an attacker-planted symlink at a guessable
 * temp name — the open fails (EEXIST) and does NOT follow the link to clobber
 * its target. On the rare collision we fail loud rather than retry into a
 * different attacker-controlled path.
 *
 * Crash-safety (matching the doc claim): the temp fd is `fsync`ed before the
 * rename and the directory fd is `fsync`ed after it, so a power loss can't leave
 * the renamed name pointing at unflushed/empty data or lose the rename itself.
 * The EXACT `mode` is applied with `fchmod` (openSync's create mode is
 * umask-masked, so it alone would drop bits), and a failed write/sync `unlink`s
 * the temp before rethrowing so no partial temp leaks. `tmpName` and `remove`
 * are injectable fault-injection seams for tests (force a known temp path; drive
 * a cleanup-unlink failure); production callers never pass them.
 * @param {string} absPath
 * @param {string} data
 * @param {number} mode
 * @param {() => string} [tmpName]
 * @param {(path: string) => void} [remove]
 */
export function atomicReplaceFile(
  absPath,
  data,
  mode,
  tmpName = () => `.${randomBytes(12).toString("hex")}.tmp`,
  remove = unlinkSync,
) {
  const dir = dirname(absPath);
  const tmp = join(dir, tmpName());
  // Exclusive create: EEXIST (incl. a planted symlink at the temp name)
  // propagates directly — no temp of ours exists yet, so nothing to clean up
  // and we must never unlink the attacker's pre-existing path.
  const fd = openSync(
    tmp,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL,
    mode,
  );
  try {
    // writeFileSync(fd, …) loops until every byte is written (a bare writeSync
    // can short-write a large payload); it does not close the caller's fd.
    writeFileSync(fd, data);
    // Preserve the EXACT mode: openSync's create mode is umask-masked, fchmod is
    // not, so this restores bits (e.g. group-write) the umask would have dropped.
    fchmodSync(fd, mode);
    // Flush the temp's bytes before the rename, else a crash can expose the
    // renamed name pointing at empty/partial content.
    fsyncSync(fd);
  } catch (err) {
    closeSync(fd);
    try {
      remove(tmp);
    } catch {
      // Best-effort cleanup only: rethrow the ORIGINAL failure below, not a
      // secondary unlink error, so the real cause stays loud.
    }
    throw err;
  }
  closeSync(fd);
  renameSync(tmp, absPath);
  // fsync the DIRECTORY so the rename (a directory metadata change) is durable
  // across a crash, not just the file's data blocks.
  const dirFd = openSync(dir, constants.O_RDONLY);
  try {
    fsyncSync(dirFd);
  } finally {
    closeSync(dirFd);
  }
}
