/**
 * The one primitive that rewrites an instruction file, private to the package
 * (not in `exports`): `cleanFile` (./instructions.mjs) is its only caller. It
 * writes the path as given, so the realpath containment lives in cleanFile and
 * `test/instruction-paths.test.mjs` partitions every fs write to hold that.
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
 * Atomically replace `absPath`'s contents with `data`, preserving `mode`: write
 * an exclusively created (O_EXCL, unpredictable-name) sibling temp, fsync it,
 * `rename` it over the original, fsync the directory. O_EXCL means a planted
 * symlink at the temp name fails EEXIST instead of being followed. A failed
 * write unlinks the temp before rethrowing. `tmpName` and `remove` are
 * fault-injection seams for tests.
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
  // EEXIST propagates uncaught: no temp of ours exists, and we must never
  // unlink the attacker's pre-existing path.
  const fd = openSync(
    tmp,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL,
    mode,
  );
  try {
    // Loops until every byte is written (a bare writeSync can short-write).
    writeFileSync(fd, data);
    // openSync's create mode is umask-masked; fchmod restores the exact bits.
    fchmodSync(fd, mode);
    // Flush before the rename, else a crash can expose empty/partial content.
    fsyncSync(fd);
  } catch (err) {
    closeSync(fd);
    try {
      remove(tmp);
    } catch {
      // Rethrow the ORIGINAL failure below, not a secondary unlink error.
    }
    throw err;
  }
  closeSync(fd);
  renameSync(tmp, absPath);
  // fsync the DIRECTORY so the rename itself is durable.
  const dirFd = openSync(dir, constants.O_RDONLY);
  try {
    fsyncSync(dirFd);
  } finally {
    closeSync(dirFd);
  }
}
