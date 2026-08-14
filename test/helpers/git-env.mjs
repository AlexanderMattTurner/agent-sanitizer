/**
 * A `process.env` with git's own variables removed, for any test that builds a
 * throwaway repository and drives it with `git`.
 *
 * `GIT_DIR`, `GIT_INDEX_FILE` and `GIT_WORK_TREE` OVERRIDE `git -C <dir>` and
 * `{ cwd }` — they name the repository directly, so a child git inherits the
 * caller's repository no matter which directory it is pointed at. Two callers
 * set them: git itself, for every hook it runs (a suite driven by `pre-commit`
 * inherits the outer repo's temporary index), and anyone reproducing a hook
 * environment by hand. Either way a fixture's `git commit`, `git branch -M
 * main` and `git push origin main` land in the REAL repository and, with a real
 * `origin`, on the real remote.
 *
 * Filtering the whole `GIT_*` prefix rather than the three names above keeps
 * `GIT_OBJECT_DIRECTORY`, `GIT_COMMON_DIR`, `GIT_NAMESPACE` and any future
 * sibling out too; a fixture repo needs none of them.
 */
export const cleanGitEnv = Object.fromEntries(
  Object.entries(process.env).filter(([key]) => !key.startsWith("GIT_")),
);
