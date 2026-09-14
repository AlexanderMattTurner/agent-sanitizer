/**
 * A `git worktree list --porcelain -z` dump, built the way git frames one:
 * every attribute NUL-TERMINATED, so a record ends on the doubled NUL its last
 * attribute's terminator forms with the record separator.
 *
 * One builder for both suites that stub this output, because a stub spelling the
 * framing differently from the parser would pass while real git fails. The
 * framing itself is pinned against real git by repo-scope.test.mjs's
 * `linkedWorktrees` case.
 * @param {string[][]} records  attribute lines per worktree, main one first
 * @returns {string}
 */
export function worktreePorcelainZ(records) {
  return records
    .map((attrs) => attrs.map((attr) => `${attr}\0`).join("") + "\0")
    .join("");
}
