// Print the highest STABLE (non-prerelease) X.Y.Z version from a list of npm
// versions, used by release-canary.sh to compute npm's max published release.
//
// Input: NPM_VERSIONS env var holding what `npm view <pkg> versions --json`
// returns — a JSON array normally, or a bare JSON string for a single-release
// package. Output: the max stable version on stdout. Exit 3 when the list holds
// no stable X.Y.Z version (the caller turns that into a loud error).
//
// Stable selection is strict — only bare `X.Y.Z` (no prerelease, no build
// metadata, no leading `v`) counts, matching the canary's precision-over-recall
// stance.
//
// Ordering is a numeric triple compare rather than the `semver` package. Every
// candidate has already been filtered to bare `X.Y.Z`, so the only part of
// semver precedence that could apply is field-wise numeric comparison — and the
// import was not merely redundant, it was unresolvable: `semver` is a
// transitive dependency here, never declared, so pnpm's non-hoisting layout
// leaves no `node_modules/semver` for a bare specifier to find. Every canary
// run died on ERR_MODULE_NOT_FOUND, which release-canary.sh then reported as
// "no stable X.Y.Z version published".
const STABLE = /^(\d+)\.(\d+)\.(\d+)$/;

/** Field-wise numeric compare; >0 when `a` is the newer release. */
function compare(a, b) {
  const left = a.match(STABLE).slice(1).map(Number);
  const right = b.match(STABLE).slice(1).map(Number);
  const differing = left.findIndex((n, i) => n !== right[i]);
  return differing === -1 ? 0 : left[differing] - right[differing];
}

const raw = JSON.parse(process.env.NPM_VERSIONS ?? "");
const all = Array.isArray(raw) ? raw : [raw];
const stable = all.filter((v) => STABLE.test(v));
if (stable.length === 0) process.exit(3);
const max = stable.reduce((acc, v) => (compare(v, acc) > 0 ? v : acc));
process.stdout.write(max);
