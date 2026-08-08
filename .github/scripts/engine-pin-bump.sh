#!/usr/bin/env bash
# Bump the plugin's pinned sanitizer engine to the newest published release and
# open an auto-merging PR for it.
#
# renovate.json5's sanitizer-engine rule describes this exact flow, but the
# hosted Renovate app is not installed on this repo, so nothing ever ran it —
# this scheduled script performs that one bump. It moves only the npm alias and
# the lockfile: plugin-dist-autofix.yaml regenerates requirements.in/.txt and
# the committed dist artifacts on the PR itself, and the reproducibility tests
# gate the merge.
#
# Skip conditions, each deferring to a later scheduled run:
#   - newest npm release equals the pin (nothing to do)
#   - release younger than MIN_AGE_HOURS: our own release is exempt from the
#     workspace's 3-day third-party minimumReleaseAge window (it is built and
#     published from this repo with provenance, per pnpm-workspace.yaml), so
#     this shorter floor is the deliberate own-package cooldown
#   - release absent from PyPI: npm and PyPI land minutes apart, and the
#     daemon the plugin provisions installs from PyPI
#
# The bump branch is per-version (bot/engine-pin-bump-<version>): a newer
# release gets a fresh plain-pushed branch, and any still-open older bump PR
# is closed as superseded — no force-push anywhere.
set -euo pipefail

MIN_AGE_HOURS="${MIN_AGE_HOURS:-24}"
BRANCH_PREFIX="bot/engine-pin-bump"

current="$(node -e 'import("./plugin/scripts/build-plugin.mjs").then((m) => process.stdout.write(m.enginePin()))')"
# Max stable X.Y.Z from the full version list, NOT `npm view … version`: that
# reads the `latest` dist-tag, which lags or leads the real max after a partial
# or aborted publish (the same rule release-canary.sh states). A lagging tag
# would make this bump silently never fire — the exact failure this exists to
# fix. npm-max-stable.mjs exits 3 when nothing stable is published, which
# `set -e` turns into a loud failure.
latest="$(NPM_VERSIONS="$(npm view agent-sanitizer versions --json)" node .github/scripts/npm-max-stable.mjs)"
echo "pinned: ${current}; latest published: ${latest}"
if [ "$current" = "$latest" ]; then
  echo "pin already current"
  exit 0
fi

# shellcheck disable=SC2016  # the ${} below is a JS template literal, not shell
age_check="$(npm view agent-sanitizer time --json | node -e '
  let raw = "";
  process.stdin.on("data", (chunk) => (raw += chunk));
  process.stdin.on("end", () => {
    const published = Date.parse(JSON.parse(raw)[process.argv[1]]);
    const hours = (Date.now() - published) / 3600000;
    const floor = Number(process.argv[2]);
    process.stdout.write(hours >= floor ? "ok" : `young:${hours.toFixed(1)}`);
  });
' "$latest" "$MIN_AGE_HOURS")"
if [ "$age_check" != "ok" ]; then
  echo "agent-sanitizer@${latest} is ${age_check#young:}h old (< ${MIN_AGE_HOURS}h); deferring to a later run"
  exit 0
fi

# The same both-registries check the reproducibility gate runs, pointed at the
# candidate instead of the committed pin — one SSOT for "this version is live
# on npm AND PyPI". Only its "absent from a registry" exit (2) is a defer:
# npm and PyPI land minutes apart. Every other failure (registry 5xx, curl
# transport error, missing exec bit) propagates loud — swallowing it would
# make this scheduled job green-and-never-bumping forever, the exact silent
# failure it exists to fix.
rc=0
.github/scripts/verify-engine-pin.sh "$latest" || rc=$?
if [ "$rc" -eq 2 ]; then
  echo "agent-sanitizer@${latest} is not yet on both registries; deferring to a later run"
  exit 0
elif [ "$rc" -ne 0 ]; then
  exit "$rc"
fi

BRANCH="${BRANCH_PREFIX}-${latest}"
existing="$(gh pr list --head "$BRANCH" --state open --json number --jq '.[0].number // empty')"
if [ -n "$existing" ]; then
  echo "bump PR #${existing} for ${latest} is already open"
  exit 0
fi

# The branch can outlive its PR: a human closed the PR (GitHub deletes the head
# branch on merge, not on close), or a run died between the push and
# `gh pr create`. A fresh commit onto it would be a non-fast-forward rejection,
# and force-pushing is deliberately not an option here, so fail with the remedy
# named rather than dying on a raw git error every day.
if git ls-remote --exit-code --heads origin "$BRANCH" >/dev/null; then
  echo "branch ${BRANCH} exists on the remote with no open PR; delete it to let the bump re-run" >&2
  exit 1
fi

# Rotate the workspace's own-package minimumReleaseAge exemption with the pin.
# pnpm-workspace.yaml deliberately exempts the pinned agent-sanitizer release
# from the 3-day third-party window (it is built and published from this repo),
# and tests/test_minimum_release_age.py fails any exclude entry package.json no
# longer pins — so the entry must move in the same commit as the alias, or the
# bump PR is either rejected at resolution (release younger than 3 days) or
# red on that contract test (stale entry). The edit anchors on the exact YAML
# list-item line — a bare substring would also rewrite comments or a
# prerelease entry sharing the pin as a prefix — and requires exactly one
# occurrence, failing loud otherwise. String surgery rather than a YAML
# round-trip so the file's comments survive. Runs before `npm pkg set` so a
# rotation failure leaves the working tree untouched.
# shellcheck disable=SC2016  # the ${} below are JS template literals, not shell
node -e '
  const { readFileSync, writeFileSync } = require("node:fs");
  const [file, from, to] = process.argv.slice(1);
  const entry = (v) => `\n  - agent-sanitizer@${v}\n`;
  const text = readFileSync(file, "utf8");
  const count = text.split(entry(from)).length - 1;
  if (count !== 1) {
    console.error(`${file}: expected exactly one "- agent-sanitizer@${from}" list entry, found ${count}`);
    process.exit(1);
  }
  writeFileSync(file, text.replace(entry(from), entry(to)));
' pnpm-workspace.yaml "$current" "$latest"
npm pkg set "devDependencies.sanitizer-engine=npm:agent-sanitizer@${latest}"
# Lockfile only: node_modules stays on the old resolution; the PR's own CI
# installs fresh. --no-frozen-lockfile because pnpm defaults to frozen in CI,
# and updating the lockfile is the whole point here. The rotated exemption
# above is what lets a release younger than the third-party window resolve.
pnpm install --lockfile-only --no-frozen-lockfile
if git diff --quiet; then
  echo "working tree unchanged after the bump; nothing to push"
  exit 0
fi

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git checkout -B "$BRANCH"
git add package.json pnpm-lock.yaml pnpm-workspace.yaml
git commit -m "build(plugin): bump the pinned sanitizer engine to ${latest}"
git push \
  "https://x-access-token:${AUTOFIX_TOKEN_ORG}@github.com/${GITHUB_REPOSITORY}.git" \
  "HEAD:refs/heads/${BRANCH}"

# A still-open bump PR for an older version is now superseded: close it (with
# its branch) so exactly one bump PR is ever pending. --limit 100 because the
# startswith filter runs in --jq, i.e. AFTER gh truncates to its default page of
# 30 — an older bump PR could otherwise fall off the page and silently break
# that invariant.
while IFS=$'\t' read -r number head; do
  if [ "$head" = "$BRANCH" ]; then continue; fi
  echo "closing superseded bump PR #${number} (${head})"
  gh pr close "$number" --delete-branch \
    --comment "Superseded by the ${latest} bump."
done < <(gh pr list --state open --limit 100 --json number,headRefName \
  --jq ".[] | select(.headRefName | startswith(\"${BRANCH_PREFIX}-\")) | [.number, .headRefName] | @tsv")

gh pr create --head "$BRANCH" \
  --title "build(plugin): bump the pinned sanitizer engine to ${latest}" \
  --body "$(
    cat <<EOF
## What & why

Automated bump of the \`sanitizer-engine\` npm alias from ${current} to ${latest} (published ≥ ${MIN_AGE_HOURS}h ago on both npm and PyPI), opened by \`.github/workflows/engine-pin-bump.yaml\`. Only the alias, the lockfile, and the rotated own-package \`minimumReleaseAgeExclude\` entry move here; \`plugin-dist-autofix.yaml\` pushes the regenerated \`requirements.in\`/\`requirements.txt\` and dist artifacts onto this branch, and the committed-bundle reproducibility tests gate the merge.
EOF
  )"
# --squash matches every other automated merge here (dependabot-auto-merge,
# template-sync-automerge); a --merge would also fail outright if merge commits
# are disabled, leaving an open PR that never lands.
gh pr merge --auto --squash "$BRANCH"
echo "bump PR opened and set to auto-merge"
