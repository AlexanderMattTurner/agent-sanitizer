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
#   - release younger than MIN_AGE_HOURS: pnpm's default minimumReleaseAge
#     policy would reject the lockfile entry, and the window doubles as the
#     supply-chain cooldown renovate.json5 relied on
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
latest="$(npm view agent-sanitizer version)"
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

pypi_status="$(curl -sS -o /dev/null -w '%{http_code}' "https://pypi.org/pypi/agent-sanitizer/${latest}/json")"
if [ "$pypi_status" != "200" ]; then
  echo "PyPI has no agent-sanitizer ${latest} yet (HTTP ${pypi_status}); deferring to a later run"
  exit 0
fi

BRANCH="${BRANCH_PREFIX}-${latest}"
existing="$(gh pr list --head "$BRANCH" --state open --json number --jq '.[0].number // empty')"
if [ -n "$existing" ]; then
  echo "bump PR #${existing} for ${latest} is already open"
  exit 0
fi

npm pkg set "devDependencies.sanitizer-engine=npm:agent-sanitizer@${latest}"
# Lockfile only: node_modules stays on the old resolution; the PR's own CI
# installs fresh. --no-frozen-lockfile because pnpm defaults to frozen in CI,
# and updating the lockfile is the whole point here. The release is past the
# minimumReleaseAge floor, so this resolution needs no policy exclusions.
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
# its branch) so exactly one bump PR is ever pending.
while IFS=$'\t' read -r number head; do
  if [ "$head" = "$BRANCH" ]; then continue; fi
  echo "closing superseded bump PR #${number} (${head})"
  gh pr close "$number" --delete-branch \
    --comment "Superseded by the ${latest} bump."
done < <(gh pr list --state open --json number,headRefName \
  --jq ".[] | select(.headRefName | startswith(\"${BRANCH_PREFIX}-\")) | [.number, .headRefName] | @tsv")

gh pr create --head "$BRANCH" \
  --title "build(plugin): bump the pinned sanitizer engine to ${latest}" \
  --body "$(
    cat <<EOF
## What & why

Automated bump of the \`sanitizer-engine\` npm alias from ${current} to ${latest} (published ≥ ${MIN_AGE_HOURS}h ago on both npm and PyPI), opened by \`.github/workflows/engine-pin-bump.yaml\`. Only the alias and the lockfile move here; \`plugin-dist-autofix.yaml\` pushes the regenerated \`requirements.in\`/\`requirements.txt\` and dist artifacts onto this branch, and the committed-bundle reproducibility tests gate the merge.
EOF
  )"
gh pr merge --auto --merge "$BRANCH"
echo "bump PR opened and set to auto-merge"
