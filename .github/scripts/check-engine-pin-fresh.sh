#!/usr/bin/env bash
# Fail while the plugin's pinned engine has lagged npm's newest published
# release for longer than Renovate should ever have taken to bump it.
#
# renovate.json5 keeps the pin current, but only if the hosted Renovate App is
# installed AND its rules still match the dependency. Both can stop being true
# with no error anywhere — an uninstalled app, a renamed package, a `matchPackageNames`
# spelling Renovate changed under us — and the pin then ages silently. That
# exact silent-aging is what produced the bespoke bump script this replaced, so
# the hosted-app precondition gets a level-triggered check rather than a comment
# in a config file.
#
# This asserts nothing about HOW the pin moves; it only asserts that it does.
# It changes no files and opens no PRs — its failure is the signal.
set -euo pipefail

# Renovate's own floor is 24h (minimumReleaseAge) and it runs nightly, so a bump
# PR should exist within ~2 days and automerge on green. A week means the bump
# path is broken, not merely slow — wide enough that a weekend of red CI on the
# bump PR does not page anyone.
MAX_LAG_DAYS="${MAX_LAG_DAYS:-7}"

current="$(node -e 'import("./plugin/scripts/build-plugin.mjs").then((m) => process.stdout.write(m.enginePin()))')"
# Max stable X.Y.Z over the full version list, NOT `npm view … version`: that
# reads the `latest` dist-tag, which lags or leads the real max after a partial
# or aborted publish. A lagging tag here would mean this guard reports "current"
# while the pin is stale — failing open on the one thing it exists to catch.
latest="$(NPM_VERSIONS="$(npm view agent-sanitizer versions --json)" node .github/scripts/npm-max-stable.mjs)"
echo "pinned: ${current}; latest published: ${latest}"
if [ "$current" = "$latest" ]; then
  echo "pin is current"
  exit 0
fi

# Age of the NEWEST release, not of the pin: the question is how long the bump
# path has had to act on something it can see.
lag_days="$(npm view agent-sanitizer time --json | node -e '
  let raw = "";
  process.stdin.on("data", (chunk) => (raw += chunk));
  process.stdin.on("end", () => {
    const published = Date.parse(JSON.parse(raw)[process.argv[1]]);
    process.stdout.write(((Date.now() - published) / 86400000).toFixed(1));
  });
' "$latest")"

# Numeric compare on a one-decimal string: bash cannot, so let node answer.
if node -e 'process.exit(Number(process.argv[1]) > Number(process.argv[2]) ? 0 : 1)' "$lag_days" "$MAX_LAG_DAYS"; then
  echo "::error::agent-sanitizer ${latest} has been published for ${lag_days} days but the plugin still pins ${current}."
  echo "The engine pin is bumped by Renovate (see renovate.json5). Check that the hosted Renovate App is still installed on this repo and that its sanitizer-engine rule still matches; the fallback is a manual bump:"
  echo "  npm pkg set devDependencies.sanitizer-engine=npm:agent-sanitizer@${latest} && pnpm install --lockfile-only"
  exit 1
fi

echo "pin lags by ${lag_days} days (< ${MAX_LAG_DAYS}); within the bump window"
