#!/usr/bin/env bash
# Fail loud unless the plugin's engine pin is published on BOTH registries.
#
# The bundle is built from the npm release; the redactor daemon the plugin
# provisions at SessionStart comes from the PyPI release of the same version.
# They are published by the same workflow but land minutes apart, so a bundle
# regenerated in that window would carry a requirements.txt naming a version pip
# cannot install — green in CI (the tests never touch the network) and broken for
# every user.
set -euo pipefail

# An argument overrides the committed pin so engine-pin-bump.sh can point the
# same both-registries check at its candidate version before bumping. Exit
# codes are part of the contract: 2 means the version is confirmed absent from
# PyPI — the retryable npm→PyPI publish lag a caller may defer on. Anything
# else non-zero is a real error (npm failure, registry 5xx, curl transport),
# never to be conflated with lag.
if [ "$#" -ge 1 ]; then
  version="$1"
  if [ -z "$version" ]; then
    echo "empty version argument; refusing to fall back to the committed pin" >&2
    exit 1
  fi
else
  version="$(node -e 'import("./plugin/scripts/build-plugin.mjs").then((m) => process.stdout.write(m.enginePin()))')"
fi
echo "checking agent-sanitizer@${version} on npm and PyPI"

npm view "agent-sanitizer@${version}" version >/dev/null
echo "npm: agent-sanitizer@${version} present"

status="$(curl -sS -o /dev/null -w '%{http_code}' "https://pypi.org/pypi/agent-sanitizer/${version}/json")"
if [ "$status" = "404" ]; then
  echo "PyPI has no agent-sanitizer ${version} (HTTP 404); the plugin would ship a requirements.txt pip cannot resolve" >&2
  exit 2
fi
if [ "$status" != "200" ]; then
  echo "PyPI returned HTTP ${status} for agent-sanitizer ${version}; cannot tell whether the release exists" >&2
  exit 1
fi
echo "PyPI: agent-sanitizer ${version} present"
