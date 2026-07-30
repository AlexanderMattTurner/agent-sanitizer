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

version="$(node -e 'import("./plugin/scripts/build-plugin.mjs").then((m) => process.stdout.write(m.enginePin()))')"
echo "engine pin: $version"

npm view "agent-sanitizer@${version}" version >/dev/null
echo "npm: agent-sanitizer@${version} present"

status="$(curl -sS -o /dev/null -w '%{http_code}' "https://pypi.org/pypi/agent-sanitizer/${version}/json")"
if [ "$status" != "200" ]; then
  echo "PyPI has no agent-sanitizer ${version} (HTTP ${status}); the plugin would ship a requirements.txt pip cannot resolve" >&2
  exit 1
fi
echo "PyPI: agent-sanitizer ${version} present"
