#!/usr/bin/env bash
# Install the agent-sanitizer package the PR-review scripts import
# (sanitize-pr-input.mjs, post-pr-review.mjs, select-resolvable-threads.mjs).
# Installs into .github/scripts/node_modules so ESM resolution from those
# scripts finds it without touching the repository's own package.json or
# lockfile — repos synced from this template need no sanitizer dependency of
# their own. This script is the single source of the pinned version.
set -euo pipefail

# First version published under the agent-sanitizer name: the rename's feat!
# merge makes auto-version cut a major from the 1.47.x line. Nothing older
# exists under this name, so a lower pin can never resolve.
SANITIZER_VERSION="2.0.0"

npm install --prefix .github/scripts --no-save --no-package-lock \
  --ignore-scripts --no-audit --no-fund \
  "agent-sanitizer@${SANITIZER_VERSION}"
