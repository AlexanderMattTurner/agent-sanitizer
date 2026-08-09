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

# In the agent-sanitizer repo itself, install the LOCAL checkout instead of
# the npm pin, so the scripts exercise the sanitizer that lives on the trusted
# base branch they were checked out from. The published pin would silently
# ignore options the scripts have since moved to (`sanitize()` drops unknown
# options), turning every option added after the pin into a fail-open no-op.
# --install-links copies the package (npm 9+ symlinks file: deps by default,
# and a symlink resolves module lookups from the repo root, where the heavy
# HTML dependencies are not installed). Downstream template-synced repos have
# no sanitizer src/ and keep the published pin.
#
# Only the install SPEC differs between the two paths, so the branch produces
# just that and one invocation carries the flags — a second flag list is a
# second thing to keep in sync. `--install-links` is inert for a registry spec
# (it only changes how `file:` deps are materialised), so it is safe on both.
local_pkg_name="$(node -p "try { require('./package.json').name } catch { '' }")"
if [ "${local_pkg_name}" = "agent-sanitizer" ]; then
  install_spec="file:${PWD}"
  # npm packs a file: dependency through pacote, which runs the package's
  # `prepare` script even under --ignore-scripts (npm/cli#4989). These
  # runners have neither pnpm nor the repo's node_modules, so `prepare`
  # (`pnpm build:types`) can only die with "pnpm: not found". The script is
  # irrelevant here anyway — it builds .d.ts files the runtime .mjs imports
  # never read — so strip it from the scratch checkout for the duration of
  # the install and restore the file afterwards. prepack does NOT run for a
  # file: install (verified against npm 10.9), so prepare is the only strip.
  # Restore from a byte copy, not git checkout — a dev running this locally
  # may have uncommitted package.json edits that a checkout would discard.
  pkg_backup="$(mktemp)"
  cp package.json "${pkg_backup}"
  trap 'mv "${pkg_backup}" package.json' EXIT
  node -e "
    const fs = require('fs');
    const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
    delete pkg.scripts.prepare;
    fs.writeFileSync('package.json', JSON.stringify(pkg, null, 2) + '\n');
  "
else
  install_spec="agent-sanitizer@${SANITIZER_VERSION}"
fi

npm install --prefix .github/scripts --no-save --no-package-lock \
  --ignore-scripts --no-audit --no-fund --install-links "${install_spec}"
