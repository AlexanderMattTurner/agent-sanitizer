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
# The local path installs from a STAGED COPY of the checkout with the lifecycle
# scripts removed, not from ${PWD} directly: npm packs a `file:` dependency by
# running that package's own `prepare`/`prepack`, and it does so even under
# --ignore-scripts (npm 10.9). This repo's `prepare` shells out to `pnpm
# build:types`, and the PR-review jobs install neither pnpm nor the typescript
# devDependency — so packing the checkout in place died with `pnpm: not found`
# and took the whole review job down before it read a single diff. Staging keeps
# npm as the packer, so the installed tree is still exactly what `files`
# publishes. `git archive` stages the COMMITTED tree; every caller runs on a
# pristine actions/checkout, so that is the tree on disk.
#
# Only the install SPEC differs between the two paths, so the branch produces
# just that and one invocation carries the flags — a second flag list is a
# second thing to keep in sync. `--install-links` is inert for a registry spec
# (it only changes how `file:` deps are materialised), so it is safe on both.
#
# `--ignore-scripts` does NOT make the local path hermetic: npm materialises a
# `file:` dep by PACKING the directory, and packing runs that package's
# `prepare` regardless (setting npm_config_ignore_scripts does not suppress it
# either — verified). `prepare` here is `pnpm build:types`, so every caller of
# this script needs pnpm and the root node_modules on hand, which in CI means
# a `.github/actions/setup-base-env` step ahead of it. Callers that skipped one
# exited 127 on every PR the moment the local path landed.
staged=""
cleanup() {
  if [ -n "${staged}" ]; then rm -rf "${staged}"; fi
}
trap cleanup EXIT

local_pkg_name="$(node -p "try { require('./package.json').name } catch { '' }")"
if [ "${local_pkg_name}" = "agent-sanitizer" ]; then
  staged="$(mktemp -d)"
  git archive --format=tar HEAD | tar -x -C "${staged}"
  # Fails loudly on an unreadable manifest or a missing `scripts` block: a
  # silently-unstripped copy would reintroduce the pnpm dependency this exists
  # to remove, and only in the jobs that lack pnpm.
  node - "${staged}/package.json" <<'STRIP_LIFECYCLE'
const fs = require("node:fs");
const manifest = process.argv[2];
const pkg = JSON.parse(fs.readFileSync(manifest, "utf8"));
delete pkg.scripts.prepare;
delete pkg.scripts.prepack;
fs.writeFileSync(manifest, `${JSON.stringify(pkg, null, 2)}\n`);
STRIP_LIFECYCLE
  install_spec="file:${staged}"
else
  install_spec="agent-sanitizer@${SANITIZER_VERSION}"
fi

npm install --prefix .github/scripts --no-save --no-package-lock \
  --ignore-scripts --no-audit --no-fund --install-links "${install_spec}"
