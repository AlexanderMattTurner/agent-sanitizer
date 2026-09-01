# shellcheck shell=bash
# shellcheck disable=SC2034  # every value here is consumed by a script that SOURCES this file
# Pinned versions and digests for tools CI downloads directly, rather than
# through a package manager that would do its own integrity check.
#
# Sourced by the install-*.sh scripts beside it. Not executable, and it must stay
# free of side effects: a consumer sources it purely to read these values.
#
# Bump a version and its digest TOGETHER. A version bumped without its digest
# fails the install closed, which is the intended direction — the opposite
# (a digest that no longer describes the pinned artifact) is the one that would
# certify an unreviewed binary.

# mergiraf backs the structural pre-pass in the resolver repository's
# auto-resolve/prepare.sh, and in template-sync-resolve.sh's tier 1: a
# syntax-aware merge that resolves the structural subset of a PR's conflicts so
# only genuinely semantic conflicts reach the paid LLM pass.
#
# install-mergiraf.sh downloads the pinned release tarball from Codeberg and
# sha256-verifies it before extracting. The digest HERE is the anchor, not the
# checksum manifest published alongside the release: a manifest fetched from the
# same tag as the artifact is re-published by anyone who can re-tag that release,
# so it proves the download was not corrupted in transit and says nothing about
# the release being the one we reviewed.
MERGIRAF_VERSION=v0.18.0
MERGIRAF_SHA256_linux_amd64=4de0986ff9155411dd105958b94362056d0055025db75369eddd3ecd25334cd2

# gitleaks backs the Required secret scan (gitleaks.yaml) and phone-home.yaml's
# scan of extracted lessons before they leave the repo. install-gitleaks.sh
# downloads the pinned release tarball from GitHub and sha256-verifies it before
# extracting; as with mergiraf, the digest HERE is the anchor — it is the
# published SHA-256 of gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz, reviewed
# when the pin was bumped, so a tampered or re-tagged release asset fails the
# install instead of injecting a malicious binary.
GITLEAKS_VERSION=8.30.1
GITLEAKS_SHA256_linux_x64=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
