#!/usr/bin/env bash
# Install the pinned gitleaks binary onto PATH. Args: [dest-dir] (default
# /usr/local/bin, which is on PATH on every hosted runner).
#
# gitleaks backs the Required secret scan (gitleaks.yaml → gitleaks-scan.sh) and
# phone-home.yaml's scan of extracted lessons before they are submitted to the
# template repo. The version and the tarball SHA-256 both live in
# .github/tool-versions.sh — one pin, consumed by every workflow that runs it.
set -euo pipefail

dest="${1:-/usr/local/bin}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=/dev/null
source "${here}/../tool-versions.sh"

# An absent or empty pin must never degrade into "install without verifying" —
# that is a supply-chain check reporting green because its input went missing.
[[ -n "${GITLEAKS_VERSION:-}" && -n "${GITLEAKS_SHA256_linux_x64:-}" ]] || {
  echo "install-gitleaks: GITLEAKS_VERSION / GITLEAKS_SHA256_linux_x64 unset or empty in" >&2
  echo "  .github/tool-versions.sh; refusing to install an unverified binary." >&2
  exit 1
}

# A template consumer that bumped the version but left the digest as a
# placeholder has not reviewed the artifact; fail before the download so the
# error names the fix.
case "$GITLEAKS_SHA256_linux_x64" in
PLACEHOLDER_*)
  echo "install-gitleaks: GITLEAKS_SHA256_linux_x64 is still the placeholder. Set the real" >&2
  echo "  published SHA-256 for gitleaks ${GITLEAKS_VERSION} in .github/tool-versions.sh." >&2
  exit 1
  ;;
*) ;;
esac

tarball="gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

# Download to a file (not a pipe) so the digest is verified before extract.
# --retry/--retry-all-errors so a transient release-CDN 5xx is retried, and
# --fail so a 5xx is an error rather than an error page saved as the tarball,
# which then fails `tar` with a misleading "not recoverable".
curl --proto '=https' -fsSL --retry 6 --retry-all-errors --retry-delay 15 --connect-timeout 30 \
  -o "${workdir}/${tarball}" \
  "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${tarball}"

# This refusal is what blocks a swapped, re-tagged, or corrupted release asset
# from reaching PATH: the digest is the reviewed one from tool-versions.sh, so a
# mismatch aborts the install rather than certifying a binary nobody vetted.
(cd "$workdir" && echo "${GITLEAKS_SHA256_linux_x64}  ${tarball}" | sha256sum -c -)
tar xzf "${workdir}/${tarball}" -C "$workdir" gitleaks

# sudo only when the destination is not already writable, so this works both on a
# hosted runner (root-owned /usr/local/bin) and in a local checkout writing to a
# user-owned dir.
if [[ -w "$dest" ]]; then
  install -m 0755 "${workdir}/gitleaks" "${dest}/gitleaks"
else
  sudo install -m 0755 "${workdir}/gitleaks" "${dest}/gitleaks"
fi

# The guard's success is the post-condition, not the exit status of the install:
# a destination off PATH would leave the scan invoking a binary it cannot find.
command -v gitleaks >/dev/null || {
  echo "install-gitleaks: installed to ${dest} but gitleaks is not on PATH" >&2
  exit 1
}
gitleaks version
