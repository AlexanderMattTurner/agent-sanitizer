# shellcheck shell=bash
# Shared by the auto-resolve PREPARE and FINALIZE steps (sourced, not run).

# True when git cannot merge the conflicted path textually: `-merge`-attributed
# (a lockfile) or binary. Git leaves such a conflict with NO markers and the
# working tree at "ours", so no marker-based resolution exists — only a human
# rerunning the owning tool (relock, re-export) can produce correct content.
# Callable only mid-merge (reads MERGE_HEAD).
is_unmergeable() {
  [[ "$(git check-attr merge -- "$1")" == *": merge: unset" ]] ||
    [[ "$(git diff --numstat HEAD MERGE_HEAD -- "$1" | cut -f1)" == "-" ]]
}

# Lockfiles auto-resolve regenerates deterministically instead of hand-merging:
# maps a conflicted path to the tool that owns it (the caller gates on
# `command -v "$tool"`). This is the SINGLE source of truth for which paths are
# claimed — regen_lockfile below dispatches on what this returns, so there is no
# second table to keep in sync.
#
# A path is claimed only when the manifest its tool needs sits beside it: a
# committed fixture named `package-lock.json` with no adjacent `package.json`
# is NOT a lockfile, and claiming it would be silent corruption rather than a
# loud failure (`npm install --package-lock-only` in a manifest-less directory
# succeeds and writes an empty-dependency lockfile over the fixture). Anything
# unclaimed falls through to the LLM/unresolvable classification unchanged.
# Always returns 0 — a non-zero return would abort the caller's `set -e` script
# through the command substitution it is read with.
lockfile_tool() {
  local dir
  dir="$(dirname "$1")"
  case "${1##*/}" in
  pnpm-lock.yaml) [[ -f "$dir/package.json" ]] && echo pnpm ;;
  package-lock.json) [[ -f "$dir/package.json" ]] && echo npm ;;
  uv.lock) [[ -f "$dir/pyproject.toml" ]] && echo uv ;;
  esac
  return 0
}

# Run a dependency-resolution tool with every push/API credential stripped from
# its environment. These tools execute PR-authored code by design: `uv lock`
# invokes PEP 517 build backends for dynamic metadata, and npm/pnpm lifecycle
# scripts are suppressed only by the `--ignore-scripts` flags below. The job
# holds a workflow-scoped org PAT, so the subprocess must not be able to read
# it — a same-repo PR author is trusted to propose a merge, not to hold the
# org's push credentials. GIT_CONFIG_VALUE_0 embeds a token in an HTTP
# extraheader, so it is stripped too.
run_untrusted() {
  env -u TEMPLATE_SYNC_TOKEN_ORG -u GITHUB_TOKEN -u GH_TOKEN -u GIT_CONFIG_VALUE_0 "$@"
}

# Regenerate one conflicted lockfile by re-running its owning tool against the
# manifests in its directory — the exact by-hand fix, automated. Call mid-merge,
# AFTER every manifest is resolved/staged, and after checking the lockfile out
# at a single side so the tool never parses conflict markers.
# --no-frozen-lockfile: pnpm defaults to a frozen lockfile under CI=true, which
# would refuse the very update this exists to make.
regen_lockfile() {
  local dir tool
  dir="$(dirname "$1")"
  tool="$(lockfile_tool "$1")"
  case "$tool" in
  pnpm) (cd "$dir" && run_untrusted pnpm install --lockfile-only --no-frozen-lockfile --ignore-scripts) ;;
  npm) (cd "$dir" && run_untrusted npm install --package-lock-only --ignore-scripts) ;;
  uv) (cd "$dir" && run_untrusted uv lock) ;;
  *) return 1 ;;
  esac
}

# True when this repo defines a `resolve-generated` npm script — an OPTIONAL
# deterministic pre-pass that regenerates/stages fully-generated conflicted
# files so the LLM only ever sees genuine source conflicts. Most repos have no
# such generator; when the script is absent the pre-pass is skipped and every
# conflict falls through to the LLM/unresolvable classification unchanged.
has_resolve_generated() {
  [[ -f package.json ]] &&
    jq -e '(.scripts // {}) | has("resolve-generated")' package.json >/dev/null 2>&1
}
