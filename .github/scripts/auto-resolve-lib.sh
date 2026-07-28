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
# maps a conflicted path to the tool that owns it (for a `command -v`
# availability gate). Prints nothing for a path no known tool owns. Extend
# together with regen_lockfile below — the two case tables must stay in sync.
lockfile_tool() {
  case "${1##*/}" in
  pnpm-lock.yaml) echo pnpm ;;
  package-lock.json) echo npm ;;
  uv.lock) echo uv ;;
  esac
}

# Regenerate one conflicted lockfile by re-running its owning tool against the
# manifests in its directory — the exact by-hand fix, automated. Call mid-merge,
# AFTER every manifest is resolved/staged, and after checking the lockfile out
# at "ours" so the tool never parses conflict markers.
# --no-frozen-lockfile: pnpm defaults to a frozen lockfile under CI=true, which
# would refuse the very update this exists to make. --ignore-scripts: resolving
# dependencies must never execute package lifecycle code in this job.
regen_lockfile() {
  local dir
  dir="$(dirname "$1")"
  case "${1##*/}" in
  pnpm-lock.yaml) (cd "$dir" && pnpm install --lockfile-only --no-frozen-lockfile --ignore-scripts) ;;
  package-lock.json) (cd "$dir" && npm install --package-lock-only --ignore-scripts) ;;
  uv.lock) (cd "$dir" && uv lock) ;;
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
