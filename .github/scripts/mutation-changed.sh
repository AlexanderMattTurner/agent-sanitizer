#!/usr/bin/env bash
# Exit 0 iff the diff between $BASE_SHA and $HEAD_SHA touches a file mutation
# testing depends on. Exit 1 means "nothing mutation-relevant changed, skip the
# expensive run". Exit 2+ means "could not determine relevance" — the caller
# must fail the job, not skip it.
#
# The relevance list is NOT duplicated here: the single source of truth is
# mutation.yaml's own on.push.paths filter, parsed out of the workflow below and
# translated glob→regex. Before this, the two copies drifted (the regex was
# missing .github/actions/setup-base-env/action.yaml, so PRs touching only that
# file skipped mutation).
#
# On a push to main (or any event without a usable base) we cannot cheaply diff,
# so we fail OPEN (exit 0) and let the full run decide — never skip a real gate
# on a missing base.

set -euo pipefail

base="${BASE_SHA:-}"
head="${HEAD_SHA:-}"

if [[ -z "$base" || -z "$head" ]]; then
  echo "No base/head SHA provided; running mutation testing (fail open)."
  exit 0
fi

# The workflow checks out with fetch-depth: 0, so the base commit is present for
# any PR/push diff. If it somehow isn't, fail OPEN rather than skip a real gate.
if ! git cat-file -e "$base^{commit}" 2>/dev/null; then
  echo "Base commit $base not present; running mutation testing (fail open)."
  exit 0
fi

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
workflow="${here}/../workflows/mutation.yaml"

# Pull the on.push.paths block sequence out of mutation.yaml without a YAML
# dependency (precedents: main-health.mjs, .hooks/pre-push). Deliberately
# narrow: it anchors on the workflow's actual two-space-per-level layout, and
# the zero-entries check below is what keeps a layout change loud instead of
# silently classifying every PR as irrelevant.
extract_push_paths() {
  awk '
    /^on:/ { in_on = 1; next }
    in_on && /^[^[:space:]#]/ { in_on = 0 }
    in_on && /^  push:/ { in_push = 1; next }
    in_on && in_push && /^  [^[:space:]]/ { in_push = 0 }
    in_push && /^    paths:/ { in_paths = 1; next }
    in_paths && /^      - / {
      line = $0
      sub(/^[[:space:]]*-[[:space:]]*/, "", line)
      gsub(/["'\'']/, "", line)
      print line
      next
    }
    # A comment or blank line inside the block is not the end of it. Ending on
    # one silently DROPPED every entry below it, so a PR touching only those
    # files was classified irrelevant and skipped the whole mutation gate — a
    # fail-open a reviewer would never see, triggered by adding a comment.
    in_paths && /^[[:space:]]*(#|$)/ { next }
    in_paths { in_paths = 0 }
  ' "$workflow"
}

# Translate one Actions path glob to an extended regex, escaping in a single
# character-by-character pass so an inserted backslash is never re-touched:
#   **/ -> (.*/)?  (zero or more whole segments — GitHub's filter patterns are
#                   minimatch-style, so src/**/*.mjs matches src/foo.mjs too)
#   **  -> .*      (matches across /)
#   *   -> [^/]*   (within one path segment)
#   ?   -> [^/]
#   regex metacharacters are escaped literally.
glob_to_regex() {
  local glob="$1" out="" c
  local -i i
  for ((i = 0; i < ${#glob}; i++)); do
    c="${glob:i:1}"
    case "$c" in
    '*')
      if [[ "${glob:i+1:2}" == "*/" ]]; then
        out+="(.*/)?"
        i+=2
      elif [[ "${glob:i+1:1}" == "*" ]]; then
        out+=".*"
        i+=1
      else
        out+="[^/]*"
      fi
      ;;
    '?') out+="[^/]" ;;
    '.' | '^' | '$' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | \\)
      out+="\\$c"
      ;;
    *) out+="$c" ;;
    esac
  done
  printf '%s' "$out"
}

paths=()
while IFS= read -r p; do
  if [[ -n "$p" ]]; then
    paths+=("$p")
  fi
done < <(extract_push_paths)

if [[ ${#paths[@]} -eq 0 ]]; then
  echo "mutation-changed: parsed ZERO entries from on.push.paths in ${workflow} —" >&2
  echo "  the workflow's layout changed out from under the parser above. Fix the" >&2
  echo "  parser (or the workflow) before trusting this gate." >&2
  exit 2
fi

regex=""
for p in "${paths[@]}"; do
  regex+="${regex:+|}$(glob_to_regex "$p")"
done

changed=$(git diff --name-only "$base" "$head" --)

# Herestring, not a pipe: `grep -q` exits on first match, and under pipefail a
# SIGPIPE-killed upstream printf would read as failure on slow runners.
grep -qE "^(${regex})$" <<<"$changed"
