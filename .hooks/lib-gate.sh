#!/bin/bash
# Shared fail-closed helper for the git hooks in .hooks/.
#
# A gate that cannot run its tool must FAIL the git operation, not silently
# exit 0 — a silent skip lets unchecked work reach the branch with no signal
# that anything was bypassed. Sourced (not executed), so gate_die_missing_tool
# exits the calling hook.

# gate_tool_path <repo-root>: put every directory session-setup.sh installs into
# on PATH, so a hook can FIND the tools that were provisioned for it.
#
# Git hooks run in a bare shell. They inherit neither the session's PATH edits
# nor `CLAUDE_ENV_FILE`, which is the only place session-setup.sh records the Go
# install directory — so `shfmt`, installed and working, was invisible to every
# git hook. lint-staged then died with a bare `Task failed to spawn: shfmt … ENOENT`
# mid-commit, which names the symptom and not one of the three things a reader
# needs (which tool, where it lives, how to get it). The Go directory is resolved
# from `go env` rather than assumed to be ~/go/bin, because GOBIN and GOPATH are
# both configurable and a wrong guess reintroduces exactly this failure.
gate_tool_path() {
  local repo_root=$1 gobin=""
  # The Go TOOLCHAIN first: a bare hook shell often lacks even `go` itself, and
  # without it the `go env` probe below silently yields nothing — which is how
  # this helper's first draft still could not find shfmt.
  [[ -d /usr/local/go/bin ]] && PATH="/usr/local/go/bin:$PATH"
  if command -v go >/dev/null 2>&1; then
    gobin="$(go env GOBIN)"
    [[ -n "$gobin" ]] || gobin="$(go env GOPATH)/bin"
  fi
  # Asked of `go` when it answers, because GOBIN and GOPATH are both
  # configurable; the conventional location is the fallback, never the guess.
  [[ -n "$gobin" ]] || gobin="$HOME/go/bin"
  [[ -d "$gobin" ]] && PATH="$gobin:$PATH"
  PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
  # LAST, so it wins: a project venv's tools must outrank a global copy that
  # lacks this project's dependencies. That is the second half of today's
  # failure — a stray `pytest` ran without the project installed and died at
  # collection, which reads as a broken test rather than an unprovisioned env.
  [[ -d "$repo_root/.venv/bin" ]] && PATH="$repo_root/.venv/bin:$PATH"
  export PATH
}

# gate_die_missing_tool <hook-name> <tool> <install-hint>: loud stderr + exit 1.
gate_die_missing_tool() {
  local hook=$1 tool=$2 hint=$3
  echo "$hook: required tool '$tool' not found — REFUSING to continue rather than skip its checks." >&2
  echo "$hook: $hint" >&2
  exit 1
}
