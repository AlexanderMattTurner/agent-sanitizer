# shellcheck shell=bash
# The one construction of git's HTTPS credential in this repo (sourced, not run).
#
# The key is scoped to `http.https://github.com/.extraheader`, never the bare
# `http.extraheader`: an unscoped key is a repo-wide default, so git sends the
# token to whatever host the operation ends up talking to — a redirect, an
# `insteadOf` rewrite, a submodule URL elsewhere. Scoping is what keeps the
# token on github.com.
# shellcheck disable=SC2034  # read by the scripts that source this file, which shellcheck lints separately
GIT_AUTH_HEADER_KEY="http.https://github.com/.extraheader"

# git_auth_header_value VAR TOKEN — sets VAR to the header value that
# authenticates as TOKEN, for `git -c "$GIT_AUTH_HEADER_KEY=$VAR" <one command>`.
#
# It assigns by name rather than printing, because a `$(…)` caller would swallow
# the `:?` abort below into an empty string and then authenticate as nobody — a
# 404 on a private ref, blamed on anything but the missing token.
git_auth_header_value() {
  local _git_auth_var="${1:?target variable name required}" _git_auth_basic
  _git_auth_basic="$(printf 'x-access-token:%s' "${2:?token required}" | base64 | tr -d '\n')"
  printf -v "$_git_auth_var" 'AUTHORIZATION: basic %s' "$_git_auth_basic"
}

# git_auth_header TOKEN — authenticates git over HTTPS for the REST OF THIS
# PROCESS, without writing the token into .git/config (every checkout here is
# persist-credentials: false). For a multi-step flow that runs many git commands
# under one credential; a script that needs auth on a single command passes
# `-c` per-command instead and leaves the environment alone.
#
# It RESETS GIT_CONFIG_COUNT rather than appending: re-authenticating with a
# second token must replace the first token's header, and starting from 1 also
# discards any GIT_CONFIG_* transport override an earlier step left behind.
git_auth_header() {
  local _git_auth_value
  git_auth_header_value _git_auth_value "${1:?token required}"
  export GIT_CONFIG_COUNT=1
  export GIT_CONFIG_KEY_0="$GIT_AUTH_HEADER_KEY"
  export GIT_CONFIG_VALUE_0="$_git_auth_value"
}
