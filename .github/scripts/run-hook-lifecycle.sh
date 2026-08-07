#!/usr/bin/env bash
# Smoke-test the full Claude hook lifecycle on a clean checkout, in the order a
# real session hits them: session setup -> pre-commit -> pre-push checks.
#
# This catches hooks that break end-to-end (a syntax error, a missing tool, a
# formatter that errors on the repo's own files) before they reach a session
# and silently block every tool call. Run by `.github/workflows/hook-lifecycle.yaml`.

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

# shellcheck source=.github/scripts/lib/phase-timer.bash
source "$repo_root/.github/scripts/lib/phase-timer.bash"

# lint-staged stashes the working tree, which needs a committer identity that CI
# runners don't configure by default.
git config user.email "ci@example.com"
git config user.name "CI"

# 1. Session setup. Mirror the Claude harness: hand it an env file and source
#    the PATH/GH_REPO exports it records, so tools it installs (shfmt, ruff via
#    uv, jq, ...) are on PATH for the hooks that run afterwards.
CLAUDE_ENV_FILE=$(mktemp "${RUNNER_TEMP:-/tmp}/claude_env_XXXXXX")
export CLAUDE_ENV_FILE
setup_log=$(mktemp "${RUNNER_TEMP:-/tmp}/session-setup_XXXXXX.log")
# Report on the way out too, so a lifecycle that dies partway still publishes
# how long it got through — that is the diagnostic for a hang or a timeout.
trap 'rm -f "$CLAUDE_ENV_FILE" "$setup_log"; timer_report "Hook lifecycle"' EXIT

timer_start
run_session_setup() { .claude/hooks/session-setup.sh 2>&1 | tee "$setup_log"; }
timed_phase "session-setup.sh" run_session_setup
# shellcheck disable=SC1090
source "$CLAUDE_ENV_FILE"

# session-setup warns (exit 0) instead of failing so a real session can still
# start, but a hook with a syntax error is exactly the regression this job
# exists to catch — so promote that specific warning to a hard failure.
if grep -q "syntax error" "$setup_log"; then
  echo "session-setup reported a hook with a syntax error — see log above" >&2
  exit 1
fi

# 2. Pre-commit hook. Stage any pending changes and run it. lint-staged only ever
#    acts on changed files, so on a clean checkout there's nothing to format
#    (repo-wide formatting is covered by the pre-commit and format-check
#    workflows) — this leg verifies the hook script itself runs without error.
git add -A
timed_phase "pre-commit" .hooks/pre-commit

# 3. Pre-push checks (build/lint/test/ruff — whichever are configured).
export CLAUDE_PROJECT_DIR="$repo_root"
timed_phase "pre-push-check.sh" .claude/hooks/pre-push-check.sh

# 4. Git pre-push hook. Feed it an empty ref list (a push with nothing to push)
#    so the pushed-range pre-commit loop is a no-op and the leg verifies the
#    hook itself — tool discovery, the workflow pin read, the symlink check —
#    runs without error.
run_pre_push() { .hooks/pre-push origin "$(git remote get-url origin)" </dev/null; }
timed_phase "pre-push" run_pre_push

echo "Hook lifecycle completed successfully."
