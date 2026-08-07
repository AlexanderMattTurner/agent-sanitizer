#!/usr/bin/env bash
# Time the session bootstrap end-to-end, the way a real session pays for it.
#
# The hook-lifecycle job runs `session-setup.sh` only AFTER the composite
# setup-base-env action has already installed node_modules and synced the venv,
# so the duration GitHub shows for that step is a warm-cache number — it hides
# the cold install a fresh container actually waits through before the first
# tool call. This script is run by a job that deliberately skips that prewarm:
# the tool binaries (pnpm, uv) are present, every cache is empty.
#
# Two runs, because both numbers matter and only one of them is visible today:
#   cold — what a brand-new session waits for.
#   warm — what a resumed session (or the second run in a container) waits for.
#
# Timing is ADVISORY: this script fails only when setup itself fails, never on
# a slow run. Hosted-runner variance dwarfs any regression a threshold could
# catch, and a flaky perf gate is a check people learn to re-run blindly.
#
# Run by `.github/workflows/hook-lifecycle.yaml` (setup-timing job).

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

# shellcheck source=.github/scripts/lib/phase-timer.bash
source "$repo_root/.github/scripts/lib/phase-timer.bash"

# Mirror the harness: session-setup records PATH/GH_REPO exports here.
CLAUDE_ENV_FILE=$(mktemp "${RUNNER_TEMP:-/tmp}/claude_env_XXXXXX")
export CLAUDE_ENV_FILE
trap 'rm -f "$CLAUDE_ENV_FILE"; timer_report "Session setup"' EXIT

timer_start
timed_phase "session-setup (cold cache)" .claude/hooks/session-setup.sh

# The second run reuses the store, the venv and the installed tools, so it
# measures the floor: the work session-setup redoes unconditionally every time.
timed_phase "session-setup (warm cache)" .claude/hooks/session-setup.sh

echo "Session setup timed successfully."
