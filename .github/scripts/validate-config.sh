#!/usr/bin/env bash
set -euo pipefail

errors=0

error() {
  echo "ERROR: $1"
  errors=$((errors + 1))
}

echo "Validating configuration consistency..."
echo ""

# 1. All hook scripts referenced in .claude/settings.json exist on disk
echo "Checking Claude hook script paths..."
if [[ -f .claude/settings.json ]]; then
  if ! commands=$(jq -r '.. | objects | select(.command?) | .command' .claude/settings.json 2>/dev/null); then
    error ".claude/settings.json could not be parsed (invalid JSON?)"
    commands=""
  fi
  while IFS= read -r cmd; do
    [[ -z "$cmd" ]] && continue
    # shellcheck disable=SC2016  # literal $CLAUDE_PROJECT_DIR matched by sed
    resolved=$(echo "$cmd" | sed 's|"\$CLAUDE_PROJECT_DIR"/\?|./|g; s|"||g; s|\$CLAUDE_PROJECT_DIR/\?|./|g')
    read -ra tokens <<<"$resolved"
    for token in "${tokens[@]}"; do
      # Compound commands (the safe-launch bootstrap) leave a `;` glued to the
      # last token of each simple command; strip it before the path check.
      token="${token%;}"
      # Filter — only hook-path-shaped tokens get an existence check; every
      # other token (flags, other args) is correctly ignored.
      # case-default-ok: no-match is the intended no-op, not a missed case.
      case "$token" in
      ./.claude/hooks/* | ./.hooks/*)
        if [[ ! -f "$token" ]]; then
          error "Hook script missing: $token"
        fi
        ;;
      esac
    done
  done <<<"$commands"
else
  error ".claude/settings.json not found"
fi

# 2. Hook scripts are syntactically valid. Files with a shebang must be
# executable (they're invoked directly); language-helper files without a
# shebang are loaded by another hook and don't need +x.
echo "Checking hook script permissions and syntax..."
for f in .hooks/* .claude/hooks/*; do
  [[ -f "$f" ]] || continue
  has_shebang=0
  # read returns 1 at EOF (empty file = no shebang, fine); >1 is a real error.
  rc=0
  IFS= read -r first_line <"$f" || rc=$?
  [[ "${rc:-0}" -le 1 ]] || error "Failed to read $f (exit $rc)"
  # Filter — has_shebang is already initialized to 0; a non-matching first
  # line correctly leaves it at that default.
  # case-default-ok: no-match is the intended no-op, not a missed case.
  case "$first_line" in '#!'*) has_shebang=1 ;; esac
  if [[ "$has_shebang" = "1" ]] && [[ ! -x "$f" ]]; then
    error "$f has a shebang but is not executable"
  fi
  case "$f" in
  *.py)
    if ! py_err=$(python3 -m py_compile "$f" 2>&1); then
      error "$f has a python syntax error: $py_err"
    fi
    ;;
  *.mjs | *.cjs | *.js)
    if ! node_err=$(node --check "$f" 2>&1); then
      error "$f has a JavaScript syntax error: $node_err"
    fi
    ;;
  *.json)
    if ! json_err=$(python3 -m json.tool "$f" 2>&1 >/dev/null); then
      error "$f is not valid JSON: $json_err"
    fi
    ;;
  *)
    if ! bash_err=$(bash -n "$f" 2>&1); then
      error "$f has a bash syntax error: $bash_err"
    fi
    ;;
  esac
done

# 3. Every PreToolUse hook must be invoked through the safe-launch BOOTSTRAP:
#   bash -n .../safe-launch.sh 2>/dev/null && exec bash .../safe-launch.sh <target>;
#   case "$AGENT_SANITIZER_FAIL_OPEN" in 0|false) printf '<ask verdict>' ;; *) printf '<additionalContext warning>' ;; esac
# safe-launch.sh guards its targets against parse/runtime faults, but nothing
# else guards safe-launch.sh itself: a merge-conflict marker in the shim is a
# bash parse error, exit 2, and a hard block on every guarded tool call. The
# inline bootstrap syntax-checks the shim first and degrades per the posture
# knob when it is corrupt or missing, so a broken shim never hard-blocks. A
# bare first-token safe-launch.sh invocation is rejected: it leaves the shim
# unguarded. BOTH posture arms are required — an open-only bootstrap silently
# strands a host that pinned AGENT_SANITIZER_FAIL_OPEN=0 (agent-glovebox) with
# the loose posture, and a closed-only one reintroduces the prompt stall.
echo "Checking PreToolUse hooks use the safe-launch bootstrap..."
if [[ -f .claude/settings.json ]]; then
  if ! pretooluse_cmds=$(jq -r '.hooks.PreToolUse // [] | .[] | .hooks[] | select(.type == "command") | .command' .claude/settings.json 2>/dev/null); then
    error ".claude/settings.json could not be parsed (invalid JSON?)"
    pretooluse_cmds=""
  fi
  while IFS= read -r cmd; do
    [[ -z "$cmd" ]] && continue
    # The fallback must be `;`-separated (`; case`), not `&&`-joined: an
    # `&&`-chained fallback never runs when `bash -n` fails, printing nothing —
    # and empty stdout with exit 0 is Claude Code's ALLOW, so the transcript
    # would carry no record that the guard was skipped.
    case "$cmd" in
    'bash -n '*'/safe-launch.sh 2>/dev/null && exec bash '*'/safe-launch.sh '*'; case '*'AGENT_SANITIZER_FAIL_OPEN'*'"permissionDecision":"ask"'*'"additionalContext"'*) ;;
    *) error "PreToolUse hook must use the safe-launch bootstrap (bash -n .../safe-launch.sh 2>/dev/null && exec bash .../safe-launch.sh <target>; case \"\$AGENT_SANITIZER_FAIL_OPEN\" with BOTH a fail-closed ask arm and a fail-open additionalContext arm, ;-separated and never &&-joined) so a corrupt safe-launch.sh degrades per the posture knob instead of hard-blocking the session: $cmd" ;;
    esac
  done <<<"$pretooluse_cmds"
fi

# 4. Hook matchers must not embed permission-rule/command syntax (e.g.
# "Bash(git push*)"). `matcher` filters only on tool name; a value shaped
# like a tool call is silently never matched (RegExp.test on the literal
# tool name), which quietly disables the whole hook. That belongs in the
# handler's own `if` field instead.
echo "Checking hook matchers don't embed command-content syntax..."
if [[ -f .claude/settings.json ]]; then
  if ! matchers=$(jq -r '.hooks // {} | .[] | .[] | .matcher? // empty' .claude/settings.json 2>/dev/null); then
    error ".claude/settings.json could not be parsed (invalid JSON?)"
    matchers=""
  fi
  while IFS= read -r matcher; do
    [[ -z "$matcher" ]] && continue
    if [[ "$matcher" =~ ^[A-Za-z_-]+\( ]]; then
      error "Hook matcher looks like command-content syntax, not a tool-name filter (use the handler's \"if\" field instead): $matcher"
    fi
  done <<<"$matchers"
fi

# Summary
echo ""
if [[ "$errors" -gt 0 ]]; then
  echo "Validation failed with $errors error(s)"
  exit 1
else
  echo "All checks passed"
fi
