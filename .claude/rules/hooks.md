---
paths:
  - ".claude/hooks/**"
  - ".hooks/**"
  - ".claude/settings.json"
---

# Hooks and their provisioning

- **Provision hook runtime deps synchronously before backgrounding slow installs.** PostToolUse hooks fire on the first tool call, which can beat a backgrounded `uv sync`/`pnpm install`; a hook that fails closed on a missing dep breaks silently during the cold-start window. Keep hook-dependency installers above any `&`-backgrounded installs in `session-setup.sh`.
- **A gate hook must not resolve its dependencies at load time.** A bare static `import` of a package that may be absent (a cold container, a missing `node_modules`) crashes the hook before any try/catch can run. The harness treats a crashed hook as a **non-blocking** error, so the tool call proceeds **unguarded** — a fail-OPEN exactly where you wanted fail-closed. Load such a dependency behind a caught dynamic `import` so the failure lands in the hook's own catch, where it can take its declared posture.
- **Always wrap a PreToolUse hook with `safe-launch.sh`, invoked through the settings.json bootstrap.** A hook that fails to parse (unresolved merge-conflict markers, a syntax error) exits 2, which Claude Code treats as a block — locking the session out of repairing the very file that is broken. `safe-launch.sh` detects the parse failure and degrades open for edits under `.claude/hooks/` and `.hooks/` so the session can self-repair; the inline bootstrap in `.claude/settings.json` (`bash -n …/safe-launch.sh && exec bash …/safe-launch.sh <target>; printf '<ask verdict>'`) covers the one file the shim cannot guard — itself. `validate-config.sh` check 3 rejects any PreToolUse command not using the bootstrap.
- **The hook stack's worst-case posture is `permissionDecision="ask"`, never a hard block.** Wrapped hooks signal denial via a JSON `permissionDecision` verdict, NEVER via exit 2 — `safe-launch.sh` treats any exit 2 (bash abort, argparse/grep/jq usage errors, `set -e` propagation) as a fault and converts it to an "ask" verdict the user can override. Exit 0 = allow, exit 1 = non-blocking advisory (stderr shown), JSON on stdout = deliberate verdict. `tests/test_safe_launch.py` pins every degradation path.
- **State each hook's failure posture in its header comment**, and make the code match it. An advisory filter passes the event through on any uncertainty; a gate denies. The posture is the whole contract — a reader cannot infer it from the code, and a silent change from deny to pass is invisible in review.
