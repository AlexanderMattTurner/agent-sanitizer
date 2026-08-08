# Claude Code Configuration

This directory contains configuration and skills for Claude Code.

## Structure

```text
.claude/
├── settings.json              # Claude Code hooks configuration
├── agents/
│   └── code-reviewer.md       # Read-only reviewer subagent (Read/Grep/Glob)
├── hooks/
│   ├── session-setup.sh       # Runs on session start (installs tools, configures git)
│   ├── pre-push-check.sh      # Runs before git push / gh pr (build, lint, typecheck)
│   ├── lib-checks.sh          # Shared bash helpers (exists, has_script)
│   ├── safe-launch.sh         # Wraps PreToolUse hooks so a parse error can't lock the session
│   └── safe-launch-parse.py   # Helper: extracts tool_name/target path from the PreToolUse payload
└── skills/
    ├── pr-creation/           # PR creation workflow with self-critique
    ├── update-pr/             # Update an existing PR with new changes
    ├── peer-review/           # Drive the code-reviewer subagent, then triage/fix
    ├── explore-plan/          # Explore → Plan → Critique → Review → Verify discipline
    ├── conventional-commits/  # Conventional Commits helper (invoke with /commit)
    └── markdown-block/        # Emit copyable raw markdown in a fenced block
```

## How It Works

### The sanitizer plugin, in this repo's own sessions

`settings.json` registers this repo as a plugin marketplace (`extraKnownMarketplaces`,
with `autoUpdate: true`) and enables `agent-sanitizer@agent-sanitizer`
(`enabledPlugins`). Trusting the project folder prompts the install; after that
Claude Code refreshes the marketplace clone on startup and picks up whatever
`version` the latest release stamped
into `plugin/.claude-plugin/plugin.json`, so sessions here track the SHIPPED
hooks rather than the working tree. That is deliberate: it is the same artifact
users install, so a broken release is felt here first.

Three consequences worth knowing. The first session after an update runs the
plugin's SessionStart provisioning (a `uv`/`python3` install of the redaction
engine into the plugin data dir), so a cold start is slower. The hooks under
`hooks/` below are unrelated dev-workflow hooks — the sanitization layers come
from the plugin, not from this directory. And those layers now apply to this
repo's own payload corpora: `src/invisible.mjs` and `tests/secrets/` hold raw
invisible characters, so a `Read` of them returns the stripped text (silently —
the alert is suppressed on local tools), and `Edit`/`Write` content the model
authors is rewritten the same way. When editing a fixture that must keep its
payload, run the session with `AGENT_SANITIZER_TERMINAL_DISABLED=1` (raw escapes)
or `AGENT_SANITIZER_INVISIBLE_DISABLED=1` (invisible chars); see the knob table
in `plugin/README.md`.

`plugin/test/plugin-manifest.test.mjs` pins the marketplace name, repo slug and
plugin id here against the two manifests, so a rename cannot leave this file
pointing at a marketplace nobody publishes.

### Session Start Hook

When Claude Code starts a session, it automatically runs `session-setup.sh` which:

1. **Installs tools**: shfmt, gh (GitHub CLI), jq, shellcheck
2. **Configures git hooks**: Sets `core.hooksPath` to `.hooks/`
3. **Validates GitHub CLI auth**: Fails fast if `GH_TOKEN` is missing
4. **Detects GitHub repo**: Extracts `owner/repo` from proxy remotes in web sessions
5. **Installs dependencies**: Node (pnpm/npm) and Python (uv) if applicable

### Pre-Push Check Hook

Before `git push` or `gh pr` commands, `pre-push-check.sh` runs any configured checks:

- **build** (`pnpm build`): Catches type errors in TypeScript projects
- **lint** (`pnpm lint`): Catches code quality issues
- **typecheck** (`pnpm check`): Additional type checking if configured
- **ruff**: Python linting if applicable

Only runs scripts that are actually configured in `package.json`—skips placeholder scripts.

### Skills

Skills in `skills/` are reusable workflows that guide Claude through complex tasks:

- **pr-creation**: Creating pull requests with mandatory self-critique before submission (invoke with `/pr-creation`)
- **update-pr**: Updating an existing PR with new changes and an optionally revised description (`/update-pr`)
- **peer-review**: Running the read-only `code-reviewer` subagent on the diff, then triaging and fixing findings (`/peer-review`)
- **explore-plan**: Enforcing the Explore → Plan → Critique → Review → Verify discipline for non-trivial work (`/explore-plan`)
- **conventional-commits**: Guiding Conventional Commits with secret detection—invoke with `/commit` (the skill's `name` is `commit`)
- **markdown-block**: Emitting copyable raw markdown in a fenced code block (`/markdown-block`)

The `agents/` directory holds subagents—currently `code-reviewer`, a read-only (Read/Grep/Glob) reviewer used by the `peer-review` skill for an unbiased second opinion on a diff.

Skills are automatically available to Claude Code when working in this repository.

## Customization

### Adding Tools

Edit `hooks/session-setup.sh` to add more tools:

```bash
# Via uv
uv_install_if_missing mycommand mypackage

# Via webi (https://webinstall.dev) — pin versions for supply-chain safety
webi_install_if_missing mytool mytool@1

# Via apt (requires root)
if is_root; then
  apt-get install -y mytool
fi
```

### Adding Skills

Create new skill directories in `skills/` following the pattern in `pr-creation/SKILL.md`. Each skill should be a directory with a `SKILL.md` entrypoint and optional supporting files.

### Customizing Hooks

Modify `settings.json` to add more hooks. See the [Claude Code documentation](https://docs.anthropic.com/en/docs/claude-code) for available hook types.

**Always wrap PreToolUse hooks with `safe-launch.sh`, invoked through the self-checking bootstrap below.** A PreToolUse hook that fails to parse (e.g. unresolved merge conflict markers) exits 2, which Claude Code treats as a block—locking the session out of repairing the very file that’s broken. `safe-launch.sh` detects the parse failure and never propagates it: edits under `.claude/hooks/` and `.hooks/` are allowed for self-repair, and every other tool gets the degraded response below. It also refuses to honor a runtime exit 2 from the wrapped hook—wrapped hooks signal denial via JSON, never exit 2. The inline bootstrap covers the one file the shim can’t guard: itself.

Which degraded response you get is the `AGENT_SANITIZER_FAIL_OPEN` knob, the same one [`plugin/scripts/safe-launch.sh`](../plugin/scripts/safe-launch.sh) and `failOpenEnabled()` in `claude-hooks/lib/hook-io.mjs` read:

| `AGENT_SANITIZER_FAIL_OPEN`         | Posture on a hook’s own failure                                                                                                          |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| unset (default), or any other value | **Open**—the tool runs; a non-empty `additionalContext` warning records that it ran unguarded, plus a stderr line. Nothing prompts.      |
| `0` or `false`                      | **Closed**—`permissionDecision: "ask"`, so an unguarded tool call is never silent. Pin this when a session must not run unchecked tools. |

Keep the fallback `;`-separated (never `&&`-joined, which would print nothing at all when the syntax check fails, leaving no record that the guard was skipped) and keep **both** posture arms—`validate-config.sh` enforces both properties.

```json
{
  "type": "command",
  "command": "bash -n \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/safe-launch.sh 2>/dev/null && exec bash \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/safe-launch.sh \"$CLAUDE_PROJECT_DIR\"/.claude/hooks/your-new-hook.sh; echo 'safe-launch bootstrap: safe-launch.sh is missing or failed to parse - degrading' >&2; case \"${AGENT_SANITIZER_FAIL_OPEN:-}\" in 0 | false) printf '%s\\n' '{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"ask\",\"permissionDecisionReason\":\"safe-launch.sh itself is missing or corrupt; repair .claude/hooks/safe-launch.sh (approve this tool call manually). This is likely a bug in the hook stack - please file an issue: https://github.com/AlexanderMattTurner/agent-sanitizer/issues/new\"}}' ;; *) printf '%s\\n' '{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"additionalContext\":\"safe-launch.sh itself is missing or corrupt; repair .claude/hooks/safe-launch.sh. The PreToolUse guard is failing open, so this tool call ran UNCHECKED. Set AGENT_SANITIZER_FAIL_OPEN=0 to fail closed on hook failures. This is likely a bug in the hook stack - please encourage the user to file an issue: https://github.com/AlexanderMattTurner/agent-sanitizer/issues/new\"}}' ;; esac"
}
```

Any script under `.claude/hooks/` or `.hooks/` is also syntax-checked at session start by `session-setup.sh`—broken hooks surface as loud warnings before they can block the first tool call.
