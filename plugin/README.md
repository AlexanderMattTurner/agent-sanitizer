# agent-sanitizer — Claude Code plugin

Sanitization for everything flowing into and out of a Claude Code session: tool
inputs, tool outputs, and user prompts. Hook failures pass through with a loud
warning by default; `AGENT_SANITIZER_FAIL_OPEN=0` makes them block instead.

## Install

```
/plugin marketplace add AlexanderMattTurner/agent-sanitizer
/plugin install agent-sanitizer@agent-sanitizer
```

**Turn auto-update on after installing.** Claude Code enables it by default only
for official Anthropic marketplaces; a third-party one like this defaults to
off, so the install stays pinned to the release you added and never picks up a
fix to a layer. The plugin ships a command for it:

```
/agent-sanitizer:enable-auto-update
```

It merges the entry below into `~/.claude/settings.json` and reports what it
changed; an existing entry pointing at a different repo stops it rather than
being overwritten. `/plugin` → **Marketplaces** → **Enable auto-update** does
the same by hand, and so does writing it into `~/.claude/settings.json`
(user-wide) or a repo's `.claude/settings.json` (everyone who trusts that
folder):

```json
{
  "extraKnownMarketplaces": {
    "agent-sanitizer": {
      "source": {
        "source": "github",
        "repo": "AlexanderMattTurner/agent-sanitizer"
      },
      "autoUpdate": true
    }
  },
  "enabledPlugins": { "agent-sanitizer@agent-sanitizer": true }
}
```

Updates are fetched in the background after startup, so the running session
keeps the version it launched with until you `/reload-plugins`.

The first session after install provisions the Python secret-redaction engine
(`agent-sanitizer[secrets]`) into the plugin's data directory. That needs `uv` or
`python3` on PATH; without either, provisioning fails loudly and tool output
reaches the model **unredacted** — set `AGENT_SANITIZER_FAIL_OPEN=0` to have it
suppressed instead.

## What it does

| Hook                   | Event            | Protection                                                                                                                                                                                    |
| ---------------------- | ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scan-invisible-chars` | SessionStart     | Scans `CLAUDE.md`, `AGENTS.md` and `.claude/` markdown for hidden-Unicode payloads; auto-cleans what it can                                                                                   |
| `sanitize-user-prompt` | UserPromptSubmit | Blocks prompts carrying payload-capable invisible Unicode or ANSI escapes (pasted SGR colour passes with a note)                                                                              |
| `pretooluse-sanitize`  | PreToolUse       | Normalizes confusable/homoglyph paths and commands, strips stego and terminal-control sequences from model-authored content, and re-anchors redacted Edit/Write inputs onto the on-disk bytes |
| `sanitize-output`      | PostToolUse      | Strips invisibles and ANSI, splices hidden HTML out of web/MCP ingress, flags exfil-shaped URLs, and redacts secrets via detect-secrets                                                       |

When a hook cannot run, it fails **open** by default: the guarded action
proceeds and the model is told, in `additionalContext`, that what it is reading
was never sanitized. What it never does is fail SILENTLY — Claude Code treats a
crashed hook as "no objection" and says nothing, so the launcher
(`scripts/safe-launch.sh`) speaks even when node is missing or the bundle is
corrupt. A deployment that would rather keep guarding than keep working sets
`AGENT_SANITIZER_FAIL_OPEN=0` (below) and gets a block, an ask, or a suppression
instead.

## Configuration

Three opt-outs, for content the sanitizer would otherwise rewrite:

| Variable                               | Effect                                                             |
| -------------------------------------- | ------------------------------------------------------------------ |
| `AGENT_SANITIZER_INVISIBLE_DISABLED=1` | Keep invisible characters in model-authored content (i18n joiners) |
| `AGENT_SANITIZER_TERMINAL_DISABLED=1`  | Keep raw escape sequences (fixtures that must contain them)        |
| `AGENT_SANITIZER_OUTPUT_DISABLED=1`    | Both of the above                                                  |

And one posture knob, for what happens when a hook itself fails:

| Variable                      | Effect                                                                                        |
| ----------------------------- | --------------------------------------------------------------------------------------------- |
| `AGENT_SANITIZER_FAIL_OPEN=0` | A hook that failed blocks/asks/suppresses instead of passing through (default: fail **open**) |

Unset, a missing `node`, a corrupt bundle, an uninstalled package, an
unreachable redaction daemon or a layer that threw all let the guarded action
proceed with the warning attached. Set to `0` (or `false`; every other value,
including `1`, is the open default) they halt instead.

Worth knowing before you leave it open: some of those failures are reachable by
whoever authored the content the hook is inspecting — colliding field names, a
tool response nested deeply enough to overflow the sanitize walk, enough
secret-shaped leaves to exhaust the redaction budget. Under the open posture a
tool response that provokes one is shown to the model verbatim, secrets
included. `=0` is the setting for a deployment where that matters more than the
session staying unblocked.

What neither posture touches is a sanitizer that RAN: a prompt or tool output
that the layers actually flagged is blocked or rewritten the same way either
way.

Variables prefixed `_AGENT_SANITIZER_` are internal plumbing (the redactor socket
and its deadlines, the sanitization budget, the trace channel). `hooks.json` sets
what it needs; they are not a stable interface and may change between releases.

## What is not included

Semantic prompt-injection filtering by a second model is **not** part of this
plugin — no inference key is read, and no request leaves the machine. The layers
above are all local and deterministic apart from the redaction daemon, which
listens on a private Unix socket.

## Contents

```
.claude-plugin/plugin.json   plugin manifest
hooks/hooks.json             the four hook registrations
skills/enable-auto-update/   the /agent-sanitizer:enable-auto-update command
scripts/safe-launch.sh       launcher (prints a response even when node is missing)
scripts/provision-redactor.sh  SessionStart provisioning of the Python redactor
scripts/build-plugin.mjs     builds dist/ from claude-hooks/ against the pinned engine
scripts/lock-redactor-deps.mjs  compiles requirements.in into the hash-pinned requirements.txt
dist/hooks/*.bundle.mjs      the committed, self-contained bundle (generated — do not edit)
dist/redactor/daemon.pyz     the committed redaction engine zipapp (generated — do not edit)
requirements.in              the PyPI half of the engine pin (generated — do not edit)
requirements.txt             the compiled, hash-pinned dependency lock (generated — do not edit)
```

`dist/hooks/` and `requirements.in` are regenerated offline by
`node plugin/scripts/build-plugin.mjs` and verified byte-for-byte in CI; they
change only when the engine pin or the hook sources do.

`requirements.txt` is the fully resolved dependency tree, every version and
artifact hash pinned. It is what both `dist/redactor/daemon.pyz` is built from
and what `scripts/provision-redactor.sh` installs at SessionStart, so the
committed zipapp floor and the provisioned venv carry the identical tree.
Compiling it reaches PyPI, so it is not part of the offline rebuild:

```bash
node plugin/scripts/lock-redactor-deps.mjs   # refresh transitives (deliberate)
node plugin/scripts/build-redactor-pyz.mjs   # rebuild the zipapp from the lock
```

Without the lock only the engine itself was pinned; a release of any transitive
(certifi, charset-normalizer, idna, pyyaml, requests, urllib3) changed the
zipapp's bytes with no diff anywhere in this repo, turning the reproducibility
byte-compare red on unrelated PRs.
