---
# prettier-ignore
name: enable-auto-update
description: >
  Turns on marketplace auto-update for agent-sanitizer by writing the
  `agent-sanitizer` entry into the user's `~/.claude/settings.json`.
  Run this once after installing the plugin: Claude Code enables auto-update by
  default only for official Anthropic marketplaces, so this install would
  otherwise stay pinned to the release it was added from and never receive a
  fix to a sanitization layer.
disable-model-invocation: true
---

# Enable auto-update for agent-sanitizer

This skill edits the user's global Claude Code settings. Run it only when the
user invokes it — never on your own initiative.

## What to write

The target file is `~/.claude/settings.json`. The entry to end up with:

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

## Steps

1. Read `~/.claude/settings.json`. If it does not exist, create it containing
   exactly the object above and skip to step 5.
2. If the file is not parseable as strict JSON — it has comments, trailing
   commas, or is otherwise JSONC — **stop**. Print the block above and tell the
   user to merge it by hand. Do not rewrite a file you cannot round-trip.
3. Merge, never replace: keep every existing key, including other entries under
   `extraKnownMarketplaces` and `enabledPlugins`. Set only the
   `agent-sanitizer` marketplace entry and the
   `agent-sanitizer@agent-sanitizer` plugin key.
4. If an `agent-sanitizer` entry already exists with a **different** `source`,
   stop and show the user both values rather than overwriting — a marketplace
   name pointing at another repo is theirs to resolve, and silently repointing
   it would change which code runs on their machine.
5. Report what changed: the file path, whether it was created or edited, and
   whether `autoUpdate` was already `true` (in which case say so and change
   nothing else).

## What to tell the user afterwards

- Updates are fetched in the background after startup, with a delay of up to ten
  minutes. The running session keeps the version it launched with until
  `/reload-plugins` or the next launch.
- The first session on a new version re-runs the plugin's SessionStart
  provisioning of the Python redaction engine, which costs a few seconds once.
- Project scope instead: the same two keys in a repo's `.claude/settings.json`
  install the plugin for everyone who trusts that folder.

## Examples

**No settings file yet** → create `~/.claude/settings.json` with exactly the
object above, then: "Created ~/.claude/settings.json with the agent-sanitizer
marketplace and auto-update enabled."

**Existing settings with unrelated keys** → keep `env`, `permissions`, `hooks`
and everything else byte-for-byte; add the two keys; then: "Edited
~/.claude/settings.json: added the agent-sanitizer marketplace with
autoUpdate: true, and enabled agent-sanitizer@agent-sanitizer. Your other
settings are unchanged."

**Already enabled** → change nothing and say: "auto-update is already on for
agent-sanitizer; no changes made."
