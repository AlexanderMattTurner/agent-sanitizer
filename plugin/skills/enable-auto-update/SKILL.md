---
name: enable-auto-update
description: >
  Turns Claude Code's background auto-update on for the agent-sanitizer marketplace, so this
  plugin picks up new releases instead of staying pinned to the catalog snapshot taken when the
  marketplace was added. Activate when the user asks to enable (or, with --disable, turn off)
  auto-update for agent-sanitizer, asks how to keep the sanitizer up to date, or asks why an
  installed version is stale. Claude Code has no slash command for this toggle — the only other
  route is the /plugin picker's Marketplaces tab.
---

# Enable auto-update for the agent-sanitizer marketplace

Run the script. It flips `autoUpdate` on the marketplace's existing entry in
Claude Code's registry:

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/enable-auto-update.mjs"
```

Pass `--disable` to turn it back off.

Report the script's output verbatim; it names the file it wrote and when the
change takes effect. Do not paraphrase a failure into a success.

## When it exits non-zero

The script refuses rather than guessing, and each refusal has one fix:

- **No registry file / marketplace not registered** — the marketplace was never
  added, or was added under a different Claude Code config directory. Tell the
  user to run `/plugin marketplace add AlexanderMattTurner/agent-sanitizer`
  first, then re-run this skill.
- **`cannot write … the OS refused it`** — most often Claude Code's Bash
  sandbox, which confines writes to the workspace: the script cannot reach the
  plugin cache from a sandboxed session, however it is invoked. Tell the
  user to run the command in a terminal outside Claude Code, or to use `/plugin`
  → **Marketplaces** → `agent-sanitizer` → **Enable auto-update**. Do not retry
  the script or edit the registry by hand.
- **Unrecognized entry shape** — a Claude Code release changed the registry
  format. Do not edit the file by hand: send the user to `/plugin` →
  **Marketplaces** → `agent-sanitizer` → **Enable auto-update**, and report that
  the script needs updating for this Claude Code version.

Auto-update fetches in the background shortly after a session starts; the new
version loads on `/reload-plugins` or at the next launch. To pull a release
immediately instead, `/plugin marketplace update agent-sanitizer` followed by
`/plugin update agent-sanitizer@agent-sanitizer`.
