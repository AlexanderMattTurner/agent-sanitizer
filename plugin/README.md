# agent-sanitizer — Claude Code plugin

Sanitization for everything flowing into and out of a Claude Code session: tool
inputs, tool outputs, and user prompts. Hook failures pass through with a loud
warning by default; `AGENT_SANITIZER_FAIL_OPEN=0` makes them block instead, and
`AGENT_SANITIZER_DISABLED_HOOKS` stands individual hooks down.

## Install

```
/plugin marketplace add AlexanderMattTurner/agent-sanitizer
/plugin install agent-sanitizer@agent-sanitizer
/agent-sanitizer:enable-auto-update
```

The hooks run on any node >=22 the launcher can find — or, on the common
platforms, on a self-contained binary a SessionStart hook provisions when no
such node exists (see [Configuration](#configuration)).

With `AGENT_SANITIZER_SECRETS_ENABLED=1` set (the secret layer is off by
default — see [Configuration](#configuration)), the first session after install
provisions the Python secret-redaction engine (`agent-sanitizer[secrets]`) into
the plugin's data directory. That needs `uv` or `python3` on PATH; without
either, provisioning fails loudly and tool output reaches the model
**unredacted** — set `AGENT_SANITIZER_FAIL_OPEN=0` to have it suppressed
instead.

### Staying current

Claude Code auto-updates Anthropic's own marketplaces by default and nobody
else's, so an install of this one pins you to the release you added and later
detector fixes never arrive. Claude Code ships no slash command for the toggle,
so the plugin ships one — the third line of the install block above.

It flips `autoUpdate` on this marketplace's existing entry in Claude Code's
registry — the same bit the picker's **Enable auto-update** writes — and prints
the file it touched. It never creates the entry: with the marketplace not yet
added it says so and exits non-zero, as it does if a Claude Code release changes
the registry's shape. `--disable` puts it back. The picker route
(`/plugin` → **Marketplaces** → `agent-sanitizer` → **Enable auto-update**)
stays available and is the fallback the skill points you to.

Either way, updates are fetched in the background shortly after a session starts
and load on `/reload-plugins` or at the next launch. To pull a release by hand
instead:

```
/plugin marketplace update agent-sanitizer
/plugin update agent-sanitizer@agent-sanitizer
```

Fleet-wide, an administrator can enable it from managed settings rather than
per user:

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
  }
}
```

## What it does

| Hook                       | Event              | Protection                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| -------------------------- | ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scan-invisible-chars`     | SessionStart       | Scans the instruction files that load at launch — the project root's `CLAUDE.md`/`CLAUDE.local.md`/`AGENTS.md`, the `CLAUDE.md` chain in every directory above it, and the context markdown under the root `.claude/` (rules, skills, agents and the other context subdirectories — never bulk data like `worktrees/`) — for hidden-Unicode payloads; auto-cleans what it can, inside the project only                                                                      |
| `scan-loaded-instructions` | InstructionsLoaded | Scans each instruction file Claude Code loads outside the launch set — a subdirectory's `CLAUDE.md`, a path-scoped rule, an `@import`, a post-compaction reload, the user-global `~/.claude/CLAUDE.md` and global rules — from the bytes the event hands it, so nothing below the launch set needs a tree walk; auto-cleans in-project findings and tells the model the file it just read is untrusted                                                                      |
| `sanitize-user-prompt`     | UserPromptSubmit   | Blocks prompts carrying payload-capable invisible Unicode or ANSI escapes (inert escapes — pasted SGR colour, a stray `ESC` — pass with a note)                                                                                                                                                                                                                                                                                                                             |
| `pretooluse-sanitize`      | PreToolUse         | Normalizes confusable/homoglyph paths and commands, strips stego and terminal-control sequences from model-authored content, re-anchors redacted Edit/Write inputs onto the on-disk bytes, names each `[REDACTED…]` placeholder and hidden-HTML splice marker (with the field carrying it and how to recover the real content) in tool calls rehydration cannot re-anchor, and requires a confirming retry before a Write drops a redacted secret from a git-untracked file |
| `sanitize-output`          | PostToolUse        | Strips invisibles and ANSI, splices hidden HTML out of web/MCP ingress, flags exfil-shaped URLs, redacts secrets via detect-secrets, and warns when a Read's raw bytes already carry literal `[REDACTED…]` placeholder text (a possibly clobbered secret)                                                                                                                                                                                                                   |

Findings come at two volumes. A **warning** means the text was
injection-shaped: something was hidden from a human reader, something a payload
would have used was removed, or a secret was redacted. A **note** means it
happened and here is how to look at it — an inert pasted terminal colour, one
soft hyphen in a paragraph, a `<script>` tag preserved on a fetched page, a
plain link whose URL merely looks exfil-shaped. Nothing about the split changes
what is stripped, spliced or redacted; a note is still reported. It exists so
the banner keeps meaning something, because a banner that fires on every
ordinary page is one you learn to skip — and then the one that mattered scrolls
past too.

Every hook also times itself, as do the SessionStart shell entry points (the
launcher's preflight, the hook-binary provisioning and the redactor
provisioning). A run that overruns its
budget — one second for a hook, a minute for a one-time install — says so in the
model's context and on stderr, naming the step and the timing and asking you to
report it, because a slow hook is otherwise indistinguishable from a slow agent.
A healthy run says nothing.

When a hook cannot run, it fails **open** by default: the guarded action
proceeds and the model is told, in `additionalContext`, that what it is reading
was never sanitized. One exception, with secrets enabled, when the hook process
starts but its machinery fails: a write-shaped call (Write/Edit/MultiEdit/NotebookEdit) whose
input carries `[REDACTED` placeholder text **asks** even under the open
default — with the sanitizer down, rehydration cannot run, and passing it
through would persist the placeholder over the real secret on disk. (A missing
`node` or a corrupt bundle is caught earlier by the launcher, which cannot
inspect the payload and always warns.) What it never does is fail SILENTLY — Claude Code treats a
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

One opt-in, for the secret layer — its denies and asks are friction, so it
engages only when an operator asked for it:

| Variable                            | Effect                                                                                                                                                                                                                        |
| ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `AGENT_SANITIZER_SECRETS_ENABLED=1` | Enable the secret-redaction layer: Layer-4 redaction of tool output, placeholder rehydration on Edit/Write, the placeholder-write hold on hook failure, and SessionStart provisioning of the Python engine (default: **off**) |

One per-hook opt-out, for a deployment that wants a whole event left alone —
prompts that legitimately carry escape sequences, or instruction files already
vetted upstream. Editing the shipped `hooks.json` is the alternative, and the
next plugin update overwrites it:

| Variable                          | Effect                                                                                                                                                                                                                                                                                                                                                                                                                       |
| --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `AGENT_SANITIZER_DISABLED_HOOKS=` | Comma-separated hook names to stand down: `scan-invisible-chars`, `scan-loaded-instructions`, `sanitize-user-prompt`, `pretooluse-sanitize`, `sanitize-output`. Each still answers, with an empty verdict, so nothing degrades — the event is simply unguarded. A name that is not a hook is reported on stderr and its hook keeps guarding: the variable is set outside the session, so a typo must not be able to halt it. |

Three knobs for how the launcher finds and reports its runtime:

| Variable                                    | Effect                                                                                                                                                                                                                                                                                                                     |
| ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `AGENT_SANITIZER_NODE=`                     | Absolute path to the node the hooks run on, skipping the search below. The hooks need node >=22; a node under that is named as the fault rather than reported as a corrupt install.                                                                                                                                        |
| `AGENT_SANITIZER_HOOK_BINARY=`              | `0` never provisions nor runs the compiled hook binary; `1` provisions it even when a usable node exists. Unset is auto: provision only when the node search below finds nothing at or above the floor, and prefer a provisioned binary once it is present.                                                                |
| `AGENT_SANITIZER_REPEAT_DEGRADED_CONTEXT=1` | Attach the fail-open warning to every affected call. By default it is attached once per session — a session whose sanitizer is broken stays broken, and the repeats told the model nothing new. The stderr warning and the fail-closed verdicts are unaffected, and repeat either way when the host exports no session id. |

A session started outside an interactive shell — launchd, cron, CI, a GUI
launch — inherits roughly `/usr/bin:/bin`, and fnm/nvm/mise/volta/asdf all put
node on `PATH` from a shell rc file that never ran there, as does Homebrew's
prefix. So a node that is not on `PATH` is looked for in those installs (newest
version wins) before the launcher gives up and degrades.

When even that search comes up empty — a host with no node install at all — a
SessionStart hook (`scripts/provision-hook-binary.sh`) downloads a
self-contained hook executable for the platform (darwin-arm64, darwin-x64,
linux-x64, linux-arm64) from this repository's GitHub release for the installed
plugin version, verifies its SHA-256 against the manifest committed at
`dist/hooks/hook-binaries.sha256` before it is ever installed, and puts it at
`${CLAUDE_PLUGIN_DATA}/hook-binary/agent-sanitizer-hooks`. With that binary
present and executable the launcher runs it directly — no node needed at all —
under the same never-silent posture: a binary that fails to produce a verdict is
named on stderr and the launcher falls back to the node search in the same
invocation. Provisioning needs only `curl` or `wget` plus `sha256sum` or
`shasum`, all stock on macOS and Linux even under `PATH=/usr/bin:/bin`; a
provisioning failure is advisory and loud on stderr, the hooks keep using the
node path meanwhile, and an unsupported platform skips silently. This closes the
session started by launchd or cron with no node installed anywhere, as long as
the host can reach github.com once.

And one posture knob, for what happens when a hook itself fails:

| Variable                      | Effect                                                                                        |
| ----------------------------- | --------------------------------------------------------------------------------------------- |
| `AGENT_SANITIZER_FAIL_OPEN=0` | A hook that failed blocks/asks/suppresses instead of passing through (default: fail **open**) |

Unset, a missing `node`, a corrupt bundle, an uninstalled package, an
unreachable redaction daemon or a layer that threw all let the guarded action
proceed with the warning attached. One exception, with secrets enabled, when the
hook process does run at all: a placeholder-bearing write asks instead — see
above. (A missing
`node` or a corrupt bundle is handled by the launcher, which cannot inspect
the payload and always warns.) Set to `0` (or `false`; every other value,
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
hooks/hooks.json             the five hook registrations
skills/enable-auto-update/   /agent-sanitizer:enable-auto-update
scripts/safe-launch.sh       launcher (prints a response even when node is missing)
scripts/enable-auto-update.mjs  flips autoUpdate on this marketplace's registry entry
scripts/provision-redactor.sh  SessionStart provisioning of the Python redactor
scripts/provision-hook-binary.sh  SessionStart provisioning of the compiled hook binary
scripts/build-plugin.mjs     builds dist/ from claude-hooks/ against this repo's src/
scripts/build-hook-binaries.mjs  compiles the bundle into the per-platform release binaries
scripts/lib/provision-common.sh  the scaffolding both SessionStart provisioners share
scripts/lib/hook-timing.sh   shell port of the hook timer, for the SessionStart scripts
scripts/lib/node-resolve.sh  the node search, for hosts whose PATH never saw a shell rc
scripts/lib/node-floor.sh    the node version floor (generated from engines.node — do not edit)
scripts/lib/fail-open.sh     the shared posture-knob reader (generated — do not edit)
scripts/lock-redactor-deps.mjs  compiles requirements.in into the hash-pinned requirements.txt
dist/hooks/*.bundle.mjs      the committed, self-contained bundle (generated — do not edit)
dist/hooks/hook-binaries.sha256  SHA-256 manifest of the release binaries (generated — do not edit)
dist/redactor/daemon.pyz     the committed redaction engine zipapp (generated — do not edit)
dist/redactor/*.whl          the committed engine wheel both the zipapp and the venv install
requirements.in              the engine's third-party dependencies (generated — do not edit)
requirements.txt             the compiled, hash-pinned dependency lock (generated — do not edit)
```

Both halves of the engine are built from this repository's own sources — the JS
from `src/`, the Python wheel from `python/` — so the shipped hooks, the zipapp
and the provisioned venv are one commit and cannot be three versions.
`dist/hooks/` and `requirements.in` are regenerated offline by
`node plugin/scripts/build-plugin.mjs` and verified byte-for-byte in CI; they
change only when the hook sources or the engine's dependencies do.

The compiled hook binaries are a third artifact class. At ~100 MB each they are
not committed; they are attached to this repository's GitHub release
`v<version>` as `agent-sanitizer-hooks-<platform>` (darwin-arm64, darwin-x64,
linux-x64, linux-arm64), compiled from the committed bundle with the pnpm-pinned
bun (`bun build --compile`) by `plugin/scripts/build-hook-binaries.mjs`. What is
committed is their SHA-256 manifest, `dist/hooks/hook-binaries.sha256`, which
the same script generates — and because bun's compile is byte-deterministic for
a fixed bun version, target, input bundle and outfile name, CI regenerates the
binaries and byte-checks their digests against the manifest: the reproducibility
gate survives as a digest round-trip. The provisioner verifies a downloaded
binary against that manifest before it is ever installed, so a release asset that
does not hash to the committed digest never runs. Compiled from the committed
bundle, the binaries stay one commit with everything above.

`requirements.txt` is the fully resolved third-party tree, every version and
artifact hash pinned. It is what both `dist/redactor/daemon.pyz` is built from
and what `scripts/provision-redactor.sh` installs at SessionStart, so the
committed zipapp floor and the provisioned venv carry the identical tree.
Compiling it reaches PyPI, so it is not part of the offline rebuild:

```bash
node plugin/scripts/lock-redactor-deps.mjs   # refresh transitives (deliberate)
node plugin/scripts/build-redactor-pyz.mjs   # rebuild the wheel and zipapp
```

The lock is what keeps the zipapp reproducible: without every transitive
(certifi, charset-normalizer, idna, pyyaml, requests, urllib3) pinned by version
and hash, any of their releases changes the zipapp's bytes with no diff anywhere
in this repo, turning the reproducibility byte-compare red on unrelated PRs.
