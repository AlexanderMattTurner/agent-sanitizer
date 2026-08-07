# agent-sanitizer — Claude Code plugin

Fail-closed sanitization for everything flowing into and out of a Claude Code
session: tool inputs, tool outputs, and user prompts.

## Install

```
/plugin marketplace add AlexanderMattTurner/agent-sanitizer
/plugin install agent-sanitizer@agent-sanitizer
```

The first session after install provisions the Python secret-redaction engine
(`agent-sanitizer[secrets]`) into the plugin's data directory. That needs `uv` or
`python3` on PATH; without either, provisioning fails loudly and secret-shaped
tool output is **suppressed** rather than shown unvetted.

## What it does

| Hook                   | Event            | Protection                                                                                                                                                                                    |
| ---------------------- | ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scan-invisible-chars` | SessionStart     | Scans `CLAUDE.md`, `AGENTS.md` and `.claude/` markdown for hidden-Unicode payloads; auto-cleans what it can                                                                                   |
| `sanitize-user-prompt` | UserPromptSubmit | Blocks prompts carrying payload-capable invisible Unicode or ANSI escapes (pasted SGR colour passes with a note)                                                                              |
| `pretooluse-sanitize`  | PreToolUse       | Normalizes confusable/homoglyph paths and commands, strips stego and terminal-control sequences from model-authored content, and re-anchors redacted Edit/Write inputs onto the on-disk bytes |
| `sanitize-output`      | PostToolUse      | Strips invisibles and ANSI, splices hidden HTML out of web/MCP ingress, flags exfil-shaped URLs, and redacts secrets via detect-secrets                                                       |

Every layer fails **closed** by default: when a check cannot run, the guarded
action is blocked, asked about, or its output suppressed — never passed through
unchecked. The launcher (`scripts/safe-launch.sh`) holds that line even when the
hook cannot start at all, because Claude Code treats a crashed hook as "no
objection". A deployment that would rather keep working than keep guarding flips
that posture with `AGENT_SANITIZER_FAIL_OPEN=1` (below).

## Configuration

Three opt-outs, for content the sanitizer would otherwise rewrite:

| Variable                               | Effect                                                             |
| -------------------------------------- | ------------------------------------------------------------------ |
| `AGENT_SANITIZER_INVISIBLE_DISABLED=1` | Keep invisible characters in model-authored content (i18n joiners) |
| `AGENT_SANITIZER_TERMINAL_DISABLED=1`  | Keep raw escape sequences (fixtures that must contain them)        |
| `AGENT_SANITIZER_OUTPUT_DISABLED=1`    | Both of the above                                                  |

And one posture knob, for when the sanitizer cannot run at all:

| Variable                      | Effect                                                                                                      |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `AGENT_SANITIZER_FAIL_OPEN=1` | A sanitizer that never RAN passes the guarded action through unsanitized instead of blocking (default: off) |

Set it and a missing `node`, a corrupt bundle or an uninstalled package stops
halting your session — the action proceeds and the model is told, in
`additionalContext`, that what it is reading was never sanitized.

The knob is deliberately narrow. It covers the sanitizer failing to **start**;
it does not cover a layer that ran and **threw**, because those throws are
composable by whoever authored the content: colliding field names, a tool
response nested deeply enough to overflow the walk, or enough secret-shaped
leaves to exhaust the redaction budget. Each of those is guarding something a
pass-through would hand the model verbatim, so they suppress in both postures —
as does an unparsable payload, and as do detection verdicts (a working sanitizer
that found an injection still blocks). The value must be exactly `1`;
`true`/`yes` leave the secure default in place.

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
scripts/safe-launch.sh       fail-closed launcher (prints a verdict even when node is missing)
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
