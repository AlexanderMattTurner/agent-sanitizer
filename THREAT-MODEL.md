# Threat model

`agent-sanitizer` defends the boundary where untrusted text enters an
agent-driven pipeline (agent tool output, RAG retrieval, fetched web pages). It is
a detect/neutralize layer, not an enforcement boundary: it makes hidden content
visible-or-gone and surfaces exfil-shaped URLs, so the model and the operator
see the same thing. Egress controls remain your enforcement layer.

Five sanitization layers are documented below — invisible characters/ANSI (1),
hidden HTML (2), exfil URLs (3), secret redaction (4, an injected redactor) and
injection filtering (5, an injected filter the caller wires) — plus the entry
points built on them: confusable folding, instruction-file scanning, the
user-prompt verdict and edit rehydration. All are independent; use only the ones
your ingress needs. The README's [entry-point
table](./README.md#entry-points) maps each to its import.

## Layer 1—invisible characters & ANSI (zero-dependency)

**What it removes**

| Category                   | Examples                                                                                                       | Why it’s a payload channel                                    |
| -------------------------- | -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| Format chars (`Cf`)        | zero-width space/joiner, bidi overrides, Unicode **tag** chars                                                 | render blank but reach the model as bytes; tags smuggle ASCII |
| Variation selectors        | U+FE00–FE0F, U+E0100–E01EF                                                                                     | not `Cf`; a run encodes a hidden payload                      |
| Blank-rendering fillers    | Hangul fillers U+115F/1160/3164/FFA0, Braille blank U+2800, zero-width combining marks (`Mn`) U+034F/17B4/17B5 | render blank, not `Cf`, so a naive `\p{Cf}` strip misses them |
| Soft hyphen / interior BOM | U+00AD, interior U+FEFF                                                                                        | either can encode hidden instructions                         |
| ANSI / SGR escapes         | `ESC[…m`, cursor moves, OSC                                                                                    | repaint or hide what an operator reads in a terminal          |

**What it preserves**

- A **single leading BOM** (a legitimate marker); interior BOMs are stripped.
- **ZWNJ (U+200C) / ZWJ (U+200D)** in genuine linguistic context: between two
  letters of a script whose orthography requires them (Arabic, Devanagari,
  Bengali, Gurmukhi, Gujarati, Oriya, Tamil, Telugu, Kannada, Malayalam,
  Sinhala) or inside an emoji ZWJ sequence. The carve-out fires only when **both**
  neighbors clearly belong to the context, and it is disabled once the total
  invisible count crosses a scatter floor—over-stripping beats under-stripping.
- **Blank fillers doing real work in their own script**: the Braille blank
  (U+2800) beside a real cell, a Hangul filler beside a real jamo/syllable. A
  _run_ of fillers has only fillers for neighbors, so it fails the anchor and is
  stripped. Because U+2800 _is_ the word space of Unicode Braille and a Hangul
  filler completes a defective syllable, these are far denser in genuine text
  than joiners are, so they carry their own document-wide allowance—one
  preserved blank per two visible anchor-script characters, above a floor—rather
  than drawing on the joiner/selector preserve budget. The allowance is counted
  per script (a blank never anchors cross-script, so Korean prose must not fund
  a Braille channel). Past that ratio no blank of that script is preserved
  (never half-spaced) and all of them count as payload, which is the density an
  alternating `syllable filler …` channel needs. Contracted (grade-2) Braille
  sits closest to the boundary: alphabet wordsigns are single cells, so a
  passage of mostly one-cell words approaches 1:1 and is stripped like the
  channel—an accepted residual false positive inherent to a density rule, not a
  gap, and not worth widening the ratio to reach.

**Reassembly hardening.** The two passes feed each other in _both_ directions:
stripping an invisible char can reconstitute an ANSI escape its split had
hidden, removing one ANSI sequence can reconstitute another, and removing an
ANSI sequence can make two invisibles adjacent that were not—a joiner run the
invisible pass treats as a payload channel rather than as linguistic. So Layer 1
does not run a fixed sequence of passes; it iterates the whole
{ANSI, invisible} composition to a fixed point (bounded, since each round
deletes at least one character), and only once that is stable does it sweep any
residual raw control introducer—7-bit ESC (U+001B) or any 8-bit C1 control
(U+0080–U+009F)—outright. Sweeping earlier would strand a hidden control as
visible text; a final unconditional sweep after the loop keeps the
no-raw-introducer guarantee independent of the iteration bound. The result
carries no raw ANSI introducer for _any_ input, and re-cleaning it reproduces
it exactly—the idempotence the Edit-repair rehydrator's soundness gate assumes.
One tokenizer answers every ANSI question (what to splice, and whether what was
removed was INERT—display-only SGR colour, or a lone 7-bit `ESC` that opened
nothing at all), so the stripper and the operator warning cannot disagree about
what a sequence is. That inert/injection-shaped split is one input to the
[severity tier](#severity-warnings-vs-notes) that keeps the warning worth
reading: a stray `ESC` sitting in a file is reported as a terse note, while
a cursor move, an erase, an OSC string, or a raw C1 introducer (which no
legitimate UTF-8 text carries, and which includes the DCS/SOS/PM/APC string
introducers) keeps the WARNING. An `ESC` that _opened_ a CSI it never completed
stays loud too: a terminal's CSI parser is stateful and keeps consuming what
follows until a final byte arrives, so `ESC[12 world` shows the human `orld`
while the model reads every word—the same model-sees/human-sees divergence a
complete sequence buys. All five ECMA-48 control strings—OSC (titles,
clickable-hyperlink URLs), DCS, SOS, PM and APC—are consumed as a
whole, for every terminator form—ST (`ESC\` or 8-bit C1 ST U+009C) and the
legacy BEL—and for the 8-bit C1 introducers (U+0090/0098/009D/009E/009F); an
_unterminated_ introducer is dropped through end-of-string (fail-closed), so no
string body survives to carry a payload. Every one of those bodies is
attacker-controlled text, which is why the introducer alone is not enough to
remove.

## Layer 2—hidden HTML (remark/rehype)

For web/HTML ingress, splice out hidden **elements** — markup a human viewing
the rendered page cannot see:

- elements hidden by inline style: `display:none`, `visibility:hidden`,
  `content-visibility:hidden`, `opacity:0`, `filter:opacity(0)`, off-screen
  positioning, zero/negative sizes, `text-indent` off-screen, collapsing
  `clip`/`clip-path`/`transform:scale(0)`, white-on-white / transparent text,
  `overflow:hidden` with a zero dimension
- elements hidden by attribute: `hidden` (`aria-hidden="true"` is **not**
  spliced — it removes an element only from the accessibility tree; a sighted
  human still sees it on the rendered page)

Spliced ranges are replaced with a placeholder; **every byte outside a spliced
range is preserved verbatim** (no re-serialization). Unclosed hidden markup
extends to the end of the fragment—fail-closed for truncated input.

Scripting/resource tags (`script`, `style`, `object`, `embed`, `iframe`, `svg`,
`math`) and `data:` URI resources are **reported, not removed**: their bodies are
page source the model may legitimately need to inspect.

HTML comments (`<!--…-->`, and the bogus `<!…>`/`<?…?>` forms) are spliced
like hidden elements — a human viewing the rendered page never sees them. But
comments are also ubiquitous in _legitimate_ markdown/HTML (PR templates,
tooling marker comments), so a destructive splice corrupts real content: an
agent that reads a spliced body and writes it back persists the loss. Every
Layer-2 splice is therefore **round-trippable**: the placeholder carries a
content-addressed key (`[HTML comment removed #<key>]`, `[hidden HTML removed
#<key>]`, key = first 12 hex chars of the original bytes' SHA-256), the result
exposes the vetted originals in `splices`, and the hook layer persists each
original beside the reveal sidecar and restores it when the model writes the
placeholder back through Edit/Write. The model never sees the hidden content;
the bytes are never lost. A comment-borne injection is additionally covered by
Layer 3, which scans the **original** text (comments included) for
exfil-shaped URLs.

## Layer 3—exfil URLs (detection only)

Report—never rewrite—URLs in markdown links/images/definitions and HTML
attributes (`src`/`href`/`background`/`srcset`/`ping`, form `action`/`formaction`,
`meta refresh`) that are shaped to carry data off-origin:

- suspicious query/fragment parameters (long base64/hex blobs, credential-shaped
  tokens), tuned to skip request-signing / pagination / analytics parameters
  that are legitimately long (`X-Amz-*`, SAS, `cursor`, `utm_*`, `gclid`, …)
- oversized or active-content (`text/html`, `image/svg+xml`, JS) `data:` URIs
- embedded `user:password@host` credentials
- unusually long query strings or fragments
- encoded-data blobs smuggled in a path segment (a beacon that avoids the query)
- off-origin form actions and `meta refresh` redirects
- `javascript:` / `vbscript:` targets

Each threat carries a `reason` and the destination `target` (never the
payload-bearing query/fragment) — the finding is shown to the operator with the
target named and the payload withheld, since re-presenting the exfil payload in
the model's context would hand the model the very bytes the finding is about.

It also carries `autoFetched`, which is what its [severity](#severity-warnings-vs-notes)
turns on: an `<img src>`, a stylesheet `<link>`, a `srcset`, a `ping`, a form
`action` or a `meta refresh` exfiltrates the moment the content renders, with
nobody deciding anything, while an `<a href>` or a markdown link cannot until
the model chooses to follow it — and the sentence reporting it is precisely the
instruction not to. A target whose kind cannot be resolved is treated as
auto-fetched (fail closed).

## Layer 4—secret redaction (injected engine)

The threat is the reverse of the other layers: not attacker text reaching the
model, but a credential in tool output (a `.env` cat, a failing curl, a CI log)
reaching a model that will paste it into the next tool call, a commit, or a
bug report.

**The package bundles no detector.** Layer 4 is an injected
`redact(text) => {text, found, note?} | null` callback on `./output`, so the npm
package ships no secret engine and a host may supply its own. The Claude Code
plugin injects the Python engine from `agent-sanitizer[secrets]`
(`python/agent_sanitizer/secrets/engine.py`) over a local daemon;
`plugin/scripts/provision-redactor.sh` installs it at SessionStart.

**It is the one fail-closed layer.** A redactor that throws — unreachable
daemon, engine error — is rethrown from `sanitizeValue` as `CRITICAL: secret
redaction failed …` (`src/output.mjs`), so the caller suppresses the output
rather than emit a value nothing vetted. That is distinct from an engine that
was never provisioned: there the hooks' posture applies, passing the output
through with a loud warning by default and suppressing it under
`AGENT_SANITIZER_FAIL_OPEN=0`. Either way the gap is announced, never silent.

**Lone surrogates are normalized to U+FFFD before the redactor sees the text.**
A secret split by an interposed lone surrogate renders as contiguous to the
model but arrives broken at the redactor, so without normalization a
reconstituted secret survives redaction. Both redact-input paths share one
normalizer so they cannot drift.

**Detection.** detect-secrets is the single oracle — its bundled plugins plus
gitleaks-sourced ones for formats it lacks — extended with a regex
for the unquoted `key=value` shapes the keyword detector misses, PEM block
collapse, cross-line reassembly of a secret split across lines, and exact-match
redaction of caller-supplied env-var **values**. Each hit becomes
`[REDACTED: <label>]` and its label joins `found`.

**The engine discovers nothing about its environment.** Every
environment-specific input — which env-var values to redact, the invisible
charset, whether the text is web ingress — arrives through `RedactorConfig`; the
engine never reads `os.environ`. Passing values rather than names is
load-bearing for the daemon, which serves many sessions and must redact the
_requester's_ keys. The invisible charset is sourced from the same SSOT Layer 1
uses (and raises if that dependency is missing rather than silently using a
partial set): a key spliced with a code point one layer omits would otherwise
escape both.

**Precision over recall, deliberately.** Redacting a UUID, a content digest, a
timestamp, a version, a filesystem path, a public endpoint URL, a `$VAR`
reference, a documentation placeholder or a markdown code span would delete text
the model needed, so each is filtered out before redaction, and an env value
shorter than `min_secret_len` (16) is treated as a test stub rather than a key.
Two config switches move the trade-off where the context justifies it:
`web_ingress` disables the name-based benign skips for attacker-controlled text,
and `high_confidence` drops the fuzzy keyword/field-value detectors for source
scans, where secret-shaped names appear legitimately.

**Redaction stays reversible for editing, never for the model.**
`redact_map` returns placeholder ↔ original pairs with offsets, which
`./rehydrate` uses to re-anchor a model `Edit` composed from the redacted view
back onto the real bytes. If the input already contains the private-use
sentinels the map machinery reserves, it returns `{"unmappable": …}` rather than
risk mis-pairing a placeholder with the wrong secret.

**Ordering.** Layer 4 runs after Layers 1–2 have removed bytes, and is re-run on
the post-deletion text whenever Layer 5 deletes a span — a deletion can
reconstitute a secret the first pass never saw intact. On `Bash.command` it runs
before `sanitizeAuthoredContent`, which is the assumption the confusable-folding
soundness argument below relies on.

## Confusable folding (tool input)

`./confusables` folds look-alike glyphs in tool-call **input** fields (paths,
commands) to their ASCII canon. A denied path/command spelled in homoglyphs (a
Cyrillic `а` for ASCII `a`) would not match an ASCII deny rule; folding closes
that cross-script bypass (CVE-2025-54794 class).

Folding is gated per **token** — a maximal run of ASCII alphanumerics and
non-ASCII glyphs, with every other ASCII character a boundary. A token folds only
when both hold:

1. **Folding leaves it pure ASCII.** The bypass requires the folded token to come
   out byte-equal to an ASCII deny-rule target, so a token that still holds an
   unmapped glyph after folding could not match one either way — skipping it
   forfeits no enforcement.
2. **It is more than a lone non-ASCII glyph.** A single-code-point token is a
   one-letter foreign word — Russian `с` (with), `о` (about), `у` (at), `а`
   (and), all mapped confusables and all among the most frequent words in the
   language — as readily as it is a disguised argument, and no deny rule targets
   a single character.

So `/etc/pаsswd` and an all-Cyrillic `раѕѕwd` still fold, while `Привет`,
`пароль.txt`, and `работа с файлом` pass through untouched. Without this gate the
layer transliterated ordinary Cyrillic and Greek text — a commit message, an
issue body, a filename — into garbage, which this repo weighs as the worse
failure.

The gate is per-token and never per-field: a field-level "any prose here → skip
the field" rule would let an attacker switch folding off for a whole command by
appending one foreign word.

**Known false positive:** a multi-letter foreign word composed _entirely_ of
mapped confusables — the Russian `сор` → `cop`, `со` → `co` — is by construction
indistinguishable from a disguised ASCII token, and still folds.

**Known false negative:** splicing one unmapped non-ASCII glyph into an otherwise
all-confusable token switches its fold off. It buys an attacker nothing on its
own — the unmapped glyph is still in the field, so the token cannot match an
ASCII deny rule either. A filter reading the raw field is what closes that, not
folding.

The soundness argument assumes no later layer erases code points from the same
field, which could remove an unmapped glyph the gate relied on after the decision
was made. Layer 4 runs before `sanitizeAuthoredContent` on `Bash.command`.

The homoglyph engine is **injected** (`{ scan }`) — the package owns no glyph
map. An all-ASCII field never invokes the scanner. This narrows a steganographic
channel; it is not an enforcement boundary (distinct code points would not match
a deny rule anyway).

## Instruction-file scanning

`./instructions` scans the markdown that loads as model context (`CLAUDE.md`,
`AGENTS.md`, `SKILL.md`, any `.claude` markdown—a **caller-supplied glob
set**), which bypasses a tool-output sanitizer entirely. It flags long invisible
runs, decodes the two common smuggling encodings (Unicode **tag** characters →
ASCII, zero-width **binary**), and catches scattered payloads below the long-run
threshold. `cleanFile` strips the payload in place (Layer-1 strip), failing loud
if a contaminated file cannot be rewritten.

As Claude Code hooks the coverage is split to match how Claude Code loads these
files, and `src/claude-context.mjs` is where the split is defined: one table of
context KINDS, each row naming what loads it and when.

- **SessionStart** (`scan-invisible-chars`) scans the launch set — the project
  root's own instruction files, the `CLAUDE.md` chain above it, and the root
  `.claude/` context subdirectories. O(directory depth), not O(tree).
- **InstructionsLoaded** (`scan-loaded-instructions`) scans each file the host
  names as it loads it: the rows marked `eventNamed` — the `CLAUDE.md` family
  and `.claude/rules` — wherever they sit, including the user-global `~/.claude`
  memory and rules that load into every session on the machine.
- **Everything else** — a nested `AGENTS.md`, a nested `.claude/` skill,
  command or output-style — is covered on demand by the whole-tree
  `CLAUDE_INSTRUCTION_GLOBS` scan (what the CLI walks) and by the PostToolUse
  sanitizer when a tool reads one. Covering those eagerly means the whole-tree
  walk at session start that this split exists to remove.

The lazy half cannot block: the file is already in context when it fires, so its
neutralization is to strip the payload from disk (so no reload re-reads it) and
tell the model to treat what it just read as untrusted data. Auto-cleaning is
confined to `CLAUDE_PROJECT_DIR` in both — an ancestor file, or one under
`~/.claude`, is shared with every other project on the machine, so it is reported
through the cross-hook alert and never rewritten. Three things lose the lazy half
entirely: a host that never wired the `InstructionsLoaded` event to
`scan-loaded-instructions`, a Claude Code build that does not emit that event,
and `scan-loaded-instructions` switched off in `AGENT_SANITIZER_DISABLED_HOOKS`.
Nothing on disk tells them apart, so the PreToolUse gate names all three, once
per session, rather than leaving the gap silent.

That table is a claim about someone else's product, so the event that names a
loaded file is also what falsifies it. `contextScopeContradiction` checks every
path the hook is handed and reports two observations: context loading out of a
`.claude/` subdirectory the whitelist does not carry (the launch scan prunes
that directory, so every other file in it is unscanned), and a kind marked
event-blind arriving through the event anyway (the lazy scan reaches further
than the table, and this section, credit it with). Everything else is silent, in
both directions: a path the table does not name — an `@import` of arbitrary
markdown — reports nothing rather than guessing, and a directory it names as
storage (`worktrees/`, `projects/`) reports nothing because whitelisting storage
is the whole-tree walk again. Both observations also require a `load_reason` the
host chose itself: an `@import` names a file the user's own markdown pointed at,
which says nothing about what a scan would reach on its own. The
notice never widens the scan on its own — one load cannot tell a context
directory from an import target, and whitelisting the wrong one buys back the
startup cost this split removed — so the whitelist stays hand-maintained and the
notice's job is to put a stale entry in front of a person.

## User-prompt verdict

`./prompt` classifies a submitted prompt as **pass / pass-with-note / block** on
payload-capable invisible Unicode and ANSI. A prompt-submission channel usually
cannot rewrite the prompt in place, so the only neutralization is to block.
One carve-out: a prompt whose only escape content is INERT passes with a note —
display-only SGR color, and/or a 7-bit `ESC` that completes no sequence (a log
line cut mid-escape). Pasting colored terminal output is the common case, and
neither form can move the cursor, erase, or carry an OSC payload. The test gates
on both the 7-bit ESC (`U+001B`) introducer and the whole 8-bit C1 control block
(U+0080–U+009F)—not just the CSI byte (`U+009B`)—so a C1-introduced cursor-move,
erase, or OSC/DCS/SOS/PM/APC string is never mistaken for benign color; and it
judges from what the Layer-1 strip actually removed, so a sequence that only
RECONSTITUTES during stripping is judged as the sequence it becomes.

## Tool-output pipeline & Layer 5

`./output` runs Layers 1–4 over structured tool output, **preserving its shape**
(a harness that gets a shape-mismatched value silently shows the raw output).
Layer 4 (secret redaction) is an **injected** redactor and is the one
fail-closed path: a redactor that throws makes the pipeline rethrow, so the
caller suppresses the output rather than emit an unvetted value. In the Claude
Code hooks the entire secret layer is **opt-in**: `secretsEnabled()`
(`claude-hooks/lib/env-config.mjs`) reads `AGENT_SANITIZER_SECRETS_ENABLED=1`,
and every secret-layer guarantee below — Layer-4 redaction, rehydration, the
placeholder guards, the placeholder-write carve-out, SessionStart engine
provisioning — is conditional on that knob being set; unset, no redactor is
spawned and no placeholders enter the model's view, because the layer's denies
and asks are friction an operator must ask for. Layer 5 is a
deliberately thin, safe slot: the injected filter returns **verbatim spans to
delete** (never replacement text), so even a compromised filter can only remove
legitimate content—it can never inject bytes into the model’s view. That removal
is bounded to the spans the filter actually named: every span is matched against
the **original** text and the deletions applied in a single ordered pass, so an
earlier deletion cannot join two kept regions into a match for a later span and
erase text neither span occurred in. A live second-LLM injection filter is the
caller’s to wire behind that contract.

The same "never inject" property governs the filter’s `warning`: it is a
**closed enum code** (`FILTER_WARNING`: `spans-removed` / `filter-flagged` /
`filter-error`), and the **library**—not the filter—owns the human-readable
string each code maps into `warnings`. This closes a seam the delete-only span
contract left open: `warnings` is concatenated into the model-facing context
**without** re-running Layer 1, so a compromised or prompt-injected filter that
could return free-text `warning` would smuggle attacker bytes straight to the
model. A filter that returns any value outside the enum makes the pipeline
**throw** (fail loud), exactly as an unrunnable Layer-4 redactor does—no
filter-supplied byte (span or warning) ever reaches the model’s view.

## Edit-repair / rehydration

Sanitizing the model’s view of a file makes that view diverge from disk: Layer 1
deletes invisible/ANSI runs, and Layer 4 replaces secrets with `[REDACTED…]`
placeholders. An Edit whose `old_string` was copied from that view then fails
exact-match, and a whole-file Write would persist the placeholder over the real
secret—so a sanitizer _without_ rehydration silently breaks editing.
`./rehydrate` (offset machinery in `./view-map`) re-derives the sanitized view,
locates the model’s `old_string` in it, and maps it span-exact back to the
on-disk bytes across both placeholder expansion and stripped invisible runs,
substituting placeholders in `new_string` with the real secrets. Two invariants
are load-bearing and **fail closed**:

- **Never mis-anchor.** Greedy deletion alignment is ambiguous when a stripped
  run abuts kept text it resembles; any call that does not re-clean back to the
  span’s view, matches multiple view locations, or cuts through a placeholder is
  **denied** with an instructive reason rather than edited at a guessed anchor.
- **Never expose a secret this call rehydrated.** Before rewriting, the
  would-be post-edit content is re-sanitized (Layer 1 + the injected
  redactor); if any secret THIS EDIT resolved from a placeholder would survive
  in the model’s next view (e.g. an edit whose `old_string`/`new_string`
  carries a placeholder and relabels a field the redactor no longer
  recognizes), the call is **denied**. This check only runs when the edit
  touches a placeholder — a relabel that never names one (e.g. `password=` →
  `notes=` with no `[REDACTED…]` in either string) is an accepted scope gap,
  not covered here: simulating full-file exposure on every relabel-adjacent
  edit would re-run redaction on every `Edit` call and risk false denials on a
  legitimate relabel in a large file. The secret flows disk → tool input only;
  the model’s next view is sanitized again.
- **Never trust the redactor’s map unverified.** The redactor’s map-mode output
  is validated before any splice: every pair’s placeholder must occupy the view
  text at its stated offset, and splicing the originals back must reconstruct
  the file’s cleaned bytes exactly — out-of-range and overlapping pairs are
  caught too. A map that fails either proof is **denied outright** — for every
  tool and hint state, stricter than the honest-unmappable arm — and never
  thrown into the host’s fail-open posture: unlike an engine reporting it
  cannot map, a validated-wrong map is affirmative evidence the engine is wrong
  about where this file’s secrets sit, so neither a splice nor a raw
  pass-through (the R1 hidden-span oracle) can be vetted against it.

MultiEdit is gated, not rehydrated. MultiEdit applies its edits sequentially,
each against the file state the previous edit produced, so the span-exact
view↔disk mapping done for a single Edit has no sound equivalent. It passes
through only when the file’s sanitized view provably equals disk AND no edit
carries a `[REDACTED…]` placeholder; every other case — a view that diverges via
redacted secrets or stripped invisible characters, an unmappable or defective
redactor map, or placeholder text aimed at a pristine file (the
foreign-placeholder rule) — is **denied**, with guidance to re-issue the changes
as single Edit calls, which _are_ rehydrated. The previous full pass-through was
both a silent clobber (the placeholder persisted over the secret) and a
character-extraction oracle.

File access and the redactor are injected via `io`; the package performs no I/O
of its own and bundles no secret engine.

**Whole-file Writes are re-anchored too.** A model that reads a file whose
legitimate content includes stripped characters (ANSI-colored logs, zero-width
runs, a lone surrogate) and writes it back would otherwise silently persist the
stripped version. Every well-formed `Write` to an existing file is diffed
against the sanitized view by position (longest common prefix/suffix, snapped
off placeholder and surrogate boundaries): the unchanged regions are restored
to their exact on-disk bytes — stripped runs and redacted secrets included —
while the genuinely-changed middle keeps the model's bytes (Layer-1 strips of
_new_ text stay stripped; that is the sanitizer working). Each restored region
passes the same re-clean soundness gate as an Edit span. On gate failure the
outcome follows the precision doctrine: a placeholder-free region falls back to
the model's bytes (**fail open** — the write merely loses stripped characters,
exactly the pre-restoration behavior), while a placeholder-bearing region is
**denied** (restoring at a misattributed anchor could graft secret bytes
wrongly; not restoring persists placeholder text over the secret — neither open
option is safe). An empty view (an all-invisible file, the archetypal
hidden-payload artifact) is never restored: a Write there is the model
replacing content it was told is suspicious, not echoing it back.

`MultiEdit` is a rehydration candidate but never re-anchored: its edits apply
sequentially, each against the result of the previous, which the span machinery
(one `old_string` against one static view) cannot model. A MultiEdit against a
file whose view equals disk passes through untouched (the common case); one
against a divergent file is **denied** with use-single-Edit guidance — an
unguarded pass-through there would be both a silent clobber and the same
extraction oracle the Edit path's hidden-span rule closes.

## Placeholder-clobber guards (hooks layer)

Rehydration re-anchors only Edit/Write, so every other write path — a shell
heredoc, `sed -i`/`tee`, an MCP file tool — persists a copied `[REDACTED…]`
placeholder literally, destroying the secret it stands for; and a Write that
simply **drops** a secret line never carries a placeholder at all. The Claude
hooks close these around the package's core, favoring precision (a false
positive costs a sentence of context, never a mangled input):

- **Grammar, not prefix.** Detection matches the exact placeholder language
  (`claude-hooks/lib/placeholder-grammar.mjs`, mirrored from the Python
  producer `placeholders.py` and pinned to it by a contract test), never the
  bare `[REDACTED` prefix — `grep "\[REDACTED"` and `[REDACTED…]` prose are
  not placeholders. It lives in the hooks layer, not the engine, so the
  plugin's pinned-engine bundle ships it immediately.
- **Doctrine at redaction time.** The Layer-4 warning that introduces
  placeholders into the model's view now states that they rehydrate only via
  Edit/Write — removing the information asymmetry that made the shell
  route-around an honest mistake.
- **Advisory on non-rehydrated tools (context-only, never a verdict).** A
  Bash/MCP/unknown-tool input carrying a placeholder gets PreToolUse context
  explaining the hazard. It cannot tell a write from a read, so it never
  blocks. The advisory **names what it found**: each distinct placeholder
  token and the dotted input field carrying it (capped, with an "and N more"
  tail). The two grammars have their own advisory each, so that the secret
  layer's env opt-in cannot also silence the Layer-2 one: the keyed splice
  placeholders (`[HTML comment removed #<key>]`, `[hidden HTML removed
#<key>]`) and the un-keyed `[HTML unparseable — withheld]` marker are
  mirrored from `src/html.mjs` into the hooks layer for the same bundle-pin
  reason as the redaction grammar. Each grammar carries its own recovery route:
  for a secret, use Edit/Write on the file that owns it, or have a shell
  command read the value from that file — and for content bound for an external
  service (a PR body, a comment) do **not** reconstruct the secret, since that
  publishes it. For a keyed splice placeholder, the advisory names the
  `span-<key>.txt` file holding the original bytes (Edit/Write restores it
  automatically); for the un-keyed unparseable marker there is no per-splice
  original, so it points at the reveal sidecar the sanitize-time warning named.
  Read either (untrusted), reconstruct the content, and re-issue the call
  without the marker.
- **No direct substitution, and no per-tool substitution allowlist.**
  Rehydrating placeholders into a non-Edit/Write input was evaluated and
  rejected in both grammars, so the advisory is the whole mechanism. Splicing a
  secret into an MCP body field would publish it to an external service —
  exfiltration by construction — and PreToolUse has no placeholder→secret map
  without a named owning file. Layer-2 placeholders ARE keyed, so
  marker→original is recoverable — but only Edit/Write substitutes it:
  splicing the stored bytes into a shell command or an arbitrary MCP payload
  risks quoting/injection breakage, and for the un-keyed unparseable marker
  there is no per-splice original to substitute at all.
- **On-disk tripwire (warning-only).** A `Read` whose RAW bytes — before this
  session's redaction — already contain placeholder text warns that an earlier
  write may have clobbered a secret. Detection rides the read, the one choke
  point every write path (including other agents) eventually crosses; reveal
  sidecars are excluded, since their bytes are redacted before persisting.
- **Clobber-by-omission confirm (`lib/secret-drop-guard.mjs`).** A Write to an
  existing, **git-untracked** file (no git recovery path — `.env` and its kin,
  or a file outside any repository) whose redacted secrets vanish from the
  final, post-rehydration content is denied once with the reason; re-issuing
  the identical Write confirms and passes. The confirmation is the model's
  deliberate retry — never a human permission prompt — held as a
  consumed-on-use, TTL-bounded sentinel (keyed to path + content + the dropped
  values) via the same squat-resistant `$TMPDIR` helpers as the invisible-char
  gate. Tracked files, secret-free files, failed git probes and unmappable
  views all skip the guard (fail open). "Tracked" approximates "recoverable":
  an uncommitted secret line on a tracked file is an accepted gap — the
  committed content survives, and probing index-vs-worktree state would trade
  precision for recall.

## Severity: warnings vs notes

Findings come back split into two tiers, and the split is a security property in
its own right — a detector whose banner fires on every ordinary page teaches its
reader to skip the banner, and then the one that mattered scrolls past with it.

| Tier        | Means                                                                                                                                                      |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **WARNING** | This text is injection-shaped: something was hidden from a human reader, something a payload would have used was removed, or a secret was redacted.        |
| **NOTE**    | This happened, and here is how to look at it, but nothing about it is attack-shaped: incidental bytes, or content that was PRESERVED and merely described. |

The tier never changes what the pipeline **does**. The same bytes are stripped,
spliced and redacted either way, and a note is still reported — all that rides on
it is which banner the operator sees. That asymmetry is why a note is the right
answer whenever the evidence is thin: an under-loud true finding is still
delivered, while an over-loud false one costs the channel its credibility.

Four decisions currently land at NOTE:

- **An incidental Layer-1 strip** — inert ANSI (display-only SGR colour, or a
  lone `ESC` that opened nothing) together with too few invisible characters to
  spell anything. Both axes must be incidental; a cursor move, an erase, an OSC,
  a raw C1 introducer or a payload-length run of invisibles keeps the WARNING.
- **A preserved scripting/resource tag** (Layer 2) — nothing was removed and
  nothing was hidden, and a `<script>` is on essentially every page ever fetched.
  The Layer-2 **splice** stays a WARNING: those bytes were invisible to a human
  reading the rendered page.
- **An exfil-shaped URL that is not auto-fetched** (Layer 3) — see above.
- **The prompt gate's inert-escape carve-out**, which predates the tier and is
  the same judgement (see [User-prompt verdict](#user-prompt-verdict)).

Layer 4 (a redacted secret) and Layer 5 (a filter finding) are always WARNINGs.

The Layer-1 downgrade is gated on the caller asserting first-party ingress
(`sgrCarveOut` in `./output`, set for local tool output). Without it — the
`./sanitize` door, a fetched page, an MCP connector — Layer 1 stays loud however
few the bytes, because that is the channel where a hidden character was _put_
there. The `sgrNote` flag on a `./output` result means "nothing here rose above a
note", so a caller can show the quiet line instead of the banner; one warning
anywhere in the walk clears it.

## Provisioned hook binary (supply chain)

The hooks can run from a self-contained executable compiled with
`bun build --compile`, so a session whose `PATH` has no node at all still
sanitizes (see `plugin/scripts/provision-hook-binary.sh`). That is the
product's only path that fetches an executable over the network and later runs
it, so what anchors its trust is worth stating exactly.

- **The anchor is in the repo, not on the wire.** `plugin/dist/hooks/hook-binaries.sha256`
  is committed, and the SessionStart provisioner refuses to install any download
  that does not hash to the digest it pins for that platform. A compromised or
  substituted release asset alone therefore cannot be installed: it fails the
  comparison, is deleted, and the launcher keeps degrading loudly through node.
- **What the digest is worth rests on the compile being reproducible.** The
  committed digests are generated from the committed bundle, and CI recompiles
  and byte-compares them (`build-hook-binaries.mjs --check`), so a manifest that
  does not describe the bundle in the same commit fails before release.
- **Not covered: an attacker who can write BOTH the repository and the release.**
  There is no signature; the manifest is trusted because it arrives through the
  same reviewed, gated path as the rest of the plugin. Rewriting it is rewriting
  the plugin, which is outside this boundary.
- **Not covered: re-verification at exec time.** The digest is checked once, at
  install. The launcher then execs
  `${CLAUDE_PLUGIN_DATA}/hook-binary/agent-sanitizer-hooks` on every hook
  invocation without re-hashing it — that would cost a ~100 MB read per tool
  call. Anything able to write inside `CLAUDE_PLUGIN_DATA` can therefore run
  code in the session, which is why the provisioner creates that directory mode
  700 and installs the binary mode 700. A user-owned data directory is the
  assumption; a shared or world-writable one is not supported.
- **Opting out.** `AGENT_SANITIZER_HOOK_BINARY=0` never downloads and never
  runs a binary, leaving the node path exactly as it was.

## Failure posture (`AGENT_SANITIZER_FAIL_OPEN`)

Installed as Claude Code hooks, these fail **open**: a hook that could not
complete lets the guarded action through with a warning in `additionalContext`
rather than blocking the session. `AGENT_SANITIZER_FAIL_OPEN=0` (or `false`)
restores the fail-closed verdicts — block, ask, suppress. The posture covers
every way a hook can fail: the launcher finding no runtime (no `node`, and the
provisioned hook binary missing, unexecutable or failing without a verdict),
a missing or corrupt bundle, the package never loading, a payload that never
parsed, and a layer that ran and threw.

One carve-out: when the PreToolUse hook itself fails (redactor daemon down,
package failed to load, a layer threw) and the call is a **write-shaped tool**
(Write/Edit/MultiEdit/NotebookEdit) whose input carries the `[REDACTED`
placeholder prefix, the hook **asks** — fail-closed, human in the loop — instead
of passing through. With the sanitizer down, rehydration cannot run, so the
placeholder text would be persisted literally over the real secret on disk: a
destructive clobber, not a missed scan. Holding these calls is safe because a
placeholder-bearing write is never the benign availability case the open default
protects — the model can retry once the sanitizer recovers, or ask the user. The
check is package-free (a literal-string test on the already-parsed payload), so
it holds even when the failure IS the missing package. Two accepted gaps: a
launcher-level failure (no `node`, corrupt bundle, a provisioned hook binary
that is missing, unexecutable or dies without a verdict) never reaches the
check — the launcher cannot inspect the payload and always warns — and `Bash`
is excluded even though shell redirection can also persist placeholder text,
because command strings mention `[REDACTED` benignly far too often for the ask
to hold precision. All other faults keep the open default, and
`AGENT_SANITIZER_FAIL_OPEN=0` behavior is unchanged.

**The open default is not enforceable against content.** Several of those
failures are composable by whoever authored the payload — in the output hook
alone, a nesting depth that overflows the sanitize walk and a redaction budget
exhausted by many secret-shaped leaves. (A **key collision** — two field names
that collapse to one after Layer 1 — used to be on that list. It no longer
fails the hook at all: only the colliding fields are withheld, and every sibling
field survives. Both colliding values are replaced **whole** by a marker string,
not walked leaf-wise: a shape-preserving walk rewrites only string leaves, so a
colliding number or boolean would reach the model verbatim under a legitimate
field name while the warning claimed it was withheld. That changes the field's
JSON type, which is accepted because a duplicate name is off-schema by
construction; what the harness's shape check turns on — the object's field
COUNT — is kept by giving the second field a disambiguated name. A hostile connector can
therefore cost the model the colliding fields, never the whole tool output, and
the withholding is posture-independent — it is a per-field fail-closed, not a
hook failure.) Under the open posture a tool
response crafted to provoke one is shown to the model verbatim, secrets
included. So an attacker who controls tool output has a route past these layers
whenever the default is left in place, and the mitigation is the knob, not a
narrower failure classification: `=0` closes all of it.

That trade is deliberate, and it is scoped to the Claude Code plugin. The
library's own fail-closed entry points are unchanged and knob-blind —
`failClosedFields` in `claude-hooks/pretooluse-sanitize.mjs` and `emitFailClosed`
in `claude-hooks/sanitize-output.mjs` — so a host that wires those directly (as
`test/downstream-parity.test.mjs` shows) keeps strict failure semantics by
construction, with no env var to remember and none an agent could set for it.

Two things the posture does NOT reach, in either direction:

- **Detection verdicts.** It speaks only to the hook FAILING; a working
  sanitizer that found an injection blocks under both settings.
- **An unknown `--hook=` mode**, which still exits 2. That is static wiring
  corruption, and passing it through would mean no hook ever runs — silently,
  for the life of the install.

The knob is operator configuration read from the process environment, so
anything that can set it for a session — `.claude/settings.json`'s `env` block,
a shell rc file, `direnv` — can also set it the other way, and a prompt-injected
agent with edit access to those files is such a thing. That is not a regression
under an open default (there is nothing for it to disarm), but it does mean `=0`
is only as durable as the files carrying it.

The knob adds no layer and changes no layer's semantics. Ambiguous input still
fails open at the detection level (precision over recall), as it always has —
that is a separate, and unrelated, sense of the phrase.
