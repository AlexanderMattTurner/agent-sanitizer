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
complete sequence buys. OSC strings (titles,
clickable-hyperlink URLs) are consumed as a
whole, for every terminator form—ST (`ESC\` or 8-bit C1 ST U+009C) and the
legacy BEL—and for the 8-bit C1 OSC introducer (U+009D); an _unterminated_ OSC
introducer is dropped through end-of-string (fail-closed), so no OSC body
survives to carry a payload.

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

HTML comments (`<!--…-->`, and the bogus `<!…>`/`<?…?>` forms) are deliberately
**preserved byte-identical** — no splice, no placeholder, no warning. Comments
are ubiquitous in legitimate markdown/HTML (PR templates, tooling marker
comments), so splicing them corrupts real content: an agent that reads a
spliced body and writes it back persists the loss. And the splice was a weak
defense — a payload does not need comment syntax to hide from a human skimming
rendered output. Precision over recall: a comment-borne injection is instead
covered by Layer 3, which scans the **original** text (comments included) for
exfil-shaped URLs, and by the semantic Layer-5 filter, the right tool for
payloads carried in visible-in-source text.

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
caller suppresses the output rather than emit an unvetted value. Layer 5 is a
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

File access and the redactor are injected via `io`; the package performs no I/O
of its own and bundles no secret engine.

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
  Bash/MCP/unknown-tool input carrying a placeholder gets one PreToolUse
  context line explaining the hazard. It cannot tell a write from a read, so
  it never blocks.
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

## Failure posture (`AGENT_SANITIZER_FAIL_OPEN`)

Installed as Claude Code hooks, these fail **open**: a hook that could not
complete lets the guarded action through with a warning in `additionalContext`
rather than blocking the session. `AGENT_SANITIZER_FAIL_OPEN=0` (or `false`)
restores the fail-closed verdicts — block, ask, suppress. The posture covers
every way a hook can fail: the launcher not starting (no `node`, missing or
corrupt bundle), the package never loading, a payload that never parsed, and a
layer that ran and threw.

**The open default is not enforceable against content.** Several of those
failures are composable by whoever authored the payload — in the output hook
alone, the key-collision guard (two field names that collapse to one after
Layer 1), a nesting depth that overflows the sanitize walk, and a redaction
budget exhausted by many secret-shaped leaves. Under the open posture a tool
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
