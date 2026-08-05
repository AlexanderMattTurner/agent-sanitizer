# Threat model

`agent-sanitizer` defends the boundary where untrusted text enters an
agent-driven pipeline (agent tool output, RAG retrieval, fetched web pages). It is
a detect/neutralize layer, not an enforcement boundary: it makes hidden content
visible-or-gone and surfaces exfil-shaped URLs, so the model and the operator
see the same thing. Egress controls remain your enforcement layer.

The three layers are independent; use only the ones your ingress needs.

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

**Reassembly hardening.** Stripping an invisible char can reconstitute an ANSI
escape its split had hidden, and removing one ANSI sequence can reconstitute
another. Layer 1 strips ANSI to a fixed point and then sweeps any residual raw
control introducer—7-bit ESC (U+001B) or 8-bit C1 CSI (U+009B)—outright, so the
result carries no raw ANSI introducer for _any_ input and the operation is
idempotent. OSC strings (titles, clickable-hyperlink URLs) are consumed as a
whole, for every terminator form—ST (`ESC\` or 8-bit C1 ST U+009C) and the
legacy BEL—and for the 8-bit C1 OSC introducer (U+009D); an _unterminated_ OSC
introducer is dropped through end-of-string (fail-closed), so no OSC body
survives to carry a payload.

## Layer 2—hidden HTML (remark/rehype)

For web/HTML ingress, splice out exactly what a human viewing the rendered page
cannot see:

- `<!-- HTML comments -->`
- elements hidden by inline style: `display:none`, `visibility:hidden`,
  `content-visibility:hidden`, `opacity:0`, `filter:opacity(0)`, off-screen
  positioning, zero/negative sizes, `text-indent` off-screen, collapsing
  `clip`/`clip-path`/`transform:scale(0)`, white-on-white / transparent text,
  `overflow:hidden` with a zero dimension
- elements hidden by attribute: `hidden`, `aria-hidden="true"`

Spliced ranges are replaced with a placeholder; **every byte outside a spliced
range is preserved verbatim** (no re-serialization). Unclosed hidden markup
extends to the end of the fragment—fail-closed for truncated input.

Scripting/resource tags (`script`, `style`, `object`, `embed`, `iframe`, `svg`,
`math`) and `data:` URI resources are **reported, not removed**: their bodies are
page source the model may legitimately need to inspect.

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
payload-bearing query/fragment), suitable for a warning shown to the operator.

## Confusable folding (tool input)

`./confusables` folds look-alike glyphs in tool-call **input** fields (paths,
commands) to their ASCII canon. A denied path/command spelled in homoglyphs (a
Cyrillic `а` for ASCII `a`) would not match an ASCII deny rule; folding closes
that cross-script bypass (CVE-2025-54794 class).

Folding is gated per **token** (a maximal run of ASCII alphanumerics and
non-ASCII glyphs; every other ASCII character is a boundary): a token folds only
when doing so leaves it **pure ASCII**. The bypass requires the folded token to
come out byte-equal to an ASCII deny-rule target, so a token that still holds an
unmapped glyph after folding could not match one either way — skipping it
forfeits no enforcement. `/etc/pаsswd`, an isolated `/а` with no ASCII anchor,
and an all-Cyrillic `раѕѕwd` all still fold; `Привет` and `пароль.txt` pass
through untouched, because their unmapped letters (П/и/в/т, п/л/ь) survive any
fold. Without this gate the layer transliterated ordinary Cyrillic and Greek
text — a commit message, an issue body, a filename — into garbage, which this
repo weighs as the worse failure.

The gate is per-token and never per-field: a field-level "any prose here → skip
the field" rule would let an attacker switch folding off for a whole command by
appending one foreign word.

**Known false positive:** a short foreign word composed _entirely_ of mapped
confusables — the Russian `сор` → `cop` — is by construction indistinguishable
from a disguised ASCII token, and still folds.

The homoglyph engine
is **injected** (`{ scan }`)—the package owns no glyph map. An all-ASCII field
never invokes the scanner. This narrows a steganographic channel; it is not an
enforcement boundary (distinct code points would not match a deny rule anyway).

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
One carve-out: a prompt whose only escape content is display-only SGR color
passes with a note (pasting colored terminal output is the common case, and SGR
cannot move the cursor, erase, or carry an OSC payload). The SGR-only test
gates on both the 7-bit ESC (`U+001B`) introducer and the whole 8-bit C1
control block (U+0080–U+009F)—not just the CSI byte (`U+009B`)—so a
C1-introduced cursor-move, erase, or OSC/DCS/SOS/PM/APC string is never
mistaken for benign color.

## Tool-output pipeline & Layer 5

`./output` runs Layers 1–4 over structured tool output, **preserving its shape**
(a harness that gets a shape-mismatched value silently shows the raw output).
Layer 4 (secret redaction) is an **injected** redactor and is the one
fail-closed path: a redactor that throws makes the pipeline rethrow, so the
caller suppresses the output rather than emit an unvetted value. Layer 5 is a
deliberately thin, safe slot: the injected filter returns **verbatim spans to
delete** (never replacement text), so even a compromised filter can only remove
legitimate content—it can never inject bytes into the model’s view. A live
second-LLM injection filter is the caller’s to wire behind that contract.

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
