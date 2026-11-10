"""Property tests for the public contract (acceptance criteria).

Invariants, over text woven from visible runs, real secret tokens, invisible
chars, and newlines:

* idempotence — redacting twice equals redacting once;
* subsequence — the redacted text with the produced placeholders removed is a
  subsequence of the input (redaction only deletes/relabels, never invents
  visible content);
* rehydration round-trip — substituting each map pair's original at its offset
  reconstructs the input byte-for-byte;
* wrapped-token exactness — a known token wrapped across lines amid benign
  lines redacts whole, and every character outside it survives verbatim.
"""

import base64
import re

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from agent_sanitizer.secrets import RedactorConfig, redact, redact_map
from agent_sanitizer.secrets.engine import _WORD_EVIDENCE_LEN, _is_word_shaped
from redactor_helpers import reconstruct

# A configured env-bound value, exercised by weaving it into the text too.
_ENV_VALUE = "qZ7vK2mNp9rT4wX1cY6bA8dF3gH5jL0e"
_CONFIG = RedactorConfig(provider_vars={"VENICE_INFERENCE_KEY": _ENV_VALUE})

# Fragments the generator samples: benign words, real secret-shaped tokens (so
# redaction actually fires), assignment context, invisibles, and separators.
_FRAGMENTS = [
    "hello",
    "world ",
    "config value",
    " = ",
    ": ",
    "\n",
    "\t",
    "password: ",
    "api_key=",
    "AKIA" + "IOSFODNN7EXAMPLE",
    "sk_live" + "_4eC39HqLyjWDarjtT1zdp7dc",
    "ghp_" + "0123456789abcdefghijklmnopqrstuvwxyz",
    "q9X2mN7pK4rT8wY1cV5bZ3dF6gH0jL2e",
    _ENV_VALUE,
    "​",  # zero-width space
    "­",  # soft hyphen
    "next_token=abcdefghij1234567890XYZ",
    "-----BEGIN PRIVATE KEY-----\nMIIBVg\n-----END PRIVATE KEY-----",
]

# Reserved sentinel code points make a map request unmappable by design; the
# generated fragments never include them. Each fragment is followed by a space or
# by nothing, so secrets are also glued directly onto a neighboring run — the
# shape where a field value would run on into a detected secret's map sentinel
# (one such case is pinned in test_glued_secret_corner_round_trips).
_text = st.lists(
    st.tuples(st.sampled_from(_FRAGMENTS), st.sampled_from(["", " "])), max_size=25
).map(lambda parts: "".join(fragment + sep for fragment, sep in parts))
# Idempotence is asked of space-separated text only. A token glued word-internally
# onto another (`AKIA…EXAMPLEghp_…`) is refused by its boundary lookbehind, and
# the first pass's placeholder (`…]ghp_…`) then hands it the boundary, so a
# second pass redacts more than the first.
_spaced_text = st.lists(st.sampled_from(_FRAGMENTS), max_size=25).map(" ".join)


def _is_subsequence(sub: str, full: str) -> bool:
    it = iter(full)
    return all(ch in it for ch in sub)


@settings(max_examples=250, deadline=None)
@given(_spaced_text)
def test_redaction_is_idempotent(text):
    once, _ = redact(text, _CONFIG)
    twice, _ = redact(once, _CONFIG)
    assert twice == once


@settings(max_examples=250, deadline=None)
@given(_text)
def test_map_mode_round_trips(text):
    view = redact_map(text, _CONFIG)
    assert "unmappable" not in view
    assert reconstruct(view) == text


@settings(max_examples=250, deadline=None)
@given(_text)
def test_map_text_matches_plain(text):
    view = redact_map(text, _CONFIG)
    plain, _ = redact(text, _CONFIG)
    assert view["text"] == plain


@settings(max_examples=250, deadline=None)
@given(_text)
def test_output_minus_placeholders_is_subsequence_of_input(text):
    view = redact_map(text, _CONFIG)
    # Remove each produced placeholder span from the view text; what remains is
    # the input with the secret spans deleted — necessarily a subsequence.
    out, last, kept = view["text"], 0, []
    for p in view["pairs"]:
        kept.append(out[last : p["start"]])
        last = p["start"] + len(p["placeholder"])
    kept.append(out[last:])
    assert _is_subsequence("".join(kept), text)


@settings(max_examples=200, deadline=None)
@given(st.text(max_size=200))
def test_never_throws_on_arbitrary_text(text):
    redact(text, _CONFIG)
    redact_map(text, _CONFIG)


def test_glued_secret_corner_round_trips():
    """A long non-detected run glued with no separator onto a detected secret,
    under a credential field. The field value stops at the AWS redaction's map
    sentinel exactly as it stops at the plain-mode placeholder's `[`, so map
    mode matches plain mode and the view round-trips."""
    text = "password: q9X2mN7pK4rT8wY1cV5bZ3dF6gH0jL2eAKIAIOSFODNN7EXAMPLE"
    plain = "password: [REDACTED][REDACTED: AWS Access Key]"
    assert redact(text)[0] == plain
    view = redact_map(text)
    assert view["text"] == plain
    assert reconstruct(view) == text


# ─── Wrapped-token exactness ─────────────────────────────────────────────────
# The fragment weave above never splits a token across lines, and no property
# there forbids deleting benign text: an over-wide span still deletes, relabels
# and round-trips. This one generates the shape the cross-line pass exists for —
# a token folded at one width with a hanging indent, an escape or zero-width char
# inside it, benign lines around it — and states the output exactly.

_CLASSIC = "ghp_" + "Zx9qW7rT2pL5mN8bV3cX6zA1sD4fG7hJ2kLm"
_STATELESS = (
    "ghs_1234567_"
    + base64.urlsafe_b64encode(b'{"alg":"RS256"}').rstrip(b"=").decode()
    + "."
    + base64.urlsafe_b64encode(b'{"iss":"Iv23liExampleApp","ins":1}' * 4)
    .rstrip(b"=")
    .decode()
    + "."
    + base64.urlsafe_b64encode(bytes(range(256))).rstrip(b"=").decode()
)
_AWS = "AKIA" + "ZYXWVUT123456789"
_SPACED_ENV = "ocean breeze quartz"
_WRAP_CONFIG = RedactorConfig(
    provider_vars={"VENICE_INFERENCE_KEY": _ENV_VALUE},
    host_cred_vars={"DOCKER_PASSWORD": _SPACED_ENV},
)
# token -> (label, shortest prefix that is already a whole detector match). A
# configured value is matched exactly and never cut, so it has no such prefix.
_WRAP_TOKENS = {
    _CLASSIC: ("GitHub Token", len(_CLASSIC)),
    _STATELESS: ("GitHub Token", _STATELESS.rfind(".") + 1 + 8),
    _AWS: ("AWS Access Key", len(_AWS)),
    _ENV_VALUE: ("VENICE_INFERENCE_KEY", None),
    _SPACED_ENV: ("DOCKER_PASSWORD", None),
}
_LEADS = ["", "  ", "GH_TOKEN=", "token: ", "key = "]
_INDENTS = ["", " ", "  ", "\t", "    "]
_NOISE = ["\x1b[31m", "\u200b"]
# Opens the line straight after the token: word-shaped (no digit, no capital
# past the first letter) or a token-class run under 8 chars, the evidence that
# tells a next-line word from a token tail. A longer mixed-case or digit-bearing
# run IS a plausible tail.
_OPENERS = [
    "1 file changed",
    "v2 ok",
    "200 OK",
    "hello",
    "Hello world",
    "Done.",
    "Traceback (most recent)",
    "echo done",
    "HOME=/root",
    "next_line_here",
    "PATH",
    "= x",
    "- item",
]
_WORDS = [*_OPENERS, "v2", "1", "mixedCase"]


def _benign_line(words: list[str], indent: str) -> str:
    return indent + " ".join(words)


@st.composite
def _wrapped_token_case(draw):
    """(text, expected, label) for one token folded at a drawn width.

    Shapes excluded, each an ambiguity the wrap geometry cannot resolve (the
    first two are the residuals test_secrets_crossline.py documents):
    * under 8 chars of the token left past a seam it is already complete
      before — read as the next line's text, so cut;
    * a continuation that is word-shaped where the lines so far give no
      one-width evidence, when the token is already complete before it or the
      continuation is indented and >= 8 chars — read as a word, so cut;
    * a token whose last line fills the width, followed directly by a line
      opening with a token-class run of 8+ chars — indistinguishable from a
      token that continues there;
    * a configured value whose own whitespace abuts a seam under added
      indentation — which blank belongs to the value is unknowable.
    """
    token = draw(st.sampled_from(sorted(_WRAP_TOKENS)))
    label, complete_at = _WRAP_TOKENS[token]
    if token == _CLASSIC:
        # A word-shaped tail is what a short continuation looks like by chance.
        tail = draw(st.text("abcdefghijklmnopqrstuvwxyz", max_size=8))
        token = token[: len(token) - len(tail)] + tail
    lead = draw(st.sampled_from(_LEADS))
    indent = draw(st.sampled_from(_INDENTS))
    width = draw(st.integers(8, len(token)))
    first = max(1, len(indent) + width - len(lead))
    chunks = [token[:first]]
    chunks += [token[i : i + width] for i in range(first, len(token), width)]
    seams_at_space = any(
        a.endswith((" ", "\t")) or b.startswith((" ", "\t"))
        for a, b in zip(chunks, chunks[1:])
    )
    assume(not (indent and seams_at_space))

    raw = list(chunks)
    long_enough = [i for i, c in enumerate(chunks) if len(c) >= 2]
    if long_enough and draw(st.booleans()):
        at = draw(st.sampled_from(long_enough))
        cut = draw(st.integers(1, len(chunks[at]) - 1))
        raw[at] = chunks[at][:cut] + draw(st.sampled_from(_NOISE)) + chunks[at][cut:]
    lines = [lead + raw[0]] + [indent + c for c in raw[1:]]

    blanks = draw(st.integers(0, 2))
    suffix = draw(
        st.lists(
            st.tuples(
                st.lists(st.sampled_from(_WORDS), min_size=1, max_size=3),
                st.sampled_from(["", "  ", "\t"]),
            ),
            max_size=3,
        )
    )
    if suffix and not blanks:
        words, line_indent = suffix[0]
        suffix[0] = ([draw(st.sampled_from(_OPENERS)), *words[1:]], line_indent)
    prefix = draw(
        st.lists(st.lists(st.sampled_from(_WORDS), min_size=1, max_size=3), max_size=3)
    )
    assume(len(chunks) > 1 or blanks or suffix)

    widths = [len(line) for line in lines]
    for k in range(len(chunks) - 1):
        evidence = k >= 1 and len(set(widths[: k + 1])) == 1
        cont = raw[k + 1]
        head = sum(len(c) for c in chunks[: k + 1])
        complete = complete_at is not None and head >= complete_at
        rest = len(("\n" + indent).join(raw[k + 1 :]))
        assume(not (complete and rest < _WORD_EVIDENCE_LEN))
        assume(
            complete_at is None
            or evidence
            or not _is_word_shaped(cont)
            or not (complete or (indent and len(cont) >= _WORD_EVIDENCE_LEN))
        )
    last = len(chunks) - 1
    if suffix and not blanks and last >= 1 and len(set(widths)) == 1:
        assume(re.match(r"[\w-]*", suffix[0][0][0]).end() < _WORD_EVIDENCE_LEN)

    before = "".join(_benign_line(words, "") + "\n" for words in prefix)
    after = "\n" * blanks + "".join("\n" + _benign_line(w, i) for w, i in suffix)
    text = before + "\n".join(lines) + after
    return text, before + lead + f"[REDACTED: {label}]" + after, label


@settings(max_examples=200, deadline=None)
@given(_wrapped_token_case())
def test_wrapped_token_redacts_whole_and_keeps_every_other_line(case):
    text, expected, label = case
    out, found = redact(text, _WRAP_CONFIG)
    assert out == expected
    # Not `== [label]`: an escape inside a token makes the raw view see a
    # truncated match beside the stripped view's whole one, and _redact_line
    # names every detected value, so the one type can appear twice.
    assert set(found) == {label}
