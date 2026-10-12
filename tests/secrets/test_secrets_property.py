"""Property tests for the public contract (acceptance criteria).

Invariants, over text woven from visible runs, real secret tokens, invisible
chars, and newlines:

* idempotence — redacting twice equals redacting once;
* subsequence — the redacted text with the produced placeholders removed is a
  subsequence of the input (redaction only deletes/relabels, never invents
  visible content);
* rehydration round-trip — substituting each map pair's original at its offset
  reconstructs the input byte-for-byte.
"""

from hypothesis import given, settings
from hypothesis import strategies as st

from agent_sanitizer.secrets import RedactorConfig, redact, redact_map
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
# generated fragments never include them. Fragments are joined with a space so no
# two secret tokens glue into one contiguous run; the glued corner is pinned
# separately in test_glued_secret_corner_round_trips.
_text = st.lists(st.sampled_from(_FRAGMENTS), max_size=25).map(" ".join)


def _is_subsequence(sub: str, full: str) -> bool:
    it = iter(full)
    return all(ch in it for ch in sub)


@settings(max_examples=250, deadline=None)
@given(_text)
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
