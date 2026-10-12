"""A secret split by a terminal escape sequence still redacts.

Every detector reads an escape-stripped view of a line beside the
invisible-stripped one, and the env-value match does too, so ``ESC[31m`` (or an
OSC, DCS, ``ESC 7``, a C1 CSI, ...) wedged into a key cannot carry it past
redaction. Everything outside a redacted span, escapes included, stays
byte-for-byte.
"""

import pytest

import agent_sanitizer.secrets.engine as E
from agent_sanitizer.secrets import invisible as I
from agent_sanitizer.secrets import redact, redact_map
from agent_sanitizer.textstrip import ANSI_RE
from redactor_helpers import cfg, reconstruct

_ENV_NAME = "OPENROUTER_API_KEY"
_ENV_VALUE = "opaquesecretvalue1234"
_ENV_CONFIG = cfg(provider_vars={_ENV_NAME: _ENV_VALUE})
_ENV_MASK = f"[REDACTED: {_ENV_NAME}]"

_KEY = "sk-or-v1-" + "0123456789abcdef" * 4
_KEY_MASK = "[REDACTED: OpenRouter API Key]"


def _env_split(sequence: str) -> str:
    return f"key opaque{sequence}secretvalue1234 sent"


def _key_split(sequence: str) -> str:
    return f"got {_KEY[:5]}{sequence}{_KEY[5:]} back"


@pytest.mark.parametrize(
    ("text", "expected", "found"),
    [
        pytest.param(
            _env_split("\x1b[31m"), f"key {_ENV_MASK} sent", [_ENV_NAME], id="csi"
        ),
        pytest.param(
            _env_split("\x1b]0;title\x07"),
            f"key {_ENV_MASK} sent",
            [_ENV_NAME],
            id="osc-bel",
        ),
        pytest.param(
            _env_split("\x1b]0;title\x1b\\"),
            f"key {_ENV_MASK} sent",
            [_ENV_NAME],
            id="osc-st",
        ),
        pytest.param(
            _env_split("\x1bPq#0;2;0;0;0\x1b\\"),
            f"key {_ENV_MASK} sent",
            [_ENV_NAME],
            id="dcs",
        ),
        pytest.param(
            _env_split("\x1b7"), f"key {_ENV_MASK} sent", [_ENV_NAME], id="esc-7"
        ),
        pytest.param(
            _env_split("\x9b31m"), f"key {_ENV_MASK} sent", [_ENV_NAME], id="c1-csi"
        ),
        pytest.param(
            _env_split("\x1b\u200b[31m"),
            f"key {_ENV_MASK} sent",
            [_ENV_NAME],
            id="csi-itself-split-by-zwsp",
        ),
        # Unclosed strings: ANSI_RE takes the body to end of input, a bare ESC,
        # or a line break; the body is the rest of the secret and must be kept.
        pytest.param(
            _env_split("\x1b]"),
            f"key {_ENV_MASK} sent",
            [_ENV_NAME],
            id="unterminated-osc-to-end-of-input",
        ),
        pytest.param(
            "key opaque\x1b]secretvalue1234\x1b[0m sent",
            f"key {_ENV_MASK}\x1b[0m sent",
            [_ENV_NAME],
            id="unterminated-osc-aborted-by-esc",
        ),
        pytest.param(
            "key opaque\x9dsecretvalue1234\nnext",
            f"key {_ENV_MASK}\nnext",
            [_ENV_NAME],
            id="unterminated-c1-osc-to-line-break",
        ),
        pytest.param(
            _key_split("\x9b31m"),
            f"got {_KEY_MASK} back",
            ["OpenRouter API Key"],
            id="shape-key-c1-csi",
        ),
        pytest.param(
            _key_split("\x1b]0;t\x07"),
            f"got {_KEY_MASK} back",
            ["OpenRouter API Key"],
            id="shape-key-osc-bel",
        ),
        pytest.param(
            f"got {_KEY[:5]}\x1b]{_KEY[5:]}",
            f"got {_KEY_MASK}",
            ["OpenRouter API Key"],
            id="shape-key-unterminated-osc",
        ),
        # The newline AND the escapes are inside the secret: the cross-line pass.
        pytest.param(
            "key opaque\x1b[0m\n\x1b[31msecretvalue1234 sent",
            f"key {_ENV_MASK} sent",
            [_ENV_NAME],
            id="cross-line-env",
        ),
        pytest.param(
            f"got {_KEY[:30]}\x1b[0m\n\x1b[31m{_KEY[30:]} back",
            f"got {_KEY_MASK} back",
            ["OpenRouter API Key"],
            id="cross-line-shape-key",
        ),
    ],
)
def test_a_secret_split_by_an_escape_sequence_redacts(text, expected, found):
    assert redact(text, _ENV_CONFIG) == (expected, found)


@pytest.mark.parametrize(
    "text",
    [
        "\x1b[1;32mPASSED\x1b[0m tests/test_x.py::test_y \x1b[2m[ 50%]\x1b[0m",
        "\x1b]8;;https://example.com/docs\x1b\\docs\x1b]8;;\x1b\\ and more",
        "\x1b]0;user@host: ~/src\x07$ git status",
        "\x1b[31m-removed line\x1b[m\n\x1b[32m+added line\x1b[m",
        "\x9b1mbold\x9b0m \x1b7saved\x1b8 \x1bPq#0\x1b\\ sixel",
        "progress \x1b]unterminated title that runs on",
        "opaque\x1b[31m and secretvalue1234 kept apart by real text",
    ],
)
def test_escapes_that_split_no_secret_survive_verbatim(text):
    assert redact(text, _ENV_CONFIG) == (text, [])


@pytest.mark.parametrize(
    ("text", "expected", "found"),
    [
        pytest.param(
            f"\x1b[1;31mERROR\x1b[0m sent {_KEY} \x1b]0;title\x07 done\x1b[0m",
            f"\x1b[1;31mERROR\x1b[0m sent {_KEY_MASK} \x1b]0;title\x07 done\x1b[0m",
            ["OpenRouter API Key"],
            id="redaction-elsewhere-on-a-colored-line",
        ),
        pytest.param(
            "\x1b[31mopaque\x1b[1msecretvalue1234\x1b[0m!",
            f"\x1b[31m{_ENV_MASK}\x1b[0m!",
            [_ENV_NAME],
            id="edge-escapes-of-a-split-secret-survive",
        ),
        # Inside a CLOSED string's body only the invisible-stripped view sees
        # the key, so dropping that view for the escape-stripped one leaks it.
        pytest.param(
            f"\x1b]8;;https://x.test/?k={_KEY}\x1b\\link\x1b]8;;\x1b\\",
            f"\x1b]8;;https://x.test/?k={_KEY_MASK}\x1b\\link\x1b]8;;\x1b\\",
            ["OpenRouter API Key"],
            id="key-inside-a-closed-osc-8-body",
        ),
    ],
)
def test_only_the_secret_span_changes_on_a_colored_line(text, expected, found):
    assert redact(text, _ENV_CONFIG) == (expected, found)


def test_map_mode_round_trips_escape_bytes_inside_a_redacted_span():
    """The recorded original is the exact bytes replaced, escapes included, so
    rehydration reproduces the input byte for byte."""
    text = "\n".join(
        [
            "\x1b[32mok\x1b[0m " + _env_split("\x1b]0;title\x07"),
            _key_split("\x9b31m"),
            "key opaque\x1b[0m",
            "\x1b[31msecretvalue1234 tail",
        ]
    )
    view = redact_map(text, _ENV_CONFIG)
    assert [pair["original"] for pair in view["pairs"]] == [
        "opaque\x1b]0;title\x07secretvalue1234",
        f"{_KEY[:5]}\x9b31m{_KEY[5:]}",
        "opaque\x1b[0m\n\x1b[31msecretvalue1234",
    ]
    assert view["text"] == "\n".join(
        [
            f"\x1b[32mok\x1b[0m key {_ENV_MASK} sent",
            f"got {_KEY_MASK} back",
            f"key {_ENV_MASK} tail",
        ]
    )
    assert reconstruct(view) == text


def test_an_unclosed_string_keeps_its_body_where_the_grammar_drops_it():
    """ANSI_RE ends an unclosed OSC at end of input and takes the body with it;
    deleting that match whole would cut a split key's tail off its head."""
    text = "head\x1b]tail and more"
    assert ANSI_RE.sub("", text) == "head"
    view, offsets = I.strip_escapes_with_map(text)
    assert view == "headtail and more"
    assert list(offsets) == [0, 1, 2, 3, *range(6, len(text))]


def test_a_closed_string_is_deleted_whole_and_offsets_map_back():
    text = "a\u200bb\x1b]0;t\x07c\x9b1md"
    view, offsets = I.strip_escapes_with_map(text)
    assert view == "abcd"
    assert list(offsets) == [0, 2, 9, 13]


def test_text_with_no_escape_has_no_second_view():
    assert I.strip_escapes_with_map("plain \u200b text, no escape") is None


def test_probing_only_the_invisible_view_would_leak_an_escape_split_key(
    monkeypatch,
):
    """Non-vacuity for the probe's second view: the key's literal exists only
    once the C1 CSI is gone, so a probe of the invisible-stripped view alone
    rules the line out before any detector sees it."""
    text = _key_split("\x9b31m")
    monkeypatch.setattr(
        E,
        "_probe_candidates",
        lambda text, stripped, charset, deadline: E._line_probe().candidates(stripped),
    )
    assert redact(text, cfg()) == (text, [])


def _consumed(text: str) -> int:
    """How much of ``text`` the escape grammar takes as ONE leading sequence."""
    match = ANSI_RE.match(text)
    return 0 if match is None else match.end()


@pytest.mark.drift_guard(
    "the generated invisible-charset.json carries the escape grammar only as one "
    "regex source; the string introducers and terminators that src/ansi.mjs "
    "names are not exported, so the Python classifier restates them"
)
def test_string_sequence_classifier_agrees_with_the_escape_grammar():
    """Every introducer ANSI_RE carries over a body to a BEL is one the
    classifier names, and every byte that closes such a body is a terminator
    the classifier names."""
    candidates = [f"\x1b{chr(cp)}" for cp in range(0x20, 0x7F)]
    candidates += [chr(cp) for cp in range(0x80, 0xA0)]
    grammar = {
        intro for intro in candidates if _consumed(f"{intro}body\x07") == len(intro) + 5
    }
    named = {intro for intro in candidates if I._STRING_INTRODUCER_RE.fullmatch(intro)}
    assert grammar == named and len(named) == 10

    closers = [chr(cp) for cp in range(0xA0)] + ["\x1b\\"]
    closing = {
        closer
        for closer in closers
        if _consumed(f"\x1b]body{closer}z") == 6 + len(closer)
    }
    assert closing == set(I._STRING_TERMINATORS)
