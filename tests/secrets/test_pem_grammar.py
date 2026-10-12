"""The PEM body grammar: a private-key block is its header, then LINES of base64
or `Field: value` headers separated by a real or JSON-escaped line break, then
its END marker (or, truncated, the end of the body lines).

Code and prose that merely NAME both markers are not a block: everything between
them stays, line for line.
"""

import base64
import hashlib

import pytest

import agent_sanitizer.secrets.engine as E
from agent_sanitizer.secrets import redact, redact_map
from redactor_helpers import reconstruct

_PLACEHOLDER = "[REDACTED: Private Key]"


def _body_lines(n: int = 6) -> list[str]:
    """``n`` full 64-char base64 lines, deterministic and well mixed."""
    raw = b"".join(hashlib.sha256(bytes([i])).digest() for i in range(n * 2))
    encoded = base64.b64encode(raw).decode()
    return [encoded[i * 64 : (i + 1) * 64] for i in range(n)]


_LINES = _body_lines()
_BEGIN = "-----BEGIN RSA PRIVATE KEY-----"
_END = "-----END RSA PRIVATE KEY-----"


def _assert_no_body(out: str) -> None:
    for line in _LINES:
        assert line not in out, line


# ─── Code and prose naming both markers keep every line ─────────────────────

_CODE_NAMING_MARKERS = [
    (
        "python predicate",
        "def is_pem(s):\n"
        '    if s.startswith("-----BEGIN PRIVATE KEY-----"):\n'
        '        body = s.split("\\n")[1:-1]\n'
        '        return s.rstrip().endswith("-----END PRIVATE KEY-----")\n'
        "    return False\n",
        ["body = s.split", "return False"],
    ),
    (
        "markdown docs",
        "A key starts with `-----BEGIN RSA PRIVATE KEY-----` and the base64\n"
        "body follows on the next lines, ending at\n"
        "`-----END RSA PRIVATE KEY-----`. Keep it out of the repo.\n",
        ["body follows on the next lines", "Keep it out of the repo."],
    ),
    (
        "js constants",
        'const BEGIN = "-----BEGIN EC PRIVATE KEY-----";\n'
        "const LINE = 64; // chars per base64 line\n"
        'const END = "-----END EC PRIVATE KEY-----";\n',
        ["const LINE = 64; // chars per base64 line"],
    ),
]


@pytest.mark.parametrize(
    "label, text, kept", _CODE_NAMING_MARKERS, ids=[c[0] for c in _CODE_NAMING_MARKERS]
)
def test_code_naming_both_markers_keeps_every_line(label, text, kept):
    out, _found = redact(text)
    assert out.count("\n") == text.count("\n"), label
    for fragment in kept:
        assert fragment in out, (label, fragment)


# ─── Real blocks redact whole ───────────────────────────────────────────────

_FULL = "\n".join([_BEGIN, *_LINES, _END])


@pytest.mark.parametrize(
    "label, text, tail",
    [
        ("multi-line", f"{_FULL}\nafter", "\nafter"),
        ("crlf", _FULL.replace("\n", "\r\n") + "\r\nafter", "\r\nafter"),
        (
            "json escaped",
            '{"k": "' + "\\n".join([_BEGIN, *_LINES, _END]) + '\\n"}',
            '\\n"}',
        ),
        (
            "json escaped slashes",
            '{"k": "'
            + "\\n".join([_BEGIN, *(line.replace("/", "\\/") for line in _LINES), _END])
            + '"}',
            '"}',
        ),
        ("space collapsed", " ".join([_BEGIN, *_LINES, _END]) + " after", " after"),
        (
            "encrypted with header fields",
            "\n".join(
                [
                    _BEGIN,
                    "Proc-Type: 4,ENCRYPTED",
                    "DEK-Info: AES-128-CBC,AB12CD34",
                    "",
                    *_LINES,
                    _END,
                ]
            ),
            "",
        ),
        ("truncated json", '{"k": "' + "\\n".join([_BEGIN, *_LINES[:3]]) + '"}', '"}'),
        ("truncated stream", "\n".join([_BEGIN, *_LINES[:3]]), ""),
    ],
)
def test_a_real_block_collapses_to_one_placeholder(label, text, tail):
    out, found = redact(text)
    assert "Private Key" in found, label
    _assert_no_body(out)
    assert out.endswith(_PLACEHOLDER + tail), (label, out)
    view = redact_map(text)
    assert reconstruct(view) == text, label
    assert view["text"] == out, label


def test_an_invisible_char_in_a_marker_does_not_hide_the_block():
    text = _FULL.replace("PRIVATE", "PRIV\u200bATE", 1) + "\nafter"
    out, _found = redact(text)
    _assert_no_body(out)
    assert out == _PLACEHOLDER + "\nafter"


def test_a_bare_header_is_recognised_across_every_line_break_spelling():
    for gap in ("", "\n", "\r\n", "\\n", "\\r\\n", "\n\n  "):
        assert E.is_bare_pem_header(_BEGIN + gap), repr(gap)
    assert not E.is_bare_pem_header(_FULL)
