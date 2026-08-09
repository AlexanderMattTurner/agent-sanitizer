"""A regular-expression literal is code that NAMES credential patterns.

The class this pins: a credential-named constant assigned a regex is the single
most common way a security codebase talks about secrets, and the field-value
detector was rewriting it into invalid source. This repo's own ``src/gates.mjs``
was the proof — its ``SECRET_HINT`` export came back as
``export const SECRET_HINT = [REDACTED][n]a|...``, which is not parseable
JavaScript. That is the harm ``CLAUDE.md``'s precision-over-recall rule names:
splicing or rewriting legitimate content removes text the model needed.
"""

import subprocess

import pytest

import agent_sanitizer.secrets.engine as E
from agent_sanitizer.secrets import RedactorConfig
from tests._helpers import REPO_ROOT

# Regex literals assigned to credential-named constants. Each is >=20 bytes and
# sits in exactly the `keyword = value` position the field detector targets.
REGEX_LITERALS = [
    # The truncated shape: the value class stops at the `[` of a character
    # class, so what the gate sees is NOT a well-formed literal. This is the
    # case a complete-literal check alone would miss.
    "/secret|token|password|passwd|pwd|bearer|credential|authorization|contrase",
    "/secret|token|password|passwd|pwd|bearer|credential/i",
    "/secretsecretsecretsecretsecret/i",
    "/secretsecretsecretsecretsecret/",
]

# Values that merely resemble one and must still redact.
STILL_SECRET = [
    # Laundering attempt: a real token wrapped in literal delimiters.
    "/ghp_abc123def456ghi789jkl/i",
    # Base64 can begin with `/`; it never contains `|` and does not end in flags.
    "/9j4AAQSkZJRgABAQAAAQABAAD2wCEAAo",
    # A bare opaque run with no delimiters at all.
    "abc123def456ghi789jkl012mno345",
]


@pytest.mark.parametrize("value", REGEX_LITERALS)
def test_a_regex_literal_is_left_verbatim(value: str) -> None:
    text = f"export const SECRET_HINT = {value};"
    # Non-vacuity: the detector must actually reach this value. A fixture the
    # field regex never matches (one truncated below the 20-byte floor by an
    # early `[`, say) would pass this test without exercising the gate at all —
    # which is exactly what one of these fixtures did before this assertion.
    match = E.FIELD_VALUE_RE.search(text)
    assert match is not None, "fixture never reaches the detector"
    assert match.group("secret_value") == value
    out, _ = E.redact(text)
    assert out == text


@pytest.mark.parametrize("value", STILL_SECRET)
def test_a_credential_is_not_laundered_by_looking_like_one(value: str) -> None:
    """Non-vacuity in the direction that matters: the gate must not have become
    a blanket skip for anything starting with a slash."""
    text = f"const secret = {value};"
    out, found = E.redact(text)
    assert out != text, "value survived redaction"
    assert value not in out
    assert found


@pytest.mark.parametrize("value", REGEX_LITERALS)
def test_the_shape_is_not_trusted_on_web_ingress(value: str) -> None:
    """The literal delimiters are a shape an attacker who controls the text can
    forge, so — like the other forgeable gates — it is trusted for LOCAL tool
    output only. Pinned so a future edit cannot quietly promote it to a
    SHAPE_GATE, which would make `/<credential>/i` a universal bypass.
    """
    text = f"export const SECRET_HINT = {value};"
    out, _ = E.redact(text, RedactorConfig(web_ingress=True))
    assert out != text


def test_the_gate_is_registered_as_forgeable_not_as_a_shape() -> None:
    """The registration IS the security property, so assert it directly rather
    than inferring it from the behaviour above."""
    assert E._is_regex_literal in E.NAME_TRUST_GATES
    assert E._is_regex_literal not in E.SHAPE_GATES


def test_this_repos_own_secret_hint_export_survives_redaction() -> None:
    """The regression that motivated the gate, asserted against the real file
    rather than a paraphrase of it — a copy in the test could drift into a
    shape the bug never had.
    """
    source = (REPO_ROOT / "src" / "gates.mjs").read_text(encoding="utf-8")
    assert "SECRET_HINT" in source, "gates.mjs no longer exports SECRET_HINT"
    out, _ = E.redact(source)
    assert out == source, "the sanitizer rewrote its own source"


def test_every_tracked_js_source_file_survives_redaction() -> None:
    """The generalization: this repo is a security codebase, so its sources are
    dense with credential-named constants and pattern literals — the exact
    corpus a false-positive-prone field detector mangles. Zero findings on all
    of it is the negative corpus CLAUDE.md asks every detector to carry.
    """
    files = subprocess.run(
        ["git", "ls-files", "src/*.mjs", "claude-hooks/*.mjs"],
        capture_output=True,
        text=True,
        check=True,
        cwd=REPO_ROOT,
    ).stdout.split()
    assert len(files) > 10, "glob matched almost nothing — the corpus is vacuous"
    mangled = []
    for name in files:
        source = (REPO_ROOT / name).read_text(encoding="utf-8")
        out, _ = E.redact(source)
        if out != source:
            mangled.append(name)
    assert mangled == [], f"redaction rewrote legitimate source files: {mangled}"
