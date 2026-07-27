"""Ported unit suite for the redaction engine (was
claude-guard/tests/test_redact_secrets_unit.py).

Every assertion from the original survives; the only mechanical changes are
API-shape: ``redact_text`` → :func:`redact`, ``run_main`` → ``run_plain``,
env-bound values come from a :class:`RedactorConfig` instead of ``os.environ``.
"""

import re
import time

import pytest

import agent_sanitizer.secrets.engine as E
from agent_sanitizer.secrets import (
    RedactorConfig,
    detected_secret_values,
    mask_secret_lines,
    redact,
    secret_previews,
)
from redactor_helpers import SAMPLES, cfg, reconstruct, run_map, run_plain

# Secrets assembled at runtime so no complete token literal triggers push protection.
STRIPE_LIVE = "sk_live" + "_4eC39HqLyjWDarjtT1zdp7dc"
AWS_KEY = "AKIA" + "ZYXWVUT123456789"

_PEM = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkSECRETBODYMATERIAL12345\n"
    "Q29udGludWVkIGtleSBtYXRlcmlhbCB0aGF0IG11c3Qgbm90IGxlYWs=\n"
    "-----END PRIVATE KEY-----"
)


# ─── Module-level constructs ────────────────────────────────────────────────


def test_plugins_list():
    names = [p["name"] for p in E.PLUGINS]
    assert {"AWSKeyDetector", "KeywordDetector"} <= set(names)
    assert all(set(p.keys()) == {"name"} for p in E.PLUGINS)


@pytest.mark.parametrize(
    "label, text, group1, group2",
    [
        (
            "basic",
            "password: SuperSecretP4ssword123456",
            "password: ",
            "SuperSecretP4ssword123456",
        ),
        (
            "early special char",
            "password: abcd!efghij1234567890XYZ",
            "password: ",
            "abcd!efghij1234567890XYZ",
        ),
        (
            "glued keyword",
            "mypassword: abcd!efghij1234567890XYZ",
            "password: ",
            "abcd!efghij1234567890XYZ",
        ),
        (
            "anchors on space",
            "token=abc123def456ghi789jkl012 trailing prose",
            "token=",
            "abc123def456ghi789jkl012",
        ),
        (
            "quoted json key+value",
            '{"token": "abc123def456ghi789jkl012"}',
            'token": ',
            "abc123def456ghi789jkl012",
        ),
        (
            "single-quoted value",
            "bearer: 'abc123def456ghi789jkl012'",
            "bearer: ",
            "abc123def456ghi789jkl012",
        ),
        (
            "walrus operator :=",
            "api_key := abc123def456ghi789jkl012",
            "api_key := ",
            "abc123def456ghi789jkl012",
        ),
        (
            "hash-rocket operator =>",
            "api_key => abc123def456ghi789jkl012",
            "api_key => ",
            "abc123def456ghi789jkl012",
        ),
        (
            "comparison operator ==",
            "api_key == abc123def456ghi789jkl012",
            "api_key == ",
            "abc123def456ghi789jkl012",
        ),
    ],
)
def test_field_value_regex(label, text, group1, group2):
    m = E.FIELD_VALUE_RE.search(text)
    assert m is not None, label
    assert m.group("field_prefix") == group1
    assert m.group("secret_value") == group2


def test_field_value_regex_case_insensitive_and_multiline():
    upper = E.FIELD_VALUE_RE.search("PASSWORD=abc123def456ghi789jkl012")
    assert upper is not None
    assert upper.group("secret_value") == "abc123def456ghi789jkl012"
    later = E.FIELD_VALUE_RE.search(
        "intro prose\nAPI_KEY=abc123def456ghi789jkl012\ntrailer"
    )
    assert later is not None
    assert later.group("secret_value") == "abc123def456ghi789jkl012"


@pytest.mark.parametrize("n", [16, 32, 48, 64])
def test_field_value_re_linear_on_underscore_run(n):
    # ReDoS adversarial input: a keyword, a long run of `_`, then a byte that is
    # not an assignment operator so no match ever completes. The old
    # `(?:[_-]\w+)*` had separator `[_-]` and body `\w` both matching `_`, so the
    # run repartitioned exponentially (measured 7.9s at n=38, doubling every 2
    # chars). The non-overlapping `(?:[_-][A-Za-z0-9]+)*` — disjoint separator
    # and body classes — parses the run exactly one way, so search stays linear.
    # Assert a wall-clock ceiling an exponential blowup at these sizes cannot
    # meet, run against the REAL compiled pattern (not an approximation).
    adversarial = "token" + "_" * n + "!"
    start = time.perf_counter()
    assert E.FIELD_VALUE_RE.search(adversarial) is None
    assert time.perf_counter() - start < 1.0, n


# ─── Bracket-wrapped values ──────────────────────────────────────────────────

_BRACKET_NEEDLE = "q9X2mN7pK4rT8wY1cV5bZ3dF6gH0jL2e"


@pytest.mark.parametrize(
    "field",
    [
        "api_key_prod",
        "api-key-prod",
        "secret_value",
        "token_value",
        "access_key_old",
        "AWS_SECRET_ACCESS_KEY_OLD",
        "password_2",
    ],
)
def test_compound_field_name_value_redacted(field):
    out, found = redact(f"{field} = {_BRACKET_NEEDLE}")
    assert _BRACKET_NEEDLE not in out, field
    assert "named secret field" in found, field


@pytest.mark.parametrize(
    "field",
    ["secretary", "tokenizer", "passwordless", "keystore", "authenticate"],
)
def test_keyword_prefix_without_separator_is_not_redacted(field):
    text = f"{field} = {_BRACKET_NEEDLE}"
    out, found = redact(text)
    assert out == text, field
    assert "named secret field" not in found, field


@pytest.mark.parametrize(
    "label, text, openb, closeb",
    [
        ("paren-wrapped value", f"password = ({_BRACKET_NEEDLE})", "(", ")"),
        ("brace-wrapped value", f"password = {{{_BRACKET_NEEDLE}}}", "{", "}"),
        ("square-bracket bare", f"password = [{_BRACKET_NEEDLE}]", "[", "]"),
        ("paren + quoted value", f'token: ("{_BRACKET_NEEDLE}")', "(", ")"),
        ("square + double-quoted value", f'token: ["{_BRACKET_NEEDLE}"]', "[", "]"),
        ("square + single-quoted value", f"token: ['{_BRACKET_NEEDLE}']", "[", "]"),
        ("no wrapper unaffected", f"password = {_BRACKET_NEEDLE}", "", ""),
        ("open-only (unclosed)", f"password = ({_BRACKET_NEEDLE}", "(", ""),
    ],
)
def test_field_value_bracket_wrapper_is_peeled(label, text, openb, closeb):
    m = E.FIELD_VALUE_RE.search(text)
    assert m is not None, label
    assert m.group("secret_value") == _BRACKET_NEEDLE, label
    assert m.group("openbracket") == openb, label
    assert m.group("closebracket") == closeb, label


def test_bracket_wrapped_secret_redacts_end_to_end():
    plain, _ = redact(f"password = {_BRACKET_NEEDLE}")
    placeholder = plain.split("password = ", 1)[1]
    wrapped, found = redact(f"password = ({_BRACKET_NEEDLE})")
    assert wrapped == f"password = ({placeholder})"
    assert _BRACKET_NEEDLE not in wrapped
    assert "named secret field" in found


@pytest.mark.parametrize("q", ['"', "'"], ids=["double", "single"])
def test_square_bracket_quoted_value_redacts_end_to_end(q):
    plain, _ = redact(f"password = {_BRACKET_NEEDLE}")
    placeholder = plain.split("password = ", 1)[1]
    wrapped, found = redact(f"token: [{q}{_BRACKET_NEEDLE}{q}]")
    assert wrapped == f"token: [{q}{placeholder}{q}]"
    assert _BRACKET_NEEDLE not in wrapped
    assert "named secret field" in found


@pytest.mark.parametrize(
    "op",
    [":=", "=>", "==", ":", "="],
    ids=["walrus", "rocket", "compare", "colon", "equals"],
)
def test_multichar_assignment_operator_redacts_end_to_end(op):
    plain, _ = redact(f"api_key = {_BRACKET_NEEDLE}")
    placeholder = plain.split("api_key = ", 1)[1]
    out, found = redact(f"api_key {op} {_BRACKET_NEEDLE}")
    assert out == f"api_key {op} {placeholder}", op
    assert _BRACKET_NEEDLE not in out, op
    assert "named secret field" in found, op


def test_bracket_peeling_leaves_env_and_call_fp_guards_intact():
    for text in (
        "api_key = ${SECRET_KEY_REFERENCE_NAME}",
        'token = os.getenv("FOO_BAR_BAZ_LONGNAME")',
    ):
        out, _ = redact(text)
        assert out == text, text


# ─── PEM block redaction ─────────────────────────────────────────────────────


def test_redact_pem_blocks_collapses_body():
    found: list[str] = []
    assert E._redact_pem_blocks(_PEM, found) == "[REDACTED: Private Key]"
    assert found == ["Private Key"]


def test_redact_pem_blocks_no_block_is_noop():
    found: list[str] = []
    assert (
        E._redact_pem_blocks("no key here\njust text", found)
        == "no key here\njust text"
    )
    assert found == []


@pytest.mark.parametrize(
    "label",
    [
        "RSA PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
        "EC PRIVATE KEY",
        "DSA PRIVATE KEY",
        "PRIVATE KEY",
        "PGP PRIVATE KEY BLOCK",
    ],
)
def test_redact_pem_realistic_labels_match(label):
    found: list[str] = []
    block = f"-----BEGIN {label}-----\nQUJDREVG\n-----END {label}-----"
    assert E._redact_pem_blocks(block, found) == "[REDACTED: Private Key]", label
    assert found == ["Private Key"], label


@pytest.mark.parametrize(
    "label",
    [
        "CERTIFICATE",
        "RSA PUBLIC KEY",
        "PUBLIC KEY",
        "PGP PUBLIC KEY BLOCK",
        "PGP MESSAGE",
        "DH PARAMETERS",
    ],
)
def test_redact_pem_public_labels_survive_verbatim(label):
    found: list[str] = []
    block = f"-----BEGIN {label}-----\nQUJDREVG\n-----END {label}-----"
    assert E._redact_pem_blocks(block, found) == block, label
    assert found == [], label


def test_redact_pem_label_length_is_bounded():
    found: list[str] = []
    runaway = "-----BEGIN " + "A" * 500 + "PRIVATE KEY" + "A" * 500 + "-----\nx\n"
    assert E._redact_pem_blocks(runaway, found) == runaway
    assert found == []


def test_main_pem_body_not_leaked():
    result = run_plain(_PEM)
    assert result is not None
    assert "Private Key" in result["found"]
    assert "[REDACTED: Private Key]" in result["text"]
    assert "SECRETBODYMATERIAL" not in result["text"]
    assert "Q29udGludWVk" not in result["text"]


# ─── redaction paths + short-circuits ────────────────────────────────────────


def test_known_prefix_redacted():
    result = run_plain("key: AKIAIOSFODNN7EXAMPLE")
    assert result is not None
    assert "AWS Access Key" in result["found"]
    assert result["text"] == "key: [REDACTED: AWS Access Key]"


# ─── Invisible-character-spliced structural secrets (engine.py `_redact_line`,
# `_cross_line_candidate_spans`) — a zero-width char wedged INSIDE a leaked
# credential must not evade a structural (prefix) detector. ──────────────────

_ANTHROPIC_BODY = ("A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6" * 3)[:93]
_ANTHROPIC_KEY = f"sk-ant-api03-{_ANTHROPIC_BODY}AA"


def test_anthropic_key_fixture_is_shaped_like_the_detector_pattern():
    assert re.fullmatch(
        r"sk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{93}AA", _ANTHROPIC_KEY
    )
    # Sanity: the CLEAN key is already caught (proves the fixture is otherwise
    # detector-eligible, isolating the spliced tests below to the splice itself).
    result = run_plain(f"leaked key: {_ANTHROPIC_KEY} end")
    assert result is not None
    assert result["text"] == "leaked key: [REDACTED: Anthropic API Key] end"


@pytest.mark.parametrize(
    "sep",
    ["​", "­", "⁦"],
    ids=["zwsp", "soft-hyphen", "bidi-isolate"],
)
def test_invisible_char_spliced_structural_secret_is_redacted(sep):
    """A zero-width char spliced into a leaked Anthropic key's body must not
    evade the structural (prefix) detector — before the fix, only the env-bound
    exact-match path tolerated interior invisibles, so this key sailed through
    every OTHER detector (including this one) untouched. Assert every visible
    byte of the key is actually gone, not just that a marker appeared somewhere.
    """
    mid = len(_ANTHROPIC_KEY) // 2
    spliced = _ANTHROPIC_KEY[:mid] + sep + _ANTHROPIC_KEY[mid:]
    text = f"leaked key: {spliced} end"

    out, found = redact(text)

    assert found == ["Anthropic API Key"], sep
    assert sep not in out, sep
    assert _ANTHROPIC_BODY not in out, sep
    assert _ANTHROPIC_KEY not in out, sep
    assert out == "leaked key: [REDACTED: Anthropic API Key] end", sep


def test_invisible_char_spliced_structural_secret_map_mode_reconstructs():
    """Map mode must record the ORIGINAL bytes (including the spliced invisible
    char) so rehydration is byte-exact, not the clean detector-matched value."""
    sep = "​"
    mid = len(_ANTHROPIC_KEY) // 2
    spliced = _ANTHROPIC_KEY[:mid] + sep + _ANTHROPIC_KEY[mid:]
    text = f"leaked key: {spliced} end\n"

    view = run_map(text)

    assert view["found"] == ["Anthropic API Key"]
    assert [p["placeholder"] for p in view["pairs"]] == [
        "[REDACTED: Anthropic API Key]"
    ]
    assert view["pairs"][0]["original"] == spliced
    assert reconstruct(view) == text


def test_invisible_char_spliced_secret_split_across_lines_is_redacted():
    """The cross-line pass must also see through a spliced invisible char: a
    structural secret split by a newline AND carrying a splice must still be
    caught whole, not just tolerated at the newline boundary."""
    sep = "​"
    mid = len(_ANTHROPIC_KEY) // 2
    spliced = _ANTHROPIC_KEY[:mid] + sep + _ANTHROPIC_KEY[mid:]
    split_point = 40
    head, tail = spliced[:split_point], spliced[split_point:]
    text = f"prefix {head}\n{tail} suffix"

    out, found = redact(text)

    assert found == ["Anthropic API Key"]
    assert sep not in out
    assert _ANTHROPIC_BODY not in out
    assert out == "prefix [REDACTED: Anthropic API Key] suffix"


def test_found_dedup():
    result = run_plain("k1: AKIAIOSFODNN7EXAMPLE\nk2: AKIAIOSFODNN7EXAMPLE")
    assert result is not None
    assert result["found"].count("AWS Access Key") == 1


def test_unquoted_field_redacted():
    result = run_plain("password: SuperSecretP4ssword123456")
    assert result is not None
    assert "named secret field" in result["found"]
    assert result["text"] == "password: [REDACTED]"


def test_quoted_token_field_redacted_preserving_quotes():
    result = run_plain('{"token": "abc123def456ghi789jkl012"}')
    assert result is not None
    assert "named secret field" in result["found"]
    assert result["text"] == '{"token": "[REDACTED]"}'


_OPAQUE = "abcDEF123ghiJKL456mnoPQR"
_MARK = "[" + "REDACTED" + "]"


@pytest.mark.parametrize(
    "label, text, expected",
    [
        ("unclosed double quote", f'{{"token": "{_OPAQUE}', f'{{"token": "{_MARK}'),
        ("unclosed single quote", f"bearer: '{_OPAQUE}", f"bearer: '{_MARK}"),
        ("mismatched quotes", f"token=\"{_OPAQUE}'", f"token=\"{_MARK}'"),
    ],
)
def test_unbalanced_quote_value_still_redacted(label, text, expected):
    result = run_plain(text)
    assert result is not None, label
    assert "named secret field" in result["found"], label
    assert _OPAQUE not in result["text"], label
    assert result["text"] == expected, label


# ─── Benign pagination-cursor exclusion ──────────────────────────────────────


@pytest.mark.parametrize(
    "label, text, expected",
    [
        ("camel nextToken", "nextToken=abcdefghij1234567890XYZ", True),
        ("dotted pageToken", "resp.pageToken=abcdefghij1234567890XYZ", True),
        ("snake page_token", "page_token=abcdefghij1234567890XYZ", True),
        ("nextPageToken", "nextPageToken=abcdefghij1234567890XYZ", True),
        ("continuationToken", "continuationToken=abcdefghij1234567890XYZ", True),
        ("sessionToken", "sessionToken=abcdefghij1234567890XYZ", False),
        ("compound access_token", "access_token=abcdefghij1234567890XYZ", False),
        ("non-token field", "password: abcdefghij1234567890XYZ", False),
    ],
)
def test_is_benign_cursor(label, text, expected):
    m = E.FIELD_VALUE_RE.search(text)
    assert m is not None, label
    assert E._is_benign_cursor(m) is expected, label


@pytest.mark.parametrize(
    "label, text",
    [
        ("camel nextToken", "nextToken=IiAiQ0FBU0ZRSVhwY2tFIg9876543"),
        ("snake next_token", "next_token: abcdefghij1234567890XYZ"),
        ("nextPageToken", "nextPageToken=abcdefghij1234567890XYZ"),
        ("scrollToken", "scrollToken=abcdefghij1234567890XYZ"),
        ("dotted pageToken", "resp.pageToken=abcdefghij1234567890XYZ"),
    ],
)
def test_benign_cursor_not_redacted(label, text):
    assert run_plain(text) is None, label


@pytest.mark.parametrize(
    "label, text, expected",
    [
        (
            "compound access_token",
            "access_token=abcdefghij1234567890XYZ",
            "access_token=[REDACTED]",
        ),
        (
            "camel accessToken",
            "accessToken=abcdefghij1234567890XYZ",
            "accessToken=[REDACTED]",
        ),
        (
            "sessionToken cursor-shaped but credential",
            "sessionToken=abcdefghij1234567890XYZ",
            "sessionToken=[REDACTED]",
        ),
        ("id_token", "id_token=abcdefghij1234567890XYZ", "id_token=[REDACTED]"),
        ("bare token", "token=abcdefghij1234567890XYZ", "token=[REDACTED]"),
    ],
)
def test_credential_token_still_redacted(label, text, expected):
    result = run_plain(text)
    assert result is not None, label
    assert "named secret field" in result["found"]
    assert result["text"] == expected, label


# ─── Placeholder / example values not redacted ───────────────────────────────


@pytest.mark.parametrize(
    "label, value, expected",
    [
        ("caps metavariable", "YOUR_API_KEY_GOES_HERE", True),
        ("caps metavariable sequence", "GITHUB_TOKEN OPENAI_API_KEY", True),
        ("angle-wrapped", "<paste-your-token-here>", True),
        ("template-wrapped", "{{ secrets.DEPLOY_TOKEN }}", True),
        ("repeated filler", "xxxxxxxxxxxxxxxxxxxxxxxx", True),
        ("repeated zeros", "00000000", True),
        ("known literal", "changeme", True),
        ("known literal cased", "ChangeMe", True),
        ("keyword noun secret", "secret", True),
        ("keyword noun cased", "SECRET", True),
        ("keyword noun password", "password", True),
        ("keyword noun token", "token", True),
        ("keyword noun apikey", "apikey", True),
        ("keyword noun prefix of longer word", "secretariat", False),
        ("sentinel test", "test", True),
        ("sentinel cased", "TEST", True),
        ("sentinel sample", "sample", True),
        ("sentinel todo", "TODO", True),
        ("sentinel none", "none", True),
        ("sentinel n/a", "N/A", True),
        ("sentinel foo", "foo", True),
        ("sentinel prefix of longer word", "testcredential9aB", False),
        ("high entropy mixed", "q9X2mN7pK4rT8wY1cV5bZ3dF6gH0jL2e", False),
        ("caps with digits", "AKIAIOSFODNN7EXAMPLE", False),
        ("digit-bearing metavariable", "API_KEY_2_q9X2mN7pK4rT8wY1c", False),
        ("mixed-case dodge", "YOUR_KEY_aGk3pQ7mXw2RtV9b", False),
        ("diceware passphrase", "correct-horse-battery-staple", False),
        ("single caps word", "SUPERSECRETVALUE", False),
        ("seven repeats below floor", "xxxxxxx", False),
    ],
)
def test_is_placeholder_value(label, value, expected):
    assert E._is_placeholder_value(value) is expected, label


@pytest.mark.parametrize(
    "label, text",
    [
        (
            "doc prose env example",
            'Example: SCRUB_SECRETS_ALLOW="GITHUB_TOKEN OPENAI_API_KEY"',
        ),
        ("unquoted caps metavariable", "api_key: YOUR_API_KEY_GOES_HERE_NOW"),
        ("repeated filler", "password: xxxxxxxxxxxxxxxxxxxxxxxx"),
        ("ci template", 'token: "{{ secrets.DEPLOY_TOKEN }}"'),
        ("known literal", 'password = "changeme"'),
        ("keyword noun as value", '"secret": "secret"'),
        ("keyword noun cased", 'secret: "SECRET"'),
        ("password noun as value", 'password: "password"'),
        ("token noun as value", 'token: "token"'),
        ("sentinel test value", 'secret: "test"'),
        ("sentinel sample value", 'api_key: "sample"'),
        ("sentinel todo value", 'token: "TODO"'),
        ("sentinel none value", 'password: "none"'),
    ],
)
def test_placeholder_values_not_redacted(label, text):
    redacted, found = redact(text)
    assert redacted == text, label
    assert found == [], label
    assert run_plain(text) is None, label


# ─── Metadata fields about secrets not redacted ──────────────────────────────


@pytest.mark.parametrize(
    "label, line, value, expected",
    [
        (
            "secret_type assign",
            'secret_type = "Anthropic API Key"',
            "Anthropic API Key",
            True,
        ),
        (
            "quoted json key",
            '"token_name": "deploy-bot-primary"',
            "deploy-bot-primary",
            True,
        ),
        ("comparison", 'secret_type == "Anthropic API Key"', "Anthropic API Key", True),
        ("walrus", 'secret_type := "Anthropic API Key"', "Anthropic API Key", True),
        (
            "hash-rocket",
            'secret_type => "Anthropic API Key"',
            "Anthropic API Key",
            True,
        ),
        (
            "key_label colon",
            "key_label: rotation-2026-june",
            "rotation-2026-june",
            True,
        ),
        ("suffix not final", 'secrets_type_x = "abc"', "abc", False),
        ("bare secret field", 'secret = "abc"', "abc", False),
        ("no assignment before value", "prose mentioning a value", "value", False),
        ("value at line start", "abc = something", "abc", False),
        ("value not in line", "secret_type = x", "missing", False),
        ("operator with empty field", '"= "secretvalue', "secretvalue", False),
        ("no-space quoted assign", 'key_type="somevalue"', "somevalue", True),
    ],
)
def test_is_metadata_field(label, line, value, expected):
    assert E._is_metadata_field(line, value) is expected, label


def test_is_metadata_field_uses_explicit_offset():
    # When the value also appears earlier in the line, the first-occurrence
    # `line.find(value)` fingers the wrong prefix; the caller passes the value's
    # real match offset so the actual assignment (a metadata field here) is seen.
    value = "AnthropicAPIKeyValue"
    line = f"note {value} then token_name = {value}"
    # No offset -> first occurrence (after "note ") has no operator -> not metadata.
    assert E._is_metadata_field(line, value) is False
    # Real offset -> the SECOND occurrence, assigned to token_name -> metadata.
    assert E._is_metadata_field(line, value, line.rindex(value)) is True


@pytest.mark.parametrize(
    "label, text",
    [
        ("secret_type", 'secret_type = "Anthropic API Key"'),
        ("kubernetes secret type", 'secret_type: "kubernetes.io/tls"'),
        ("token_kind", 'token_kind = "refresh-token-v2-long"'),
    ],
)
def test_metadata_fields_not_redacted(label, text):
    assert run_plain(text) is None, label


# ─── Markdown code prose not redacted ────────────────────────────────────────


@pytest.mark.parametrize(
    "label, value, expected",
    [
        ("backtick markdown prose", "re.IGNORECASE | re.MULTILINE` `flags", True),
        ("spaced passphrase", "correct horse battery staple", False),
        ("backtick but no whitespace", "P@ss`word", False),
        ("contiguous credential", "q9X2mN7pK4rT8wY1cV5bZ3dF6gH0jL2e", False),
    ],
)
def test_is_markdown_code_prose(label, value, expected):
    assert E._is_markdown_code_prose(value) is expected, label


# ─── Lowercase metavariables / timestamps / versions not redacted ────────────


@pytest.mark.parametrize(
    "label, value, expected",
    [
        ("your-...-here", "your-api-key-here", True),
        ("paste imperative", "paste-your-token-here-now", True),
        ("replace imperative", "replace-with-real-secret", True),
        ("example prefix", "example-api-key", True),
        ("underscore separated", "your_api_key_here", True),
        ("space separated", "paste your token here", True),
        (
            "diceware passphrase (real credential)",
            "correct-horse-battery-staple",
            False,
        ),
        ("no metavariable token", "prod-service-worker-01", False),
        ("passphrase word here not a token", "here-horse-battery-staple", False),
        ("passphrase word enter not a token", "enter-horse-battery-staple", False),
        ("single word", "your", False),
        ("uppercase present", "Your-API-Key-Here", False),
        ("smuggled opaque run", "your-key-here-deadbeef0123456789abcd", False),
    ],
)
def test_is_lowercase_metavariable(label, value, expected):
    assert E._is_lowercase_metavariable(value) is expected, label


@pytest.mark.parametrize(
    "label, value, expected",
    [
        ("date only", "2024-01-15", True),
        ("datetime Z", "2024-01-15T10:30:00.000000Z", True),
        ("datetime offset space", "2024-01-15 10:30:00+02:00", True),
        ("datetime no seconds", "2024-01-15T10:30", True),
        ("trailing tag not absorbed", "2024-01-15T10:30:00Z-batch01", False),
        ("not a date", "q9X2mN7pK4rT8wY1cV5bZ3dF6gH0jL2e", False),
        ("partial date", "2024-01", False),
    ],
)
def test_is_timestamp(label, value, expected):
    assert E._is_timestamp(value) is expected, label


@pytest.mark.parametrize(
    "label, value, expected",
    [
        ("semver", "1.2.3", True),
        ("v-prefixed", "v2.0.1", True),
        ("prerelease build", "1.2.3-alpha.build.abcdef", True),
        ("four segments", "1.2.3.4", True),
        ("two segments only", "1.2", False),
        ("smuggled secret in tail", "1.2.3-q9X2mN7pK4rT8wY1cV5bZ3", False),
        ("not a version", "q9X2mN7pK4rT8wY1cV5bZ3dF6gH0jL2e", False),
    ],
)
def test_is_version(label, value, expected):
    assert E._is_version(value) is expected, label


@pytest.mark.parametrize(
    "label, text",
    [
        ("lowercase metavariable", 'api_key: "your-api-key-here"'),
        ("paste metavariable", 'token: "paste-your-token-here-now"'),
        ("iso timestamp keyword field", 'token_created: "2024-01-15T10:30:00.000000Z"'),
        ("iso date field-value", "secret_updated: 2024-01-15"),
        ("semver keyword field", 'secret_version: "1.2.3-alpha.build.abcdef"'),
        ("version field-value", "token_api_version: v2.0.1"),
    ],
)
def test_shape_skips_not_redacted(label, text):
    redacted, found = redact(text)
    assert redacted == text, label
    assert found == [], label
    # Value-shape skips are source-independent — they hold on web ingress too.
    web, web_found = redact(text, cfg(web_ingress=True))
    assert web == text and web_found == [], f"{label} (web)"


@pytest.mark.parametrize(
    "label, text, needle",
    [
        (
            "diceware passphrase still redacts",
            'password: "correct-horse-battery-staple"',
            "correct-horse",
        ),
        (
            "secret smuggled in version tail still redacts",
            'secret: "1.2.3-q9X2mN7pK4rT8wY1cV5bZ3"',
            "q9X2mN7pK4rT8wY1",
        ),
        (
            "secret smuggled behind metavariable token still redacts",
            'api_key: "your-key-here-deadbeef0123456789abcdef0123"',
            "deadbeef0123456789",
        ),
    ],
)
def test_shape_skips_never_leak_real_secrets(label, text, needle):
    redacted, _ = redact(text, cfg(web_ingress=True))
    assert needle not in redacted, label


def test_is_benign_keyword_match_none_secret_value():
    from detect_secrets.core.potential_secret import PotentialSecret

    secret = PotentialSecret(type="Secret Keyword", filename="f", secret="x")
    secret.secret_value = None
    assert E._is_benign_keyword_match(secret, "some line", False) is False


def test_markdown_code_prose_skipped_locally_redacted_on_web(monkeypatch):
    import types

    value = "re.IGNORECASE | re.MULTILINE` `flags"
    text = "doc says " + value + " here"
    fake = types.SimpleNamespace(type="Secret Keyword", secret_value=value)
    monkeypatch.setattr(E, "scan_line", lambda line: [fake] if value in line else [])

    local, local_found = redact(text, cfg(web_ingress=False))
    web, web_found = redact(text, cfg(web_ingress=True))

    assert local == text and local_found == [], "local: prose must pass through"
    assert web_found == ["Secret Keyword"] and "[REDACTED" in web, "web: must redact"


@pytest.mark.parametrize(
    "label, text, marker",
    [
        (
            "spaced passphrase",
            'password: "correct horse battery staple ok"',
            "[REDACTED: Secret Keyword]",
        ),
        (
            "metadata suffix near-miss",
            'secrets_type_x = "q9X2mN7pK4rT8wY1cV5bZ3dF6gH0jL2e"',
            "[REDACTED: Secret Keyword]",
        ),
        (
            "mixed-case metavariable dodge",
            'secret = "YOUR_KEY_aGk3pQ7mXw2RtV9b"',
            "[REDACTED: Secret Keyword]",
        ),
        (
            "aws docs example key",
            "key: AKIAIOSFODNN7EXAMPLE",
            "[REDACTED: AWS Access Key]",
        ),
    ],
)
def test_placeholder_skips_never_leak_real_shapes(label, text, marker):
    result = run_plain(text)
    assert result is not None, label
    assert marker in result["text"], label


@pytest.mark.parametrize(
    "label, text, leak",
    [
        (
            "aws key under metadata field (type sorts before Secret Keyword)",
            "key_type: " + "AKIA" + "IOSFODNN7EXAMPLE",
            "IOSFODNN7EXAMPLE",
        ),
        (
            "stripe key under metadata field (type sorts after Secret Keyword)",
            'token_type = "' + "sk_live" + '_4eC39HqLyjWDarjtT1zdp7dc"',
            "4eC39HqLyjWDarjtT1zdp7dc",
        ),
    ],
)
def test_prefix_detectors_redact_in_metadata_fields(label, text, leak):
    result = run_plain(text)
    assert result is not None, label
    assert leak not in result["text"], label


def test_placeholder_skip_does_not_suppress_other_detections_on_line():
    aws = "AKIA" + "IOSFODNN7EXAMPLE"
    result = run_plain(f'token_type = "changeme" key: {aws}')
    assert result is not None
    assert aws not in result["text"]
    assert "AWS Access Key" in result["found"]
    assert '"changeme"' in result["text"]


# ─── Env-var / config references not redacted ────────────────────────────────


@pytest.mark.parametrize(
    "label, value, expected",
    [
        ("bare $VAR", "$ANTHROPIC_AUTH_TOKEN", True),
        ("underscore-led $_VAR", "$_INTERNAL_TOKEN_VALUE", True),
        ("node process.env", "process.env.MY_API_KEY_NAME", True),
        ("vite import.meta.env", "import.meta.env.VITE_SECRET_KEY", True),
        ("python os.environ bracket", 'os.environ["DATABASE_URL_VAR"]', True),
        ("deno env", "Deno.env.MY_TOKEN_NAME", True),
        ("jq $ENV", "$ENV.SEED_TOKEN_VALUE", True),
        ("django settings", "settings.SECRET_KEY_NAME", True),
        ("config chain", "config.auth.accessTokenField", True),
        ("environ attr", "environ.DATABASE_PASSWORD_VAR", True),
        ("self attr", "self.api_token_attribute", True),
        ("config-prefixed token", "configBcd3Fg7Hj9Kl2Mn4Pq6Rs", False),
        ("processenv-prefixed", "processXenvY1234567890ZabcD", False),
        ("bcrypt $2b", "$2b$12$R9hcIPz0giURNNX3kh2OPST", False),
        ("sha512crypt $6", "$6$roundsalt$abcdefghij1234567890", False),
        ("apache apr1 $apr1", "$apr1$ZjTqBB3f$IF9gdYAGlMrs2fuINjHsz", False),
        ("yescrypt $y", "$y$j9T$F5Jx5fExrKuPp53xLKQA1$wTBQv5", False),
        ("ordinary secret", "SuperSecretP4ssword123456", False),
    ],
)
def test_is_env_reference(label, value, expected):
    assert E._is_env_reference(value) is expected, label


@pytest.mark.parametrize(
    "label, text",
    [
        ("node process.env", "apiKey: process.env.MY_API_KEY_NAME"),
        ("vite import.meta.env", "secret_key: import.meta.env.VITE_SECRET_KEY"),
        ("jq $ENV", "accessToken:$ENV.SEED_TOKEN_VALUE"),
        ("django settings", "secret_key = settings.SECRET_KEY_ATTR_NAME"),
        ("config chain", "authToken: config.auth.accessTokenField"),
    ],
)
def test_env_reference_field_value_not_redacted(label, text):
    assert run_plain(text) is None, label


def test_env_reference_keyword_match_skipped():
    import types

    fake = types.SimpleNamespace(
        type="Secret Keyword", secret_value="process.env.SOME_SECRET_VAR"
    )
    assert E._is_benign_keyword_match(fake, "k = process.env.SOME_SECRET_VAR", False)
    assert E._is_benign_keyword_match(fake, "k = process.env.SOME_SECRET_VAR", True)


_ENV_REF_NEEDLE = "q9X2mN7pK4rT8wY1cV5bZ3dF6gH0jL2e"


@pytest.mark.parametrize("root", ["settings", "config", "environ", "self"])
def test_forgeable_env_root_redacts_on_web_ingress(root):
    value = f"{root}.{_ENV_REF_NEEDLE}"
    assert E._is_env_reference(value, web_ingress=False) is True
    assert E._is_env_reference(value, web_ingress=True) is False
    text = f"api_key: {value}"
    local, _ = redact(text, cfg(web_ingress=False))
    web, _ = redact(text, cfg(web_ingress=True))
    assert local == text, f"{root}: local config read must be kept"
    assert _ENV_REF_NEEDLE not in web and "[REDACTED" in web, (
        f"{root}: web-ingress credential must redact"
    )


@pytest.mark.parametrize(
    "value",
    [
        f"${_ENV_REF_NEEDLE}",
        f"process.env.{_ENV_REF_NEEDLE}",
        f"import.meta.env.{_ENV_REF_NEEDLE}",
        f'os.environ["{_ENV_REF_NEEDLE}"]',
        f"Deno.env.{_ENV_REF_NEEDLE}",
    ],
)
def test_unforgeable_env_root_trusted_on_web_ingress(value):
    assert E._is_env_reference(value, web_ingress=True) is True


@pytest.mark.parametrize(
    "label, text",
    [
        (
            "shell expansion chain",
            '[ -z "${MONITOR_API_KEY:-}${ANTHROPIC_API_KEY:-}" ]',
        ),
        ("bare var ref", "ANTHROPIC_AUTH_TOKEN=$ANTHROPIC_AUTH_TOKEN"),
        ("code call parens", 'secret = randomBytes(32).toString("hex")'),
    ],
)
def test_code_constructs_not_redacted(label, text):
    assert run_plain(text) is None, label


@pytest.mark.parametrize(
    "label, value",
    [
        ("bcrypt", "$2b$12$R9hcIPz0giURNNX3kh2OPST"),
        ("sha512crypt", "$6$rounds656000$abcdefghij1234567890"),
        ("apache apr1", "$apr1$ZjTqBB3f$IF9gdYAGlMrs2fuINjHsz"),
        ("yescrypt", "$y$j9T$F5Jx5fExrKuPp53xLKQA1$wTBQv5"),
    ],
)
def test_crypt_hash_still_redacted(label, value):
    result = run_plain(f"password: {value}")
    assert result is not None, label
    assert "named secret field" in result["found"], label
    assert result["text"] == "password: [REDACTED]", label


@pytest.mark.parametrize(
    "label, value, expected",
    [
        ("docker mount mode", "/run/monitor-secret:ro", True),
        ("plain abs path", "/var/lib/secret-store/data", True),
        ("mount with cached", "/home/node/.claude:cached", True),
        ("single segment", "/wJalrXUtnFEMIK7MDENG", False),
        ("aws secret-shaped", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", False),
        ("path-shaped token", "/abcdefghij/klmnopqrst/uvwxyz1234", False),
    ],
)
def test_is_filesystem_path(label, value, expected):
    m = E.FIELD_VALUE_RE.search(f"secret={value}")
    assert m is not None, label
    assert E._is_filesystem_path(m) is expected, label


# ─── Content digests, UUIDs ──────────────────────────────────────────────────

_REDACTED = "[" + "REDACTED]"


@pytest.mark.parametrize(
    "label, value, expected",
    [
        ("sha256 oci digest", "sha256:" + "a1b2c3d4e5f60718" * 4, True),
        ("sha1 git object", "sha1:" + "0123456789abcdef0123", True),
        ("blake2b digest", "blake2b:" + "deadbeefcafef00d" * 2, True),
        ("md5 digest", "md5:" + "0123456789abcdef0123", True),
        ("digest at 16-hex floor", "sha256:" + "0123456789abcdef", True),
        ("digest below 16-hex floor", "sha256:" + "0123456789abcde", False),
        ("eth address 0x40", "0x" + "abcdef0123456789ABCDEF0123456789abcdef01", True),
        ("eth tx hash 0x64", "0x" + "0123456789abcdef" * 4, True),
        ("unknown algo", "sha999:" + "0123456789abcdef0123", False),
        ("non-hex body", "sha256:" + "z" * 40, False),
        ("0x wrong length 50", "0x" + "abcdef0123" * 5, False),
        ("0x wrong length short", "0x" + "abcdef0123", False),
        ("bare hex no prefix", "0123456789abcdef0123456789abcdef", False),
    ],
)
def test_is_content_digest(label, value, expected):
    assert E._is_content_digest(value) is expected, label


@pytest.mark.parametrize(
    "label, value, expected",
    [
        ("canonical uuid", "12345678-90ab-cdef-1234-567890abcdef", True),
        ("uppercase uuid", "ABCDEF01-2345-6789-ABCD-EF0123456789", True),
        ("short last group", "12345678-90ab-cdef-1234-567890abcde", False),
        ("non-hex char", "g2345678-90ab-cdef-1234-567890abcdef", False),
        ("missing dashes", "1234567890abcdef1234567890abcdef", False),
    ],
)
def test_is_uuid(label, value, expected):
    assert E._is_uuid(value) is expected, label


@pytest.mark.parametrize(
    "label, value",
    [
        ("oci image digest", "sha256:" + "a1b2c3d4e5f60718" * 4),
        ("blockchain tx hash", "0x" + "0123456789abcdef" * 4),
        ("correlation uuid", "12345678-90ab-cdef-1234-567890abcdef"),
    ],
)
def test_content_digest_and_uuid_skipped_after_keyword(label, value):
    text = f"key: {value}"
    local, found_local = redact(text, cfg(web_ingress=False))
    web, found_web = redact(text, cfg(web_ingress=True))
    assert local == text and found_local == [], label
    assert web == text and found_web == [], label


def test_credential_after_keyword_still_redacts():
    value = "aB3xK9mN2pQ7rT4wY1cV5bZ8dF0gH6jL"
    out, found = redact(f"api_key: {value}")
    assert out == f"api_key: {_REDACTED}"
    assert found == ["named secret field"]


# ─── Public endpoint URLs (a credential-named field holding a bare URL) ───────

# A Slack webhook URL embeds its secret in the path; its final segment is a
# 24-char opaque token mixing letters and digits. Assembled at runtime (like
# STRIPE_LIVE/AWS_KEY above) so the whole webhook literal never appears in the
# source and trips GitHub push protection.
_SLACK_WEBHOOK = (
    "https://hooks.slack.com/services/"
    + "T00000000/B00000000/"
    + "aB3xK9mN2pQ7rT4wY1cV5bZ8"
)


@pytest.mark.parametrize(
    "label, value, expected",
    [
        ("google oauth token endpoint", "https://oauth2.googleapis.com/token", True),
        (
            "azure authorize endpoint",
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            True,
        ),
        ("openai completions endpoint", "https://api.openai.com/v1/completions", True),
        (
            "hyphen-joined dated path (no opaque run)",
            "https://example.com/hooks/report-2024-01-15-final-summary",
            True,
        ),
        ("slack webhook with token path", _SLACK_WEBHOOK, False),
        (
            "userinfo password in authority",
            "https://user:s3cr3tpassw0rd@example.com/api",
            False,
        ),
        (
            "opaque token in query",
            "https://example.com/cb?access=aB3xK9mN2pQ7rT4wY1cV5bZ8",
            False,
        ),
        ("not a url", "aB3xK9mN2pQ7rT4wY1cV5bZ8dF0gH6jL", False),
        ("url with trailing junk is not fullmatch", "not-a-url-just-text-here", False),
    ],
)
def test_is_public_endpoint_url(label, value, expected):
    assert E._is_public_endpoint_url(value) is expected, label


@pytest.mark.parametrize(
    "field",
    ["token_url", "access_token_url", "secret_endpoint", "auth_url"],
)
def test_public_endpoint_url_skipped_after_keyword(field):
    # A public endpoint under a credential-named field is NOT a secret; skip it
    # on BOTH local and web ingress (a clean URL smuggles no credential).
    text = f"{field} = https://oauth2.googleapis.com/token"
    for web in (False, True):
        out, found = redact(text, cfg(web_ingress=web))
        assert out == text, (field, web)
        assert found == [], (field, web)


# A URL embedding a token/password IS a secret and must still redact — whether
# the field-value regex catches it or a structural detector (Slack/BasicAuth)
# does first. The carve-out must not let the embedded secret survive.
@pytest.mark.parametrize(
    "label, text, needle",
    [
        (
            "slack webhook token path",
            f"webhook_url = {_SLACK_WEBHOOK}",
            "aB3xK9mN2pQ7rT4wY1cV5bZ8",
        ),
        (
            "userinfo password",
            "auth_url = https://user:s3cr3tpassw0rd@example.com/api",
            "s3cr3tpassw0rd",
        ),
    ],
)
def test_secret_bearing_url_still_redacted(label, text, needle):
    assert E._is_public_endpoint_url(text.split(" = ", 1)[1]) is False, label
    for web in (False, True):
        out, found = redact(text, cfg(web_ingress=web))
        assert needle not in out, (label, web)
        assert found, (label, web)


# ─── Web-ingress disables relabelable skips ──────────────────────────────────


@pytest.mark.parametrize(
    "label, text, secret_value",
    [
        (
            "benign cursor",
            "next_token: abcdefghij1234567890XYZ",
            "abcdefghij1234567890XYZ",
        ),
        (
            "metadata field",
            'secret_type = "q9X2mN7pK4rT8wY1cV5bZ3dF6gH0jL2e"',
            "q9X2mN7pK4rT8wY1cV5bZ3dF6gH0jL2e",
        ),
        (
            "filesystem path",
            "secret=/run/monitor-secret:ro",
            "/run/monitor-secret:ro",
        ),
    ],
)
def test_web_ingress_disables_relabelable_skips(label, text, secret_value):
    local, _ = redact(text, cfg(web_ingress=False))
    web, _ = redact(text, cfg(web_ingress=True))
    assert local == text, f"{label}: local output must be unchanged"
    assert "[REDACTED" in web and web != text, f"{label}: web ingress must redact"
    assert secret_value not in web, f"{label}: web ingress must remove the secret value"


def test_handle_request_web_ingress_flag_redacts():
    result = handle_request_web("next_token: abcdefghij1234567890XYZ")
    assert result is not None
    assert "[REDACTED" in result["text"]


def handle_request_web(text):
    return run_plain(text, cfg(web_ingress=True))


def test_compose_mount_path_not_redacted():
    assert run_plain("- monitor-secret:/run/monitor-secret:ro") is None


@pytest.mark.parametrize(
    "value",
    [
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "/abcdefghij/klmnopqrst/uvwxyz1234",
    ],
)
def test_path_shaped_secret_still_redacted(value):
    result = run_plain(f"secret = {value}")
    assert result is not None
    assert result["text"] == "secret = [REDACTED]"


@pytest.mark.parametrize(
    "label, text",
    [
        ("no secret", "just a normal line of code"),
        ("short value", "password: short"),
        ("empty", ""),
    ],
)
def test_main_returns_nothing(label, text):
    assert run_plain(text) is None, label


def test_preserves_structure_and_json_contract():
    text = "line1: safe\npassword: SuperSecretP4ssword123456\nline3: also safe"
    result = run_plain(text)
    assert result is not None
    assert set(result.keys()) == {"text", "found"}
    assert result["text"] == "line1: safe\npassword: [REDACTED]\nline3: also safe"


def test_both_detectors_one_secret():
    result = run_plain(f'api_key = "{STRIPE_LIVE}"')
    assert result is not None
    assert "sk_live" not in result["text"]
    assert "_4eC39HqLyjWDarjtT1zdp7dc" not in result["text"]
    assert result["text"].count("[REDACTED") >= 1


# ─── Secret-format drift guard (engine side) ─────────────────────────────────


@pytest.mark.parametrize(
    "sample", SAMPLES, ids=[f"{s['name']}-{s['parts'][0]}" for s in SAMPLES]
)
def test_fixture_sample_is_redacted(sample):
    token = "".join(sample["parts"])
    result = run_plain(f"key: {token}")
    assert result is not None, sample
    assert sample["name"] in result["found"], sample
    assert token not in result["text"], sample


@pytest.mark.parametrize(
    "sample", SAMPLES, ids=[f"{s['name']}-{s['parts'][0]}" for s in SAMPLES]
)
def test_fixture_bodies_are_credential_shaped(sample):
    parts = sample["parts"]
    for chunk in [*parts, "".join(parts)]:
        longest = max(
            (len(m.group(0)) for m in re.finditer(r"(?P<c>.)(?P=c)*", chunk)),
            default=0,
        )
        assert longest < 8, (sample["name"], chunk)


@pytest.mark.parametrize(
    "sample", SAMPLES, ids=[f"{s['name']}-{s['parts'][0]}" for s in SAMPLES]
)
def test_fixture_token_is_redaction_eligible(sample):
    token = "".join(sample["parts"])
    assert E._is_placeholder_value(token) is False, sample
    result = run_plain(f"key: {token}")
    assert result is not None, sample
    assert sample["name"] in result["found"], sample
    assert token not in result["text"], sample


_BODY_RE = re.compile(r"^[A-Za-z0-9]{12,}$")
_SECRET_BODIES = [
    (s["name"], "".join(s["parts"]), body)
    for s in SAMPLES
    if s.get("robust", True)
    for body in s["parts"]
    if _BODY_RE.match(body)
]


def test_body_leak_guard_covers_prefix_token_formats():
    covered = {name for name, _, _ in _SECRET_BODIES}
    assert {"GitHub Token", "GitLab Token"} <= covered


@pytest.mark.parametrize(
    "name, token, body",
    _SECRET_BODIES,
    ids=[f"{n}-{b[:8]}" for n, _, b in _SECRET_BODIES],
)
def test_fixture_secret_body_fully_redacted(name, token, body):
    result = run_plain(f"key: {token}")
    assert result is not None, name
    assert body not in result["text"], (name, body)


# ─── Canonical needle ────────────────────────────────────────────────────────

_CANONICAL_NEEDLE_HALVES = ("q9X2mN7pK4rT8wY1", "cV5bZ3dF6gH0jL2e")
_CANONICAL_NEEDLE = "".join(_CANONICAL_NEEDLE_HALVES)


@pytest.mark.parametrize("value", [_CANONICAL_NEEDLE, *_CANONICAL_NEEDLE_HALVES])
def test_canonical_needle_is_credential_shaped(value):
    assert not E._is_placeholder_value(value), (
        f"redaction-test needle {value!r} is treated as a documentation placeholder"
    )


# ─── Map mode ────────────────────────────────────────────────────────────────


def test_map_mode_parity_and_reconstruction():
    text = (
        "# config\n"
        "password: SuperSecretP4ssword123456\n"
        "literal [REDACTED] stays\n"
        "DEBUG=1\n"
    )
    normal = run_plain(text)
    view = run_map(text)
    assert view["text"] == normal["text"]
    assert reconstruct(view) == text
    assert [p["placeholder"] for p in view["pairs"]] == ["[REDACTED]"]
    assert view["pairs"][0]["original"] == "SuperSecretP4ssword123456"
    assert view["found"] == normal["found"]


@pytest.mark.parametrize(
    "sample", SAMPLES, ids=[f"{s['name']}-{s['parts'][0]}" for s in SAMPLES]
)
def test_map_mode_reconstructs_every_sample_format(sample):
    token = "".join(sample["parts"])
    text = f"before\nkey: {token}\nafter\n"
    normal = run_plain(text)
    assert normal is not None, sample
    view = run_map(text)
    assert view["text"] == normal["text"], sample
    assert reconstruct(view) == text, sample


def test_map_mode_env_value_yields_pair_per_occurrence():
    value = "venicekeyvenicekeyvenicekeyX"
    config = cfg(provider_vars={"VENICE_INFERENCE_KEY": value})
    text = f"first {value} then {value} done\n"
    view = run_map(text, config)
    assert reconstruct(view) == text
    assert [p["original"] for p in view["pairs"]] == [value, value]
    assert {p["placeholder"] for p in view["pairs"]} == {
        "[REDACTED: VENICE_INFERENCE_KEY]"
    }


def test_map_mode_three_distinct_secrets_keep_their_own_original():
    vals = [
        "".join(["AlphaPwdValue", "0000000111"]),
        "".join(["BetaPwdValue", "00000002222"]),
        "".join(["GammaPwdValue", "0000003333"]),
    ]
    text = "".join(f"password: {v}\n" for v in vals)
    normal = run_plain(text)
    view = run_map(text)
    assert view["text"] == normal["text"]
    assert reconstruct(view) == text
    assert [p["placeholder"] for p in view["pairs"]] == ["[REDACTED]"] * 3
    assert [p["original"] for p in view["pairs"]] == vals


def test_map_mode_pem_block_swallowing_env_mark_reconstructs():
    value = "venicekeyvenicekeyvenicekeyX"
    config = cfg(provider_vars={"VENICE_INFERENCE_KEY": value})
    dashes = "-" * 5
    pem = (
        f"{dashes}BEGIN RSA PRIVATE KEY{dashes}\n"
        f"Zm9vYmFy{value}cXV4\n"
        f"{dashes}END RSA PRIVATE KEY{dashes}"
    )
    text = f"head\n{pem}\ntail\n"
    normal = run_plain(text, config)
    view = run_map(text, config)
    assert view["text"] == normal["text"]
    assert reconstruct(view) == text
    pem_pairs = [
        p for p in view["pairs"] if p["placeholder"] == "[REDACTED: Private Key]"
    ]
    assert len(pem_pairs) == 1
    assert pem_pairs[0]["original"] == pem


def test_map_mode_refuses_input_with_sentinel_chars():
    text = f"password: abc{chr(0xE000)}def0123456789abcdef\n"
    result = run_map(text)
    assert result == {"unmappable": "input contains reserved sentinel characters"}


def test_map_mode_empty_input():
    assert run_map("") == {"text": "", "pairs": [], "found": []}


def test_map_mode_clean_input_emits_empty_pairs():
    text = "nothing hidden here\n"
    view = run_map(text)
    assert view == {"text": text, "pairs": [], "found": []}


def test_detected_secret_values_harvests_raw_values():
    aws = "AKIA" + "IOSFODNN7EXAMPLE"
    values = detected_secret_values(f"aws_access_key_id={aws}\n")
    assert aws in values
    assert not any(v.startswith("[REDACTED") for v in values)


def test_detected_secret_values_dedupes_repeats():
    aws = "AKIA" + "IOSFODNN7EXAMPLE"
    values = detected_secret_values(f"a={aws}\nb={aws}\n")
    assert values.count(aws) == 1


def test_detected_secret_values_clean_text_is_empty():
    assert detected_secret_values("nothing to see here\n") == []


# ─── high_confidence ─────────────────────────────────────────────────────────


def test_high_confidence_plugin_subset_drops_keyword_detector():
    names = {p["name"] for p in E.PLUGINS_HIGH_CONFIDENCE}
    assert "KeywordDetector" not in names
    assert names == {p["name"] for p in E.PLUGINS} - {"KeywordDetector"}


def test_high_confidence_drops_keyword_match():
    text = 'password: "hunter2longplaintextvalue"\n'
    assert "hunter2longplaintextvalue" in detected_secret_values(text)
    assert detected_secret_values(text, cfg(high_confidence=True)) == []


def test_high_confidence_drops_named_field_regex():
    text = "access_token=abcdefghijklmnopqrstuvwxyz0123\n"
    assert detected_secret_values(text)
    assert detected_secret_values(text, cfg(high_confidence=True)) == []


def test_high_confidence_keeps_structural_detection():
    aws = "AKIA" + "IOSFODNN7EXAMPLE"
    assert aws in detected_secret_values(
        f"aws_access_key_id={aws}\n", cfg(high_confidence=True)
    )


def test_high_confidence_keeps_pem_block():
    pem = "-----BEGIN PRIVATE KEY-----\nMIIBVgIBADAN\n-----END PRIVATE KEY-----\n"
    assert detected_secret_values(pem, cfg(high_confidence=True))


# ─── masked context previews ─────────────────────────────────────────────────


def test_mask_secret_lines_empty_when_no_values():
    assert mask_secret_lines("anything at all\n", []) == []


def test_secret_previews_masks_value_keeps_context():
    aws = "AKIA" + "IOSFODNN7EXAMPLE"
    previews = secret_previews(f"aws_access_key_id={aws}\n")
    assert previews == ["aws_access_key_id=********"]
    assert aws not in "".join(previews)


def test_secret_previews_only_lines_with_a_secret():
    aws = "AKIA" + "IOSFODNN7EXAMPLE"
    text = f"TIMEOUT=30\naws_access_key_id={aws}\nRETRIES=5\n"
    assert secret_previews(text) == ["aws_access_key_id=********"]


def test_secret_previews_dedupes_identical_lines():
    aws = "AKIA" + "IOSFODNN7EXAMPLE"
    text = f"key={aws}\nkey={aws}\n"
    assert secret_previews(text) == ["key=********"]


def test_secret_previews_caps_long_line_keeps_field_visible():
    aws = "AKIA" + "IOSFODNN7EXAMPLE"
    text = "x" * 200 + f" aws_access_key_id={aws}\n"
    [preview] = secret_previews(text)
    assert len(preview) <= E._PREVIEW_MAX_LEN
    assert preview.startswith("...")
    assert preview.endswith("aws_access_key_id=********")
    assert aws not in preview


def test_secret_previews_caps_long_trailing_keeps_field_at_start():
    aws = "AKIA" + "IOSFODNN7EXAMPLE"
    text = f"key={aws} " + "y" * 200 + "\n"
    assert secret_previews(text) == ["key=********"]


def test_secret_previews_multiline_pem_collapses_to_one_line():
    pem = "-----BEGIN PRIVATE KEY-----\nMIIBVgIBADAN\n-----END PRIVATE KEY-----"
    [preview] = secret_previews(pem)
    assert "\n" not in preview and "********" in preview
    assert "MIIBVgIBADAN" not in preview


def test_secret_previews_honors_high_confidence():
    text = 'password: "hunter2longplaintextvalue"\n'
    assert secret_previews(text)
    assert secret_previews(text, cfg(high_confidence=True)) == []


# ─── Default-argument behaviour ──────────────────────────────────────────────


def test_default_web_ingress_keeps_benign_cursor():
    cursor = "next_token=abcdefghij1234567890XYZ"
    text, found = redact(cursor)
    assert text == cursor and found == []
    assert detected_secret_values(cursor) == []


def test_default_high_confidence_keeps_field_value_detector():
    field = "api_key=Zk3pQ7mW9nR2tY5cV8bN1dF4hG6jL0aZ"
    assert "named secret field" in redact(field)[1]
    assert detected_secret_values(field) != []


def test_configure_plugins_then_redact_configured():
    """The daemon's hot path: configure the plugin set ONCE, then redact many
    times without the per-call cache dance. Result must equal the one-shot
    ``redact``."""
    from agent_sanitizer.secrets import configure_plugins, redact_configured

    text = "key: AKIAIOSFODNN7EXAMPLE"
    with configure_plugins():
        out, found = redact_configured(text, None, RedactorConfig())
    assert out == "key: [REDACTED: AWS Access Key]"
    assert found == ["AWS Access Key"]


def test_env_value_re_not_memoized_so_no_plaintext_retention():
    """`_env_value_re` must NOT be wrapped in functools.cache / lru_cache: such a
    cache is keyed on the PLAINTEXT secret ``value`` and, being unbounded, would
    retain every requester's secret forever (memory leak + secret hoarding). The
    presence of ``cache_info``/``cache_clear`` is the tell-tale of that wrapper;
    their ABSENCE proves distinct plaintext values are not retained across calls.
    re.compile self-caches the compiled Pattern, so no function-level memo is
    needed for perf and the pattern is still built correctly."""
    from agent_sanitizer.secrets.invisible import default_charset

    assert not hasattr(E._env_value_re, "cache_info")
    assert not hasattr(E._env_value_re, "cache_clear")
    charset = default_charset()
    assert E._env_value_re("abcdef", charset).fullmatch("abcdef")


def test_configure_plugins_exit_propagates_cache_clear_error(eng, monkeypatch):
    """`configure_plugins().__exit__` must not swallow an exception raised in its
    `try` body. A `return` inside the `finally` would mask a failing
    ``cache_clear()``; the fixed version releases the transient settings in the
    `finally` and lets the exception propagate."""
    from agent_sanitizer.secrets import configure_plugins

    class _Boom(Exception):
        pass

    ctx = configure_plugins()
    ctx.__enter__()

    class _RaisingMapping:
        def cache_clear(self):
            raise _Boom("cache_clear failed")

    monkeypatch.setattr(eng, "get_mapping_from_secret_type_to_class", _RaisingMapping())
    with pytest.raises(_Boom):
        ctx.__exit__(None, None, None)


def test_precision_legit_nonsecret_input_yields_zero_findings():
    """Precision guard: ordinary prose and benign config-shaped lines must produce
    NO findings — a false positive here mangles real content the model needed."""
    benign = "\n".join(
        [
            "The quick brown fox jumps over the lazy dog.",
            "user: alice",
            "port: 8080",
            "path: /usr/local/bin/agent-sanitizer",
            "retries: 3",
            "level: info",
        ]
    )
    out, found = redact(benign)
    assert found == []
    assert out == benign


def test_named_field_keeps_content_digest_value():
    digest = "sha256:3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b"
    needle = "api_key=" + digest
    out, found = redact(needle)
    assert out == needle and found == []


# ─── SSOT-driven per-member guards for the keyword enumerations ───────────────


def _top_level_alternatives(pattern: str) -> list[str]:
    alts: list[str] = []
    depth = 0
    cur: list[str] = []
    for ch in pattern:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "|" and depth == 0:
            alts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    alts.append("".join(cur))
    return alts


_FIELD_NAME_REPRESENTATIVES = [
    "api_key",
    "secret",
    "client_secret",
    "access_token",
    "private_key",
    "authorization",
    "password",
    "passwd",
    "bearer",
    "token",
]


def test_field_names_every_member_redacts():
    alts = _top_level_alternatives(E._FIELD_NAMES)
    assert len(alts) == len(_FIELD_NAME_REPRESENTATIVES), {
        "members": alts,
        "representatives": _FIELD_NAME_REPRESENTATIVES,
    }
    for alt, field in zip(alts, _FIELD_NAME_REPRESENTATIVES, strict=True):
        assert re.fullmatch(alt, field), f"{field!r} is not an instance of {alt!r}"
        out, found = redact(f"{field} = {_BRACKET_NEEDLE}")
        assert _BRACKET_NEEDLE not in out, f"{field} value survived redaction"
        assert found, f"{field} reported no finding"


def test_benign_token_prefixes_every_member_passes_through():
    assert (
        frozenset(
            {"next", "page", "nextpage", "continuation", "scroll", "sync", "pagination"}
        )
        == E._BENIGN_TOKEN_PREFIXES
    )
    for prefix in sorted(E._BENIGN_TOKEN_PREFIXES):
        text = f"{prefix}_token = {_BRACKET_NEEDLE}"
        out, found = redact(text)
        assert _BRACKET_NEEDLE in out, f"{prefix}_token cursor was redacted"
        assert found == [], f"{prefix}_token reported a finding: {found}"


def test_fs_path_every_root_skips_local_redaction():
    inner = re.search(r"/\(\?:(?P<roots>[^)]+)\)", E._FS_PATH_RE.pattern)
    assert inner, "could not locate the root alternation in _FS_PATH_RE"
    roots = inner.group("roots").split("|")
    assert len(roots) >= 15, roots
    for root in roots:
        out, found = redact(f"token: /{root}/{_BRACKET_NEEDLE}")
        assert f"/{root}/{_BRACKET_NEEDLE}" in out, f"/{root}/ path was redacted"
        assert found == [], f"/{root}/ path reported a finding"
    out, found = redact(f"token: /notaroot/{_BRACKET_NEEDLE}")
    assert _BRACKET_NEEDLE not in out, "non-root path unexpectedly skipped"
    assert found
