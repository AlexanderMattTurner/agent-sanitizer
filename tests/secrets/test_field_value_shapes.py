"""Credential-named fields whose value is quoted with spaces or escapes, or is
short under an upper-case env-style name — each case leaked on 2.58.9.

Driven through the public :func:`redact`, asserting the exact output, so the
regex arm, the floor decision in ``_replace_field`` and the benign gates are
all exercised together.
"""

import pytest

from agent_sanitizer.secrets import redact

_FIELD = ["named secret field"]
_KEYWORD = ["Secret Keyword"]


@pytest.mark.parametrize(
    "text, expected, found",
    [
        # A quoted value runs to its own closing quote, spaces included.
        (
            'FOO_TOKEN: "FAKEFAKEsecret0123456789 tail"',
            'FOO_TOKEN: "[REDACTED]"',
            _FIELD,
        ),
        (
            'FOO_TOKEN: "short FAKEFAKEsecret0123456789"',
            'FOO_TOKEN: "[REDACTED]"',
            _FIELD,
        ),
        ('GH_AUTH_TOKEN="hunter2 tail"', 'GH_AUTH_TOKEN="[REDACTED]"', _FIELD),
        ('SSH_PASSPHRASE="hunter2 tail"', 'SSH_PASSPHRASE="[REDACTED]"', _FIELD),
        (
            'SSH_PASSPHRASE="correct horse battery staple"',
            'SSH_PASSPHRASE="[REDACTED]"',
            _FIELD,
        ),
        ("token: 'abc def ghi1'", "token: '[REDACTED]'", _FIELD),
    ],
)
def test_quoted_value_with_spaces_redacts_whole(text, expected, found):
    assert redact(text) == (expected, found)


@pytest.mark.parametrize(
    "text, expected, found",
    [
        (
            '{"FOO_TOKEN":"a\\"FAKEFAKEsecret0123456789"}',
            '{"FOO_TOKEN":"[REDACTED]"}',
            _FIELD,
        ),
        (
            '{"FOO_TOKEN":"FAKEFAKEsecret0123456789\\"FAKEtail"}',
            '{"FOO_TOKEN":"[REDACTED]"}',
            _FIELD,
        ),
        # The keyword detector's double-quoted value reads `\"` as one unit too.
        (
            '{"password": "abc\\"defghijklmnopqrstuvwxyz"}',
            '{"password": "[REDACTED: Secret Keyword]"}',
            _KEYWORD,
        ),
        (
            '{"password": "hu\\"nter2"}',
            '{"password": "[REDACTED: Secret Keyword]"}',
            _KEYWORD,
        ),
        # A single-quoted value keeps the backslash literal (shell `'v\'`).
        (
            "password: 'hunter2\\'",
            "password: '[REDACTED: Secret Keyword]'",
            _KEYWORD,
        ),
    ],
)
def test_json_value_with_escaped_quote_redacts_whole(text, expected, found):
    assert redact(text) == (expected, found)


@pytest.mark.parametrize(
    "text, expected",
    [
        ("DB_PASSWORD=hunter2", "DB_PASSWORD=[REDACTED]"),
        ("FOO_TOKEN=hunter2", "FOO_TOKEN=[REDACTED]"),
        ('"FOO_TOKEN": "s3cret-value"', '"FOO_TOKEN": "[REDACTED]"'),
        ("export FOO_TOKEN=s3cret-value", "export FOO_TOKEN=[REDACTED]"),
        (
            "--build-arg ANTHROPIC_API_KEY=s3cret-value",
            "--build-arg ANTHROPIC_API_KEY=[REDACTED]",
        ),
        ("PGPASSWORD=hunter2 psql", "PGPASSWORD=[REDACTED] psql"),
        ("GH_TOKEN=abc1;", "GH_TOKEN=[REDACTED];"),
    ],
)
def test_short_value_under_credential_name_redacts(text, expected):
    assert redact(text) == (expected, _FIELD)


@pytest.mark.parametrize(
    "text, expected, found",
    [
        # A quoted header keeps its scheme, as the unquoted form does.
        (
            '{"Authorization": "Bearer Zx9qW7rT2pL5mN8bV3cX6zA1sD4f"}',
            '{"Authorization": "Bearer [REDACTED]"}',
            _FIELD,
        ),
        (
            "Authorization: Bearer Zx9qW7rT2pL5mN8bV3cX6zA1sD4f",
            "Authorization: Bearer [REDACTED]",
            _FIELD,
        ),
        (
            "AUTHORIZATION: BEARER Zx9qW7rT2pL5mN8bV3cX6zA1sD4f",
            "AUTHORIZATION: BEARER [REDACTED]",
            _FIELD,
        ),
        (
            "Authorization: Basic dXNlcjpwYXNzd29yZA==",
            "Authorization: Basic [REDACTED]",
            _FIELD,
        ),
        (
            "curl -H 'Authorization: Bearer Zx9qW7rT2pL5mN8bV3cX6zA1sD4f' x",
            "curl -H 'Authorization: Bearer [REDACTED]' x",
            _FIELD,
        ),
        (
            "https://user:hunter2pass@host.example.com",
            "https://user:[REDACTED: Basic Auth Credentials]@host.example.com",
            ["Basic Auth Credentials"],
        ),
    ],
)
def test_header_and_url_credentials_keep_their_shape(text, expected, found):
    assert redact(text) == (expected, found)


@pytest.mark.parametrize(
    "text",
    [
        "password=prose",
        "max_tokens=1000",
        "NEXT_TOKEN=abc",
        '"token": "the access token"',
        "sk-ant-xxx",
        # Below the 20-char floor, a lower-case name is not an env assignment.
        "password: hunter2",
        "token = abc123",
        # The noun must END the name; a suffix names metadata.
        'token_type: "Bearer abc"',
        "PASSWORD_MIN_LENGTH=8",
        'API_KEY_NAME="prod"',
        # `:` on an upper-case name is an annotation or header, not assignment.
        'API_KEY: str = ""',
        "API_KEY: hunter2",
        # References and calls name a secret without holding one.
        "API_KEY=$API_KEY",
        "TOKEN=${TOKEN}",
        'API_KEY = getenv("API_KEY")',
        "GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}",
        "SECRET_KEY = settings.SECRET_KEY",
        "API_KEY=None",
        "TOKEN=",
        '"token": "Token"',
        # An "opening" quote that really closes an outer string.
        '(e.g. old_string: "password=", new_string: "notes=" — neither)',
        'msg = "set TOKEN=" + value',
    ],
)
def test_benign_field_text_is_untouched(text):
    assert redact(text) == (text, [])
