"""RedactorConfig: env-secret union semantics and charset resolution."""

from agent_sanitizer.secrets import RedactorConfig, redact
from agent_sanitizer.secrets.config import DEFAULT_MIN_SECRET_LEN

_LONG = "qZ7vK2mNp9rT4wX1cY6bA8dF3gH5jL0e"


def test_env_secrets_unions_provider_and_host_provider_first():
    """env_secrets is the provider vars then the host-credential vars, deduped by
    name (provider position kept). This mirrors the two SSOTs the caller passes —
    the inference keys and the sandbox-blanked host creds — that the JS redactor
    also unions; a drift here silently splits host-credential redaction."""
    config = RedactorConfig(
        provider_vars={"MONITOR_API_KEY": "m", "ANTHROPIC_API_KEY": "a"},
        host_cred_vars={"GH_TOKEN": "g", "AWS_SECRET_ACCESS_KEY": "s"},
    )
    assert list(config.env_secrets) == [
        "MONITOR_API_KEY",
        "ANTHROPIC_API_KEY",
        "GH_TOKEN",
        "AWS_SECRET_ACCESS_KEY",
    ]


def test_env_secrets_host_value_wins_on_name_collision():
    config = RedactorConfig(
        provider_vars={"TOKEN": "provider"},
        host_cred_vars={"TOKEN": "host"},
    )
    assert config.env_secrets == {"TOKEN": "host"}


def test_default_min_secret_len():
    assert RedactorConfig().min_secret_len == DEFAULT_MIN_SECRET_LEN == 16


def test_both_provider_and_host_values_redact():
    config = RedactorConfig(
        provider_vars={"VENICE_INFERENCE_KEY": _LONG},
        host_cred_vars={"GH_TOKEN": "a" * 20},
    )
    out, found = redact(f"v={_LONG} g={'a' * 20}", config)
    assert _LONG not in out
    assert "VENICE_INFERENCE_KEY" in found and "GH_TOKEN" in found


def test_explicit_charset_is_used_without_touching_shared_dep():
    """An explicit invisible_charset short-circuits resolved_charset, so it never
    imports the shared dependency."""
    config = RedactorConfig(invisible_charset=frozenset({0x200B}))
    assert config.resolved_charset() == frozenset({0x200B})


def test_resolved_charset_defaults_to_shared_ssot():
    from agent_sanitizer.invisible import invisible_charset

    assert RedactorConfig().resolved_charset() == invisible_charset()


def test_bare_config_has_no_env_secrets():
    assert RedactorConfig().env_secrets == {}
