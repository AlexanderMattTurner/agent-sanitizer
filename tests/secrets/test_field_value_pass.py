"""The `field = value` pass: where a benign verdict stops, which quotes wrap a
value, which locators and field names hold no secret, which view it reads, and
which code points it refuses.

Every positive case is paired with the legitimate shape it must leave alone, and
the shared negative corpus stays at zero findings — a false positive here
deletes text the model needed.
"""

import pytest

import agent_sanitizer.secrets.engine as E
from agent_sanitizer.secrets import (
    detected_secret_values,
    mask_secret_lines,
    redact,
    redact_map,
)
from redactor_helpers import LEGITIMATE, SAMPLES, cfg, reconstruct, run_plain

# Opaque, mixed-case and mixed-digit: caught by the field-value pass alone, so a
# leak of it is the field pass's leak and no structural detector's catch.
_OPAQUE = "Zq8wLm3Vt7Rk2Xp9Nb4Hc6Jd"
_LDQ, _RDQ = "\u201c", "\u201d"
_LSQ, _RSQ = "\u2018", "\u2019"
_ZWSP = "\u200b"
_WORD_JOINER = "\u2060"


def _plain(text: str, **config) -> str:
    out, _found = redact(text, cfg(**config))
    return out


# ─── A benign verdict consumes nothing ────────────────────────────────────────


@pytest.mark.parametrize(
    "text, kept",
    [
        (f"token_type=bearer&access_token={_OPAQUE}", "token_type=bearer&"),
        (f"secret_name=prod;password={_OPAQUE}", "secret_name=prod;"),
        (f"secret_path=/run/x&password={_OPAQUE}", "secret_path=/run/x&"),
        (f"nextPageToken=CiAKGjBpNDd2;secret={_OPAQUE}", "nextPageToken=CiAKGjBpNDd2;"),
        (
            f"token_type=bearer&token_name=ci&client_secret={_OPAQUE}",
            "token_type=bearer&token_name=ci&",
        ),
    ],
)
def test_a_pair_inside_a_benign_value_is_still_judged(text, kept):
    """`token_type=bearer&access_token=X` reads as ONE metadata value; judging it
    benign must not skip the credential pair it contains."""
    out = _plain(text)
    assert _OPAQUE not in out, text
    assert out.startswith(kept), out


@pytest.mark.parametrize("label", sorted(LEGITIMATE))
@pytest.mark.parametrize("sep", ["&", ";", ","])
def test_no_benign_prefix_shadows_a_following_secret(label, sep):
    """Every legitimate line, glued to a credential pair: whatever the prefix's
    verdict, the pair after it is judged on its own."""
    text = f"{LEGITIMATE[label]}{sep}password={_OPAQUE}"
    result = run_plain(text)
    assert result is not None, text
    assert _OPAQUE not in result["text"], text


@pytest.mark.parametrize("sample", SAMPLES, ids=lambda s: s["name"])
def test_no_benign_metadata_value_shadows_a_sample_secret(sample):
    secret = "".join(sample["parts"])
    out = _plain(f"secret_path=/run/x&api_key={secret}")
    assert secret not in out, sample["name"]


def test_nested_pairs_inside_a_benign_value_leave_benign_inner_values():
    """The inner pairs are judged like any other: a benign one stays verbatim."""
    text = (
        "token_url=https://idp.example/authorize?response_type=code&token_type=bearer"
    )
    assert run_plain(text) is None


# ─── Typographic quotes wrap a value, they are not part of it ────────────────


@pytest.mark.parametrize(
    "text",
    [
        f"password: {_LDQ}process.env.DB_PASSWORD{_RDQ}",
        f"api_key = {_LSQ}os.environ['API_KEY']{_RSQ}",
        f"token: {_LDQ}<your-token-here>{_RDQ}",
        "secret = \u00ab${SECRET_FILE}\u00bb",
    ],
)
def test_a_curly_quoted_reference_is_not_a_secret(text):
    """Peeled as a pair, the quotes stay out of the value, so the
    fullmatch-anchored benign-shape gates judge the reference itself."""
    assert run_plain(text) is None, text


@pytest.mark.parametrize(
    "opener, closer",
    [
        (_LDQ, _RDQ),
        (_LSQ, _RSQ),
        ("\u00ab", "\u00bb"),
        ("\u201e", _LDQ),
        ("\uff02", "\uff02"),
    ],
)
def test_a_curly_quoted_secret_redacts_inside_its_quotes(opener, closer):
    out = _plain(f"password = {opener}{_OPAQUE}{closer} tail")
    assert out == f"password = {opener}[REDACTED]{closer} tail", out


def test_every_quote_pair_is_in_the_value_exclusion_class():
    """The value class is derived from the pair table, so a pair added there is
    excluded from values with no second edit."""
    for opener, closer in E._TYPOGRAPHIC_QUOTE_PAIRS:
        assert opener in E._QUOTE_CHARS and closer in E._QUOTE_CHARS
    assert len(E._TYPOGRAPHIC_QUOTE_PAIRS) >= 5


# ─── A locator is a location, unless it carries a token ─────────────────────


@pytest.mark.parametrize(
    "value",
    [
        "/Users/alice/.config/gh/hosts.yml",
        "~/.config/gh/hosts.yml",
        "./config/dev-secrets.yaml",
        "../shared/tokens/ci.txt",
        "C:\\Users\\alice\\AppData\\pw.txt",
        "C:/ProgramData/app/secret.bin",
        "/Volumes/keys/deploy.pem",
        "/etc/vault/agent/current-token",
    ],
)
def test_a_filesystem_path_is_not_redacted_locally(value):
    assert run_plain(f"token: {value}") is None, value
    # A forgeable spelling: web ingress still redacts it.
    assert value not in _plain(f"token: {value}", web_ingress=True), value


@pytest.mark.parametrize(
    "value", [f"/etc/{_OPAQUE}", f"~/{_OPAQUE}", f"./keys/{_OPAQUE}", f"C:\\{_OPAQUE}"]
)
def test_a_path_carrying_an_opaque_run_still_redacts(value):
    assert _OPAQUE not in _plain(f"token: {value}"), value


def test_path_and_url_share_one_locator_verdict():
    """Both gates refuse a locator carrying an opaque run, through one predicate."""
    url = E.Candidate(value=f"https://hooks.example/{_OPAQUE}", line="")
    path = E.Candidate(value=f"/srv/{_OPAQUE}", line="")
    assert not E._is_public_endpoint_url(url)
    assert not E._is_filesystem_path(path)
    assert E._is_clean_locator("https://idp.example/token", E._ENDPOINT_URL_RE)
    assert E._is_clean_locator("/srv/app/token", E._FS_PATH_RE)


# ─── Non-secret field-name suffixes come from the shared vocabulary ─────────


@pytest.mark.parametrize(
    "text",
    [
        '"private_key_id": "2b5e8c1d9f3a4b6c7d8e9f0a1b2c3d4e5f6a7b8c",',
        "signing_key_id = 7f3a9c2e4b6d8f0a1c3e5b7d9f2a4c6e",
        'ssh_public_key = "AAAAB3NzaC1yc2EAAAADAQABAAABAQC7xyzQ"',
    ],
)
def test_a_non_secret_suffixed_field_is_not_redacted(text):
    assert run_plain(text) is None, text


def test_a_bare_id_suffix_is_not_a_non_secret_marker():
    """Vault's AppRole `secret_id` IS a credential: only the two-word `key_id`
    marks an identifier."""
    assert "8f3c2a1b9d7e6f5a4c3b2a1d" not in _plain(
        "secret_id = 8f3c2a1b9d7e6f5a4c3b2a1d9e8f7a6b"
    )


def test_the_metadata_suffixes_are_the_vocabularys_non_secret_suffixes():
    """One list: the engine's metadata gate reads the same `nonSecretSuffixes`
    the name matchers decline."""
    expected = {s.lower() for s in E.non_secret_name_segments()}
    assert set(E._METADATA_SUFFIXES) == expected
    assert {"key_id", "public_key", "type", "path"} <= expected
    assert "id" not in expected


# ─── Every pass reads the invisible-stripped view ─────────────────────────────


@pytest.mark.parametrize(
    "text",
    [
        f"pass{_ZWSP}word = {_OPAQUE}",
        f"to{_WORD_JOINER}ken: {_OPAQUE}",
        f"client_{_ZWSP}secret={_OPAQUE}",
    ],
)
def test_an_invisible_char_in_a_field_name_does_not_hide_its_value(text):
    result = run_plain(text)
    assert result is not None, text
    assert _OPAQUE not in result["text"], text
    # Everything outside the value is kept byte-for-byte, invisible included.
    assert result["text"].startswith(text[: text.index(_OPAQUE)]), result["text"]


def test_an_invisible_char_inside_a_value_goes_with_it():
    text = f"password = Zq8wLm3V{_ZWSP}t7Rk2Xp9Nb4Hc6Jd tail"
    assert _plain(text) == "password = [REDACTED] tail"
    view = redact_map(text)
    assert reconstruct(view) == text
    assert view["text"] == _plain(text)


# ─── The reserved code points ───────────────────────────────────────────────


def test_a_value_stops_at_every_reserved_code_point():
    for sentinel in E._SENTINEL_CHARS:
        match = E.FIELD_VALUE_RE.search(f"password={_OPAQUE}{sentinel}tail")
        assert match is not None
        assert match.group("secret_value") == _OPAQUE, repr(sentinel)


def test_a_secret_glued_onto_a_detected_token_round_trips_in_map_mode():
    """The field value stops at the AWS redaction's map sentinel exactly as it
    stops at a plain-mode placeholder's bracket, so the two modes agree."""
    text = "password: q9X2mN7pK4rT8wY1cV5bZ3dF6gH0jL2eAKIAIOSFODNN7EXAMPLE"
    view = redact_map(text)
    assert reconstruct(view) == text
    assert view["text"] == _plain(text)
    assert "IOSFODNN7EXAMPLE" not in view["text"]


@pytest.mark.parametrize("sentinel", list(E._SENTINEL_CHARS))
def test_every_path_that_plants_a_sentinel_refuses_one_in_its_input(sentinel):
    text = f"aws_access_key_id=AKIAIOSFODNN7EXAMPLE {sentinel}"
    assert "unmappable" in redact_map(text)
    with pytest.raises(ValueError, match="reserved sentinel"):
        detected_secret_values(text)
    with pytest.raises(ValueError, match="reserved sentinel"):
        mask_secret_lines(text, ["AKIAIOSFODNN7EXAMPLE"])


def test_the_mask_path_still_masks_clean_text():
    """Positive marker for the refusal above: clean text reaches the mask."""
    assert mask_secret_lines("k=AKIAIOSFODNN7EXAMPLE", ["AKIAIOSFODNN7EXAMPLE"]) == [
        "k=********"
    ]
