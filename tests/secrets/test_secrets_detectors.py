"""Ported custom-detector tests (was the secret_plugins.py half of the suite)."""

import json
import re
import string
import time

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import agent_sanitizer.secrets.detectors as D
import agent_sanitizer.secrets.engine as E
from redactor_helpers import SAMPLES, run_plain

_DETECTORS_JSON = D.DETECTORS_FILE
_INLINE_DETECTOR = "JwtFullTokenDetector"


def test_custom_plugins_derived_from_detector_ssot():
    configured = [
        entry["const"] for entry in json.loads(_DETECTORS_JSON.read_text())["detectors"]
    ]
    names = [plugin["name"] for plugin in E.CUSTOM_PLUGINS]
    assert names == [*configured, _INLINE_DETECTOR]
    assert all(p["path"].endswith("detectors.py") for p in E.CUSTOM_PLUGINS)
    for name in names:
        assert isinstance(getattr(D, name, None), type), (
            f"{name} is registered but detectors.py exposes no class of that name"
        )


_JWT_HEADER = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
_JWT_PAYLOAD = "eyJzdWIiOiIxMjM0NTY3ODkwIn0"


@pytest.mark.parametrize("siglen", [40, 41, 42, 43, 44, 45])
@pytest.mark.parametrize("trailing", ["", "-", "_", ".", " ", "="])
def test_jwt_redacts_regardless_of_signature_length(siglen, trailing):
    detector = D.JwtFullTokenDetector()
    token = f"{_JWT_HEADER}.{_JWT_PAYLOAD}.{'A' * siglen}{trailing}"
    assert list(detector.analyze_string(token)), (
        f"JWT leaked (siglen={siglen} mod4={siglen % 4}, trailing={trailing!r})"
    )


@pytest.mark.parametrize(
    "token",
    [
        "eyJ" + "A" * 12 + ".eyJ" + "B" * 12 + ".CCCC",
        _JWT_HEADER + ".eyJ" + "Z" * 12 + ".CCCC",
        "eyJAA.eyJzdWIiOiIxMjM0In0.CCCC",
    ],
)
def test_jwt_rejects_non_json_header_or_payload(token):
    detector = D.JwtFullTokenDetector()
    assert not list(detector.analyze_string(token))


def test_jwt_with_x5c_cert_chain_header_is_redacted():
    """A JWT whose header carries an x5c certificate CHAIN (RFC 7515) runs the
    header segment well past the old 8192-char per-segment bound; the bounded
    quantifier must clear a multi-cert header or the whole token leaks."""
    import base64

    # A valid base64url-JSON header whose encoded length exceeds 8192 chars — a
    # realistic x5c chain is several base64 DER certs.
    header = {"alg": "RS256", "typ": "JWT", "x5c": ["M" * 7000]}
    encoded_header = (
        base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    )
    assert len(encoded_header) > 8192
    token = f"{encoded_header}.{_JWT_PAYLOAD}.{'A' * 43}"
    detector = D.JwtFullTokenDetector()
    assert list(detector.analyze_string(token)), "x5c-header JWT leaked in cleartext"


def test_custom_detectors_defined():
    anthropic = D.AnthropicApiKeyDetector
    google = D.GoogleApiKeyDetector
    assert anthropic.secret_type == "Anthropic API Key"
    assert google.secret_type == "Google API Key"
    assert anthropic.denylist[0].search("sk-ant-api03-" + "A" * 93 + "AA")
    assert google.denylist[0].search("AIza" + "Sy" + "A" * 33)


@pytest.mark.parametrize(
    "cls_name, secret_type, hit, misses",
    [
        (
            "OpenRouterApiKeyDetector",
            "OpenRouter API Key",
            "sk-or-v1-" + "0" * 64,
            ["sk-or-v1-" + "0" * 10, "sk-or-v1-release-2024"],
        ),
        (
            "GroqApiKeyDetector",
            "Groq API Key",
            "gsk_" + "a" * 52,
            ["gsk_" + "a" * 8, "gsk_render_node_new_widget"],
        ),
        (
            "XaiApiKeyDetector",
            "xAI API Key",
            "xai-" + "a" * 80,
            ["xai-" + "a" * 8, "xai-config-loader-v2"],
        ),
        (
            "ReplicateApiTokenDetector",
            "Replicate API Token",
            "r8_" + "a" * 37,
            ["r8_" + "a" * 8, "r8_cache_key_lookup"],
        ),
        (
            "DigitalOceanTokenDetector",
            "DigitalOcean Token",
            "dop_v1_" + "a" * 64,
            ["dop_v1_" + "a" * 30, "dop_v1_" + "g" * 64, "dox_v1_" + "a" * 64],
        ),
        (
            "CloudflareOriginCaKeyDetector",
            "Cloudflare Origin CA Key",
            "v1.0-" + "a" * 24 + "-" + "b" * 146,
            [
                "v1.0-" + "a" * 24 + "-" + "b" * 40,
                "v2.0-" + "a" * 24 + "-" + "b" * 146,
                "v1.0-" + "a" * 24 + "-" + "g" * 146,
            ],
        ),
        (
            "VaultTokenDetector",
            "Vault Token",
            "hvs." + "a" * 90,
            ["hvs." + "a" * 20, "hvx." + "a" * 90, "hvs-" + "a" * 90],
        ),
        (
            "HashiCorpTerraformTokenDetector",
            "Terraform Cloud API Token",
            "a" * 14 + ".atlasv1." + "b" * 65,
            [
                "a" * 14 + ".atlasv1." + "b" * 20,
                "a" * 5 + ".atlasv1." + "b" * 65,
                "a" * 14 + ".atlasv2." + "b" * 65,
            ],
        ),
        (
            "GitHubFineGrainedPatDetector",
            "GitHub Fine-Grained PAT",
            "github_pat_" + "a" * 82,
            [
                "github_pat_" + "a" * 20,
                "github_pot_" + "a" * 82,
                "github_pat_" + "-" * 82,
            ],
        ),
    ],
)
def test_non_gitleaks_provider_detectors(cls_name, secret_type, hit, misses):
    det = getattr(D, cls_name)
    assert det.secret_type == secret_type
    assert det.denylist[0].search(hit)
    for miss in misses:
        assert not det.denylist[0].search(miss), miss


@pytest.mark.parametrize(
    "cls_name, prefix, floor",
    [
        ("GroqApiKeyDetector", "gsk_", 32),
        ("XaiApiKeyDetector", "xai-", 40),
        ("ReplicateApiTokenDetector", "r8_", 37),
    ],
)
def test_prefix_detectors_pin_distinctive_length_floor(cls_name, prefix, floor):
    denylist = getattr(D, cls_name).denylist[0]
    assert denylist.search(prefix + "a" * floor)
    assert not denylist.search(prefix + "a" * (floor - 1))


# ─── Multi-member prefix families: one redaction case per member ─────────────

_DETECTOR_PATTERNS = {
    d["secret_type"]: d["patterns"]
    for d in json.loads(_DETECTORS_JSON.read_text())["detectors"]
}


def _sample_token(secret_type: str) -> str:
    for s in SAMPLES:
        if s["name"] == secret_type:
            return "".join(s["parts"])
    raise AssertionError(f"no fixture sample for {secret_type}")


_PREFIX_FAMILIES = [
    ("Anthropic API Key", "api03-", ["api03-", "admin01-"]),
    ("DigitalOcean Token", "dop_", ["doo_", "dop_", "dor_"]),
    ("Vault Token", "hvs.", ["hvs.", "hvb."]),
    ("GitHub Token", "ghp_", ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"]),
    (
        "GitLab Token",
        "glpat-",
        ["glpat-", "gldt-", "glft-", "glsoat-", "glrt-", "glcbt-"],
    ),
]

_PREFIX_MEMBER_CASES = [
    (secret_type, member, _sample_token(secret_type).replace(base, member, 1))
    for secret_type, base, members in _PREFIX_FAMILIES
    for member in members
]
_PREFIX_MEMBER_CASES.append(
    (
        "GitLab Token",
        "glcbt-ab_",
        _sample_token("GitLab Token").replace("glpat-", "glcbt-ab_", 1),
    )
)


@pytest.mark.parametrize(
    "secret_type, member, token",
    _PREFIX_MEMBER_CASES,
    ids=[f"{n}-{m}" for n, m, _ in _PREFIX_MEMBER_CASES],
)
def test_prefix_family_member_redacts(secret_type, member, token):
    assert any(re.search(p, token) for p in _DETECTOR_PATTERNS[secret_type]), (
        secret_type,
        member,
    )
    result = run_plain(f"key: {token}")
    assert result is not None, (secret_type, member)
    assert secret_type in result["found"], (secret_type, member)
    assert token not in result["text"], (secret_type, member)


def _encoded_member_count(patterns: list[str]) -> int:
    total = 0
    for pattern in patterns:
        alt = re.search(r"\(\?:(?P<members>[A-Za-z0-9]+(?:\|[A-Za-z0-9]+)+)\)", pattern)
        cls = re.search(r"[A-Za-z0-9]\[(?P<chars>[A-Za-z]+)\]", pattern)
        if alt:
            total += len(alt.group("members").split("|"))
        elif cls:
            total += len(cls.group("chars"))
        else:
            total += 1
    return total


@pytest.mark.parametrize(
    "secret_type, members",
    [(t, m) for t, _, m in _PREFIX_FAMILIES],
    ids=[t for t, _, _ in _PREFIX_FAMILIES],
)
def test_prefix_family_covers_every_pattern_member(secret_type, members):
    assert _encoded_member_count(_DETECTOR_PATTERNS[secret_type]) == len(members), (
        secret_type
    )


# ─── Active-detector / cross-line eligibility drift guards ───────────────────


def _active_detector_secret_types() -> set[str]:
    from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class

    with E.configure_plugins():
        by_class = {
            cls.__name__: cls
            for cls in get_mapping_from_secret_type_to_class().values()
        }
        bundled = {by_class[p["name"]].secret_type for p in E.PLUGINS}
        custom = {getattr(D, p["name"]).secret_type for p in E.CUSTOM_PLUGINS}
    return bundled | custom


@pytest.mark.drift_guard
def test_fixture_covers_every_active_detector():
    covered = {s["name"] for s in SAMPLES}
    missing = _active_detector_secret_types() - covered
    assert not missing, (
        "active engine detectors with no secret-format-samples.json sample: "
        f"{sorted(missing)}"
    )


_CROSS_LINE_INELIGIBLE_TYPES = frozenset(
    {
        "Secret Keyword",
        "Basic Auth Credentials",
        "Artifactory Credentials",
        "Azure Storage Account access key",
        "Cloudant Credentials",
        "SoftLayer Credentials",
        "IBM Cloud IAM Key",
        "IBM COS HMAC Credentials",
        "Groq API Key",
        "xAI API Key",
        "Replicate API Token",
        "Twilio API Key",
        "Telegram Bot Token",
        "Mailchimp Access Key",
    }
)


@pytest.mark.drift_guard
def test_cross_line_eligibility_partitions_every_active_detector():
    eligible = E._CROSS_LINE_ELIGIBLE_TYPES
    ineligible = _CROSS_LINE_INELIGIBLE_TYPES
    assert not (eligible & ineligible), "a type is both eligible and ineligible"
    active = _active_detector_secret_types()
    assert eligible | ineligible == active, {
        "unclassified": sorted(active - eligible - ineligible),
        "stale_in_eligible": sorted(eligible - active),
        "stale_in_ineligible": sorted(ineligible - active),
    }
    assert {"Groq API Key", "xAI API Key", "Replicate API Token"} <= ineligible


# ─── NpmDetector: equivalence with the upstream quadratic pattern ────────────
# detect-secrets' bundled NpmDetector denylist — quoted verbatim (not imported:
# the whole point of replacing it is that this repo no longer loads it) so the
# equivalence claim below is checked against the actual upstream shape, not a
# restatement of the replacement.
_UPSTREAM_NPM_RE = re.compile(r"\/\/.+\/:_authToken=\s*((npm_.+)|([A-Fa-f0-9-]{36})).*")
_NEW_NPM_RE = D.NpmDetector.denylist[0]


def _npmrc_line(host: str, path: str, token: str) -> str:
    return f"//{host}/{path}/:_authToken={token}"


_NPM_POSITIVE_CORPUS = [
    _npmrc_line("registry.npmjs.org", "", "npm_" + "a" * 36),
    _npmrc_line("registry.npmjs.org", "@scope", "npm_" + "A1b2C3" * 6),
    _npmrc_line("npm.pkg.github.com", "myorg", "a1b2c3d4-e5f6-7890-abcd-ef0123456789"),
    _npmrc_line("registry.yarnpkg.com", "", "A" * 36),
]


@pytest.mark.parametrize("line", _NPM_POSITIVE_CORPUS)
def test_npm_detector_matches_every_upstream_shaped_line(line):
    assert _UPSTREAM_NPM_RE.search(line), (
        f"test corpus line not upstream-shaped: {line}"
    )
    assert _NEW_NPM_RE.search(line), f"replacement missed a genuine npmrc token: {line}"


# Alphabet excludes whitespace (both patterns require a whitespace-free run up
# to `:_authToken=`) and `/` (kept out of host/path so the generator can't
# accidentally produce a SECOND `/:_authToken=` sentinel mid-string, which would
# change which occurrence each pattern anchors on).
_TOKEN_ALPHABET = string.ascii_letters + string.digits + "-_."
_HOST_PATH_ALPHABET = string.ascii_letters + string.digits + "-_.@"


@given(
    host=st.text(alphabet=_HOST_PATH_ALPHABET, min_size=1, max_size=40),
    path=st.text(alphabet=_HOST_PATH_ALPHABET, min_size=0, max_size=40),
    token=st.text(alphabet=_TOKEN_ALPHABET, min_size=1, max_size=80),
)
@settings(max_examples=200, deadline=None)
def test_npm_detector_detection_matches_upstream_over_random_npmrc_shapes(
    host, path, token
):
    line = _npmrc_line(host, path, token)
    upstream_hit = bool(_UPSTREAM_NPM_RE.search(line))
    new_hit = bool(_NEW_NPM_RE.search(line))
    assert new_hit == upstream_hit, (host, path, token, line)


# The one accepted behaviour difference (see the JSON entry's note): the
# upstream pattern's ungrouped trailing `.*` lets its reported value swallow
# trailing prose after the token; the replacement stops the value at the next
# whitespace, like every other token detector in this file. Detection agrees on
# every case above — only the captured VALUE differs.
def test_npm_detector_value_stops_at_whitespace_unlike_upstream():
    token = "npm_" + "a" * 36
    line = f"//registry.npmjs.org/:_authToken={token} trailing prose here"
    upstream_match = _UPSTREAM_NPM_RE.search(line)
    new_match = _NEW_NPM_RE.search(line)
    assert upstream_match and new_match
    assert upstream_match.group(1) == f"{token} trailing prose here"
    assert new_match.group(1) == token


# A pathological whitespace-free line is exactly what made the upstream pattern
# quadratic (its leading `.+` restarts at every `//`); this pins the fix at the
# regex level, cheaper than re-running the whole-corpus benchmark per commit.
def test_npm_detector_denylist_is_linear_on_whitespace_free_input():
    adversarial = "//" + "a" * 200_000
    started = time.monotonic()
    _NEW_NPM_RE.search(adversarial)
    elapsed = time.monotonic() - started
    assert elapsed < 1.0, f"NpmDetector denylist took {elapsed:.2f}s — quadratic again?"
