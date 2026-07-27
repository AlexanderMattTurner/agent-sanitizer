"""Ported custom-detector tests (was the secret_plugins.py half of the suite)."""

import json
import re

import pytest

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
