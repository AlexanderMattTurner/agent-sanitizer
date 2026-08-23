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
from detect_secrets.plugins.cloudant import CloudantDetector as _UpstreamCloudant
from detect_secrets.plugins.ibm_cloud_iam import IbmCloudIamDetector as _UpstreamIbmIam
from detect_secrets.plugins.ibm_cos_hmac import IbmCosHmacDetector as _UpstreamIbmCos
from detect_secrets.plugins.softlayer import SoftlayerDetector as _UpstreamSoftlayer
from detect_secrets.settings import get_plugins
from redactor_helpers import LEGITIMATE, SAMPLES, run_plain

_DETECTORS_JSON = D.DETECTORS_FILE
_INLINE_DETECTORS = tuple(E._INLINE_PLUGINS)


def test_custom_plugins_derived_from_detector_ssot():
    configured = [
        entry["const"] for entry in json.loads(_DETECTORS_JSON.read_text())["detectors"]
    ]
    names = [plugin["name"] for plugin in E.CUSTOM_PLUGINS]
    assert names == [*configured, *_INLINE_DETECTORS]
    # Non-vacuity for the derivation above: the two registries are disjoint (a
    # detector carries its regex in the JSON or inline, never both) and each is
    # actually populated, so `names` cannot be equal by both sides being empty.
    assert set(configured).isdisjoint(_INLINE_DETECTORS)
    assert "BoundedKeywordDetector" in _INLINE_DETECTORS
    assert len(configured) >= 10
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


# ─── Precision: a shape detector must not fire on legitimate content ─────────

# Detectors whose precision lives in the GATES, not in their regex: each matches
# a credential NOUN beside a value (`secret_id = "..."`) by design, so a raw
# denylist assertion over one would demand the opposite of how it is built.
# `test_negative_corpus_produces_zero_findings` is their negative corpus.
_GATE_DEPENDENT_DETECTORS = frozenset(
    {
        "BoundedKeywordDetector",
        "CloudantCredentialsDetector",
        "IbmCloudIamKeyDetector",
        "IbmCosHmacKeyDetector",
        "SoftlayerCredentialsDetector",
    }
)

# Everything else the engine registers, from BOTH registries — a detector whose
# credential shape is in its own denylist owes this test whichever list it is on.
_SHAPE_DETECTORS = [
    name
    for name in (*E._CONFIGURED_DETECTORS, *E._INLINE_PLUGINS)
    if name not in _GATE_DEPENDENT_DETECTORS
]


@pytest.mark.parametrize("label", sorted(LEGITIMATE))
def test_shape_detectors_find_nothing_in_legitimate_content(label):
    """Every SHAPE detector's own regex, against the engine's negative corpus.

    `test_negative_corpus_produces_zero_findings` asks whether the ENGINE emits
    anything, which a gate can clear after a detector has matched. This asks the
    detector directly, so a prefix arm that widens until it matches ordinary
    text is caught at the regex rather than resting on a gate to hide it — the
    precision-over-recall doctrine applied one layer down.

    Only the keyword-shaped detectors are out, and by NAME rather than by which
    registry they live in: an inline detector whose credential shape sits in its
    own denylist — `JwtFullTokenDetector` — belongs here exactly as much as a
    JSON-backed one, so a new inline detector is covered the day it lands.

    detect-secrets' own BUNDLED plugins are out for a different reason: this repo
    does not own their regexes and `detectors.py` exposes no class to reach them
    through. Two corpus entries therefore do nothing HERE and are carried by the
    engine-level test alone — "url with query string" (`BasicAuthDetector`) and
    "prose naming a key prefix" (the upstream `sk-` arms).
    """
    text = LEGITIMATE[label]
    for cls_name in _SHAPE_DETECTORS:
        denylist = getattr(D, cls_name).denylist
        # A detector with an empty denylist would pass by matching nothing.
        assert denylist, cls_name
        for pattern in denylist:
            found = pattern.search(text)
            assert found is None, f"{cls_name} matched {found!r} in {text!r}"


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


def _cross_line_verdict_by_class() -> dict[str, bool]:
    """Every detector CLASS the engine can enable, mapped to its declared
    cross-line verdict — read from the three registries that declare it, which
    is the same union `engine._CROSS_LINE_ELIGIBLE_CLASSES` is built from."""
    rows = json.loads(_DETECTORS_JSON.read_text())["detectors"]
    return {
        **E._BUNDLED_PLUGINS,
        **{entry["const"]: entry["cross_line"] for entry in rows},
        **E._INLINE_PLUGINS,
    }


def test_every_json_detector_row_declares_a_cross_line_verdict():
    """The verdict is a REQUIRED field, with a note saying why — so a detector
    added to the SSOT cannot land uncategorised and silently ineligible."""
    rows = json.loads(_DETECTORS_JSON.read_text())["detectors"]
    assert len(rows) >= 10, "no detector rows discovered — this check is vacuous"
    for entry in rows:
        assert isinstance(entry.get("cross_line"), bool), entry["const"]
        assert len(entry.get("cross_line_note", "")) > 20, entry["const"]
    # Both verdicts are actually represented, so neither branch is untested.
    assert {entry["cross_line"] for entry in rows} == {True, False}


def test_cross_line_eligibility_partitions_every_active_detector():
    """Every LIVE plugin's type is either cross-line eligible or exempt, and the
    two sides are disjoint. Driven off the live plugin set and the declared
    verdicts, so a new detector with no verdict fails here rather than defaulting
    to one."""
    verdicts = _cross_line_verdict_by_class()
    # The map above re-derives what engine._CROSS_LINE_ELIGIBLE_CLASSES unions,
    # so pin the two together: a test reading the registries differently from the
    # engine would partition a set the engine never uses.
    assert {
        name for name, eligible in verdicts.items() if eligible
    } == E._CROSS_LINE_ELIGIBLE_CLASSES
    with E.configure_plugins():
        live = {type(plugin).__name__: plugin.secret_type for plugin in get_plugins()}
        eligible = E._cross_line_eligible_types()
    assert live, "no live plugins discovered — this partition would be vacuous"
    unclassified = sorted(set(live) - set(verdicts))
    assert not unclassified, f"live plugins with no cross_line verdict: {unclassified}"
    exempt = {
        secret_type
        for cls, secret_type in live.items()
        if not verdicts[cls] and secret_type not in eligible
    }
    assert not (eligible & exempt), "a type is both eligible and exempt"
    assert eligible | exempt == set(live.values()), {
        "unclassified": sorted(set(live.values()) - eligible - exempt),
        "stale_in_eligible": sorted(eligible - set(live.values())),
    }
    # Positive markers on both sides, so neither can pass by being empty.
    assert {"AWS Access Key", "GitHub Token", "Private Key"} <= eligible
    assert {
        "Groq API Key",
        "xAI API Key",
        "Replicate API Token",
        "Secret Keyword",
    } <= exempt


# ─── NpmDetector: equivalence with the upstream quadratic pattern ────────────
# detect-secrets' bundled NpmDetector denylist — quoted verbatim (not imported:
# the whole point of replacing it is that this repo no longer loads it) so the
# equivalence claim below is checked against the actual upstream shape, not a
# restatement of the replacement.
_UPSTREAM_NPM_RE = re.compile(
    r"\/\/.+\/:_authToken=\s*(?P<value>(?:npm_.+)|(?:[A-Fa-f0-9-]{36})).*"
)
_NEW_NPM_RE = D.NpmDetector.denylist[0]


def _npmrc_line(host: str, path: str, token: str, gap: str = "") -> str:
    return f"//{host}/{path}/:_authToken={gap}{token}"


_NPM_POSITIVE_CORPUS = [
    _npmrc_line("registry.npmjs.org", "", "npm_" + "a" * 36),
    _npmrc_line("registry.npmjs.org", "@scope", "npm_" + "A1b2C3" * 6),
    _npmrc_line("npm.pkg.github.com", "myorg", "a1b2c3d4-e5f6-7890-abcd-ef0123456789"),
    _npmrc_line("registry.yarnpkg.com", "", "A" * 36),
    # Upstream's gap before the token is unbounded (`\s*`); a real-world value
    # is never THIS padded, but the replacement's bound must still cover
    # whatever upstream would have matched, up to its own {0,256} floor.
    _npmrc_line("registry.npmjs.org", "", "npm_" + "a" * 36, gap=" " * 20),
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
    # The one dimension the two patterns bound differently (upstream: unbounded
    # `\s*`; replacement: `{0,256}`) — generated explicitly so equivalence is
    # actually exercised across it, not just assumed from the fixed corpus.
    gap=st.text(alphabet=" \t", max_size=30),
)
@settings(max_examples=200, deadline=None)
def test_npm_detector_detection_matches_upstream_over_random_npmrc_shapes(
    host, path, token, gap
):
    line = _npmrc_line(host, path, token, gap=gap)
    upstream_hit = bool(_UPSTREAM_NPM_RE.search(line))
    new_hit = bool(_NEW_NPM_RE.search(line))
    assert new_hit == upstream_hit, (host, path, token, gap, line)


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
    assert upstream_match.group("value") == f"{token} trailing prose here"
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


# ─── Keyword-context detectors: equivalence with the upstream cubic patterns ──
# detect-secrets' bundled Cloudant / IBM Cloud IAM / IBM COS HMAC / SoftLayer
# detectors spell their separator `(?: *)(?:=|:|:=|=>| +|::)(?: *)`, which splits
# a run of k spaces O(k^2) ways and rates complexity 3 (cubic) under regexploit.
# `"key" + " "*1200` cost 8.5s of CPU in one redact() call. The bundled patterns
# are quoted through their upstream MODULES (imported here only — engine.py no
# longer enables them) so the equivalence claim below is checked against the real
# upstream shape rather than a restatement of it.
_REPLACED_DETECTORS = {
    "Cloudant Credentials": (_UpstreamCloudant, D.CloudantCredentialsDetector),
    "IBM Cloud IAM Key": (_UpstreamIbmIam, D.IbmCloudIamKeyDetector),
    "IBM COS HMAC Credentials": (_UpstreamIbmCos, D.IbmCosHmacKeyDetector),
    "SoftLayer Credentials": (_UpstreamSoftlayer, D.SoftlayerCredentialsDetector),
}

_H64 = "9af3b71e6c2d80f54e9b1a7c3d6f20e8" * 2
_A24 = "qxmzfwbnlvkrtdpghsjcyuxb"
_V44 = "q9x2mn7pk4rt8wy1cv5bz3df6gh0jl2eq9x2mn7pk4rt"
_H48 = "9af3b71e6c2d80f54e9b1a7c3d6f20e89af3b71e6c2d80f5"
_SL64 = "q9x2mn7pk4rt8wy1cv5bz3df6gh0jl2e" * 2

# Every separator, wrapper and casing spelling the upstream patterns accept, plus
# negatives (a mid-identifier name, a value one char short) so agreement is
# checked in both directions rather than only on hits.
_KEYWORD_CONTEXT_CORPUS = [
    f'cloudant_key = "{_A24}"',
    f"cloudant_key {_A24}",
    f"CLOUDANT_PASSWORD: {_H64}",
    f'["cl_pw"] := "{_A24}"',
    f"clou-token=  {_A24}",
    f"cloudantkey::{_A24}",
    f"cloudant_key   =>   '{_A24}'",
    f"my_cloudant_key = {_A24}",
    f"cloudant_key = {_A24[:-1]}",
    f"https://user:{_H64}@acct.cloudant.com",
    f'iam_key = "{_V44}"',
    f"iam_key => {_V44}",
    f"ibm_cloud_iam_api_key: {_V44}",
    f"key = {_V44}",
    f"IAM_TOKEN  ::  {_V44}",
    f'cos_secret_access_key = "{_H48}"',
    f"secret_key {_H48}",
    f"ibm-cos-hmac_secret_access_key={_H48}",
    f'softlayer_key = "{_SL64}"',
    f"softlayer_key {_SL64}",
    f'sl_api_key: "{_SL64}"',
    f"https://api.softlayer.com/soap/v3/{_SL64}",
    f"softlayer_key = {_SL64[:-1]}",
    "nothing here at all",
    f"password = {_V44}",
]


@pytest.mark.parametrize("line", _KEYWORD_CONTEXT_CORPUS)
@pytest.mark.parametrize("secret_type", sorted(_REPLACED_DETECTORS))
def test_linear_detector_reports_exactly_what_the_bundled_one_did(secret_type, line):
    """The replacement changes the DECISION PROCEDURE, not the verdict: same
    reported values on every corpus line, hit and miss alike."""
    upstream, replacement = _REPLACED_DETECTORS[secret_type]
    assert replacement.secret_type == upstream.secret_type
    old = sorted({m for p in upstream.denylist for m in p.findall(line)})
    new = sorted({m for p in replacement.denylist for m in p.findall(line)})
    assert new == old, line


@pytest.mark.parametrize("secret_type", sorted(_REPLACED_DETECTORS))
def test_linear_detector_corpus_actually_exercises_it(secret_type):
    """Non-vacuity for the equivalence above: agreeing on nothing but misses
    would pass it. Each detector must fire on at least two corpus lines."""
    _upstream, replacement = _REPLACED_DETECTORS[secret_type]
    hits = [
        line
        for line in _KEYWORD_CONTEXT_CORPUS
        if any(p.search(line) for p in replacement.denylist)
    ]
    assert len(hits) >= 2, hits


@pytest.mark.parametrize("secret_type", sorted(_REPLACED_DETECTORS))
def test_linear_detector_is_linear_on_a_space_run(secret_type):
    """The defect itself: a run of spaces after a credential noun. Cubic means
    doubling the run costs 8x, so a 4000-space run is the shape that cost
    seconds; every replacement must scan it in milliseconds."""
    _upstream, replacement = _REPLACED_DETECTORS[secret_type]
    adversarial = "key" + " " * 4000
    started = time.monotonic()
    for pattern in replacement.denylist:
        pattern.search(adversarial)
    elapsed = time.monotonic() - started
    assert elapsed < 0.5, f"{secret_type} took {elapsed:.2f}s on a space run"


def test_redact_is_linear_on_the_reported_redos_payload():
    """End-to-end floor for the whole engine on the audit's own repro: `"key" +
    " "*1200` measured 8.53s of CPU, and 400/800/1600 spaces measured
    0.54s/4.76s/40.1s (cubic). One second is far above the post-fix cost
    (milliseconds) and far below the pre-fix one."""
    started = time.monotonic()
    run_plain("key" + " " * 1200)
    elapsed = time.monotonic() - started
    assert elapsed < 1.0, f"redact() took {elapsed:.2f}s on the ReDoS payload"
