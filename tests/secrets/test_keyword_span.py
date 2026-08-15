"""Regression suite for the ``Secret Keyword`` unbounded-span incident.

A GitHub PR body's `` `_load_secret`, `` opened a keyword "value" that ran
greedily to the last backtick-then-semicolon in a single-line (``\\n``-escaped)
JSON tool payload, redacting ~2,800 characters of unrelated prose as one
``[REDACTED: Secret Keyword]``. Root cause: the bundled ``KeywordDetector``
treats a markdown backtick as a THIRD quote character alongside ``'``/``"``,
and its value class does not exclude it — so a backtick-opened value has no
closing delimiter to stop at. ``BoundedKeywordDetector`` (``detectors.py``)
replaces it with a value class that excludes backtick, whitespace runs beyond
8 words, and newlines entirely, so the shape is structurally unreachable
rather than merely suppressed downstream.

Every assertion here pins the redacted SPAN via ``redact_map``'s ``pairs``
(``{"placeholder", "original", "start"}``) — not just the presence of a
finding — since a test that only checks ``found`` cannot fail on a match that
is merely too wide.
"""

import pytest

import agent_sanitizer.secrets.detectors as D
import agent_sanitizer.secrets.engine as E
from redactor_helpers import SAMPLES, cfg, run_map, run_plain

# The exact identifier list from the incident report, wrapped in the same
# prose/fence/list shape the swallowed span crossed: paragraphs, a fenced code
# block, a bullet list, and a second fenced block.
_IDENTIFIERS = (
    "`services_ready`, `wait_completed`, `toggle_on`, `inert_excludes`, "
    "`_dial_endpoints`, `_load_secret`, `find_provider_key`, `is_stacked_child`, "
    "`_rewrite_args`, `shard_timeout_from_env`, `escaping_paths`, "
    "`_prewarm_claim_alive`, `audit_only_post`, `ensure_secret`, "
    "`image_progress_enabled`"
)
_INCIDENT_BODY = (
    f"The lint flagged these Python identifiers as unused: {_IDENTIFIERS}\n"
    "\n"
    "Three of these are referenced only from a test helper, so the lint "
    "cannot see them.\n"
    "\n"
    "```\n"
    "vulture claims 7 unused names\n"
    "```\n"
    "\n"
    "- one\n"
    "- two\n"
    "- three\n"
    "\n"
    "```sh\n"
    "uv run vulture\n"
    "```\n"
    "\n"
    "The pool pickles its worker by module name, so a module loaded through "
    "`tests/_helpers.load_script` raised `PicklingError`; and that is that.\n"
)
# The GitHub MCP server returns a PR body as one JSON string, whose newlines
# are the two-character `\n` escape — the leaf the sanitizer's PostToolUse
# hook actually scans is therefore one physical LINE, which is what let the
# span cross paragraphs, a bullet list, and two fenced code blocks: a real
# newline would have stopped `_redact_line`'s per-line scan on its own.
_INCIDENT_ONE_LINE = _INCIDENT_BODY.replace("\n", "\\n")


@pytest.mark.parametrize("web_ingress", [False, True])
def test_incident_prose_is_never_the_match(web_ingress):
    out, found = E.redact(_INCIDENT_ONE_LINE, cfg(web_ingress=web_ingress))
    assert found == []
    assert out == _INCIDENT_ONE_LINE


def test_real_credential_in_same_paragraph_still_redacts_exactly():
    """The negative direction: a real credential in the same paragraph as the
    swallowed prose must still redact, and the span must be exactly the
    token — not the token plus any of the surrounding identifier list."""
    token = "ghp_" + "A1b2C3d4E5" * 4
    text = _INCIDENT_ONE_LINE + f" See the token {token} above."
    view = run_map(text, cfg(web_ingress=True))
    assert "GitHub Token" in view["found"]
    assert token not in view["text"]
    matching = [p for p in view["pairs"] if p["original"] == token]
    assert len(matching) == 1, view["pairs"]
    assert matching[0]["start"] == text.index(token)


def test_a_keyword_span_never_exceeds_the_published_bound():
    """Property over the shared fixture corpus: every ``Secret Keyword`` pair's
    original text is within the detector's own published bound and contains no
    newline — so no future change can silently widen the span back out.
    A positive marker (asserted below) proves the corpus isn't vacuously empty
    for this type."""
    keyword_pairs = []
    for sample in SAMPLES:
        token = "".join(sample["parts"])
        view = run_map(f"key: {token}")
        keyword_pairs.extend(
            p for p in view["pairs"] if sample["name"] == "Secret Keyword"
        )
    assert keyword_pairs, "no Secret Keyword sample produced a pair — corpus is vacuous"
    for pair in keyword_pairs:
        assert len(pair["original"]) <= D.KEYWORD_VALUE_MAX_LEN, pair
        assert "\n" not in pair["original"], pair


@pytest.mark.parametrize(
    "label, text, expected_value",
    [
        ("sub-floor password", 'password: "hunter2xyz"', "hunter2xyz"),
        ("pwd noun (upstream-only)", 'pwd = "sh0rtPass99"', "sh0rtPass99"),
        (
            "spaced passphrase",
            'password: "correct horse battery staple ok"',
            "correct horse battery staple ok",
        ),
        (
            "reverse comparison",
            'if ("hunter2xyzvalue" == my_password_secure) {}',
            "hunter2xyzvalue",
        ),
        ("arrow assignment", 'api_key => "K9x2Lm4Qp7Rt"', "K9x2Lm4Qp7Rt"),
        (
            "directive form",
            'private_key "abcd1234efgh5678";',
            "abcd1234efgh5678",
        ),
    ],
)
def test_recall_is_unchanged_for_every_arm(label, text, expected_value):
    view = run_map(text)
    assert expected_value not in view["text"], label
    assert [p["original"] for p in view["pairs"]] == [expected_value], label


def test_a_value_past_the_word_bound_is_still_redacted_by_the_field_path():
    """The bound must refuse to match, never truncate: a truncated match would
    redact a prefix and leave the tail in cleartext — the exact defect class
    the GitHub/GitLab/JWT reimplementations in detectors.py already fix for
    their own formats. A contiguous value past the keyword bound is still
    caught by FIELD_VALUE_RE, which has no upper bound."""
    token = "aB3" * 100
    text = f'password: "{token}"'
    assert not any(p.findall(text) for p in D.BoundedKeywordDetector.denylist)
    out, found = E.redact(text)
    assert token not in out
    assert found == ["named secret field"]


def test_amplifier_a_unrelated_occurrence_of_the_same_string_is_untouched():
    """A benign value string repeated elsewhere on the line, with no keyword
    context of its own, must not be redacted as a side effect of a real match
    found near it."""
    text = 'pwd = "swordfish99x"; note that swordfish99x is also the demo fixture name'
    view = run_map(text, cfg(web_ingress=True))
    assert view["found"] == ["Secret Keyword"]
    assert [p["original"] for p in view["pairs"]] == ["swordfish99x"]
    assert view["pairs"][0]["start"] == text.index('"') + 1
    assert "swordfish99x is also the demo fixture name" in view["text"]


def test_amplifier_b_structural_detection_wins_and_keyword_is_still_named():
    """A structural detector's span wins arbitration over an overlapping
    ``Secret Keyword`` guess of the same length, and the operator warning
    names BOTH — the keyword guess is covered, not silently dropped."""
    token = "ghp_" + "A1b2C3d4E5" * 4
    text = f'secret = "{token}"; end'
    view = run_map(text, cfg(web_ingress=True))
    assert view["found"] == ["GitHub Token", "Secret Keyword"]
    assert token not in view["text"]
    assert [p["original"] for p in view["pairs"]] == [token]


def test_bounded_keyword_detector_is_the_registered_secret_keyword_plugin():
    """Non-vacuity floor: prove the engine actually loads the fix, not the
    bundled detector under a name that happens to still say 'Secret Keyword'.

    Compared by NAME, not identity: detect-secrets loads a custom plugin via
    ``import_file_as_module``, which creates a second, separately-identitied
    module object for ``detectors.py`` — the same idiom
    ``test_secrets_detectors.py::_active_detector_secret_types`` already uses
    for this reason.
    """
    from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class

    with E.configure_plugins():
        cls = get_mapping_from_secret_type_to_class()["Secret Keyword"]
    assert cls.__name__ == "BoundedKeywordDetector"
    assert len(cls.denylist) == len(D.BoundedKeywordDetector.denylist)


def test_the_bundled_detector_really_did_over_capture():
    """Control: the exact incident shape, run through the UNMODIFIED upstream
    pattern (quoted verbatim, not imported — the point is this repo no longer
    loads it), over-captures hundreds of characters. Without this, the tests
    above could pass identically against a detector that never fires at all."""
    import re

    upstream_quote = r"[\'\"`]"
    upstream_secret = r"(?=[^\v\'\"]*)(?=\w+)[^\v\'\"]*[^\v,\'\"`]"
    upstream = re.compile(
        r"(?:secret)\w*[^\s]{0,50}?\s*("
        + upstream_quote
        + r")("
        + upstream_secret
        + r")(\1);",
        re.IGNORECASE,
    )
    m = upstream.search(_INCIDENT_BODY)
    assert m is not None
    # No real credential runs this long; a match anywhere near this size can
    # only be prose, not a secret — proving the upstream shape really is
    # unbounded on this input, not merely picking up one over-long token.
    assert len(m.group(2)) > 200, (
        "upstream's own pattern no longer over-captures — test is stale"
    )
    assert not any(p.findall(_INCIDENT_BODY) for p in D.BoundedKeywordDetector.denylist)


def test_run_plain_matches_map_mode_on_the_incident():
    """Sanity: the plain-mode API used by the rest of the suite agrees with
    map mode on the headline case."""
    assert run_plain(_INCIDENT_ONE_LINE, cfg(web_ingress=True)) is None
