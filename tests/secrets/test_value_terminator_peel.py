"""A trailing statement/list terminator never changes a redaction verdict.

The class this pins: ``FIELD_VALUE_RE`` decides the value's EXTENT, and nine of
the twelve benign-shape gates then judge that value with an anchored
``fullmatch``/``\\Z``. So a single un-peeled byte glued onto the value disarms
every one of those gates at once — ``const token = process.env.GH_TOKEN;``
redacted to ``const token = [REDACTED];``, destroying source the model needed
(the harm ``CLAUDE.md``'s precision-over-recall rule exists to prevent).

Asserting ``;`` after ``process.env.X`` is fine would only pin the one symptom.
The invariant is the whole cross product: for EVERY gate, and every terminator,
the verdict is the one the bare value gets.
"""

import pytest

import agent_sanitizer.secrets.engine as E

# One canonical benign `field = value` per gate. Keyed by gate function name so
# the partition assertion below can prove the cross product covers every gate
# rather than whichever ones someone remembered.
#
# This is a DRIFT GUARD, not an SSOT contract test, and the distinction matters:
# nothing derives this table from the gate tuples, because a gate function
# cannot yield a canonical benign value for itself — the value has to be
# hand-chosen. So the table is a genuine second copy of the gate list, and the
# partition assertion is what keeps the two from drifting apart. The honest
# framing is "a second list exists and is guarded", not "there is one source of
# truth here".
CASES: dict[str, tuple[str, str]] = {
    "_is_placeholder_value": ("api_key", "YOUR_API_KEY_GOES_HERE"),
    "_is_code_env_reference": ("token", "process.env.GH_TOKEN"),
    "_is_content_digest": ("token", "a" * 64),
    "_is_uuid": ("secret", "123e4567-e89b-12d3-a456-426614174000"),
    "_is_public_endpoint_url": ("token_url", "https://example.com/v1/status"),
    "_is_timestamp": ("secret", "2026-08-09T12:34:56.789012Z"),
    # A pre-release/build tail is rejected by `_has_opaque_run`, so the
    # canonical version has to be a long dotted run of short segments.
    "_is_version": ("secret", "1.2.3.4.5.6.7.8.9.10.11"),
    "_is_config_attr_reference": ("password", "settings.database.password_field"),
    "_is_benign_cursor": ("next_token", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    "_is_filesystem_path": ("token", "/etc/vault/agent/current-token"),
    "_is_metadata_field": ("secret_name", "prod-database-primary-credential"),
    "_is_regex_literal": ("SECRET_HINT", "/secret|token|password/i"),
}

# Gates that CANNOT fire on the field-value path, so there is no terminator case
# to write for them. Listed with a reason rather than silently omitted: that is
# what makes the partition assertion below a real cover check instead of a
# restatement of whichever gates someone happened to think of.
NOT_FIELD_REACHABLE: dict[str, str] = {}

# "" proves the bare value is benign in the first place: without it every
# assertion below could pass because the value redacts identically with and
# without the terminator.
TERMINATORS = ("", ";", ",", ";;", ",,", ";\n", ",\n")


def test_cases_cover_every_live_gate() -> None:
    """The cross product is only as complete as this table. A gate added to
    either tuple without a case here would never be exercised with a
    terminator, which is exactly how this class came back."""
    live = {gate.__name__ for gate in E.SHAPE_GATES + E.NAME_TRUST_GATES}
    assert live, "gate tuples are empty — the cross product would be vacuous"
    assert set(CASES) | set(NOT_FIELD_REACHABLE) == live
    assert not (set(CASES) & set(NOT_FIELD_REACHABLE)), (
        "a gate is both exercised and exempted"
    )
    for gate_name, reason in NOT_FIELD_REACHABLE.items():
        assert len(reason) > 20, f"NOT_FIELD_REACHABLE[{gate_name}] needs a real reason"


@pytest.mark.parametrize("gate_name", sorted(NOT_FIELD_REACHABLE))
def test_exempt_gates_really_are_field_unreachable(gate_name: str) -> None:
    """Stops the exemption map from becoming a place to park an inconvenient
    gate: the claim is that no FIELD_VALUE_RE match can satisfy it, so a value
    that does satisfy it must not be matchable in the first place."""
    gate = next(
        g for g in E.SHAPE_GATES + E.NAME_TRUST_GATES if g.__name__ == gate_name
    )
    # A value carrying whitespace and a backtick — the shape this gate needs.
    reaching_value = "some `code` prose that spans whitespace"
    assert gate(E.Candidate(value=reaching_value, line=reaching_value))
    assert E.FIELD_VALUE_RE.search(f"password = {reaching_value}") is None or (
        E.FIELD_VALUE_RE.search(f"password = {reaching_value}").group("secret_value")
        != reaching_value
    )


@pytest.mark.parametrize("gate_name", sorted(CASES))
def test_bare_value_is_benign(gate_name: str) -> None:
    """Non-vacuity for the cross product: each canonical value must survive
    redaction untouched on its own. A value that was never benign would make
    its terminator cases pass by redacting identically either way."""
    field, value = CASES[gate_name]
    text = f"{field} = {value}"
    out, _ = E.redact(text)
    assert out == text


@pytest.mark.parametrize("terminator", TERMINATORS)
@pytest.mark.parametrize("gate_name", sorted(CASES))
def test_terminator_never_changes_the_verdict(gate_name: str, terminator: str) -> None:
    field, value = CASES[gate_name]
    text = f"{field} = {value}{terminator}"
    out, _ = E.redact(text)
    assert out == text, (
        f"{gate_name}: a trailing {terminator!r} defeated the gate — the value's "
        "extent must be normalized at the mint point, not per gate"
    )


@pytest.mark.parametrize("terminator", (";", ",", ";;"))
def test_a_real_secret_still_redacts_and_keeps_its_terminator(terminator: str) -> None:
    """The peel must not become a bypass: the terminator is punctuation of the
    enclosing syntax, so it stays OUTSIDE the placeholder and the credential
    itself is still removed."""
    secret = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"
    text = f"aws_secret_access_key = {secret}{terminator}"
    out, found = E.redact(text)
    assert secret not in out
    assert out.endswith(terminator)
    assert found


def test_terminator_is_peeled_rather_than_swallowed() -> None:
    """Pins the mechanism, not just the outcome: the match must expose the
    terminator as its own group with the value already clean, so a future gate
    cannot receive an un-peeled value."""
    m = E.FIELD_VALUE_RE.search("password = abc123def456ghi789jkl012;")
    assert m is not None
    assert m.group("secret_value") == "abc123def456ghi789jkl012"
    assert m.group("terminator") == ";"


def test_a_sub_floor_value_is_no_longer_inflated_over_the_floor_by_its_terminator() -> (
    None
):
    """A deliberate, narrow recall change, pinned so it stays deliberate.

    The engine's 20-byte floor exists because shorter values lack the entropy to
    be credentials. A 19-byte value followed by `;` used to clear that floor only
    because the terminator was counted as part of the value — the floor was being
    met by punctuation. Peeling the terminator means such a value now falls below
    the floor and is left alone, which is the floor working as intended rather
    than a new blind spot.
    """
    assert E.FIELD_VALUE_RE.search("password = abcdefghijklmnopqrs;") is None
    # The same value one byte longer is still caught, so the floor moved by
    # exactly one byte's worth of punctuation and nothing else.
    m = E.FIELD_VALUE_RE.search("password = abcdefghijklmnopqrst;")
    assert m is not None
    assert m.group("secret_value") == "abcdefghijklmnopqrst"


def test_a_dot_is_not_peeled() -> None:
    """`.` is a JWT's own segment separator, so peeling it would truncate a real
    credential. Pinned so the terminator class is never widened to it."""
    m = E.FIELD_VALUE_RE.search("password = abc123def456ghi789jkl012.")
    assert m is not None
    assert m.group("secret_value").endswith(".")
    assert m.group("terminator") == ""
