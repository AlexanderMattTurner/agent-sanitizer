"""Guard the pnpm supply-chain cooling-off window.

`minimumReleaseAge` tells pnpm to refuse to resolve a dependency version
published less than N minutes ago. It is the cheapest defense we have against
the npm attack that actually keeps happening: a maintainer account is taken
over, a malicious patch release is published, and it is unpublished hours later
— after everyone who installed in that window is compromised.

Two ways the window rots, both of which failed silently before this guard:

1. **The key disappears (or was never there).** `pnpm-workspace.yaml` carried
   `minimumReleaseAgeExclude` with no `minimumReleaseAge` above it. pnpm does
   not warn about an exclude list for a disabled feature, so the config read as
   "we thought about supply-chain risk" while enforcing nothing at all.
2. **An exemption outlives its pin.** Every name in the exclude list is a hole
   in the window, and a hole pinned to `foo@1.2.3` keeps exempting `foo@1.2.3`
   long after nothing depends on it — and a *bare* name (no `@version`) exempts
   every future version of that package forever.

So this asserts the window exists and is at least as long as the agreed floor,
and that each exemption still names a version this repo genuinely pins.

The same floor binds the other two resolvers that pick versions here: uv's
`exclude-newer` for the Python dev toolchain, and Renovate's own
`minimumReleaseAge`, which otherwise opens bump PRs pnpm then refuses to install.
"""

import json
import re

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 (the package floor) has no tomllib
    import tomli as tomllib

import json5
import pytest
import yaml

from tests._helpers import REPO_ROOT

# 3 days, in minutes — pnpm reads `minimumReleaseAge` in minutes. The floor is a
# minimum, not an equality: raising the window is always safe, lowering it needs
# a deliberate edit here.
MINIMUM_WINDOW_MINUTES = 3 * 24 * 60

DEPENDENCY_FIELDS = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
)


@pytest.fixture(scope="module")
def workspace() -> dict:
    """`pnpm-workspace.yaml`, parsed by a real YAML parser."""
    text = (REPO_ROOT / "pnpm-workspace.yaml").read_text(encoding="utf-8")
    parsed = yaml.safe_load(text)
    assert isinstance(parsed, dict) and parsed, (
        "pnpm-workspace.yaml did not parse to a non-empty mapping; every "
        "assertion below would pass vacuously against an empty document"
    )
    return parsed


@pytest.fixture(scope="module")
def package_json() -> dict:
    return json.loads((REPO_ROOT / "package.json").read_text(encoding="utf-8"))


def _pinned_exact_versions(pkg: dict) -> set[tuple[str, str]]:
    """Every `(name, version)` package.json pins to one exact published version.

    A pin is a direct dependency on a bare version, `"acorn": "8.18.0"`. A range
    such as `^8.18.0` does not name one version and is deliberately excluded, as
    is a `link:`/`file:` spec, which resolves to a path rather than to anything
    the registry could serve inside the cooling-off window.
    """
    pinned: set[tuple[str, str]] = set()
    for field in DEPENDENCY_FIELDS:
        for name, spec in (pkg.get(field) or {}).items():
            # A bare, fully-qualified semver (no range operator) pins exactly.
            if spec and spec[0].isdigit():
                pinned.add((name, spec))
    return pinned


def _split_spec(entry: str) -> tuple[str, str]:
    """Split `name@version` into its parts, tolerating a scoped `@scope/name`."""
    name, _, version = entry.rpartition("@")
    return name, version


@pytest.mark.drift_guard
def test_release_age_window_is_enabled(workspace: dict) -> None:
    """The window exists, is an integer count of minutes, and clears the floor."""
    assert "minimumReleaseAge" in workspace, (
        "pnpm-workspace.yaml has no `minimumReleaseAge`, so dependency "
        "resolution accepts a version published seconds ago. Note that any "
        "`minimumReleaseAgeExclude` list is inert without it — pnpm does not "
        "warn about exclusions from a disabled window."
    )
    window = workspace["minimumReleaseAge"]
    assert isinstance(window, int) and not isinstance(window, bool), (
        f"`minimumReleaseAge` must be an integer number of minutes, got "
        f"{window!r} ({type(window).__name__})"
    )
    assert window >= MINIMUM_WINDOW_MINUTES, (
        f"`minimumReleaseAge` is {window} minutes, below the agreed "
        f"{MINIMUM_WINDOW_MINUTES}-minute (3-day) floor. Raising the window is "
        f"fine; lowering it needs a deliberate edit to MINIMUM_WINDOW_MINUTES."
    )


@pytest.mark.drift_guard
def test_every_exemption_names_a_version_we_actually_pin(
    workspace: dict, package_json: dict
) -> None:
    """No exemption may outlive its pin, and none may be a bare package name."""
    pinned = _pinned_exact_versions(package_json)
    for entry in workspace.get("minimumReleaseAgeExclude") or []:
        name, version = _split_spec(entry)
        assert name and version, (
            f"`minimumReleaseAgeExclude` entry {entry!r} is not `name@version`. "
            f"A bare package name exempts EVERY future version of that package "
            f"from the window, permanently."
        )
        assert (name, version) in pinned, (
            f"`minimumReleaseAgeExclude` exempts {entry}, but package.json "
            f"pins no such version. Drop the stale exemption — it is a hole in "
            f"the cooling-off window that protects nothing."
        )


# Packages published by a repository we control, each with npm provenance, from
# a release workflow we can read. The window defends against a takeover of a
# maintainer account we do not control, so for these it delays adopting a fix we
# just shipped and buys nothing. Every other package stays behind the window.
#
# Approved exemptions, one entry per VERSION. A bare package name here would
# pre-approve every future release of it, which is the takeover the window
# covers: bump the pin, add a config line, install a release minutes old. Naming
# the version means each new one is a code edit a reviewer sees.
#
# `agent-control-plane-core` is the guardrail contract the Claude hooks load on
# every gated tool call. Its own repo publishes it through the same auto-version
# and provenance path this repo uses.
FIRST_PARTY_EXEMPTIONS = frozenset({"agent-control-plane-core@0.8.1"})


@pytest.mark.drift_guard
def test_every_exemption_is_an_approved_first_party_version(
    workspace: dict, package_json: dict
) -> None:
    """Exempting a package is a decision, not a config tweak.

    A first-party release is built and published from a repository we control
    with npm provenance, so waiting three days to depend on it buys nothing.
    Any other exemption reopens exactly the window this setting exists to close,
    so it must fail here and be argued for explicitly.
    """
    own = package_json["name"]
    unapproved = sorted(
        entry
        for entry in workspace.get("minimumReleaseAgeExclude") or []
        if entry not in FIRST_PARTY_EXEMPTIONS and _split_spec(entry)[0] != own
    )
    assert not unapproved, (
        f"`minimumReleaseAgeExclude` carries unapproved exemption(s) "
        f"{unapproved}. Only {sorted(FIRST_PARTY_EXEMPTIONS)} and this repo's "
        f"own {own!r} are exempt by policy. A version bump needs its new "
        f"`name@version` added to FIRST_PARTY_EXEMPTIONS in the same commit, "
        f"with a reason."
    )


@pytest.mark.drift_guard
def test_pin_extraction_tells_a_pin_from_a_range(package_json: dict) -> None:
    """Non-vacuity for the two tests above.

    Both walk `_pinned_exact_versions`, and with `minimumReleaseAgeExclude`
    empty they iterate zero entries — so this is the only thing standing between
    them and silence. Asserted against a synthetic manifest, because comparing
    the extraction's output back against the same manifest it read is a
    tautology: it fails only if one name appears twice with different specs.
    """
    assert _pinned_exact_versions(
        {"dependencies": {"a": "1.2.3", "b": "^1.2.3", "c": "link:."}}
    ) == {("a", "1.2.3")}, (
        "_pinned_exact_versions no longer tells an exact pin apart from a range "
        "or a path spec, so the exemption guard cannot see the pins it checks"
    )
    assert _pinned_exact_versions(package_json), (
        "no exact version pins resolved out of the real package.json — the "
        "dependency fields it walks have been renamed or emptied"
    )


# The ISO 8601 subset uv accepts for a relative `exclude-newer` (uv itself
# rejects calendar months and years), and Renovate's `<n> <unit>` form.
ISO_DURATION = re.compile(
    r"P(?:(?P<weeks>\d+)W)?(?:(?P<days>\d+)D)?"
    r"(?:T(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?)?"
)
RENOVATE_DURATION = re.compile(r"(?P<count>\d+) (?P<unit>minute|hour|day|week)s?")
RENOVATE_UNIT_MINUTES = {"minute": 1, "hour": 60, "day": 24 * 60, "week": 7 * 24 * 60}


def _iso_duration_minutes(text: str) -> int:
    """Minutes in an ISO 8601 `P…` duration; raises on any other spelling."""
    match = ISO_DURATION.fullmatch(text)
    # `P` and a trailing `T` match the all-optional pattern yet name no span.
    if not match or text == "P" or text.endswith("T"):
        raise ValueError(
            f"{text!r} is not an ISO 8601 week/day/hour/minute duration "
            f"(e.g. `P3D`); spell the window that way so this guard can read it"
        )
    weeks, days, hours, minutes = (
        int(match[unit] or 0) for unit in ("weeks", "days", "hours", "minutes")
    )
    return ((weeks * 7 + days) * 24 + hours) * 60 + minutes


def _renovate_duration_minutes(text: str) -> int:
    """Minutes in a Renovate `<n> <unit>` duration; raises on any other spelling."""
    match = RENOVATE_DURATION.fullmatch(text)
    if not match:
        raise ValueError(
            f"{text!r} is not a `<n> <minute|hour|day|week>[s]` duration "
            f"(e.g. `3 days`); spell the window that way so this guard can read it"
        )
    return int(match["count"]) * RENOVATE_UNIT_MINUTES[match["unit"]]


# Relative `exclude-newer` durations arrived in uv 0.9.17 (uv CHANGELOG). An
# older uv cannot parse `P3D`, so the file that holds the window must also
# refuse to run under one.
UV_RELATIVE_WINDOW_MIN_VERSION = (0, 9, 17)


@pytest.fixture(scope="module")
def uv_config() -> dict:
    """`uv.toml`, the file uv reads for the window — see the file for why not pyproject."""
    return tomllib.loads((REPO_ROOT / "uv.toml").read_text("utf-8"))


@pytest.mark.drift_guard
def test_uv_release_age_window_clears_the_floor(uv_config: dict) -> None:
    """uv's `exclude-newer` holds the Python dev toolchain to the same floor."""
    window = uv_config.get("exclude-newer")
    assert isinstance(window, str), (
        "uv.toml has no `exclude-newer`, so `uv lock`/`uv run` "
        "accept a distribution uploaded seconds ago"
    )
    assert _iso_duration_minutes(window) >= MINIMUM_WINDOW_MINUTES, (
        f"uv.toml `exclude-newer` is {window!r}, below the agreed "
        f"{MINIMUM_WINDOW_MINUTES}-minute (3-day) floor"
    )


@pytest.mark.drift_guard
def test_uv_cooldown_cannot_be_dropped_by_an_older_uv(uv_config: dict) -> None:
    """A uv that cannot parse `P3D` must be refused, not left to ignore the window."""
    required = uv_config.get("required-version")
    assert isinstance(required, str), (
        "uv.toml has no `required-version`: a uv older than 0.9.17 parses a "
        "relative `exclude-newer` as a malformed timestamp and re-resolves "
        "without the cooldown"
    )
    match = re.fullmatch(r">=(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)", required)
    assert match, f"`required-version` {required!r} must be a single `>=X.Y.Z` floor"
    assert (
        tuple(int(match[part]) for part in ("major", "minor", "patch"))
        >= UV_RELATIVE_WINDOW_MIN_VERSION
    ), f"`required-version` {required!r} admits a uv without relative `exclude-newer`"
    assert "uv" not in tomllib.loads(
        (REPO_ROOT / "pyproject.toml").read_text("utf-8")
    ).get("tool", {}), (
        "pyproject.toml carries a `[tool.uv]` table beside uv.toml: uv ignores "
        "it, so any setting added there silently does nothing"
    )


@pytest.mark.drift_guard
def test_renovate_release_age_window_clears_the_floor() -> None:
    """Renovate waits at least as long as pnpm will before proposing a bump."""
    renovate = json5.loads((REPO_ROOT / "renovate.json5").read_text("utf-8"))
    window = renovate.get("minimumReleaseAge")
    assert isinstance(window, str), (
        "renovate.json5 has no top-level `minimumReleaseAge`, so Renovate "
        "proposes a version the moment it is published"
    )
    assert _renovate_duration_minutes(window) >= MINIMUM_WINDOW_MINUTES, (
        f"renovate.json5 `minimumReleaseAge` is {window!r}, below the agreed "
        f"{MINIMUM_WINDOW_MINUTES}-minute (3-day) floor: Renovate would open "
        f"bump PRs whose install pnpm's own window refuses"
    )


@pytest.mark.parametrize(
    "parse, text, minutes",
    [
        (_iso_duration_minutes, "P3D", 3 * 24 * 60),
        (_iso_duration_minutes, "PT24H", 24 * 60),
        (_iso_duration_minutes, "P1WT30M", 7 * 24 * 60 + 30),
        (_renovate_duration_minutes, "3 days", 3 * 24 * 60),
        (_renovate_duration_minutes, "1 day", 24 * 60),
        (_renovate_duration_minutes, "24 hours", 24 * 60),
    ],
)
def test_duration_parsers_read_the_window(parse, text: str, minutes: int) -> None:
    assert parse(text) == minutes


@pytest.mark.parametrize(
    "parse, text",
    [
        (_iso_duration_minutes, "P"),
        (_iso_duration_minutes, "PT"),
        (_iso_duration_minutes, "P3DT"),
        (_iso_duration_minutes, "P1M"),
        (_iso_duration_minutes, "3 days"),
        (_renovate_duration_minutes, "P3D"),
        (_renovate_duration_minutes, "3 months"),
    ],
)
def test_duration_parsers_reject_a_spelling_they_cannot_read(parse, text: str) -> None:
    with pytest.raises(ValueError):
        parse(text)
