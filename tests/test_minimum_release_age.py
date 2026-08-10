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
"""

import json

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
# `agent-control-plane-core` is the guardrail contract the Claude hooks load on
# every gated tool call; it ships from AlexanderMattTurner/agent-control-plane-core
# via the same auto-version + provenance path this repo uses.
FIRST_PARTY_PACKAGES = frozenset({"agent-control-plane-core"})


@pytest.mark.drift_guard
def test_only_first_party_packages_are_exempt(
    workspace: dict, package_json: dict
) -> None:
    """Exempting a third party is a decision, not a config tweak.

    A first-party release is built and published from a repository we control
    with npm provenance, so waiting three days to depend on it buys nothing. A
    third-party exemption is the opposite: it reopens exactly the window this
    setting exists to close, so it must fail here and be argued for explicitly.
    """
    exempt_by_policy = FIRST_PARTY_PACKAGES | {package_json["name"]}
    foreign = sorted(
        {
            _split_spec(entry)[0]
            for entry in workspace.get("minimumReleaseAgeExclude") or []
        }
        - exempt_by_policy
    )
    assert not foreign, (
        f"`minimumReleaseAgeExclude` exempts third-party package(s) {foreign} "
        f"from the release-age window. Only {sorted(exempt_by_policy)} — each "
        f"published by a repository we control — is exempt by policy. If a "
        f"third-party exemption is genuinely needed, add it to "
        f"FIRST_PARTY_PACKAGES in the same commit and say why."
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
