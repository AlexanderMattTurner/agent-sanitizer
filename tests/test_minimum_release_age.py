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
import subprocess
from pathlib import Path

import pytest
import yaml

# Resolve the repo root via git rather than parent-walking from __file__, so the
# test keeps working if it is moved (per the project test conventions).
REPO_ROOT = Path(
    subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
)

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

    Two idioms count, and both are exercised by the non-vacuity test below:

    - a direct dependency on a bare version, `"acorn": "8.18.0"` (a range such
      as `^8.18.0` does NOT pin one version and is deliberately excluded); and
    - an npm alias, `"sanitizer-engine": "npm:agent-sanitizer@2.20.0"`, which is
      how this repo depends on its own published release.
    """
    pinned: set[tuple[str, str]] = set()
    for field in DEPENDENCY_FIELDS:
        for alias, spec in (pkg.get(field) or {}).items():
            if spec.startswith("npm:"):
                name, _, version = spec[len("npm:") :].rpartition("@")
                if name and version:
                    pinned.add((name, version))
                continue
            # A bare, fully-qualified semver (no range operator) pins exactly.
            if spec and spec[0].isdigit():
                pinned.add((alias, spec))
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


@pytest.mark.drift_guard
def test_only_this_repo_s_own_package_is_exempt(
    workspace: dict, package_json: dict
) -> None:
    """Exempting a third party is a decision, not a config tweak.

    Our own release is built and published from this repository with npm
    provenance, so waiting three days to depend on it buys nothing. A
    third-party exemption is the opposite: it reopens exactly the window this
    setting exists to close, so it must fail here and be argued for explicitly.
    """
    own = package_json["name"]
    foreign = sorted(
        {
            _split_spec(entry)[0]
            for entry in workspace.get("minimumReleaseAgeExclude") or []
        }
        - {own}
    )
    assert not foreign, (
        f"`minimumReleaseAgeExclude` exempts third-party package(s) {foreign} "
        f"from the release-age window. Only {own!r} — published by this repo's "
        f"own release workflow — is exempt by policy. If a third-party "
        f"exemption is genuinely needed, change this test in the same commit "
        f"and say why."
    )


@pytest.mark.drift_guard
def test_pin_extraction_sees_both_idioms(package_json: dict) -> None:
    """Non-vacuity for the two tests above.

    Both walk `_pinned_exact_versions`. If it silently returned an empty set —
    a renamed dependency field, a changed alias syntax — the exemption test
    would still pass for an empty exclude list and start failing spuriously for
    a real one, so pin that each extraction arm resolves something.
    """
    pinned = _pinned_exact_versions(package_json)
    assert pinned, "no exact version pins resolved out of package.json at all"

    aliases = {
        spec
        for field in DEPENDENCY_FIELDS
        for spec in (package_json.get(field) or {}).values()
        if spec.startswith("npm:")
    }
    assert aliases, (
        "package.json declares no `npm:` alias; the alias arm of "
        "_pinned_exact_versions is now dead code and the exemption guard "
        "cannot see the pin it is meant to check"
    )
    for spec in aliases:
        name, version = _split_spec(spec[len("npm:") :])
        assert (name, version) in pinned, f"alias {spec} did not resolve to a pin"
