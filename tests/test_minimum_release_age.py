"""Guard the pnpm supply-chain cooling-off window.

`minimumReleaseAge` tells pnpm to refuse to resolve a dependency version
published less than N minutes ago. It is the cheapest defense we have against
the npm attack that actually keeps happening: a maintainer account is taken
over, a malicious patch release is published, and it is unpublished hours later
— after everyone who installed in that window is compromised.

The window rotted once already, silently: `pnpm-workspace.yaml` carried
`minimumReleaseAgeExclude` with no `minimumReleaseAge` above it. pnpm does not
warn about an exclude list for a disabled feature, so the config read as "we
thought about supply-chain risk" while enforcing nothing at all. CI could not
see it either — every job installs with `--frozen-lockfile`, which never
consults a resolution-time setting.

Scope: this module owns the WINDOW (it exists, and it is at least as long as the
agreed floor) and the POLICY on who may be exempt from it. The SHAPE of an
exemption entry — version-less rather than pinned, so it cannot detach from the
`sanitizer-engine` pin — is owned by tests/test_pnpm_workspace.py, whose entry
parser mirrors pnpm's own and is imported here so the two guards can never
disagree about what an entry means.
"""

import json

import pytest
import yaml

from tests._helpers import REPO_ROOT
from tests.test_pnpm_workspace import ENTRY

# 3 days, in minutes. pnpm reads `minimumReleaseAge` in minutes — its resolver
# computes `minimumReleaseAge * 60 * 1e3` to get milliseconds. The floor is a
# minimum, not an equality: raising the window is always safe, lowering it needs
# a deliberate edit here.
MINIMUM_WINDOW_MINUTES = 3 * 24 * 60


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
def test_only_this_repo_s_own_package_is_exempt(workspace: dict) -> None:
    """Exempting a third party is a decision, not a config tweak.

    Our own release is built and published from this repository with npm
    provenance, so waiting three days to depend on it buys nothing — and that is
    what makes the version-LESS entry shape safe here, since "this package,
    always" only ever waives the window for an artifact we published ourselves.
    A third-party exemption is the opposite: bare or pinned, it reopens exactly
    the window this setting exists to close, so it must fail here and be argued
    for explicitly.
    """
    own = json.loads((REPO_ROOT / "package.json").read_text(encoding="utf-8"))["name"]
    names = set()
    for entry in workspace.get("minimumReleaseAgeExclude") or []:
        parsed = ENTRY.match(entry)
        assert parsed, f"unparseable minimumReleaseAgeExclude entry: {entry!r}"
        names.add(parsed.group("name"))

    # Non-vacuity: an emptied or renamed key would make the assertion below pass
    # while waiving nothing, so pin that we are looking at a real entry set.
    assert names, "pnpm-workspace.yaml no longer declares minimumReleaseAgeExclude"

    foreign = sorted(names - {own})
    assert not foreign, (
        f"`minimumReleaseAgeExclude` exempts third-party package(s) {foreign} "
        f"from the release-age window. Only {own!r} — published by this repo's "
        f"own release workflow — is exempt by policy. If a third-party "
        f"exemption is genuinely needed, change this test in the same commit "
        f"and say why."
    )
