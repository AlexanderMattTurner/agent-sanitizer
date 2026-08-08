"""`pnpm-workspace.yaml` may not carry a version that can go stale.

`minimumReleaseAgeExclude` waives pnpm's release-age floor for our own package,
because a first-party release published minutes ago is below any floor by
construction. Written as `agent-sanitizer@<version>` it silently detached from
the `sanitizer-engine` pin it was supposed to track — the exclusion sat on 2.1.0
long after the pin moved, waiving nothing.

pnpm reads an entry with no `@version` as "this package, always", so a
version-less entry is the shape that CANNOT drift. This holds that shape: an
entry may pin a version only if that exact version is what `package.json`
actually depends on, so re-pinning it without moving the dependency fails here.
"""

import json
import re

import pytest
import yaml

from tests._helpers import REPO_ROOT

WORKSPACE = REPO_ROOT / "pnpm-workspace.yaml"

#: Mirrors pnpm's own parse (`parseVersionPolicyRule`): the version begins at the
#: first `@` AFTER a leading scope `@`, so `@scope/name` alone is a bare name.
ENTRY = re.compile(r"^(?P<name>@?[^@]+)(?:@(?P<version>.+))?$")


def _config() -> dict:
    return yaml.safe_load(WORKSPACE.read_text(encoding="utf-8"))


def _declared_versions(name: str) -> set[str]:
    """Every version of `name` package.json depends on, including aliased
    (`npm:agent-sanitizer@2.12.0`) specs, which is how the engine is pinned."""
    manifest = json.loads((REPO_ROOT / "package.json").read_text(encoding="utf-8"))
    specs = {
        **manifest.get("dependencies", {}),
        **manifest.get("devDependencies", {}),
    }
    versions = set()
    for alias, spec in specs.items():
        aliased = spec.removeprefix("npm:") if spec.startswith("npm:") else None
        if aliased is None and alias == name:
            versions.add(spec.lstrip("^~"))
        if aliased is not None and aliased.rsplit("@", 1)[0] == name:
            versions.add(aliased.rsplit("@", 1)[1])
    return versions


def test_the_exclusion_exists_and_is_non_empty() -> None:
    """Non-vacuity: the checks below say nothing about an absent key."""
    entries = _config().get("minimumReleaseAgeExclude")
    assert entries, "pnpm-workspace.yaml no longer declares minimumReleaseAgeExclude"


@pytest.mark.drift_guard
@pytest.mark.parametrize("entry", _config().get("minimumReleaseAgeExclude") or [])
def test_no_exclusion_entry_pins_a_version_that_is_not_depended_on(entry: str) -> None:
    parsed = ENTRY.match(entry)
    assert parsed, f"unparseable minimumReleaseAgeExclude entry: {entry!r}"
    version = parsed.group("version")
    if version is None:
        return  # version-less: the drift-proof shape, nothing to check.
    declared = _declared_versions(parsed.group("name"))
    assert version in declared, (
        f"{entry!r} pins a version package.json does not depend on "
        f"(declared: {sorted(declared) or 'none'}). Drop the `@{version}` — pnpm "
        "reads a bare package name as an unconditional exclusion, which cannot "
        "drift out from under the dependency."
    )
