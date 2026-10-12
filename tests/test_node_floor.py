"""One Node floor, restated nowhere without a guard.

``package.json``'s ``engines.node`` is the floor npm enforces. Code that can
read it does: the esbuild target and the plugin launcher's generated
``node-floor.sh`` both derive from it through ``scripts/gen-node-floor-lib.mjs``.
What cannot read it is prose and operator-facing messages that ship where
``package.json`` is not on disk — the wheel's ``RuntimeError``, the plugin
README, the provisioner's degraded-mode notice — plus the CI runtimes pinned in
workflow YAML.

So this derives the floor from the generator's own parse of ``engines.node`` and
asserts, as a partition, that every Node-version claim in a tracked file either
states that floor or is listed in :data:`NOT_THE_FLOOR` with a reason, and that
no CI job pins a Node below it.
"""

import functools
import json
import re
import subprocess

import pytest
import yaml

from tests._helpers import REPO_ROOT

pytestmark = pytest.mark.drift_guard(
    "the Node floor is restated in operator-facing prose and messages that ship "
    "without package.json (the wheel, the installed plugin) and in workflow "
    "runtime pins; each is checked against engines.node instead"
)

# A floor claim: the runtime's name, then `>=` and a version. The name is
# required so a bare range (a test's parser fixture, a semver pin) is not read
# as a claim. No literal example here: this module is scanned too.
FLOOR_CLAIM = re.compile(
    r"\bnode(?:\.js)?\s*\(?\s*(?:>=|\u2265)\s*(?P<version>\d+(?:\.\d+)*)",
    re.IGNORECASE,
)
# A version-qualified mention that is not a range: `Node NN`, or an esbuild-style
# `nodeNN` target typed by hand. U+00A0 because the guides put non-breaking
# spaces around short tokens.
NODE_MENTION = re.compile(r"\bnode(?:\.js)?[ \u00a0]?(?P<version>\d{2})\b", re.I)

# (path, version) -> why this mention is NOT a statement of the package floor.
# Every entry is asserted to still be found, so a stale one fails too.
NOT_THE_FLOOR = {
    ("plugin/scripts/safe-launch.sh", "22.1"): (
        "the release NODE_COMPILE_CACHE first shipped in — a runtime feature fact"
    ),
    ("scripts/data/README.md", "22"): (
        "which Unicode each Node release's bundled ICU carries, from the vendored data's README"
    ),
    ("plugin/test/plugin-bundle.test.mjs", "18"): (
        "the too-old runtime a fixture stubs to drive the below-floor diagnosis"
    ),
}

# Positive markers: copies that cannot read package.json where they run, so
# the scan must keep seeing each of them as a floor claim.
KNOWN_FLOOR_COPIES = (
    "README.md",
    "plugin/README.md",
    "plugin/scripts/provision-hook-binary.sh",
    "python/README.md",
    "python/agent_sanitizer/__init__.py",
    "python/pyproject.toml",
)

# Tracked but not hand-written: a generated bundle, the lockfiles and the
# append-only release notes restate versions nobody here chose.
GENERATED_PREFIXES = ("plugin/dist/", "CHANGELOG.md")
GENERATED_NAMES = ("pnpm-lock.yaml", "uv.lock")


def _node_major_floor() -> str:
    """The floor as `scripts/gen-node-floor-lib.mjs` parses `engines.node`."""
    module = (REPO_ROOT / "scripts" / "gen-node-floor-lib.mjs").as_uri()
    script = (
        f"import {{ nodeMajorFloor }} from {json.dumps(module)};\n"
        "process.stdout.write(String(nodeMajorFloor()));"
    )
    return subprocess.run(
        ["node", "--input-type=module", "-e", script],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout


#: The one source of truth: engines.node, read by the generator that renders it.
FLOOR = _node_major_floor()


def _tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [
        p
        for p in out.split("\0")
        if p
        and not p.startswith(GENERATED_PREFIXES)
        and p.rsplit("/", 1)[-1] not in GENERATED_NAMES
    ]


@functools.cache
def _mentions() -> frozenset[tuple[str, str]]:
    found = set()
    for path in _tracked_files():
        full = REPO_ROOT / path
        if not full.is_file():
            continue
        text = full.read_text(encoding="utf-8", errors="ignore")
        for pattern in (FLOOR_CLAIM, NODE_MENTION):
            found.update((path, m["version"]) for m in pattern.finditer(text))
    return frozenset(found)


def test_the_floor_is_a_major_version() -> None:
    assert FLOOR.isdigit(), f"gen-node-floor-lib rendered {FLOOR!r} as the floor"


def test_every_node_version_claim_is_the_floor_or_classified() -> None:
    """The partition: a Node-version claim in a tracked file states the floor or
    is a classified fact about Node itself. A new copy is guarded the moment it
    is written."""
    mentions = _mentions()
    unseen = sorted(
        path for path in KNOWN_FLOOR_COPIES if (path, FLOOR) not in mentions
    )
    assert not unseen, f"the scan no longer reads a floor claim in {unseen}"
    unclassified = sorted(
        (path, version)
        for path, version in mentions
        if version != FLOOR and (path, version) not in NOT_THE_FLOOR
    )
    assert not unclassified, (
        f"these name a Node other than the {FLOOR} floor in engines.node: "
        f"{unclassified}. Fix them, or add them to NOT_THE_FLOOR with the "
        "reason they are not floor claims."
    )


@pytest.mark.parametrize("entry", sorted(NOT_THE_FLOOR))
def test_each_classified_exception_still_exists(entry: tuple[str, str]) -> None:
    assert entry in _mentions(), (
        f"{entry} is in NOT_THE_FLOOR but no longer appears — drop the entry"
    )


def _node_version_pins(node: object, path: str) -> list[tuple[str, str]]:
    """Every literal `node-version` a workflow or action pins, including an
    action input's `default`. A `${{ … }}` expression forwards a pin found
    elsewhere and is skipped; any other non-numeric spelling fails loudly."""
    pins: list[tuple[str, str]] = []
    if isinstance(node, list):
        for item in node:
            pins += _node_version_pins(item, path)
    if not isinstance(node, dict):
        return pins
    for key, value in node.items():
        if key == "node-version":
            literal = value.get("default") if isinstance(value, dict) else value
            literal = str(literal)
            if literal.startswith("${{"):
                continue
            assert re.fullmatch(r"\d+(?:\.\d+)*", literal), (
                f"{path}: node-version {literal!r} is not a numeric version"
            )
            pins.append((path, literal))
        else:
            pins += _node_version_pins(value, path)
    return pins


def test_no_ci_job_runs_below_the_floor() -> None:
    """A CI job on a Node under engines.node tests a runtime the package refuses
    to install on, and a floor bump that misses the pin goes untested."""
    pins = []
    for path in _tracked_files():
        if path.startswith(".github/") and path.endswith((".yaml", ".yml")):
            text = (REPO_ROOT / path).read_text(encoding="utf-8")
            pins += _node_version_pins(yaml.safe_load(text), path)
    assert pins, "no node-version pin found under .github — did the walk rot?"
    below = sorted(
        (path, version)
        for path, version in pins
        if int(version.split(".")[0]) < int(FLOOR)
    )
    assert not below, f"CI pins Node below the {FLOOR} floor: {below}"
