"""One Python floor, restated nowhere without a guard.

``python/pyproject.toml``'s ``requires-python`` is the floor the wheel actually
installs against. Every other statement of it — the root ``pyproject.toml``, the
ruff target, the CI job that deliberately runs the suite ON the floor, and the
operator-facing message ``plugin/scripts/provision-redactor.sh`` prints when no
interpreter is found — is a COPY, and a copy drifts: the provisioner went on
telling operators to install 3.11+ after the floor was lowered to 3.10, sending
them to fetch an interpreter they did not need.

Rather than pin each copy to a literal, this derives the floor from the wheel's
declaration and asserts every copy matches. The prose scan is a partition: each
``Python 3.N`` in a tracked file either states the floor (and must equal it) or
is listed in :data:`NOT_THE_FLOOR` with a reason, so a NEW restatement fails here
until it is classified. Statements about Python itself — "``re`` only learned
possessive quantifiers in 3.11" — are the classified exceptions, not floor
claims.

This is a DRIFT GUARD, marked as one rather than dressed up as an SSOT: four
hand-written copies of the floor still exist and this only asserts they agree.
Killing the duplication is infeasible at the concrete boundary that matters —
``provision-redactor.sh`` runs inside an installed Claude Code plugin, where
``python/pyproject.toml`` is not on disk (and the whole point of the message is
that no interpreter was found to read it with), so the floor it prints cannot be
sourced at runtime.
"""

import re
import subprocess

import pytest

from tests._helpers import REPO_ROOT

pytestmark = pytest.mark.drift_guard(
    "the Python floor is restated in pyproject.toml x2, ruff's target-version, "
    "the CI job pin and an operator-facing script message — none can read the "
    "others across their tool/ecosystem boundary, so each copy is checked "
    "against the wheel's own requires-python instead"
)

# A prose version claim, with an optional trailing `+`. The literal prefix is
# required so bare version-ish numbers (hashes, ratios, dependency pins) are not
# read as floor claims. Do not spell out an example here: this module is scanned
# like every other tracked file, and an example would match itself.
#
# The separator class must include U+00A0: the repo's guides are written with
# non-breaking spaces around short tokens, so an ASCII-space-only pattern read
# right past `CLAUDE.md`'s version mention while catching the SAME sentence in
# `.claude/skills/writing-tests/SKILL.md` — one file guarded, its twin invisible,
# which is the coverage hole this module exists to close.
PYTHON_VERSION_PROSE = re.compile(r"Python[ \u00a0](?P<version>3\.\d+)\+?")

# (path, version) -> why this mention is NOT a statement of the package floor.
# Keyed by version rather than line number so the entry survives an edit above
# it. Every entry is asserted to still be found, so a stale one fails too.
NOT_THE_FLOOR = {
    ("CLAUDE.md", "3.9"): (
        "the same builtin-generics language fact, from the root guide"
    ),
    (".claude/skills/writing-tests/SKILL.md", "3.9"): (
        "a fact about the language (when builtin generics landed), not our floor"
    ),
    ("python/agent_sanitizer/secrets/engine.py", "3.11"): (
        "why the engine cannot use possessive quantifiers — a language fact"
    ),
    ("tests/secrets/test_redos_static_guard.py", "3.11"): (
        "the same possessive-quantifier language fact, from the ReDoS guard"
    ),
    ("python/agent_sanitizer/secrets/prefilter.py", "3.11"): (
        "which release renamed the stdlib regex parser to `re._parser` — a "
        "language fact naming the version the import branches on, and the branch "
        "exists precisely BECAUSE the floor is lower"
    ),
}


# Tracked but not hand-written: a generated bundle, a lockfile and the
# append-only release notes restate versions nobody here chose, and none of them
# is a place a maintainer would copy the floor into.
GENERATED_PREFIXES = ("plugin/dist/", "pnpm-lock.yaml", "uv.lock", "CHANGELOG.md")


def _tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [p for p in out.split("\0") if p and not p.startswith(GENERATED_PREFIXES)]


def _requires_python(relative: str) -> str:
    """The ``>=X.Y`` floor from a pyproject, read without ``tomllib`` so this
    guard runs unchanged on the 3.10 floor it is guarding."""
    text = (REPO_ROOT / relative).read_text(encoding="utf-8")
    match = re.search(r'^requires-python\s*=\s*">=(?P<floor>\d+\.\d+)"', text, re.M)
    assert match, f'no `requires-python = ">=X.Y"` line in {relative}'
    return match.group("floor")


#: The one source of truth: what the published wheel requires.
FLOOR = _requires_python("python/pyproject.toml")


def test_the_two_pyprojects_declare_the_same_floor() -> None:
    """The root pyproject drives `uv run --extra dev pytest`; the wheel's drives
    what users can install. A split between them means CI is testing a Python
    the package does not claim to support (or vice versa)."""
    assert _requires_python("pyproject.toml") == FLOOR


def test_ruff_targets_the_floor() -> None:
    """ruff's target-version decides which syntax it accepts. Targeting above the
    floor lets 3.11-only syntax through lint and explode at install time — which
    is exactly how a possessive quantifier once reached the engine."""
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^target-version\s*=\s*"py(?P<v>\d+)"', text, re.M)
    assert match, "no `[tool.ruff] target-version` in pyproject.toml"
    assert match.group("v") == FLOOR.replace(".", "")


def test_ci_runs_the_suite_on_the_floor() -> None:
    """The floor is only real if something runs on it. `validate-config.yaml`
    pins pytest to it deliberately; a bump that misses this line silently stops
    exercising the version users install on."""
    workflow = (REPO_ROOT / ".github" / "workflows" / "validate-config.yaml").read_text(
        encoding="utf-8"
    )
    pins = re.findall(r"uv run --python (?P<v>3\.\d+) --extra dev pytest", workflow)
    assert pins, "validate-config.yaml no longer pins the pytest run to a Python"
    assert set(pins) == {FLOOR}


def test_provisioner_names_the_floor() -> None:
    """The one operator-facing statement of the floor: what to install when the
    Layer-4 engine could not be provisioned."""
    script = (REPO_ROOT / "plugin" / "scripts" / "provision-redactor.sh").read_text(
        encoding="utf-8"
    )
    versions = {m.group("version") for m in PYTHON_VERSION_PROSE.finditer(script)}
    assert versions == {FLOOR}, (
        f"provision-redactor.sh advertises {sorted(versions)}; the wheel's floor "
        f"is {FLOOR}"
    )


def _prose_mentions() -> list[tuple[str, str]]:
    found = []
    for path in _tracked_files():
        full = REPO_ROOT / path
        if not full.is_file():
            continue
        text = full.read_text(encoding="utf-8", errors="ignore")
        for match in PYTHON_VERSION_PROSE.finditer(text):
            found.append((path, match.group("version")))
    return found


def test_every_python_version_in_prose_is_the_floor_or_classified() -> None:
    """The partition: a `Python 3.N` in a tracked file either states the floor or
    is a classified language fact. A new copy of the floor is guarded the moment
    it is written; a new language fact must say so out loud."""
    mentions = _prose_mentions()
    assert mentions, "no `Python 3.N` prose found at all — did the pattern rot?"
    unclassified = sorted(
        {
            (path, version)
            for path, version in mentions
            if version != FLOOR and (path, version) not in NOT_THE_FLOOR
        }
    )
    assert not unclassified, (
        f"these name a Python other than the {FLOOR} floor: {unclassified}. Fix them, "
        "or add them to NOT_THE_FLOOR with the reason they are not floor claims."
    )


@pytest.mark.parametrize("entry", sorted(NOT_THE_FLOOR))
def test_each_classified_exception_still_exists(entry: tuple[str, str]) -> None:
    """A stale exception is a hole: it would silently excuse a future mention of
    the same version in the same file."""
    assert entry in _prose_mentions(), (
        f"{entry} is in NOT_THE_FLOOR but no longer appears — drop the entry"
    )
