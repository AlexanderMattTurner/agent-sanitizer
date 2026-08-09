"""Guards that .gitleaks.toml allowlist paths are anchored.

gitleaks matches allowlist `paths` regexes unanchored, so an unanchored
`tests/secrets/.*` also matches `x/tests/secrets/foo` — letting an attacker
bypass the Required scan by nesting secrets under a lookalike directory. These
tests assert every allowlist path is anchored with `^` and verify the anchoring
behaves (rejects the nested lookalike, still accepts the real fixture path).
"""

import re

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 (the package floor) has no tomllib
    import tomli as tomllib

from tests._helpers import REPO_ROOT

GITLEAKS_TOML = REPO_ROOT / ".gitleaks.toml"


def _allowlist_paths() -> list[str]:
    config = tomllib.loads(GITLEAKS_TOML.read_text())
    # `[[allowlists]]` (array of tables), not a single `[allowlist]`: each
    # allowlist scopes its own paths and reason, so widening one cannot
    # silently widen another. Every table's paths are guarded here.
    allowlists = config["allowlists"]
    assert len(allowlists) > 1, (
        "expected the per-scope allowlist tables; a collapse back to one "
        "table would let a single widened scope cover every fixture path"
    )
    paths = [path for allowlist in allowlists for path in allowlist["paths"]]
    assert paths, "expected at least one allowlist path"
    return paths


def test_every_allowlist_path_is_anchored() -> None:
    paths = _allowlist_paths()
    unanchored = [p for p in paths if not p.startswith("^")]
    assert not unanchored, f"unanchored allowlist paths bypass the scan: {unanchored}"


def test_nested_lookalike_is_not_allowlisted() -> None:
    paths = _allowlist_paths()
    compiled = [re.compile(p) for p in paths]
    # Negative: a nested directory an attacker adds must NOT be allowlisted.
    assert not any(c.search("x/tests/secrets/foo") for c in compiled)
    assert not any(
        c.search("evil/python/agent_sanitizer/secrets/data/secret-detectors.json")
        for c in compiled
    )
    # Positive markers: the real fixture paths still match, so we know the
    # patterns are live and the negatives above aren't passing vacuously.
    assert any(c.search("tests/secrets/aws.txt") for c in compiled)
    assert any(
        c.search("python/agent_sanitizer/secrets/data/secret-detectors.json")
        for c in compiled
    )
