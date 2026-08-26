"""Both readers of git's repository-location overrides strip the same names.

PROBLEM CLASS — the list existed twice, once in `.hooks/run-guard-pairs.mjs` and
once in `tests/_helpers.py`, with nothing tying them together. A name added to
one alone drifts SILENTLY: the guard suites the pre-commit hook spawns keep
inheriting the override, so a suite that commits into a throwaway repo writes
those commits onto the developer's real branch and nothing reports an error.

`config/git-location-vars.json` is now the one list. These tests measure each
reader's BEHAVIOUR against it — the exact set of names it removes from a real
environment — so a reader that grows a private copy, or stops reading the shared
file, reds here rather than drifting.
"""

import json
import os
import subprocess

from tests._helpers import GIT_LOCATION_VARS_CONFIG, REPO_ROOT, env_without_git_location

VARS = frozenset(
    json.loads((REPO_ROOT / GIT_LOCATION_VARS_CONFIG).read_text(encoding="utf-8"))[
        "vars"
    ]
)

#: Names shaped like the list's members but deliberately absent from it. A reader
#: carrying a private copy is most likely to differ on one of these, and the
#: exact-set assertions below fail on any difference either way.
_NEAR_MISSES = ("GIT_NAMESPACE", "GIT_ALTERNATE_OBJECT_DIRECTORIES")

_NODE_PROBE = """
import { envWithoutGitLocation } from "./.hooks/lib/git-location-env.mjs";
const before = Object.keys(process.env);
const after = new Set(Object.keys(envWithoutGitLocation(process.env)));
process.stdout.write(JSON.stringify(before.filter((k) => !after.has(k))));
"""


def _probe_env() -> dict[str, str]:
    """A real environment with every listed name, and every near miss, set."""
    return {**os.environ, **{name: "probe" for name in (*VARS, *_NEAR_MISSES)}}


def test_the_shared_list_is_not_empty() -> None:
    # Non-vacuity: both assertions below compare against VARS, and an empty list
    # would make each one hold over nothing.
    assert VARS


def test_the_python_reader_strips_exactly_the_listed_names(monkeypatch) -> None:
    for name, value in _probe_env().items():
        monkeypatch.setenv(name, value)
    stripped = set(os.environ) - set(env_without_git_location())
    assert stripped == set(VARS)


# not-a-drift-guard: behavior tested against the one shared JSON config
# (config/git-location-vars.json), not compared against a second hand-copy.
def test_the_node_reader_strips_exactly_the_listed_names() -> None:
    env = _probe_env()
    result = subprocess.run(
        ["node", "--input-type=module", "-e", _NODE_PROBE],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
        env=env,
    )
    assert set(json.loads(result.stdout)) == set(VARS)
