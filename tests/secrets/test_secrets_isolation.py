"""The base package must stay dependency-free.

A headline guarantee of the `secrets` extra is that every ``detect-secrets``
import lives inside ``agent_sanitizer.secrets`` — so a plain
``import agent_sanitizer`` never pulls in the optional dependency. This
guards that invariant: it breaks the day someone adds a top-level
``from .secrets import ...`` to the base package, which would silently make the
base install require detect-secrets.
"""

import subprocess
import sys

from tests._helpers import REPO_ROOT

_PKG = REPO_ROOT / "python"


def test_base_import_does_not_pull_detect_secrets():
    # A fresh interpreter (not this test process, which has already imported the
    # engine) so the module cache is clean.
    code = (
        "import sys; "
        "import agent_sanitizer; "
        "assert 'detect_secrets' not in sys.modules, "
        "'base import leaked detect_secrets'; "
        # Sanity: importing the subpackage DOES load it, proving the negative
        # above is not vacuous (e.g. detect-secrets simply absent).
        "import agent_sanitizer.secrets; "
        "assert 'detect_secrets' in sys.modules, "
        "'secrets subpackage failed to load its oracle'; "
        "print('ok')"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(_PKG),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"
