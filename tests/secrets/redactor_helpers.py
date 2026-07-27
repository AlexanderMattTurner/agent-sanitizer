"""Shared helpers for the agent_sanitizer.secrets test suite.

The engine takes config *in* (never discovered), so these helpers call the
public API directly: ``run_plain`` returns ``None`` when nothing is emitted
(clean input), ``run_map`` drives map mode, and ``cfg`` builds a
:class:`RedactorConfig`. No env clearing is needed — a bare config has no
env-bound values.
"""

import json
import sys
from pathlib import Path

from tests._helpers import REPO_ROOT

# The distribution package lives under python/; put it on the path so
# `import agent_sanitizer.secrets` resolves to the working tree.
_PKG = REPO_ROOT / "python"
if str(_PKG) not in sys.path:
    sys.path.insert(0, str(_PKG))

from agent_sanitizer.secrets import (  # noqa: E402
    RedactorConfig,
    handle_request,
    redact_map,
)

SAMPLES_FILE = Path(__file__).resolve().parent / "secret-format-samples.json"
SAMPLES = json.loads(SAMPLES_FILE.read_text())["samples"]


def cfg(**kwargs) -> RedactorConfig:
    """A RedactorConfig with the given overrides (bare by default)."""
    return RedactorConfig(**kwargs)


def run_plain(text: str, config: RedactorConfig | None = None) -> dict | None:
    """Plain-mode redaction as a JSON-shaped dict, or ``None`` when nothing is
    emitted (clean input) — the ``run_main`` stand-in."""
    return handle_request(text, False, config or RedactorConfig())


def run_map(text: str, config: RedactorConfig | None = None) -> dict:
    """Map-mode redaction (always returns a dict)."""
    return redact_map(text, config or RedactorConfig())


def reconstruct(view: dict) -> str:
    """Substitute each pair's original at its placeholder offset in the view —
    the rehydration contract."""
    out, last = [], 0
    for p in view["pairs"]:
        out.append(view["text"][last : p["start"]])
        out.append(p["original"])
        last = p["start"] + len(p["placeholder"])
    out.append(view["text"][last:])
    return "".join(out)
