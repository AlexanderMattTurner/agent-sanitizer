"""Shared helpers for the agent_sanitizer.secrets test suite.

The engine takes config *in* (never discovered), so these helpers call the
public API directly: ``run_plain`` returns ``None`` when nothing is emitted
(clean input), ``run_map`` drives map mode, and ``cfg`` builds a
:class:`RedactorConfig`. No env clearing is needed — a bare config has no
env-bound values.
"""

import json
import socket
import time
from pathlib import Path

from tests._helpers import ensure_python_pkg_on_path

# Put python/ on the path so `import agent_sanitizer.secrets` resolves to the
# working tree.
ensure_python_pkg_on_path()

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


def wait_for_listener(socket_path: str, timeout: float = 10.0) -> None:
    """Block until a daemon is ACCEPTING on ``socket_path``, or raise.

    Waiting for the socket *file* to appear is not the same thing and is a real
    race: ``serve()`` binds, then listens, and ``bind()`` is what creates the
    file. A probe landing in that window connects to a bound-but-not-listening
    path, gets ECONNREFUSED, and correctly concludes the path is reclaimable —
    which is exactly the verdict a caller may be asserting is ``False``. Probing
    with a real connect() removes the window, because connect() succeeds only
    once listen() has run.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.connect(socket_path)
            return
        except (FileNotFoundError, ConnectionRefusedError):
            time.sleep(0.02)
        finally:
            # Closed either way: on success the daemon reads EOF and drops the
            # connection, so the probe leaves no state behind.
            probe.close()
    raise AssertionError(
        f"no daemon accepting on {socket_path} after {timeout}s "
        "(socket file may exist without a listener)"
    )
