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


# ─── Negative corpus: legitimate content must produce ZERO findings ──────────
# Precision doctrine — a false positive here deletes text the model needed.

LEGITIMATE = {
    "python import": "from agent_sanitizer.secrets import redact, redact_map",
    "env reference in code": "api_key = os.environ['ANTHROPIC_API_KEY_NAME']",
    "shell default": 'TOKEN_FILE="${SECRET_FILE:-/etc/app/secret}"',
    "docker compose mount": "  - secret_path: /run/secrets/app-config:ro",
    "oauth discovery doc": "token_url = https://oauth2.googleapis.com/token",
    "oci image digest": "image_digest: sha256:" + "a1b2c3d4e5f60718" * 4,
    "uuid record id": 'session_secret_id = "550e8400-e29b-41d4-a716-446655440000"',
    "iso timestamp": 'access_token_expiry = "2025-11-04T10:30:00.000000Z"',
    "semver": 'secret_version = "1.14.2-rc.1"',
    "pagination cursor": "nextPageToken=CiAKGjBpNDd2Nmp2Zml2c2Vh",
    "docs metavariable": 'export ANTHROPIC_API_KEY="<your-api-key-here>"',
    "ci template": "  api_key: {{ secrets.ANTHROPIC_API_KEY }}",
    "markdown prose": "Pass the `--api-key` flag or set `ANTHROPIC_API_KEY` first.",
    "metadata field": 'secret_type = "Anthropic API Key"',
    "prose about secrets": (
        "The password field is redacted before the transcript is stored."
    ),
    "json config skeleton": '{"client_secret": "changeme", "token": "TODO"}',
    "log line": "2025-11-04 10:30:00 INFO  auth: token refreshed for user 42",
    "sql schema": "  api_key_hash CHAR(64) NOT NULL,  -- sha256 of the key",
    "diff header": "--- a/python/agent_sanitizer/secrets/engine.py",
    # Deliberately a documented stand-in slug, not a real owner: this corpus is
    # scanned by tests/test_repo_slug.py, which requires every github.com URL in
    # the tree to name this repo or a classified one. The detector under test
    # cares about the URL's shape, not whose repo it names.
    "public repo url": "git clone https://github.com/owner/repo.git",
    # Shape-adjacent to a provider key, so these reach the prefix and length
    # arms rather than the keyword path the entries above exercise.
    "commit sha": "commit 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b landed",
    "hashed asset filename": "the bundle main.9fbe7a2c4d.css loaded fine",
    "sub-floor prefix words": "the r8_cache lookup and the xai-config loader moved",
    "url with query string": "https://example.invalid/s?q=redaction&page=12&sort=rel",
    "base64 of a sentence": "dGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5",
    "prose naming a key prefix": "every OpenAI key starts with the sk- prefix",
    "pip requirement pin": "detect-secrets==1.5.0 ; python_version >= '3.10'",
    # A token prefix reached WORD-INTERNALLY: "wei|ghs_" inside an ordinary
    # snake_case name, with an identifier-shaped tail long enough to complete
    # the classic-GitHub body. This is the shape that made a real pytest name
    # redact as a GitHub token.
    "snake_case name containing a token prefix": (
        "def test_planner_weighs_a_burned_in_check_at_its_own_repeat_count():"
    ),
}


# The subset that must ALSO survive attacker-controlled ingress: everything
# whose verdict rests on the value's own shape, never on a forgeable field name.
SHAPE_ONLY_LEGITIMATE = (
    "commit sha",
    "hashed asset filename",
    "sub-floor prefix words",
    "url with query string",
    "base64 of a sentence",
    "prose naming a key prefix",
    "pip requirement pin",
    "snake_case name containing a token prefix",
    "python import",
    "env reference in code",
    "oauth discovery doc",
    "oci image digest",
    "uuid record id",
    "iso timestamp",
    "semver",
    "docs metavariable",
    "ci template",
    "markdown prose",
    "prose about secrets",
    "json config skeleton",
    "diff header",
    "public repo url",
)
