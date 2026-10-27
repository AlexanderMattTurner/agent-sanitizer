"""SSOT contract for .github/scripts/lib/shared-names.json label spellings.

Bash/JS/Python consumers read the JSON (directly or via shared-names.bash), but
workflow `if:` expressions cannot call jq, so a YAML literal necessarily
duplicates the merge-conflict label name. This test pins that literal to the
JSON value: renaming the label in one place without the other fails here
instead of silently leaving a gate that never fires.
"""

import json

from tests._helpers import REPO_ROOT

SHARED_NAMES = json.loads(
    (REPO_ROOT / ".github" / "scripts" / "lib" / "shared-names.json").read_text(
        encoding="utf-8"
    )
)
MERGE_CONFLICT = SHARED_NAMES["pr_labels"]["merge_conflict"]


def test_auto_resolve_labeled_gate_literal_matches_json() -> None:
    text = (
        REPO_ROOT / ".github" / "workflows" / "auto-resolve-conflicts.yaml"
    ).read_text(encoding="utf-8")
    # Positive marker first: the labeled-event gate must still exist at all —
    # without it the equality assertion below would pass vacuously.
    assert "github.event.label.name ==" in text, (
        "the labeled-event gate is gone from auto-resolve-conflicts.yaml; "
        "update this contract test alongside it"
    )
    assert f"github.event.label.name == '{MERGE_CONFLICT}'" in text
