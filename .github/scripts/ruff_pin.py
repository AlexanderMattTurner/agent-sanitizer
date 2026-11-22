"""Print the ruff version that .pre-commit-config.yaml pins, or nothing if it pins none.

PROBLEM CLASS — two readers of the ruff-pre-commit rev that disagree. A regex
over the YAML reads the SHA of a `# frozen:` rev, and a neighbouring repo's rev
can match too. This is the one reader; .hooks/ruff.sh calls it through
run-with-pyyaml.sh.

Usage: run-with-pyyaml.sh ruff_pin.py <pre-commit-config.yaml>
"""

import re
import sys

import yaml

VERSION = r"v(\d+(?:\.\d+)+)"


def ruff_pin(text: str) -> str | None:
    """A SHA rev takes its version from that line's `# [frozen: ]vX.Y.Z` comment."""
    lines = text.splitlines()
    repos = next((v for k, v in yaml.compose(text).value if k.value == "repos"), None)
    for entry in repos.value if repos else []:
        fields = {k.value: v for k, v in entry.value}
        if "astral-sh/ruff-pre-commit" not in fields["repo"].value:
            continue
        rev = fields["rev"]
        comment = lines[rev.end_mark.line][rev.end_mark.column :]
        m = re.fullmatch(VERSION, rev.value) or re.fullmatch(
            rf"\s*#\s*(?:frozen:\s*)?{VERSION}\s*", comment
        )
        return m[1] if m else None
    return None


if __name__ == "__main__":
    with open(sys.argv[1], encoding="utf-8") as f:
        pin = ruff_pin(f.read())
    if pin:
        print(pin)
