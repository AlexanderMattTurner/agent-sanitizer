"""The credential-FILE vocabulary (``data/credential-files.json``) and the path
matcher built from it; JavaScript reads the same file as
``agent-sanitizer/credential-files``.

``nameGlobs`` match a path's leaf name, ``pathGlobs`` the whole posix path (each
starts ``*/`` so the tool directory may sit anywhere), ``directories`` any
component. Matching is case-insensitive and says a path is credential-shaped, not
that it holds a secret. A malformed spec raises: an empty list matches nothing and
a wildcard-only glob matches everything.
"""

import functools
import json
import re
from collections.abc import Callable, Mapping, Sequence
from fnmatch import fnmatchcase
from pathlib import Path
from typing import NamedTuple

CREDENTIAL_FILES_FILE = Path(__file__).parent / "data" / "credential-files.json"

# Lower-case only: the text is lower-cased first. fullmatch, since `$` matches before "\n".
_NAME_GLOB_RE = re.compile(r"[a-z0-9_.*-]+")
_PATH_GLOB_RE = re.compile(r"\*/[a-z0-9_.*/-]+")
_DIRECTORY_RE = re.compile(r"[a-z0-9_.-]+")
_LITERAL_RE = re.compile(r"[a-z0-9_.-]")


class CredentialFiles(NamedTuple):
    name_globs: tuple[str, ...]
    path_globs: tuple[str, ...]
    directories: tuple[str, ...]


def _entries(
    spec: Mapping[str, object], field: str, shape: re.Pattern[str]
) -> tuple[str, ...]:
    """``spec[field]`` as a validated, de-duplicated tuple, or raise naming it."""
    value = spec.get(field)
    items = tuple(value) if isinstance(value, (list, tuple)) else ()
    if not items:
        raise ValueError(f"credential-files.json: {field} is empty or missing")
    bad = [
        item
        for item in items
        if not (
            isinstance(item, str)
            and shape.fullmatch(item)
            # A glob of wildcards alone matches every path, and `..` would flag
            # every path that climbs a directory.
            and _LITERAL_RE.search(item)
            and item not in (".", "..")
        )
    ]
    if bad:
        raise ValueError(f"credential-files.json: bad entr(ies) {bad} in {field}")
    return tuple(dict.fromkeys(items))


def parse_credential_files(spec: Mapping[str, object]) -> CredentialFiles:
    """Validate ``spec`` and return it; pure, so a substitute spec can drive it."""
    return CredentialFiles(
        name_globs=_entries(spec, "nameGlobs", _NAME_GLOB_RE),
        path_globs=_entries(spec, "pathGlobs", _PATH_GLOB_RE),
        directories=_entries(spec, "directories", _DIRECTORY_RE),
    )


@functools.cache
def _rendered() -> CredentialFiles:
    """The validated packaged vocabulary; raises if the data file is absent."""
    return parse_credential_files(
        json.loads(CREDENTIAL_FILES_FILE.read_text(encoding="utf-8"))
    )


def credential_name_globs() -> tuple[str, ...]:
    return _rendered().name_globs


def credential_path_globs() -> tuple[str, ...]:
    return _rendered().path_globs


def credential_directories() -> tuple[str, ...]:
    return _rendered().directories


def _components(path: str) -> Sequence[str]:
    """Lower-cased components minus ``.`` and empty ones; ``..`` drops its parent.
    ``str.lower`` agrees with JavaScript's ``toLowerCase``; ``casefold`` does not."""
    parts: list[str] = []
    for part in path.lower().split("/"):
        if part == "..":
            if parts:
                parts.pop()
        elif part not in ("", "."):
            parts.append(part)
    return parts


def credential_path_matcher(
    *, spec: Mapping[str, object] | None = None
) -> Callable[[str], bool]:
    """A predicate: is this path a credential file, or inside a credential directory?

    A relative path is matched as if a ``/`` preceded it, and ``~`` is an ordinary
    component, so ``~/.pgpass`` matches unexpanded. Build the predicate once.
    """
    rendered = _rendered() if spec is None else parse_credential_files(spec)
    directories = frozenset(rendered.directories)

    def is_credential_path(path: str) -> bool:
        parts = _components(path)
        if not parts:
            return False
        if directories.intersection(parts):
            return True
        if any(fnmatchcase(parts[-1], glob) for glob in rendered.name_globs):
            return True
        posix = "/" + "/".join(parts)
        return any(fnmatchcase(posix, glob) for glob in rendered.path_globs)

    return is_credential_path
