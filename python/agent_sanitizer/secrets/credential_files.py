"""The published credential-FILE vocabulary: the paths that hold a secret.

``data/credential-files.json`` is the single source; this module validates it and
builds the one predicate every consumer needs, :func:`credential_path_matcher`.
Two consumers once kept their own lists (a find-by-name pattern set and a
substring list over command text) and the lists disagreed, so ``cat ~/.pgpass``
was flagged by neither. The words are shared here, and so is the rule:

* ``nameGlobs`` match the path's leaf name;
* ``pathGlobs`` match the whole posix path, and start ``*/`` so the tool
  directory may sit anywhere in it;
* ``directories`` match any path component, so a whole directory is covered.

Matching is case-insensitive and uses :func:`fnmatch.fnmatchcase` on casefolded
text. A match reports that a path is credential-shaped, not that it holds a secret.

A malformed spec raises rather than degrading: an empty list matches nothing (every
credential file passes) and a glob made only of wildcards matches everything.

The same file is published to JavaScript consumers as the npm subpath export
``agent-sanitizer/credential-files``.
"""

import functools
import json
import re
from collections.abc import Callable, Mapping, Sequence
from fnmatch import fnmatchcase
from pathlib import Path
from typing import NamedTuple

CREDENTIAL_FILES_FILE = (
    Path(__file__).resolve().parent / "data" / "credential-files.json"
)

_FILE_LABEL = "credential-files.json"

# Lower-case only, because the text is casefolded before it is compared: an
# upper-case glob would never match, which is a silent hole, so it is refused.
# Matched with fullmatch, not `$`, because `$` also matches before a trailing
# newline and the JavaScript validator must accept and reject the same entries.
_NAME_GLOB_RE = re.compile(r"[a-z0-9_.*-]+")
_PATH_GLOB_RE = re.compile(r"\*/[a-z0-9_.*/-]+")
_DIRECTORY_RE = re.compile(r"[a-z0-9_.-]+")
_LITERAL_RE = re.compile(r"[a-z0-9_.-]")


class CredentialFiles(NamedTuple):
    """A validated credential-file spec."""

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
        raise ValueError(f"{_FILE_LABEL}: {field} is empty or missing")
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
        raise ValueError(f"{_FILE_LABEL}: bad entr(ies) {bad} in {field}")
    return tuple(dict.fromkeys(items))


def parse_credential_files(spec: Mapping[str, object]) -> CredentialFiles:
    """Validate ``spec`` and return it.

    Pure and public so a consumer, and the fail-closed tests, can drive the
    validator with a substitute spec instead of only through the packaged file.
    """
    return CredentialFiles(
        name_globs=_entries(spec, "nameGlobs", _NAME_GLOB_RE),
        path_globs=_entries(spec, "pathGlobs", _PATH_GLOB_RE),
        directories=_entries(spec, "directories", _DIRECTORY_RE),
    )


@functools.cache
def _rendered() -> CredentialFiles:
    """The validated packaged vocabulary. Raises if the data file is absent (fail
    closed: a partial vocabulary silently under-matches)."""
    return parse_credential_files(
        json.loads(CREDENTIAL_FILES_FILE.read_text(encoding="utf-8"))
    )


def credential_name_globs() -> tuple[str, ...]:
    """Lower-case leaf-name globs of credential files (``.npmrc``, ``*.pem``)."""
    return _rendered().name_globs


def credential_path_globs() -> tuple[str, ...]:
    """Lower-case posix path globs, each starting ``*/`` (``*/.docker/config.json``)."""
    return _rendered().path_globs


def credential_directories() -> tuple[str, ...]:
    """Lower-case directory names whose whole contents count (``.ssh``)."""
    return _rendered().directories


def _components(path: str) -> Sequence[str]:
    """The casefolded path components, without empty or ``.`` ones."""
    return [part for part in path.casefold().split("/") if part not in ("", ".")]


def credential_path_matcher(
    *, spec: Mapping[str, object] | None = None
) -> Callable[[str], bool]:
    """A predicate: is this path a credential file, or inside a credential directory?

    A path matches when any one holds, case-insensitively:

    * its leaf name matches a ``nameGlobs`` entry;
    * its posix path matches a ``pathGlobs`` entry. A relative path is matched as
      if a ``/`` preceded it, so ``.docker/config.json`` meets ``*/.docker/config.json``;
    * any of its components is in ``directories``.

    ``~`` is an ordinary component, so ``~/.pgpass`` matches without expansion.
    The returned predicate closes over the parsed vocabulary, so build it once.
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
