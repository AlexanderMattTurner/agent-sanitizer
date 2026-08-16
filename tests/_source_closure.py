"""The files a shell entry point needs at runtime, derived from the scripts.

`source_closure` answers one question — what does this script `source`, and what
do those source in turn — so no caller retypes the answer into a workflow's
sparse-checkout list or a test fixture. A retyped copy goes stale silently: the
checkout omits a library and the job dies at the `source` line under `set -e`.

Lives beside `_helpers.py` rather than inside it because `tests/conftest.py`
imports that module, and a tree-sitter import there would make the whole suite
uncollectable in an environment that has not installed the dev extra.

The bash GRAMMAR answers the question, never a text scan: a `source` written
into a heredoc body or a message string is text no shell runs, and a scan that
tried to exclude those would miss real ones and fail OPEN — the direction a
checkout-completeness check must never fail.
"""

import subprocess

from tree_sitter import Language, Parser, Query, QueryCursor
from tree_sitter_bash import language as bash_language

from tests._helpers import REPO_ROOT, env_without_git_location

#: The bash grammar answers the one structural question below: what does
#: this script `source`? A text scan cannot tell a real `source` from one written
#: into a heredoc body or a message string, so it fails open on exactly the
#: omission the sparse-checkout closure guard exists to catch.
_BASH_LANGUAGE = Language(bash_language())
_BASH_PARSER = Parser(_BASH_LANGUAGE)
_BASH_COMMANDS = Query(_BASH_LANGUAGE, "(command) @command")


def tracked_files() -> set[str]:
    """Every path git tracks, as repo-relative strings.

    Git's index is the authority on what is in the repo, so a scratch file
    sharing a name with a real library cannot enter a source closure.
    """
    listing = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
        env=env_without_git_location(),
    ).stdout
    return {entry for entry in listing.split("\0") if entry}


def _literal_tail(argument) -> str:
    """The fixed text at the end of a `source` argument, expansions dropped.

    A script names its libraries through a root it computes —
    `"$SCRIPT_DIR/lib/reviewer-identity.bash"` — so the only part of the runtime
    path written literally is the string's trailing literal. The bash grammar
    hands that over as the argument's last `string_content` child; everything
    before it is an expansion whose value cannot be known statically.
    """
    if argument.type == "word":
        return argument.text.decode()
    # A single-quoted target holds no expansion at all, so the whole literal is
    # the tail — and the grammar gives it as the node's own text, not a child.
    if argument.type == "raw_string":
        return argument.text.decode().strip("'")
    literals = [
        c for c in argument.children if c.type in ("string_content", "raw_string")
    ]
    return literals[-1].text.decode().strip("\"'") if literals else ""


def _resolve_tail(tail: str, sourcing_file: str, tracked: set[str]) -> str | None:
    """The tracked file `tail` names, or None when it names none.

    Matched by path SUFFIX, longest candidate first, because the tail is the end
    of the runtime path rather than the whole of it. A tail matching more than
    one tracked file raises rather than guessing — a wrong closure member is a
    requirement placed on the wrong checkout list.
    """
    if not tail or tail == "/dev/null":
        return None
    trimmed = tail.lstrip("/")
    for start in range(len(trimmed)):
        if start and trimmed[start - 1] != "/":
            continue
        candidate = trimmed[start:]
        matches = {p for p in tracked if p == candidate or p.endswith("/" + candidate)}
        if not matches:
            continue
        if len(matches) > 1:
            raise AssertionError(
                f"{sourcing_file} sources '{tail}', which names {sorted(matches)} — "
                "ambiguous, so the source closure cannot say which file is needed"
            )
        return matches.pop()
    return None


def sourced_by(rel: str, tracked: set[str]) -> set[str]:
    """The tracked files `rel` sources, read off the bash grammar."""
    tree = _BASH_PARSER.parse((REPO_ROOT / rel).read_bytes())
    sourced = set()
    captures = QueryCursor(_BASH_COMMANDS).captures(tree.root_node)
    for command in captures.get("command", []):
        name = command.child_by_field_name("name")
        if name is None or name.text.decode() not in ("source", "."):
            continue
        arguments = [
            c
            for c in command.children[1:]
            if c.type in ("word", "string", "raw_string")
        ]
        if not arguments:
            raise AssertionError(
                f"{rel}: cannot read the target of `{command.text.decode()}`"
            )
        target = _resolve_tail(_literal_tail(arguments[0]), rel, tracked)
        if target is not None:
            sourced.add(target)
    return sourced


def source_closure(entries: set[str]) -> set[str]:
    """`entries` plus every tracked file they transitively `source`.

    This is what "the files a shell entry point needs at runtime" means, derived
    from the scripts themselves so no caller retypes it into a checkout list, a
    test fixture, or a workflow.
    """
    tracked = tracked_files()
    seen: set[str] = set()
    queue = list(entries)
    while queue:
        rel = queue.pop()
        if rel in seen or rel not in tracked:
            continue
        seen.add(rel)
        queue.extend(sourced_by(rel, tracked) - seen)
    return seen
