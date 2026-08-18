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

The walk holds the same line on the targets themselves. A target it can READ and
that names no tracked file is dropped, because that is an answer. A target it
CANNOT read raises, whatever the quoting, unless `_RUNTIME_NAMED_TARGETS` gives
the reason its name exists only while the job runs.
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
_BASH_ASSIGNMENTS = Query(_BASH_LANGUAGE, "(variable_assignment) @a")


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


#: `source` argument shapes the walk below reads. A shape outside this set is
#: unresolvable, which is loud rather than skipped.
_ARGUMENT_TYPES = (
    "word",
    "string",
    "raw_string",
    "simple_expansion",
    "expansion",
    "concatenation",
)

#: `source` targets whose NAME only comes into existence at runtime, so no
#: checkout list can carry them and no closure should demand one. Keyed by the
#: sourcing file and the argument exactly as written; the value is the reason.
#: Every other unresolvable target raises — a dropped edge is a checkout
#: requirement this check silently failed to state.
_RUNTIME_NAMED_TARGETS = {
    (".github/scripts/run-hook-lifecycle.sh", '"$CLAUDE_ENV_FILE"'): (
        "an `mktemp` file this script creates and session-setup.sh writes, so the "
        "name exists only while the job runs"
    ),
    (".github/scripts/decide-reusable-diff.sh", '"$PATHS_REGEX_FILE"'): (
        "a workflow input naming a file in the CALLING repository's checkout, which "
        "this repository cannot name"
    ),
}


def _literal_tail(argument) -> str | None:
    """The fixed text at the end of a `source` argument, or None when there is none.

    A script names its libraries through a root it computes —
    `"$SCRIPT_DIR/lib/reviewer-identity.bash"` — so the only part of the runtime
    path written literally is the string's trailing literal. The bash grammar
    hands that over as the argument's last `string_content` child; everything
    before it is an expansion whose value cannot be known statically.

    None means the argument carries NO literal text at all (`"$LIB"`), which the
    caller must treat as unresolved rather than as "names nothing".
    """
    if argument.type == "word":
        return argument.text.decode()
    # A single-quoted target holds no expansion at all, so the whole literal is
    # the tail — and the grammar gives it as the node's own text, not a child.
    if argument.type == "raw_string":
        return argument.text.decode().strip("'")
    literals = [
        c
        for c in argument.children
        if c.type in ("string_content", "raw_string", "word")
    ]
    return literals[-1].text.decode().strip("\"'") if literals else None


def _expansion_name(argument) -> str | None:
    """The variable a whole-argument expansion names, as in `"$LIB"` or `$LIB`."""
    if argument.type == "string":
        inner = [c for c in argument.children if c.type != '"']
        return _expansion_name(inner[0]) if len(inner) == 1 else None
    if argument.type not in ("simple_expansion", "expansion"):
        return None
    names = [c for c in argument.children if c.type == "variable_name"]
    return names[0].text.decode() if len(names) == 1 else None


def _assigned_tails(tree) -> dict[str, set[str]]:
    """Every literal tail this file assigns to each variable name.

    A library is usually named once and sourced on the next line
    (`lib="$dir/lib/x.sh"` then `. "$lib"`), so the assignment carries the
    literal the `source` itself does not.
    """
    tails: dict[str, set[str]] = {}
    for node in QueryCursor(_BASH_ASSIGNMENTS).captures(tree.root_node).get("a", []):
        name, value = (
            node.child_by_field_name("name"),
            node.child_by_field_name("value"),
        )
        tail = None if value is None else _literal_tail(value)
        if name is not None and tail:
            tails.setdefault(name.text.decode(), set()).add(tail)
    return tails


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


#: Command names whose first argument is read like a `source`: the script
#: named there has to be on the same checkout list as `rel` itself. `bash` is
#: lenient rather than strict like `source`/`.` below — a repo-wide grep turns
#: up `bash -c`, `bash <(...)`, and third-party scripts nothing here tracks,
#: and demanding every one of those resolve would raise on code this check was
#: never meant to cover. It only ever ADDS an edge, on a target it can resolve.
_LENIENT_INVOCATIONS = ("bash",)
_STRICT_INVOCATIONS = ("source", ".")

#: A tracked file with one of these suffixes is walked further for its own
#: `source`s; anything else (`config/review-severities.json`) is a leaf the
#: closure still has to list.
_SHELL_SUFFIXES = (".sh", ".bash")


def _source_targets(rel: str, tracked: set[str]):
    """(argument as written, tracked file or None) for each checkout-relevant
    reference in `rel`: a `source`/`.`/`bash` target, or an assignment whose
    literal tail names a tracked non-shell file.

    None means the target is a real path that is simply not tracked here — an
    absolute system path, say. A `source`/`.` target the grammar cannot READ
    raises instead: telling those two apart is the whole point, because a
    silently dropped edge is a checkout requirement this module failed to
    state. `bash` and the assignment scan below never raise on an unresolved
    target — they only add edges, on the class of reference proven to exist
    (`review-findings-gate.sh` reads `config/review-severities.json` through a
    plain assignment, never a `source`).
    """
    tree = _BASH_PARSER.parse((REPO_ROOT / rel).read_bytes())
    assigned = _assigned_tails(tree)

    # A config/data path is routinely tested (`[[ -f "$VAR" ]]`) or read
    # (`jq ... "$VAR"`) without ever being `source`d, so the assignment itself
    # is the only place that reference shows up.
    for tails in assigned.values():
        for tail in tails:
            resolved = _resolve_tail(tail, rel, tracked)
            if resolved is not None and not resolved.endswith(_SHELL_SUFFIXES):
                yield tail, resolved

    for command in (
        QueryCursor(_BASH_COMMANDS).captures(tree.root_node).get("command", [])
    ):
        name = command.child_by_field_name("name")
        name_text = None if name is None else name.text.decode()
        strict = name_text in _STRICT_INVOCATIONS
        if not strict and name_text not in _LENIENT_INVOCATIONS:
            continue
        arguments = [c for c in command.children[1:] if c.type in _ARGUMENT_TYPES]
        written = arguments[0].text.decode() if arguments else ""
        tail = _literal_tail(arguments[0]) if arguments else None
        if tail is not None:
            resolved = _resolve_tail(tail, rel, tracked)
            if strict or resolved is not None:
                yield written, resolved
            continue
        # No literal in the argument itself: the name usually comes from an
        # assignment in the same file, so ask that before giving up.
        variable = _expansion_name(arguments[0]) if arguments else None
        resolved = {
            _resolve_tail(t, rel, tracked) for t in assigned.get(variable, set())
        } - {None}
        if len(resolved) > 1:
            raise AssertionError(
                f"{rel} sources `{written}`, and this file assigns it "
                f"{sorted(resolved)} — the source closure cannot say which is needed"
            )
        if resolved:
            yield written, resolved.pop()
            continue
        if not strict:
            continue
        reason = _RUNTIME_NAMED_TARGETS.get((rel, written))
        if reason is None:
            raise AssertionError(
                f"{rel}: cannot read the target of `{command.text.decode()}`. Name the "
                f"file literally, assign it in this file, or — if the name only exists "
                f"at runtime — add ({rel!r}, {written!r}) to _RUNTIME_NAMED_TARGETS in "
                f"{__name__} with the reason."
            )
        yield written, None


def sourced_by(rel: str, tracked: set[str]) -> set[str]:
    """The tracked files `rel` sources, read off the bash grammar."""
    return {target for _, target in _source_targets(rel, tracked) if target is not None}


def unresolved_sources(rel: str, tracked: set[str]) -> set[str]:
    """The `source` arguments in `rel` that reach no tracked file."""
    return {
        written for written, target in _source_targets(rel, tracked) if target is None
    }


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
