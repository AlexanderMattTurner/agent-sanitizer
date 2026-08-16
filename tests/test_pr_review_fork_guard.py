"""The trust gate on claude-pr-review.yaml's title-driven skip path.

A PR title is written by the PR author. Two jobs key on it: `decide` skips the
model review for a `chore:`/`style:`/`release:` title, and `auto-approve-skipped`
answers that same skip with an approving review, a green "Review findings
resolved" check run, and a re-derived "Automated review posted" status. Three
merge levers, chosen by a string the author controls — so an untrusted PR named
`chore: bump` merged without ever being read.

Both jobs now require a TRUST signal before the title means anything: the PR is
same-repo, or its author is an OWNER/MEMBER/COLLABORATOR of the base repo. The
two gates must move together, which is what these tests pin:

  * no title routes a cross-repository PR into `auto-approve-skipped`; and
  * every non-draft PR is reviewed OR auto-approved, never neither — guarding
    the fork PR titled `chore:` that a one-sided fix would strand with no
    review, no approval, and no further event able to produce either.

The workflow `if:` expressions are EVALUATED here (over the payload shapes
GitHub sends) rather than pattern-matched as text: a text assertion keeps
passing when the condition is rearranged into an equivalent-looking form that
decides differently.
"""

import itertools
import re

import pytest
import yaml

from tests._helpers import REPO_ROOT

WORKFLOW = REPO_ROOT / ".github" / "workflows" / "claude-pr-review.yaml"
JOBS = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]
DECIDE_IF = JOBS["decide"]["if"]
AUTO_APPROVE_IF = JOBS["auto-approve-skipped"]["if"]

# The titles the skip path recognizes, plus ordinary ones it must not.
SKIP_TITLES = [
    "chore: bump deps",
    "chore(deps): bump deps",
    "style: reformat",
    "style(css): reformat",
    "release: v1.2.3",
    "release(npm): v1.2.3",
]
REVIEWED_TITLES = ["feat: add a layer", "fix: patch the parser", "docs: rewrite"]

# `author_association` values that carry no write access to the base repo.
UNTRUSTED_ASSOCIATIONS = [
    "CONTRIBUTOR",
    "FIRST_TIME_CONTRIBUTOR",
    "FIRST_TIMER",
    "MANNEQUIN",
    "NONE",
]
TRUSTED_ASSOCIATIONS = ["OWNER", "MEMBER", "COLLABORATOR"]

BASE_REPO = "acme/agent-sanitizer"


class _Null:
    """GitHub's `null`: any property of it is null, and it equals nothing."""

    def __getattr__(self, _name: str) -> "_Null":
        return self

    def __eq__(self, _other: object) -> bool:
        return False

    def __hash__(self) -> int:
        return 0


NULL = _Null()


class _Ctx:
    """Dotted context lookup with GitHub's missing-property-is-null semantics."""

    def __init__(self, data: dict):
        self._data = data

    def __getattr__(self, name: str):
        if name not in self._data:
            return NULL
        value = self._data[name]
        return _Ctx(value) if isinstance(value, dict) else value


def _starts_with(value, prefix: str) -> bool:
    return isinstance(value, str) and value.startswith(prefix)


# GitHub's expression grammar is a subset of Python's once the operators are
# spelled Python's way; the translation is textual because the surface used in
# these two conditions is exactly: || && ! == != ( ) 'literal' false
# startsWith(). Anything else must be added here deliberately rather than
# silently evaluating as Python.
_ALLOWED = re.compile(
    r"""\s|\(|\)|,|'[^']*'|&&|\|\||!=|==|!|true|false|startsWith|github(?:\.[A-Za-z_]+)+"""
)


def _to_python(expression: str) -> str:
    leftover = _ALLOWED.sub("", expression)
    assert not leftover.strip(), (
        f"unsupported syntax in the workflow condition: {leftover!r} — extend "
        "this evaluator instead of letting it evaluate as raw Python"
    )
    out = expression.replace("!=", "\0NE\0")
    out = out.replace("!", " not ")
    out = out.replace("\0NE\0", "!=")
    out = out.replace("&&", " and ").replace("||", " or ")
    out = re.sub(r"\bfalse\b", "False", out)
    out = re.sub(r"\btrue\b", "True", out)
    return out


def _evaluate(expression: str, github: dict) -> bool:
    return bool(
        eval(  # noqa: S307 — the input is this repo's own workflow, checked above
            _to_python(expression),
            {"__builtins__": {}},
            {"github": _Ctx(github), "startsWith": _starts_with},
        )
    )


def _github(
    title: str,
    *,
    action: str = "opened",
    draft: bool = False,
    user_type: str = "User",
    association: str = "CONTRIBUTOR",
    head_repo: str = BASE_REPO,
) -> dict:
    """The `github` context of a pull_request_target event, as GitHub sends it."""
    return {
        "repository": BASE_REPO,
        "event": {
            "action": action,
            "pull_request": {
                "title": title,
                "draft": draft,
                "user": {"type": user_type},
                "author_association": association,
                "head": {"repo": {"full_name": head_repo}},
            },
        },
    }


FORK_REPO = "attacker/agent-sanitizer"
UNTRUSTED = [
    {"association": association, "head_repo": FORK_REPO}
    for association in UNTRUSTED_ASSOCIATIONS
]
TRUSTED = [
    {"association": association, "head_repo": FORK_REPO}
    for association in TRUSTED_ASSOCIATIONS
] + [
    {"association": association, "head_repo": BASE_REPO}
    for association in UNTRUSTED_ASSOCIATIONS
]


def test_the_evaluator_is_not_vacuous() -> None:
    # Both verdicts must be reachable, or every assertion below is worthless.
    assert _evaluate("github.event.action == 'labeled'", _github("x", action="labeled"))
    assert not _evaluate("github.event.action == 'labeled'", _github("x"))
    assert _evaluate(
        "!(github.event.pull_request.draft == false)", _github("x", draft=True)
    )
    assert _evaluate(
        "startsWith(github.event.pull_request.title, 'chore:')", _github("chore: x")
    )
    # A property GitHub omits reads as null and matches nothing.
    assert not _evaluate(
        "github.event.pull_request.head.repo.full_name == github.repository",
        {"repository": BASE_REPO, "event": {"pull_request": {"head": {}}}},
    )


def test_both_gates_actually_read_the_trust_signals() -> None:
    # A positive marker: the conditions must mention the payload fields the
    # tests below rely on, so a rewrite that drops the guard entirely fails
    # here rather than passing on some accidentally-equivalent shape.
    for condition in (DECIDE_IF, AUTO_APPROVE_IF):
        assert "author_association" in condition
        assert "head.repo.full_name" in condition


@pytest.mark.parametrize("title", SKIP_TITLES + REVIEWED_TITLES)
@pytest.mark.parametrize("trust", UNTRUSTED, ids=lambda t: t["association"])
@pytest.mark.parametrize("user_type", ["User", "Bot"])
def test_no_title_routes_a_cross_repository_pr_into_auto_approve(
    title: str, trust: dict, user_type: str
) -> None:
    # The finding: `auto-approve-skipped` submits an approving review, greens
    # the review-findings check run and re-derives the review status. A fork PR
    # must reach none of that by naming itself.
    github = _github(title, user_type=user_type, **trust)
    assert not _evaluate(AUTO_APPROVE_IF, github)


@pytest.mark.parametrize("title", SKIP_TITLES)
@pytest.mark.parametrize("trust", UNTRUSTED, ids=lambda t: t["association"])
def test_a_cross_repository_pr_is_reviewed_whatever_it_calls_itself(
    title: str, trust: dict
) -> None:
    # The other half of the fix: guarding only the approval would leave this PR
    # skipped by `decide` AND unapproved — stranded on both gates forever.
    assert _evaluate(DECIDE_IF, _github(title, **trust))


@pytest.mark.parametrize("title", SKIP_TITLES)
@pytest.mark.parametrize(
    "trust", TRUSTED, ids=lambda t: f"{t['association']}-{t['head_repo']}"
)
def test_a_trusted_low_risk_pr_still_skips_the_review_and_is_approved(
    title: str, trust: dict
) -> None:
    assert not _evaluate(DECIDE_IF, _github(title, **trust))
    assert _evaluate(AUTO_APPROVE_IF, _github(title, **trust))


def test_a_same_repo_bot_pr_still_skips_the_review_and_is_approved() -> None:
    # Dependabot pushes its branch to this repo, so it stays in the skipped
    # class the auto-approve job exists to unblock.
    github = _github("Bump acorn from 8.0.0 to 8.0.1", user_type="Bot")
    assert not _evaluate(DECIDE_IF, github)
    assert _evaluate(AUTO_APPROVE_IF, github)


@pytest.mark.parametrize("title", REVIEWED_TITLES)
def test_an_ordinary_title_is_reviewed_and_never_auto_approved(title: str) -> None:
    github = _github(title, association="MEMBER")
    assert _evaluate(DECIDE_IF, github)
    assert not _evaluate(AUTO_APPROVE_IF, github)


@pytest.mark.parametrize("title", SKIP_TITLES)
def test_a_draft_reaches_neither_job(title: str) -> None:
    # Drafts cannot merge; they are picked up on `ready_for_review`.
    github = _github(title, action="opened", draft=True, association="MEMBER")
    assert not _evaluate(DECIDE_IF, github)
    assert not _evaluate(AUTO_APPROVE_IF, github)


@pytest.mark.parametrize(
    "title,trust,user_type",
    list(
        itertools.product(
            SKIP_TITLES + REVIEWED_TITLES, UNTRUSTED + TRUSTED, ["User", "Bot"]
        )
    ),
    ids=str,
)
def test_every_non_draft_pr_is_reviewed_or_approved_never_neither(
    title: str, trust: dict, user_type: str
) -> None:
    # The exhaustiveness invariant the two gates hold jointly. A PR that reaches
    # neither job gets no review to clear "Automated review posted" and no
    # approval to clear the review-required ruleset, and no later event
    # produces either — it is stuck, silently.
    github = _github(title, user_type=user_type, **trust)
    assert _evaluate(DECIDE_IF, github) or _evaluate(AUTO_APPROVE_IF, github)
