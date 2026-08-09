"""Every self-referential GitHub reference names ONE repo, and all of them are guarded.

npm publishes with provenance: the sigstore bundle is minted from
``GITHUB_REPOSITORY``, so the registry rejects the upload with
``E422 … Failed to validate repository information`` when ``package.json``'s
``repository.url`` names a different owner/repo. That makes the slug a release
blocker, and it is hand-written in twenty-odd places — manifests, docs, workflow
defaults, hook error messages, `/plugin marketplace add` lines. A fork or a
transfer that updates four of them and misses the rest dies at the first publish.

Piecemeal guards (one per manifest) are how the class survives: they cover the
copies someone thought of. This is a PARTITION instead — every GitHub repo
reference and every mention of the owner in the tree must fall into a named
bucket:

* the SSOT slug read from ``package.json``;
* an explicitly allowlisted EXTERNAL repo (the upstream template, ci-truth-serum,
  pre-commit hook repos) — distinguished by name, never by pattern luck, because
  CLAUDE.md requires a fork to leave those pointing upstream;
* an explicit documentation placeholder (``owner/repo``);
* a github.com path that is not a repo at all (``settings/tokens``).

An unguarded new copy lands in none of them and fails here. Each allowlist entry
is also asserted to still occur, so the lists cannot silently rot into holes.

This is a DRIFT GUARD, marked as one rather than dressed up as an SSOT: the slug
is still hand-written in every one of those places and this only asserts they
agree. Killing the duplication is infeasible at the concrete boundaries involved
— the copies live in four ecosystems that cannot read each other's manifests
(npm ``package.json``, a hatchling ``pyproject.toml``, Claude Code plugin JSON,
GitHub Actions YAML) plus prose in Markdown and an operator message baked into a
shell script, and npm's provenance check reads the ``package.json`` copy
specifically.
"""

import json
import re
import subprocess

import pytest

from tests._helpers import REPO_ROOT

pytestmark = pytest.mark.drift_guard

# The committed plugin bundle inlines megabytes of third-party sources whose
# comments cite unrelated repos; it is generated from the linted sources.
GENERATED_PREFIXES = ("plugin/dist/",)

GITHUB_REPO_URL = re.compile(
    r"github\.com/(?P<slug>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?(?![\w.-])"
)

#: owner/repo pairs that are genuinely other people's repos. A fork of this repo
#: MUST leave these pointing upstream (CLAUDE.md), so they are named rather than
#: matched by shape.
EXTERNAL_REPOS = {
    "alexander-turner/claude-automation-template": "the upstream template this repo syncs from",
    "alexander-turner/ci-truth-serum": "an upstream CI tool this repo consumes",
    "astral-sh/ruff-pre-commit": "pinned pre-commit hook source",
    "gitleaks/gitleaks": "pinned pre-commit hook source",
    "pre-commit/pre-commit-hooks": "pinned pre-commit hook source",
    "scop/pre-commit-shfmt": "pinned pre-commit hook source",
    "shellcheck-py/shellcheck-py": "pinned pre-commit hook source",
    "Yelp/detect-secrets": "the upstream scanner the README credits for the secret detectors",
}

#: Deliberate stand-ins in docs, tests and error prose — never a real repo.
PLACEHOLDER_SLUGS = {
    "o/r": "shortest slug a workflow-parsing test can use",
    "org/repo": "documentation stand-in",
    "owner/repo": "documentation stand-in",
    "owner/downstream-repo": "template-sync documentation stand-in",
}

#: github.com paths whose first two segments are not an owner/repo pair.
NON_REPO_PATHS = {
    "apps/claude": "the GitHub App install page",
    "settings/tokens": "a GitHub account settings page",
}

#: Repos owned by THIS owner that are nonetheless not this repo. The workflows
#: interpolate the owner as the default for the template fork, so the owner
#: legitimately appears next to a repo name that is not the SSOT one.
OTHER_REPOS_UNDER_THIS_OWNER = {"claude-automation-template"}


def _tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [p for p in out.split("\0") if p and not p.startswith(GENERATED_PREFIXES)]


def _read(relative: str) -> str:
    return (REPO_ROOT / relative).read_text(encoding="utf-8", errors="ignore")


def _package_json() -> dict:
    return json.loads(_read("package.json"))


def _ssot_slug() -> str:
    """`owner/repo` from the one field npm's provenance check reads."""
    url = _package_json()["repository"]["url"]
    match = GITHUB_REPO_URL.search(url)
    assert match, f"package.json repository.url is not a GitHub URL: {url!r}"
    return match.group("slug")


SLUG = _ssot_slug()
OWNER, REPO = SLUG.split("/")


def _lines() -> list[tuple[str, int, str]]:
    return [
        (path, number, line)
        for path in _tracked_files()
        if (REPO_ROOT / path).is_file()
        for number, line in enumerate(_read(path).splitlines(), start=1)
    ]


ALL_LINES = _lines()


def test_the_source_of_truth_is_readable_and_shaped_like_a_slug() -> None:
    assert re.fullmatch(r"[\w.-]+/[\w.-]+", SLUG), SLUG
    assert ALL_LINES, "no tracked lines scanned — the walk is broken"


def test_every_manifest_url_names_the_source_of_truth() -> None:
    """The provenance-critical fields, checked structurally rather than by text
    scan: a typo'd host or a URL moved to another key still has to resolve here."""
    package = _package_json()
    plugin = json.loads(_read("plugin/.claude-plugin/plugin.json"))
    marketplace = json.loads(_read(".claude-plugin/marketplace.json"))
    pyproject = _read("python/pyproject.toml")

    urls = {
        "package.json repository.url": package["repository"]["url"],
        "package.json bugs.url": package["bugs"]["url"],
        "package.json homepage": package["homepage"],
        "plugin.json author.url": plugin["author"]["url"],
        "plugin.json homepage": plugin["homepage"],
        "plugin.json repository": plugin["repository"],
    }
    for field in ("Homepage", "Repository", "Issues"):
        match = re.search(rf'^{field}\s*=\s*"(?P<url>[^"]+)"', pyproject, re.M)
        assert match, f"python/pyproject.toml [project.urls] lost {field}"
        urls[f"python/pyproject.toml {field}"] = match.group("url")

    mismatched = {
        where: url
        for where, url in urls.items()
        if (found := GITHUB_REPO_URL.search(url)) is None or found.group("slug") != SLUG
    }
    assert not mismatched, f"these do not name {SLUG}: {mismatched}"

    # The marketplace manifest carries the OWNER alone, not a repo.
    owner_url = marketplace["owner"]["url"]
    assert owner_url == f"https://github.com/{OWNER}", owner_url


def _repo_url_slugs() -> dict[str, set[str]]:
    """slug -> the files it appears in, across every tracked non-generated file."""
    seen: dict[str, set[str]] = {}
    for path, _, line in ALL_LINES:
        for match in GITHUB_REPO_URL.finditer(line):
            seen.setdefault(match.group("slug"), set()).add(path)
    return seen


REPO_URL_SLUGS = _repo_url_slugs()


def test_every_github_url_falls_in_a_named_bucket() -> None:
    """The partition. A stale slug left behind by a fork or a transfer belongs to
    no bucket and fails here, naming the files to fix."""
    known = {SLUG, *EXTERNAL_REPOS, *PLACEHOLDER_SLUGS, *NON_REPO_PATHS}
    unclassified = {
        slug: sorted(files)
        for slug, files in REPO_URL_SLUGS.items()
        if slug not in known
    }
    assert not unclassified, (
        f"github.com URLs naming neither {SLUG} nor a classified repo: "
        f"{unclassified}. If one is this repo under a new name, update every "
        "copy; if it is someone else's, add it to EXTERNAL_REPOS with a reason."
    )
    assert SLUG in REPO_URL_SLUGS, f"no github.com URL names {SLUG} at all"


@pytest.mark.parametrize(
    "slug", sorted({*EXTERNAL_REPOS, *PLACEHOLDER_SLUGS, *NON_REPO_PATHS})
)
def test_each_allowlisted_slug_is_still_referenced(slug: str) -> None:
    """A stale allowlist entry is a pre-approved hole for a future stale slug."""
    assert slug in REPO_URL_SLUGS, f"{slug} is allowlisted but no longer referenced"


def _classify_owner_mention(line: str, start: int) -> str | None:
    """Name the shape a mention of the owner takes, or None if unrecognized."""
    before, after = line[:start], line[start + len(OWNER) :]
    in_url = before.endswith("github.com/")
    if re.match(rf"/{re.escape(REPO)}(?:\.git)?(?![\w.-])", after):
        return "ssot-url" if in_url else "ssot-slug"
    if in_url and not after.startswith("/"):
        return "owner-profile-url"
    # `${{ vars.X || 'OWNER' }}/other-repo` — the owner as a fork-default, with
    # template syntax between it and the repo name it applies to.
    for other in OTHER_REPOS_UNDER_THIS_OWNER:
        if re.match(rf"[^\w/]{{0,12}}/{re.escape(other)}(?![\w.-])", after):
            return "other-repo-under-this-owner"
    return None


def _owner_mentions() -> list[tuple[str, int, str, str | None]]:
    found = []
    for path, number, line in ALL_LINES:
        for match in re.finditer(re.escape(OWNER), line):
            found.append(
                (path, number, line, _classify_owner_mention(line, match.start()))
            )
    return found


OWNER_MENTIONS = _owner_mentions()


def test_every_mention_of_the_owner_takes_a_recognized_shape() -> None:
    """The coverage half of the partition: a copy of the slug written in a NEW
    shape (a YAML key, a shell variable, a JSON field) is unguarded until it is
    either one of these shapes or deliberately added here."""
    assert OWNER_MENTIONS, f"the tree no longer mentions {OWNER} anywhere"
    unrecognized = [
        f"{path}:{number}: {line.strip()[:120]}"
        for path, number, line, shape in OWNER_MENTIONS
        if shape is None
    ]
    assert not unrecognized, (
        "these mention the owner in a shape this guard cannot check, so a "
        f"rename would leave them stale: {unrecognized}"
    )


@pytest.mark.parametrize(
    "shape",
    ["ssot-url", "ssot-slug", "owner-profile-url", "other-repo-under-this-owner"],
)
def test_each_recognized_shape_still_occurs(shape: str) -> None:
    """Non-vacuity per branch: a classifier arm that stopped matching would let
    its whole shape through unchecked."""
    assert any(found == shape for *_, found in OWNER_MENTIONS), (
        f"no mention classified as {shape} — the classifier arm is dead"
    )


def test_marketplace_add_instructions_name_the_ssot_repo() -> None:
    """The bare-slug form users copy/paste. It is not a URL, so the URL partition
    never sees it, and a stale one silently installs someone else's marketplace."""
    advertised = {
        (path, match.group("slug"))
        for path, _, line in ALL_LINES
        for match in re.finditer(
            r"/plugin marketplace add (?P<slug>[\w.-]+/[\w.-]+)", line
        )
    }
    assert advertised, "nothing tells the user how to add the marketplace"
    wrong = sorted(entry for entry in advertised if entry[1] != SLUG)
    assert not wrong, f"these advertise a marketplace other than {SLUG}: {wrong}"
