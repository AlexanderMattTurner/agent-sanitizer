"""Every job running ``install-sanitizer.sh`` sets up pnpm first.

Regression: PR #263 switched ``install-sanitizer.sh`` from the published npm
pin to the LOCAL checkout (``file:${PWD}``) when it runs inside this repo, so
the review scripts exercise the sanitizer on the trusted base branch instead of
a stale registry version. That is the right call, but it changed the install's
runtime requirements in a way nothing announced: npm materialises a ``file:``
dependency by PACKING the directory, and packing runs that package's
``prepare`` — here ``pnpm build:types`` — no matter what ``--ignore-scripts``
says (``npm_config_ignore_scripts`` does not suppress it either).

Three workflows (``claude-pr-review``, ``claude-review-thread-resolve``,
``claude-merge-delta-review``) called the script with no pnpm on PATH. They had
never needed one, because a registry install runs no lifecycle script of ours.
The moment the local path landed, every one of them died with ``sh: 1: pnpm:
not found`` / exit 127 — on every open PR at once, ``template-sync`` included.
``node-tests.yaml`` was unaffected purely by accident: it runs ``pnpm test``
earlier, so the toolchain was already there.

That is why this is a guard and not a one-time fix. The coupling is invisible
at both ends — the workflow says ``run: bash …/install-sanitizer.sh`` and the
script says ``npm install``; the word "pnpm" appears in neither — so the next
workflow to call the script will omit the setup step exactly as these three
did.

WHAT A PASS DOES NOT MEAN. This checks that a pnpm-providing step PRECEDES the
install within the same job. It does not verify the install itself succeeds,
and it cannot see a caller outside ``.github/workflows`` (a composite action or
a locally-run script). It also accepts any of the accepted setup idioms below
rather than one blessed step, so it stays green through a refactor that swaps
one for another.
"""

import pytest
import yaml

from tests._helpers import REPO_ROOT

WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"

INSTALL_SCRIPT = "install-sanitizer.sh"

#: Steps that leave pnpm (and the root ``node_modules`` ``prepare`` needs) on
#: PATH. Enumerated rather than pattern-matched so a step that merely mentions
#: pnpm in a comment cannot satisfy the guard. A new idiom belongs here.
SETUP_USES = ("./.github/actions/setup-base-env", "pnpm/action-setup")
SETUP_RUN_MARKERS = ("corepack enable", "pnpm install")


def _workflows() -> list[tuple[str, dict]]:
    found = []
    for path in sorted(WORKFLOW_DIR.glob("*.y*ml")):
        # `on:` parses as the boolean True in YAML 1.1; irrelevant here, but it
        # means the document must not be assumed to have string keys only.
        found.append((path.name, yaml.safe_load(path.read_text(encoding="utf-8"))))
    return found


def _provides_pnpm(step: dict) -> bool:
    uses = step.get("uses", "")
    if any(uses.startswith(prefix) for prefix in SETUP_USES):
        return True
    run = step.get("run", "")
    return any(marker in run for marker in SETUP_RUN_MARKERS)


def _install_sites() -> list[tuple[str, str, list[dict], int]]:
    """(workflow, job, steps, index-of-the-install-step) for every call site."""
    sites = []
    for name, doc in _workflows():
        for job_id, job in (doc.get("jobs") or {}).items():
            steps = job.get("steps") or []
            for index, step in enumerate(steps):
                if INSTALL_SCRIPT in step.get("run", ""):
                    sites.append((name, job_id, steps, index))
    return sites


INSTALL_SITES = _install_sites()


def test_the_scan_found_the_call_sites() -> None:
    """Non-vacuity: an empty scan would make every assertion below trivially
    true, which is exactly what a renamed script or a broken parse produces."""
    assert INSTALL_SITES, f"no workflow step runs {INSTALL_SCRIPT}"
    workflows = {name for name, _, _, _ in INSTALL_SITES}
    # The four known callers. A NEW caller is fine (it just has to pass the
    # guard below); a caller that VANISHES means the scan stopped seeing it.
    assert workflows >= {
        "claude-pr-review.yaml",
        "claude-review-thread-resolve.yaml",
        "claude-merge-delta-review.yaml",
        "node-tests.yaml",
    }, workflows


@pytest.mark.parametrize(
    ("workflow", "job", "steps", "index"),
    INSTALL_SITES,
    ids=[f"{name}:{job}" for name, job, _, _ in INSTALL_SITES],
)
def test_pnpm_is_set_up_before_the_sanitizer_install(
    workflow: str, job: str, steps: list[dict], index: int
) -> None:
    assert any(_provides_pnpm(step) for step in steps[:index]), (
        f"{workflow} job {job!r} runs {INSTALL_SCRIPT} with no pnpm setup step "
        f"before it. In this repo that install packs the local checkout, which "
        f"runs `prepare` (`pnpm build:types`) and exits 127 without pnpm. Add "
        f"`uses: ./.github/actions/setup-base-env` ahead of it."
    )
