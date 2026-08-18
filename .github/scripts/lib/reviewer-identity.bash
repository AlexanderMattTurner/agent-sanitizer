# shellcheck shell=bash
# Contract: sourced into strict-mode (set -euo pipefail) callers; do not re-set shell options.
#
# WHO the automated reviewer is, and how to recognize its work — in ONE place.
# Every gate, sweep and resolver that reads a PR's reviews or review threads
# answers the same two questions: is this node authored by the reviewer, and is
# it a REAL review rather than one GitHub synthesized. A second spelling of
# either answer is a gate keyed to a different reviewer than its sibling, which
# is a required context nothing that runs can ever clear.
#
# Deliberately sources NOTHING. Three workflow jobs fetch a single gate script
# through a narrow `sparse-checkout` list and this file rides along in each; a
# `source` here would need its own target added to those lists too.
# tests/test_sparse_checkout_source_closure.py derives each list's requirement
# from the scripts' own `source` lines, so an omission reds CI rather than
# killing the gate at runtime under `set -e`.
#
# Consumers: review-gate.sh, review-findings-gate.sh,
# approve-if-reviewer-hold-clear.sh, lib/pr-reviews.bash, lib/review-threads.bash.

REVIEWER_LOGIN="${REVIEWER_LOGIN:-github-actions[bot]}"

# GitHub's REST API spells an app bot's login WITH the `[bot]` suffix while
# GraphQL spells it WITHOUT (`github-actions[bot]` vs `github-actions`). Both
# sides are stripped before comparing, so either spelling of the configured
# value matches either spelling an API returns. Comparing the two raw matched
# zero reviews, and the readers took that for "the reviewer never spoke".
REVIEWER_LOGIN_BARE="${REVIEWER_LOGIN%'[bot]'}"

# Exported because the predicate below reads the login out of `env`, inside the
# jq that `gh` runs in its own process.
export REVIEWER_LOGIN REVIEWER_LOGIN_BARE

# The jq prelude every reviewer-identity query prepends to its program.
#
# `is_reviewer` reads BOTH node shapes: a GraphQL node carries `.author`, a REST
# node carries `.user`, and a missing key yields null, so one definition serves
# both — and a thread's root comment is just another authored node
# (`.comments.nodes[0] | is_reviewer`).
#
# `is_reviewer_review` adds the discriminator that says this is a review AT ALL.
# GitHub synthesizes a body-less COMMENTED review by the same bot around every
# standalone review-comment POST (any reply on a review thread), so a
# "has the reviewer spoken?" gate that counts one is satisfied vacuously on
# exactly the PRs that carry threads. Every real writer passes a non-empty body
# (post-pr-review.mjs falls back to "Automated review."), so the test is free.
# shellcheck disable=SC2034 # spliced into the sourcing scripts' jq programs
REVIEWER_JQ='def bare_login: (. // "") | sub("\\[bot\\]$"; "");
def is_reviewer: (.author.login // .user.login) | bare_login == env.REVIEWER_LOGIN_BARE;
def is_reviewer_review: is_reviewer and ((.body // "") != "");
'
