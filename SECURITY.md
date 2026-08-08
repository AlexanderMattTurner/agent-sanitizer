# Security Policy

`agent-sanitizer` is a security library: it sits between untrusted text
and a model, so a vulnerability here can defeat the very protection a downstream
pipeline is relying on. Please treat reports accordingly.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.** A public
report tips off attackers before downstream users can update.

Instead, report privately through one of:

- GitHub's [private vulnerability reporting](https://github.com/AlexanderMattTurner/agent-sanitizer/security/advisories/new)
  ("Report a vulnerability" under the **Security** tab), or
- email the maintainer at `security@turntrout.com`.

Please include enough to reproduce: the input that triggers it, the entry point
(`/invisible`, `/html`, `/confusables`, `/rehydrate`, etc.), what the sanitizer
did versus what it should have done, and the package version.

A bypass that lets payload-capable content reach the model unflagged, a splice
that exposes a secret, or a crash on adversarial input are all in scope. Please
don't include real credentials in a report—a credential-shaped placeholder is
enough.

## Dependency supply chain

Dependency versions must age before this repo will resolve them:
`pnpm-workspace.yaml` sets `minimumReleaseAge` to 4320 minutes (3 days), so a
package published minutes ago cannot enter the lockfile. The npm compromises
this defends against are typically detected and unpublished within hours to a
couple of days, and the window is where that detection happens.

The setting gates resolution only — `pnpm install --frozen-lockfile` installs
what the lockfile already names — so it constrains `pnpm add` and `pnpm update`,
which is where a poisoned release would enter.

`minimumReleaseAgeExclude` exempts only `agent-sanitizer` itself, which this
repository builds and publishes with npm provenance. `tests/test_minimum_release_age.py`
fails if the window is removed or shortened, if an exemption names a version
nothing pins, or if a third-party package is exempted.

## What to expect

The maintainer will acknowledge your report and work with you on a fix and a
coordinated disclosure timeline before any public detail is published. Fixes
ship in a patched release with the advisory.
