# detect-secrets' BasePlugin/RegexBasedDetector declare `secret_type` and `denylist`
# as abstract properties whose documented override is a plain class variable (see the
# base class docstring). Every detector below follows that intended pattern, so
# pyright's property-override and assignment-type checks are false positives here;
# this module holds nothing but those detector classes plus the denylist loader.
# pyright: reportIncompatibleMethodOverride=false, reportAssignmentType=false
"""Custom detect-secrets plugins for credential formats the bundled detectors
lack.

Each class is the detect-secrets *adapter* for one entry in
``data/secret-detectors.json`` — the single source of truth for these regex
patterns. The class keeps the name the engine loads it by (``CUSTOM_PLUGINS`` in
``engine.py``) and supplies the detect-secrets ``secret_type`` label; its
``denylist`` is compiled from the shared file. When detect-secrets gains a native
detector for one of these, drop the class here and the JSON entry.

detect-secrets has no Google or Anthropic detector (verified against its plugin
list); both are credential formats a coding agent's tool output can leak, so they
must be redacted before the model sees them.

The pure-regex classes load their ``denylist`` from the shared JSON. The one
structural exception is ``JwtFullTokenDetector``, which subclasses a bundled
detector to keep its base64/JSON validation and so carries its own regex inline
rather than a JSON entry.
"""

import base64
import json
import re
from pathlib import Path

# Imported as a MODULE, not `from … import JwtTokenDetector` / `KeywordDetector`:
# detect-secrets' custom-plugin loader (get_plugins_from_file) scans this
# module's attributes for any BasePlugin subclass and keys them by secret_type,
# so a bare `JwtTokenDetector`/`KeywordDetector` name in scope would be
# re-registered under its own secret_type and, sorting after the subclass below
# it, overwrite it — leaving the subclass unfindable by classname ("No such
# JwtFullTokenDetector/BoundedKeywordDetector plugin"). A module attribute is
# not a class, so the scanner ignores it.
from detect_secrets.plugins import jwt as _jwt
from detect_secrets.plugins import keyword as _keyword
from detect_secrets.plugins.base import RegexBasedDetector

# Compiled denylists keyed by detector class name, loaded from the shared SSOT
# packaged alongside this module. Patterns are constrained to a JS-portable regex
# subset (see the file's `description`); that constraint is enforced by
# test/secret-detectors-portability.test.mjs, which compiles every pattern with
# the real JS `RegExp` — not re-approximated here in Python.
DETECTORS_FILE = Path(__file__).resolve().parent / "data" / "secret-detectors.json"
_DENYLISTS = {
    entry["const"]: [re.compile(pattern) for pattern in entry["patterns"]]
    for entry in json.loads(DETECTORS_FILE.read_text())["detectors"]
}


class AnthropicApiKeyDetector(RegexBasedDetector):
    """Anthropic API keys (``sk-ant-…``). gitleaks rule: ``anthropic-api-key``."""

    secret_type = "Anthropic API Key"  # noqa: S105 — a detector label, not a secret
    denylist = _DENYLISTS["AnthropicApiKeyDetector"]


class GoogleApiKeyDetector(RegexBasedDetector):
    """Google / GCP API keys (``AIza…``). gitleaks rule: ``gcp-api-key``."""

    secret_type = "Google API Key"  # noqa: S105 — a detector label, not a secret
    denylist = _DENYLISTS["GoogleApiKeyDetector"]


class DigitalOceanTokenDetector(RegexBasedDetector):
    """DigitalOcean tokens (``do{o,p,r}_v1_…``). gitleaks rules:
    ``digitalocean-access-token`` (``doo_``), ``digitalocean-pat`` (``dop_``),
    ``digitalocean-refresh-token`` (``dor_``)."""

    secret_type = "DigitalOcean Token"  # noqa: S105 — a detector label, not a secret
    denylist = _DENYLISTS["DigitalOceanTokenDetector"]


class CloudflareOriginCaKeyDetector(RegexBasedDetector):
    """Cloudflare Origin CA keys (``v1.0-…``). gitleaks rule:
    ``cloudflare-origin-ca-key``. The keyword-context ``cloudflare-api-key`` /
    ``cloudflare-global-api-key`` rules have no standalone shape (skipped in the
    triage)."""

    secret_type = "Cloudflare Origin CA Key"  # noqa: S105 — a detector label, not a secret
    denylist = _DENYLISTS["CloudflareOriginCaKeyDetector"]


class VaultTokenDetector(RegexBasedDetector):
    """HashiCorp Vault tokens (``hvs.…`` service, ``hvb.…`` batch). gitleaks
    rules: ``vault-service-token``, ``vault-batch-token``. The legacy ``s.<24>``
    form is deliberately omitted — too generic to match without false positives."""

    secret_type = "Vault Token"  # noqa: S105 — a detector label, not a secret
    denylist = _DENYLISTS["VaultTokenDetector"]


class HashiCorpTerraformTokenDetector(RegexBasedDetector):
    """Terraform Cloud / Enterprise API tokens (``….atlasv1.…``). gitleaks rule:
    ``hashicorp-tf-api-token``."""

    secret_type = "Terraform Cloud API Token"  # noqa: S105 — a detector label, not a secret
    denylist = _DENYLISTS["HashiCorpTerraformTokenDetector"]


class GitHubFineGrainedPatDetector(RegexBasedDetector):
    """GitHub fine-grained PATs (``github_pat_…``). gitleaks rule:
    ``github-fine-grained-pat``. detect-secrets' ``GitHubTokenDetector`` only
    matches the ``gh[pousr]_`` classic-token prefixes, not ``github_pat_``."""

    secret_type = "GitHub Fine-Grained PAT"  # noqa: S105 — a detector label, not a secret
    denylist = _DENYLISTS["GitHubFineGrainedPatDetector"]


# ── Formats with no gitleaks default rule ────────────────────────────────────
# gitleaks does not ship a rule for these, so the regex is sourced from the
# provider's own key shape rather than a gitleaks rule. Keys with no distinctive
# structural shape (e.g. Venice — verified to have no documented prefix) are
# redacted by env-var-value binding (RedactorConfig.env_secrets) instead, not
# here, since a bare-token regex would either over-redact or miss.


class OpenRouterApiKeyDetector(RegexBasedDetector):
    """OpenRouter API keys (``sk-or-v1-…``). No gitleaks rule; the ``sk-or-v1-``
    prefix is verified from OpenRouter's docs and the 64-hex body from observed
    keys (https://openrouter.ai/docs/api/reference/authentication)."""

    secret_type = "OpenRouter API Key"  # noqa: S105 — a detector label, not a secret
    denylist = _DENYLISTS["OpenRouterApiKeyDetector"]


class GroqApiKeyDetector(RegexBasedDetector):
    """Groq API keys (``gsk_…``). No gitleaks rule; prefix from Groq's console
    docs (https://console.groq.com/keys)."""

    secret_type = "Groq API Key"  # noqa: S105 — a detector label, not a secret
    denylist = _DENYLISTS["GroqApiKeyDetector"]


class XaiApiKeyDetector(RegexBasedDetector):
    """xAI / Grok API keys (``xai-…``). No gitleaks rule; prefix from xAI's docs
    (https://docs.x.ai/overview)."""

    secret_type = "xAI API Key"  # noqa: S105 — a detector label, not a secret
    denylist = _DENYLISTS["XaiApiKeyDetector"]


# ── Reimplementation of a bundled detector with a quadratic pattern ───────────
# detect-secrets' NpmDetector denylist is `\/\/.+\/:_authToken=\s*((npm_.+)|
# ([A-Fa-f0-9-]{36})).*` — the unbounded `.+` before the required
# `/:_authToken=` literal is retried at every `//` in the scanned text, so a
# payload with no whitespace at all (minified code, or the secrets engine's own
# cross-line pass, which joins every line into one) makes each attempt scan the
# ENTIRE remaining text. See the JSON entry's note for the measurement and the
# bundled pattern's second bug (a capture-group leak that under-reports when
# several tokens share one scanned line).
class NpmDetector(RegexBasedDetector):
    """npmrc authTokens (``//<registry>/:_authToken=<token>``). Non-quadratic
    reimplementation of the bundled ``NpmDetector`` — see the module comment
    above and the JSON entry's note."""

    secret_type = "NPM tokens"  # noqa: S105 — a detector label, not a secret
    denylist = _DENYLISTS["NpmDetector"]


class ReplicateApiTokenDetector(RegexBasedDetector):
    """Replicate API tokens (``r8_…``). No gitleaks rule; prefix from Replicate's
    docs (https://replicate.com/docs/topics/security/api-tokens)."""

    secret_type = "Replicate API Token"  # noqa: S105 — a detector label, not a secret
    denylist = _DENYLISTS["ReplicateApiTokenDetector"]


# ── Reimplementations of bundled detectors with a capture-group leak ──────────
# detect-secrets' GitHubTokenDetector and GitLabTokenDetector wrap the token
# PREFIX in a capturing group, and detect-secrets reports re.findall's group as
# the secret value — so the redactor replaced only the prefix and left the token
# body in cleartext. These replace the built-ins (dropped from PLUGINS in
# engine.py) with NON-capturing groups so findall returns the whole match and the
# full token redacts. secret_type is identical to the built-in's.


class GitHubClassicTokenDetector(RegexBasedDetector):
    """Classic GitHub tokens (``gh[pousr]_``). Non-capturing reimplementation of
    the bundled ``GitHubTokenDetector`` (which leaked the body). gitleaks rules:
    ``github-pat`` / ``github-oauth`` / ``github-app-token`` /
    ``github-refresh-token``."""

    secret_type = "GitHub Token"  # noqa: S105 — a detector label, not a secret
    denylist = _DENYLISTS["GitHubClassicTokenDetector"]


class GitLabAccessTokenDetector(RegexBasedDetector):
    """GitLab PATs and CI/deploy/runner tokens (``glpat-``/``glcbt-``/…).
    Non-capturing reimplementation of the bundled ``GitLabTokenDetector`` (which
    leaked the body). gitleaks rules: ``gitlab-pat`` and the other ``gitlab-*``
    token rules."""

    secret_type = "GitLab Token"  # noqa: S105 — a detector label, not a secret
    denylist = _DENYLISTS["GitLabAccessTokenDetector"]


# ── Reimplementation of a bundled detector with a lazy-quantifier leak ────────
# Unlike the GitHub/GitLab capture-group cases above, this detector is
# structural (it keeps detect-secrets' base64/JSON validation), so its regex is
# NOT a pure-regex SSOT entry — it subclasses the bundled JwtTokenDetector and
# overrides only the denylist. The bundled regex ends the signature segment with
# a LAZY ``[A-Za-z0-9-_.+/=]*?``, which matches the *minimal* JWT (``header.
# payload.``) and leaves the signature in cleartext; the redactor then replaced
# only ``header.payload.`` and emitted ``[REDACTED: JSON Web Token]<signature>``.
# A GREEDY signature segment (no trailing ``?``) consumes the whole token so the
# full JWT redacts. The signature class excludes ``.`` so a greedy match can
# never spill past the three segments into trailing text. is_formally_valid is
# overridden to gate on the header/payload base64url-JSON only — see its docstring
# for why the bundled signature padding check leaks real tokens.


class JwtFullTokenDetector(_jwt.JwtTokenDetector):
    """JSON Web Tokens, redacting the signature the bundled detector leaks.
    Subclasses ``JwtTokenDetector`` to keep its base64/JSON validation; only the
    signature quantifier changes from lazy to greedy. gitleaks rule: ``jwt``."""

    # Per-segment quantifiers are BOUNDED ({1,65536}) rather than ``+``: an
    # unbounded run retried at every ``eyJ`` start makes an unanchored search
    # polynomial, and a finite bound is provably linear. The bound must clear a
    # full RFC 7515 header carrying an ``x5c`` certificate CHAIN — several base64
    # DER certs run well past 8192 chars, and a header that overflowed the bound
    # matched NOTHING and leaked the whole JWT in cleartext. 65536 base64
    # chars/segment dwarfs even a multi-cert chain while staying linear. The
    # third segment is optional so unsigned (``header.payload.``) and two-part
    # JWTs still match, exactly as the bundled detector did.
    # noqa rationale: detect-secrets' RegexBasedDetector declares `denylist` as an
    # instance attribute, so a ClassVar annotation errors pyright; the subclass sets it
    # as a class attribute by framework contract, which is the shared-state RUF012 flags.
    denylist = [  # noqa: RUF012
        re.compile(
            r"eyJ[A-Za-z0-9_=-]{1,65536}\.[A-Za-z0-9_=-]{1,65536}"
            r"(?:\.[A-Za-z0-9_=-]{0,65536})?"
        ),
    ]

    @staticmethod
    def is_formally_valid(token: str) -> bool:
        """Validate ONLY the header and payload as base64url JSON. The bundled
        validator also padding-checks the signature, but the signature is opaque
        bytes, not JSON, and its length need not be a multiple of four. When the
        greedy regex absorbs a trailing base64url char from adjacent text (or a
        genuine signature simply has length ≡ 1 mod 4), that padding check raises
        "Incorrect padding" and discards the whole real token — leaking it. The
        ``eyJ``-anchored base64url-JSON gate on the first two segments is what
        actually rejects false positives; the signature needs no structural check
        (the regex already constrains it to base64url, with ``.`` excluded so a
        greedy match can't spill past the token)."""
        for part_str in token.split(".")[:2]:
            try:
                part = part_str.encode("ascii")
                if len(part) % 4 == 1:
                    return False
                part += b"=" * (-len(part) % 4)
                json.loads(base64.urlsafe_b64decode(part).decode("utf-8"))
            except (TypeError, ValueError, UnicodeDecodeError):
                return False
        return True


# ── Reimplementation of a bundled detector with an unbounded value span ──────
# The bundled KeywordDetector's own value class (``keyword.SECRET``) is
# ``[^\v'"]*`` — excluding only VERTICAL TAB (in Python `re`, `\v` is `\x0b`,
# not "any line break") and the two real quote characters — while its own
# ``keyword.QUOTE`` treats a MARKDOWN BACKTICK as a third quote alongside `'`/
# `"`. A quoted value's body already excludes both real quote characters, so it
# is bounded by its own closing delimiter; a backtick-opened value has no such
# stop. A GitHub PR body's `` `_load_secret`, `` opened a "value" that ran
# greedily to the LAST backtick-then-semicolon in the scanned text, swallowing
# ~2,800 characters of unrelated prose into one `[REDACTED: Secret Keyword]`.
# This reimplementation drops the backtick from both the quote and the value
# classes entirely: a backtick is markdown emphasis, never a credential byte,
# so excluding it from the value everywhere (not just as a delimiter) makes the
# over-capture shape structurally impossible from this detector, not merely
# suppressed downstream. The value is also a BOUNDED run of quote/backtick/
# whitespace-free words (see ``_KEYWORD_VALUE`` below): unbounded like the
# upstream body would let an unterminated quote retry an unbounded scan for its
# own close (the same class of ReDoS risk NpmDetector/JwtFullTokenDetector
# above already guard against), and a length past the bound cannot be a
# real single credential.
#
# The noun vocabulary (``_keyword.DENYLIST``) is upstream's own, not re-typed —
# only the regex SHAPE around it is this repo's. Reimplements only the one
# regex table `scan_line` ever reaches: detect-secrets scans with
# ``filename='adhoc-string-scan'`` (no extension), so
# ``KeywordDetector.analyze_line``'s file-type dispatch always falls back to
# ``QUOTES_REQUIRED_DENYLIST_REGEX_TO_GROUP`` — the other filetype-specific
# tables in ``REGEX_BY_FILETYPE`` are unreachable through this engine and are
# not reimplemented.
_KEYWORD_QUOTE = r"[\"']"
# A single word excludes whitespace, both quote characters, and the backtick;
# up to 8 such words joined by a single space/tab is generous enough for a
# diceware passphrase (`correct horse battery staple`) while remaining a hard
# ceiling no keyword-adjacent prose paragraph can cross.
_KEYWORD_WORD = r"[^\s\"'`]{1,64}"
_KEYWORD_VALUE = rf"{_KEYWORD_WORD}(?:[ \t]{_KEYWORD_WORD}){{0,7}}"
KEYWORD_VALUE_MAX_LEN = 8 * 64 + 7
# Bounded affix/closing runs, matching this module's own bounded-quantifier
# convention rather than upstream's unbounded `\w*`.
_KEYWORD_NOUN = "(?:" + "|".join(_keyword.DENYLIST) + r")\w{0,40}"
_KEYWORD_CLOSING = r"[]'\"]{0,2}"


class BoundedKeywordDetector(RegexBasedDetector):
    """Secret-sounding field names with a length- and shape-bounded value.

    Each pattern below carries exactly ONE capture group: unlike upstream's
    ``KeywordDetector`` (a plain ``BasePlugin`` with its own ``analyze_string``
    and per-arm group index), ``RegexBasedDetector.analyze_string`` reports
    ``regex.findall(string)`` and yields every truthy submatch of a tuple
    result — a second group would be reported as a secret of its own."""

    secret_type = "Secret Keyword"  # noqa: S105 — a detector label, not a secret
    denylist = [  # noqa: RUF012
        # my_password = "v" / api_key: "v" / secret == "v" / api_key => "v"
        re.compile(
            rf"{_KEYWORD_NOUN}{_KEYWORD_CLOSING}\s*(?:={{1,3}}|!={{1,2}}|=>|:)"
            rf"\s*{_KEYWORD_QUOTE}({_KEYWORD_VALUE}){_KEYWORD_QUOTE}",
            re.IGNORECASE,
        ),
        # if ("v" == my_password_secure)
        re.compile(
            rf"{_KEYWORD_QUOTE}({_KEYWORD_VALUE}){_KEYWORD_QUOTE}"
            rf"\s*[!=]{{2,3}}\s*\w{{0,40}}{_KEYWORD_NOUN}"
        ),
        # private_key "v"; — a config directive's argument sits directly
        # beside its keyword, so upstream's `[^\s]{0,50}?` slop between them is
        # dropped rather than bounded: nothing legitimate needs it.
        re.compile(
            rf"{_KEYWORD_NOUN}\s+{_KEYWORD_QUOTE}({_KEYWORD_VALUE}){_KEYWORD_QUOTE};",
            re.IGNORECASE,
        ),
    ]
