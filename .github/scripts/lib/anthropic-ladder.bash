# shellcheck shell=bash
# anthropic-ladder.bash — one /v1/messages call, walked across an ordered
# credential ladder.
#
# The tempting alternative — picking the credential with a GitHub expression
# `${{ secrets.A || secrets.B || secrets.C }}` — is not a ladder. `||` picks
# the first NON-EMPTY value at expression time, so a credential that is present
# but expired, revoked, or over its cap is never fallen back from — the later
# secrets are dead weight, reachable only by unsetting the first one, and one
# expired subscription token takes down every direct-API caller while live
# credentials sit configured beside it.
#
# Here the fallback is a runtime decision on the API's own answer. A rung is
# abandoned when the API's verdict is about the CREDENTIAL: an HTTP 401/403
# outright, or a 429 that survives the rung's own retries — a token over its own
# quota, which is how a live subscription credential most often stops answering.
# Everything else keeps its existing meaning: 408/5xx and transport failures
# retry on the SAME credential (transient, and no evidence about the token), and
# any other 4xx fails the run immediately (the request itself is malformed, so
# every rung would reject it identically). Exhausting the ladder fails loud.
# Walking it therefore only changes WHO answers, never WHAT the answer is.
#
# Contract: sourced into strict-mode (set -euo pipefail) callers; do not re-set
# shell options. Requires .github/scripts/lib-ci-retry.sh to be sourced first.

# The ladder, in attempt order: the same subscription tokens the Claude
# workflows use, and ONLY those. A metered ANTHROPIC_API_KEY rung used to sit at
# the bottom; it was removed deliberately, so no caller of THIS ladder (the
# direct-API callers: changelog polishing, the conflict-resolver fan-out, the
# pre-push self-review) can fall through to spending real credits. Exhausting
# the subscription rungs now degrades — e.g. the changelog prose falls back to
# a plain commit list — rather than billing. claude-run/action.yaml, the
# separate ladder claude-code-action callers (like PR review) go through, does
# have one opt-in metered rung; it does not touch this file.
# shellcheck source=.github/scripts/lib/claude-oauth-ladder.bash
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/claude-oauth-ladder.bash"

# The ladder IS the OAuth ladder. Kept as a named alias rather than reading
# CLAUDE_OAUTH_LADDER_VARS directly at each use, so the "no credential is
# configured" error below can name this caller's own list.
_ANTHROPIC_LADDER_VARS=("${CLAUDE_OAUTH_LADDER_VARS[@]}")

# anthropic_ladder — the configured credentials on stdout, one per line, in
# attempt order. Empty rungs are dropped and duplicates collapse, so an unset
# middle tier is stepped over rather than ending the ladder, and a credential
# configured twice is not paid for twice.
anthropic_ladder() {
  local -A seen=()
  local var cred
  for var in "${_ANTHROPIC_LADDER_VARS[@]}"; do
    cred="${!var:-}"
    [[ -n "$cred" && -z "${seen["$cred"]:-}" ]] || continue
    seen["$cred"]=1
    printf '%s\n' "$cred"
  done
}

# anthropic_auth_headers CRED — the header set for ONE credential, into
# AUTH_HEADERS; AUTH_MODE names the scheme so a failure is diagnosable from the
# log. Only Claude subscription OAuth tokens (sk-ant-oat…) are accepted: Bearer
# plus the oauth beta header.
#
# An unrecognized shape does NOT fall back to the x-api-key scheme this ladder
# used to support: that fallback is exactly how a metered key would creep back
# in — a secret renamed into an OAuth slot would silently authenticate and bill.
#
# Returns 1 rather than exiting, so the caller treats a wrong-shaped rung the
# way it treats a rejected one: log it and step to the next credential. Exiting
# here would let one pasted-in-the-wrong-slot key strand every working rung
# below it, breaking this file's own contract that walking the ladder "only
# changes WHO answers, never WHAT the answer is". Exhausting every rung still
# fails loud, at the end of anthropic_messages.
anthropic_auth_headers() {
  local cred="$1"
  if [[ "$cred" != sk-ant-oat* ]]; then
    AUTH_MODE="unusable (not an sk-ant-oat… token)"
    AUTH_HEADERS=()
    return 1
  fi
  AUTH_MODE="Bearer + oauth beta (sk-ant-oat)"
  AUTH_HEADERS=(
    -H "authorization: Bearer $cred"
    -H "anthropic-beta: oauth-2025-04-20"
    -H "anthropic-version: 2023-06-01"
  )
}

# Surface the reason for a non-200 (the auth mode plus the API's own error
# message, or the raw body when it isn't Anthropic-shaped) so the failure is
# diagnosable from the log. The credential never appears in the response.
_anthropic_report_failure() {
  local code="$1" msg
  echo "Claude API call failed (HTTP $code) using auth mode: $AUTH_MODE" >&2
  msg=$(jq -r '.error.message // empty' "$_ANTHROPIC_RESPONSE_FILE" 2>/dev/null || true)
  if [[ -n "$msg" ]]; then
    echo "API error: $msg" >&2
  else
    echo "API response body:" >&2
    head -c 2000 "$_ANTHROPIC_RESPONSE_FILE" >&2
    echo >&2
  fi
}

# One POST on the currently-selected credential. Sets _ANTHROPIC_CRED_REJECTED
# when the API rejected the CREDENTIAL, which is what tells the caller to step to
# the next rung instead of retrying this one.
# invoked via `retry`'s "$@" dispatch
_anthropic_post() {
  # A rung that has already been rejected is not attempted again: 401/403 is
  # deterministic for a given credential, and the answer to it is the NEXT
  # credential, not another try at this one. `retry` owns the attempt loop, so
  # this guard is how a rejection leaves it early.
  [[ "$_ANTHROPIC_CRED_REJECTED" == "true" ]] && return 1
  local code
  # pin-exempt: Anthropic API JSON response, parsed by jq — never executed/extracted; echo-fallback-ok: "000" is the case analysis's own transport-failure code — the `*)` arm below retries it on this rung, exactly as a 5xx
  code=$(curl -s -o "$_ANTHROPIC_RESPONSE_FILE" -w "%{http_code}" \
    --max-time 30 https://api.anthropic.com/v1/messages \
    -H "Content-Type: application/json" \
    "${AUTH_HEADERS[@]}" \
    -d "$_ANTHROPIC_REQUEST_BODY" || echo "000")
  [[ "$code" == "200" ]] && return 0
  _anthropic_report_failure "$code"
  _ANTHROPIC_HTTP_CODE="$code"
  # Re-derived on each attempt, so the flag the caller reads is the LAST attempt's
  # verdict: a rung that was rate-limited once and then hit a server error is
  # not a rung that is over quota.
  _ANTHROPIC_RATE_LIMITED=false
  case "$code" in
  # The credential's own verdict — a bad, revoked, or over-cap token. The next
  # rung is a different credential and may well answer, so this is the one
  # failure that must NOT end the run.
  401 | 403)
    _ANTHROPIC_CRED_REJECTED=true
    ;;
  # A rate limit is transient FIRST and credential-scoped SECOND, so it is both:
  # this rung's backoff gets a chance to outlast a short burst, and a rung whose
  # whole budget goes to 429 is a token over its own quota — the likeliest way a
  # live subscription credential stops answering. Ending the run there would
  # leave the remaining configured credentials unspent on exactly the outage
  # this ladder exists to survive, so the exhaustion is recorded for the caller
  # to walk past.
  429) _ANTHROPIC_RATE_LIMITED=true ;;
  # A timeout is transient and says nothing about the credential: retry here,
  # and do not step a rung on it.
  408) ;;
  # Any other deterministic client error is about the REQUEST (a malformed
  # body, an unknown model). Every rung would reject it identically, so walking
  # the ladder only wastes the run's time before failing with the same reason.
  # `retry` runs us in the caller's shell, so exit ends the run.
  4??)
    echo "Error: Claude API rejected the request (HTTP $code); not retrying — see the reason above." >&2
    exit 1
    ;;
  # 5xx and a transport failure (curl's own 000) are transient by definition:
  # retry on this rung.
  *) ;;
  esac
  return 1
}

# anthropic_messages REQUEST_BODY RESPONSE_FILE — POST one /v1/messages request,
# walking the ladder until a credential answers. The response body lands in
# RESPONSE_FILE. Returns 0 on an HTTP 200; every other outcome exits the run
# loudly, so a caller never has to distinguish "no answer" from "an answer".
anthropic_messages() {
  _ANTHROPIC_REQUEST_BODY="$1"
  _ANTHROPIC_RESPONSE_FILE="$2"
  local -a ladder
  mapfile -t ladder < <(anthropic_ladder)
  [[ ${#ladder[@]} -gt 0 ]] || {
    echo "Error: no Anthropic credential is configured. Set one of: ${_ANTHROPIC_LADDER_VARS[*]}." >&2
    exit 1
  }
  local cred rung=0
  for cred in "${ladder[@]}"; do
    rung=$((rung + 1))
    if ! anthropic_auth_headers "$cred"; then
      echo "Credential ${rung}/${#ladder[@]} is not a Claude subscription OAuth token (expected sk-ant-oat…); trying the next one." >&2
      continue
    fi
    _ANTHROPIC_CRED_REJECTED=false
    _ANTHROPIC_RATE_LIMITED=false
    _ANTHROPIC_HTTP_CODE=""
    RETRY_MAX=3 RETRY_BASE_DELAY=2 retry _anthropic_post && return 0
    if [[ "$_ANTHROPIC_CRED_REJECTED" == "true" ]]; then
      echo "Credential ${rung}/${#ladder[@]} was rejected (HTTP ${_ANTHROPIC_HTTP_CODE}); trying the next one." >&2
      continue
    fi
    if [[ "$_ANTHROPIC_RATE_LIMITED" == "true" ]]; then
      echo "Credential ${rung}/${#ladder[@]} is still rate-limited after 3 attempts; trying the next one." >&2
      continue
    fi
    echo "Error: Claude API unreachable after 3 transient-failure attempts; see the reasons above." >&2
    exit 1
  done
  echo "Error: every configured Anthropic credential (${#ladder[@]}) was unusable, rejected, or rate-limited; see the reasons above." >&2
  exit 1
}
