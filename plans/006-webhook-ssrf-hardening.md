# Plan 006: Harden webhook SSRF validation (fail-closed DNS, explicit no-redirects)

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving on. If a
> "STOP condition" occurs, stop and report. When done, update this plan's row
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat ccf9970..HEAD -- backend/app/services/webhooks.py`
> If the file changed since this plan was written, compare the "Current state"
> excerpts to the live code before proceeding; on a mismatch, STOP.

## Status

- **Priority**: P2
- **Effort**: S
- **Risk**: LOW
- **Depends on**: 001 (for CI to run the new tests)
- **Category**: security
- **Planned at**: commit `ccf9970`, 2026-06-15

## Why this matters

CHAD lets operators configure webhook URLs that the server then calls — a classic SSRF surface. The existing `_validate_url_components` resolves the hostname and rejects private/internal IP ranges (good), and the send path correctly aborts when validation fails (`webhooks.py:343-345`). But two gaps remain:

1. **Fail-open on DNS failure** (`webhooks.py:86-89`): when `socket.getaddrinfo` raises `gaierror`, the code falls through and *allows* the request. An attacker-controlled name that resolves intermittently can slip past the IP check on a transient failure.
2. **Validate-time vs connect-time resolution (DNS rebinding)**: validation resolves the name once; `httpx` re-resolves at request time, so the IP actually connected to need not be the one that was validated.

This plan fixes (1) outright (fail-closed) and makes the no-redirect posture explicit (a 3xx to an internal URL must not be followed — `httpx` already defaults to this, but stating it documents the security intent and guards against a future default change). The *complete* fix for (2) is connect-time IP pinning, which is larger and riskier; it is honestly scoped as a deferred follow-up, not silently dropped. Because `_validate_url_components` is the shared validator (also used by `enrichment_webhook.py`), the fail-closed fix benefits every webhook caller.

## Current state

- `backend/app/services/webhooks.py:29-39` — `BLOCKED_IP_RANGES` covers loopback, RFC1918, link-local (incl. `169.254.0.0/16` AWS metadata), IPv6 loopback/private/link-local.
- `backend/app/services/webhooks.py:73-89` — the validation core, with the fail-open branch:

```python
        if not allow_internal:
            try:
                addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
                for family, _, _, _, sockaddr in addr_info:
                    ip_str = sockaddr[0]
                    try:
                        ip = ipaddress.ip_address(ip_str)
                        for blocked_range in BLOCKED_IP_RANGES:
                            if ip in blocked_range:
                                return False, "URL resolves to a private/internal IP address", None
                    except ValueError:
                        continue
            except socket.gaierror:
                # DNS resolution failed - could be temporary, allow the request
                # The actual HTTP request will fail if the host is unreachable
                pass
```

- `backend/app/services/webhooks.py:108-137` — `sanitize_webhook_url` returns `(None, error)` on invalid input.
- `backend/app/services/webhooks.py:341-357` — send path; correctly aborts on `None`, then:

```python
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                sanitized_url,
                json=payload,
                timeout=timeout,
                headers={"Content-Type": "application/json"},
            )
```
  The client is created with default options (httpx defaults to `follow_redirects=False`).
- `allow_internal` comes from `settings.ALLOW_INTERNAL_WEBHOOK_IPS` (an intentional dev/internal escape hatch) — preserve that path unchanged.
- Existing tests: `backend/tests/services/test_enrichment_webhook.py` exercises the enrichment webhook (which reuses this validator). Add the SSRF-validator regression tests near the webhook service tests.

Repo conventions: stdlib `socket`/`ipaddress`, `httpx.AsyncClient`. Keep them.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Webhook tests | `docker compose -f docker-compose.dev.yml run --rm backend pytest tests/services/test_enrichment_webhook.py -q` | all pass |
| New validator test | `docker compose -f docker-compose.dev.yml run --rm backend pytest -k "ssrf or safe_url" -q` | all pass |
| Lint | `docker compose -f docker-compose.dev.yml run --rm backend ruff check app/services/webhooks.py` | exit 0 |

## Scope

**In scope**:
- `backend/app/services/webhooks.py` (validation fail-closed + explicit `follow_redirects=False` on the client)
- A test file for the validator — create `backend/tests/services/test_webhook_ssrf.py` (or add to an existing webhook test module if one fits better).

**Out of scope** (do NOT touch):
- `BLOCKED_IP_RANGES` — the ranges are correct; don't change them.
- The `ALLOW_INTERNAL_WEBHOOK_IPS` escape hatch — keep its behavior.
- `enrichment_webhook.py` — it reuses the shared validator and inherits the fix; do not refactor it here.
- Connect-time IP pinning / custom transports — explicitly deferred (see Maintenance notes).

## Git workflow

- Branch: `advisor/006-webhook-ssrf-hardening`
- Commit message: `fix(security): fail-closed webhook DNS validation, explicit no-redirect`
- Do NOT push or open a PR unless instructed.

## Steps

### Step 1: Make DNS-resolution failure fail-closed

In `backend/app/services/webhooks.py`, change the `except socket.gaierror` branch (lines 86-89) so a resolution failure **rejects** the URL instead of allowing it:

```python
            except socket.gaierror:
                # Fail closed: if we cannot resolve the host we cannot prove the
                # destination is not internal, so refuse rather than allow.
                return False, "Webhook host could not be resolved", None
```

Leave the `allow_internal` short-circuit (when `settings.ALLOW_INTERNAL_WEBHOOK_IPS` is true) exactly as it is — that path never reaches this block.

### Step 2: Make the no-redirect posture explicit on the send client

At `backend/app/services/webhooks.py:351`, construct the client with `follow_redirects=False` explicitly:

```python
        async with httpx.AsyncClient(follow_redirects=False) as client:
```

(This matches httpx's current default; making it explicit prevents a redirect to an internal URL from ever being followed if the default changes.)

**Verify**: `docker compose -f docker-compose.dev.yml run --rm backend ruff check app/services/webhooks.py` → exit 0.

### Step 3: Add regression tests for the validator

Create `backend/tests/services/test_webhook_ssrf.py`. Use `unittest.mock.patch` to control `socket.getaddrinfo` (mirror the mocking style in `test_enrichment_webhook.py`). Cover:
- A public-IP hostname (mock `getaddrinfo` → a public IP like `93.184.216.34`) → `is_safe_url` returns `(True, "")`.
- A hostname resolving to a private IP (mock → `10.0.0.5`) → returns `(False, ...)`.
- A hostname resolving to link-local `169.254.169.254` → `(False, ...)`.
- **DNS failure** (mock `getaddrinfo` to raise `socket.gaierror`) → `(False, ...)` — this is the new fail-closed behavior (would have been `True` before).
- A non-http(s) scheme (`file://…`) → `(False, ...)`.

Test against `app.services.webhooks.is_safe_url` (and/or `sanitize_webhook_url`).

**Verify**: `docker compose -f docker-compose.dev.yml run --rm backend pytest tests/services/test_webhook_ssrf.py -q` → all pass.

## Test plan

- New `test_webhook_ssrf.py` covering public-allowed, private-blocked, link-local-blocked, DNS-failure-blocked (the regression this plan introduces), and bad-scheme cases.
- Run the existing enrichment-webhook suite to confirm the shared validator change didn't break callers.

## Done criteria

ALL must hold:

- [ ] The `except socket.gaierror` branch returns `(False, ...)` (grep: `grep -n "gaierror" backend/app/services/webhooks.py` then confirm the body returns False)
- [ ] `webhooks.py:351` client uses `follow_redirects=False`
- [ ] `docker compose -f docker-compose.dev.yml run --rm backend pytest tests/services/test_webhook_ssrf.py tests/services/test_enrichment_webhook.py -q` → all pass
- [ ] `ruff check app/services/webhooks.py` exits 0
- [ ] `ALLOW_INTERNAL_WEBHOOK_IPS` behavior unchanged; `BLOCKED_IP_RANGES` unchanged
- [ ] Only `webhooks.py` and the new test file modified (`git status`)
- [ ] `plans/README.md` status row updated

## STOP conditions

Stop and report back if:
- The "Current state" excerpts don't match the live file (drift).
- Existing webhook tests relied on the fail-open behavior (a test expecting an unresolvable host to be allowed) — report it; do not revert the fix.
- The `allow_internal` path is entangled with the `gaierror` branch in a way the excerpt didn't show.

## Maintenance notes

- **Deferred (the complete DNS-rebinding fix)**: validation resolves the name once, but `httpx` re-resolves at connect time, so a rebinding attacker can still point the name at an internal IP between validation and connection. Fully closing this requires resolving the host once, validating that specific IP, and pinning the connection to it (custom `httpx` transport / connecting by IP with a `Host` header). That is L-effort and behavior-sensitive — scope it as its own plan if the threat model warrants it. This plan deliberately does the high-confidence, low-risk subset.
- Reviewer should confirm the escape hatch (`ALLOW_INTERNAL_WEBHOOK_IPS`) still works for legitimate internal webhooks, and that the same validator is what `enrichment_webhook.py` calls.
