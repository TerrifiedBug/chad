# Plan 007: Bound and name the alert-list over-fetch (clustering / owner filter)

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving on. If a
> "STOP condition" occurs, stop and report. When done, update this plan's row
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat ccf9970..HEAD -- backend/app/api/alerts.py`
> If the file changed since this plan was written, compare the "Current state"
> excerpt to the live code before proceeding; on a mismatch, STOP.

## Status

- **Priority**: P3
- **Effort**: S
- **Risk**: LOW
- **Depends on**: 001 (for CI to run the new test)
- **Category**: perf
- **Planned at**: commit `ccf9970`, 2026-06-15

## Why this matters

When alert clustering is enabled (the default) or an `owner` filter is applied, the alert-list endpoint discards the caller's `limit`/`offset` and force-fetches a hardcoded `1000` documents from OpenSearch starting at offset 0 (`api/alerts.py:142-151`). This is **partly by design** — clustering genuinely needs to see the full candidate set, and a 30-second Redis cache (`AlertCache`) plus a circuit breaker soften the cost. So this plan does **not** try to remove the over-fetch; that would break clustering. Instead it makes the magic number an explicit, documented, single-source constant so the cost is visible, tunable, and bounded — and adds a test that pins the fetch-strategy behavior so a future refactor can't silently change it. Small, safe, and it turns an unexplained `1000` into an intentional knob.

## Current state

- `backend/app/api/alerts.py:110-151` — `list_alerts(...)` chooses a fetch strategy:

```python
    fetch_limit = limit
    fetch_offset = offset
    if clustering_settings and clustering_settings.get("enabled", False):
        fetch_limit = 1000  # Fetch more alerts when clustering
        fetch_offset = 0    # Always start from the beginning for clustering
    elif owner_id:
        # "Assigned to me" filter - fetch all assigned alerts for the user
        fetch_limit = 1000
        fetch_offset = 0
```

- The query `limit` param is already bounded at the API boundary: `limit: int = Query(100, ge=1, le=1000)` (line 120). The `1000` over-fetch matches that ceiling but is written as a bare literal in two places.
- A 30s cache (`AlertCache`, line 156) and circuit breaker (line 160) wrap the OpenSearch call, so repeated identical queries within 30s don't re-hit OpenSearch.
- Tests: `backend/tests/services/test_alert_clustering.py` and `backend/tests/services/test_alerts.py` exist — use them as the structural pattern for the new test.

Repo conventions: module-level constants are UPPER_SNAKE near the top of the file; FastAPI routers under `app/api/`. Match them.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Alert tests | `docker compose -f docker-compose.dev.yml run --rm backend pytest tests/services/test_alert_clustering.py tests/services/test_alerts.py -q` | all pass |
| API alert tests | `docker compose -f docker-compose.dev.yml run --rm backend pytest tests/api -k alert -q` | all pass |
| Lint | `docker compose -f docker-compose.dev.yml run --rm backend ruff check app/api/alerts.py` | exit 0 |

## Scope

**In scope**:
- `backend/app/api/alerts.py` (extract the constant; no behavior change to the chosen values)
- A test asserting the fetch strategy (add to `backend/tests/api/` near the existing alert API tests, or create `backend/tests/api/test_alert_fetch_strategy.py`).

**Out of scope** (do NOT touch):
- The clustering algorithm / `AlertService` internals — the full-fetch-for-clustering behavior is intentional and stays.
- The `AlertCache` / circuit-breaker wiring.
- The response schemas (`AlertListResponse` / `ClusteredAlertListResponse`).
- Changing the actual fetch ceiling value (keep it equal to the current `1000` unless the operator asks otherwise).

## Git workflow

- Branch: `advisor/007-alert-list-fetch-bound`
- Commit message: `perf(alerts): name and bound the cluster/owner over-fetch limit`
- Do NOT push or open a PR unless instructed.

## Steps

### Step 1: Extract the over-fetch limit to a named module constant

Near the top of `backend/app/api/alerts.py` (after imports, with the other module-level definitions), add:

```python
# When clustering or the owner filter is active we must fetch a wider window
# than the caller's page so the service sees the full candidate set. Bounded to
# the same ceiling as the `limit` query param (le=1000). Results are cached for
# 30s (see AlertCache) so repeat queries don't re-hit OpenSearch.
ALERT_WIDE_FETCH_LIMIT = 1000
```

Replace both `fetch_limit = 1000` literals (lines ~145 and ~150) with `fetch_limit = ALERT_WIDE_FETCH_LIMIT`. Do not change the `fetch_offset = 0` lines or the branching logic.

**Verify**: `grep -n "= 1000" backend/app/api/alerts.py` shows only the `Query(100, ge=1, le=1000)` param (the literal `1000` ceiling on the query arg is fine to leave); the two strategy assignments now reference the constant. `ruff check app/api/alerts.py` → exit 0.

### Step 2: Add a fetch-strategy regression test

Add a test (model it on the existing alert API tests; they set up an authenticated client and mock the OpenSearch/AlertService layer) that asserts:
- With clustering enabled, the service is asked for `ALERT_WIDE_FETCH_LIMIT` results at offset 0 regardless of the requested `limit`/`offset`.
- With clustering disabled and no owner filter, the service is asked for exactly the requested `limit`/`offset`.

If the existing tests already mock `AlertService.get_alerts`/`get_alerts_cached`, assert on the `limit`/`offset` (or `size`/`from`) passed through. If wiring a full request test is heavy, a focused test that imports the constant and the endpoint's strategy is acceptable — but prefer asserting through the service mock to catch real regressions.

**Verify**: `docker compose -f docker-compose.dev.yml run --rm backend pytest tests/api -k "alert and (fetch or strateg)" -q` → passes.

## Test plan

- New test pinning the two fetch strategies (wide for clustering/owner, exact for the default path), referencing `ALERT_WIDE_FETCH_LIMIT`.
- Existing alert + clustering suites must stay green (the change is a pure literal→constant extraction).

## Done criteria

ALL must hold:

- [ ] `grep -n "ALERT_WIDE_FETCH_LIMIT" backend/app/api/alerts.py` shows the constant defined once and used in both strategy branches
- [ ] No bare `fetch_limit = 1000` literals remain
- [ ] `docker compose -f docker-compose.dev.yml run --rm backend pytest tests/services/test_alert_clustering.py tests/services/test_alerts.py -q` → all pass
- [ ] New fetch-strategy test passes
- [ ] `ruff check app/api/alerts.py` exits 0
- [ ] Only `alerts.py` and the test file modified (`git status`)
- [ ] `plans/README.md` status row updated

## STOP conditions

Stop and report back if:
- The "Current state" excerpt doesn't match the live file (drift).
- You discover the over-fetch causes a *correctness* problem (e.g. clustering silently drops alerts beyond 1000) — that's a different, larger finding; report it rather than changing the value here.
- Asserting the strategy requires touching `AlertService` internals (out of scope).

## Maintenance notes

- If alert volumes routinely exceed `ALERT_WIDE_FETCH_LIMIT` per clustering window, clustering becomes lossy — consider server-side clustering/aggregation in OpenSearch rather than raising this number unbounded. Flag that as a separate design discussion.
- This constant could later be promoted to a runtime setting (like `alert_clustering`) if operators need to tune it; deferred here to keep the change small.
- Reviewer should confirm no behavior changed — only the literal was named.
