# Plan 002: Fix naive `datetime.utcnow()` in the correlation engine (tz-aware mismatch)

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving on. If a
> "STOP condition" occurs, stop and report — do not improvise. When done,
> update this plan's row in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat ccf9970..HEAD -- backend/app/services/correlation.py backend/app/models/correlation_state.py`
> If either file changed since this plan was written, compare the "Current
> state" excerpts against the live code before proceeding; on a mismatch,
> treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: S
- **Risk**: LOW
- **Depends on**: 001 (so the new test actually gates in CI — not a hard blocker; this fix is safe to land independently)
- **Category**: bug
- **Planned at**: commit `ccf9970`, 2026-06-15

## Why this matters

`CorrelationState.triggered_at` and `expires_at` are declared `DateTime(timezone=True)` (timezone-aware). The correlation service builds the values and the lookup cutoff with `datetime.utcnow()`, which returns a **naive** datetime. Mixing naive and tz-aware datetimes against a `timezone=True` column is the classic source of "can't compare offset-naive and offset-aware" errors and silent off-by-timezone-offset window math — and correlation windows are a core *detection* primitive (a missed or mistimed correlation is a missed detection). `datetime.utcnow()` is also deprecated as of Python 3.11+ and the CI runs Python 3.12. The rest of the backend already standardizes on `datetime.now(UTC)` (e.g. `services/threshold.py`), so this is also a consistency fix. `UTC` is already imported in the target file, so the change is mechanical and low-risk.

## Current state

- `backend/app/models/correlation_state.py:24-25` — the columns are timezone-aware:

```python
    triggered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
```

- `backend/app/services/correlation.py:9` — `UTC` is already imported: `from datetime import UTC, datetime, timedelta`.
- `backend/app/services/correlation.py:283` — inside `check_correlation(...)`:

```python
        now = datetime.utcnow()
```
  `now` is then used for the window `cutoff = now - timedelta(...)` (line 295), the `expires_at = now + timedelta(...)` written to the tz-aware column (line 344), `triggered_at=now` (line 350), and `second_triggered_at: now.isoformat()` (line 335).

- `backend/app/services/correlation.py:378` — inside `cleanup_expired_states(...)`:

```python
    now = datetime.utcnow()
```
  used as `CorrelationState.expires_at < now` (line 381).

- Exemplar of the correct pattern in this repo: `backend/app/services/threshold.py:67,118` use `datetime.now(UTC)` for the same kind of window/cleanup math. Match it.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Run correlation tests (service) | `docker compose -f docker-compose.dev.yml run --rm backend pytest tests/services/test_correlation.py -q` | all pass |
| Run correlation model tests | `docker compose -f docker-compose.dev.yml run --rm backend pytest tests/models/test_correlation_models.py -q` | all pass |
| Confirm no naive utcnow remains in file | `grep -n "datetime.utcnow()" backend/app/services/correlation.py` | no matches |
| Lint the file | `docker compose -f docker-compose.dev.yml run --rm backend ruff check app/services/correlation.py` | exit 0 |

## Scope

**In scope**:
- `backend/app/services/correlation.py`
- `backend/tests/services/test_correlation.py` (add a regression test)

**Out of scope** (do NOT touch):
- `backend/app/services/rate_limit.py` — it also uses `datetime.utcnow()` but **deliberately** normalizes with `.replace(tzinfo=None)` (line ~93) against its own columns; changing it risks breaking lockout math. Leave it for a separate, dedicated plan.
- `backend/app/api/stats.py` and `backend/app/services/webhooks.py` — their `utcnow()` calls feed `.isoformat()` strings / fallback timestamps (cosmetic), not tz-aware column comparisons. Out of scope here.
- The `correlation_state` model and its migration — no schema change needed; the columns are already correct.

## Git workflow

- Branch: `advisor/002-correlation-tz-aware-datetime`
- Commit message: `fix: use tz-aware datetime in correlation engine`
- Do NOT push or open a PR unless instructed.

## Steps

### Step 1: Replace the two naive `datetime.utcnow()` calls

In `backend/app/services/correlation.py`:
- Line 283: change `now = datetime.utcnow()` → `now = datetime.now(UTC)`
- Line 378: change `now = datetime.utcnow()` → `now = datetime.now(UTC)`

No import change is needed (`UTC` is already imported on line 9). Do not change any other line — every downstream use of `now` keeps working and simply becomes tz-aware.

**Verify**: `grep -n "datetime.utcnow()" backend/app/services/correlation.py` → no matches. `docker compose -f docker-compose.dev.yml run --rm backend ruff check app/services/correlation.py` → exit 0.

### Step 2: Add a regression test

In `backend/tests/services/test_correlation.py`, add a test that asserts the datetimes produced/stored by the correlation flow are timezone-aware. Model it after the existing tests in that file (same fixtures, same async style). The key assertion shape:

- After a `check_correlation(...)` call that stores a new `CorrelationState` (the "first rule fires, no pair yet" path), load the stored row and assert `state.expires_at.tzinfo is not None` and `state.triggered_at.tzinfo is not None`.
- If the existing tests don't already exercise the store path with a real DB session, add a focused unit test that calls the function and inspects the added `CorrelationState` object's `expires_at`/`triggered_at` for `tzinfo is not None`.

If `test_correlation.py` is structured so this is awkward, follow the structure of `tests/models/test_correlation_models.py` instead and assert tz-awareness there.

**Verify**: `docker compose -f docker-compose.dev.yml run --rm backend pytest tests/services/test_correlation.py -q` → all pass, including the new test.

## Test plan

- New test (in `tests/services/test_correlation.py`, patterned on the file's existing tests): the correlation store path produces tz-aware `expires_at`/`triggered_at`. This is the exact regression this plan fixes.
- Run the full correlation suite (service + model tests) and confirm green.
- Verification: both pytest commands above pass.

## Done criteria

ALL must hold:

- [ ] `grep -n "datetime.utcnow()" backend/app/services/correlation.py` → no matches
- [ ] `docker compose -f docker-compose.dev.yml run --rm backend pytest tests/services/test_correlation.py tests/models/test_correlation_models.py -q` → all pass
- [ ] A regression test asserting tz-aware correlation datetimes exists and passes
- [ ] `ruff check app/services/correlation.py` exits 0
- [ ] Only `correlation.py` and `test_correlation.py` modified (`git status`)
- [ ] `plans/README.md` status row updated

## STOP conditions

Stop and report back if:
- The "Current state" excerpts don't match the live file (drift).
- The correlation tests were already failing before your change (Step 1) — report that first; it's a pre-existing problem, not yours to fix here.
- Making the test pass appears to require changing the model or a migration (it should not).

## Maintenance notes

- A future cleanup should sweep the remaining `datetime.utcnow()` sites (`rate_limit.py`, `stats.py`, `webhooks.py`) on a case-by-case basis — `rate_limit.py` in particular relies on naive normalization and must be handled carefully, not blanket-replaced.
- Reviewer should confirm no behavior change beyond tz-awareness: the window arithmetic (`now ± timedelta`) is identical; only the operands' tzinfo changes.
