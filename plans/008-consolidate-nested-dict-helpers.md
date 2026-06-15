# Plan 008: Consolidate the duplicated `get_nested_value` / `set_nested_value` helpers

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving on. If a
> "STOP condition" occurs, stop and report. When done, update this plan's row
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat ccf9970..HEAD -- backend/app/services/alerts.py backend/app/services/enrichment.py backend/app/services/correlation.py`
> If any changed since this plan was written, compare the "Current state"
> excerpts to the live code before proceeding; on a mismatch, STOP.

## Status

- **Priority**: P3
- **Effort**: S
- **Risk**: LOW
- **Depends on**: none
- **Category**: tech-debt
- **Planned at**: commit `ccf9970`, 2026-06-15

## Why this matters

`get_nested_value(dict, "a.b.c")` (dot-path lookup) is reimplemented three times across the services layer, and `set_nested_value` exists once. The copies have already drifted: `correlation.py`'s version is annotated `-> any` (the builtin `any`, a latent typo for `typing.Any`) and uses `.get(key)` while the other two use `key in value`/`value[key]` — functionally equivalent today, but three copies mean a future fix (e.g. supporting array indices) must be made in three places or they diverge further. Consolidating into one shared utility removes the drift risk and gives future dot-path features a single home. The existing `app/utils/` package is the natural location. This is a pure refactor — no behavior change.

## Current state

Three functionally-equivalent definitions (all map a dotted path over nested dicts, returning `None` for any missing/non-dict segment):

- `backend/app/services/alerts.py:55`:

```python
def get_nested_value(obj: dict, path: str) -> Any:
    """Get a value from a nested dict using dot notation."""
    keys = path.split(".")
    value = obj
    for key in keys:
        if isinstance(value, dict) and key in value:
            value = value[key]
        else:
            return None
    return value
```

- `backend/app/services/enrichment.py:52` — identical body to the above, plus `set_nested_value` at `enrichment.py:64`:

```python
def set_nested_value(doc: dict, path: str, value: Any):
    """Set a value in a nested dict using dot notation."""
    keys = path.split(".")
    current = doc
    for key in keys[:-1]:
        if key not in current:
            current[key] = {}
        current = current[key]
    current[keys[-1]] = value
```

- `backend/app/services/correlation.py:47` — equivalent but `-> any` (typo) and `.get(key)` style.

- Existing util package: `backend/app/utils/` contains `__init__.py`, `crud.py`, `decorators.py`, `request.py`. It is a **leaf** package (services import from utils, not the reverse), so importing from it introduces no cycle.
- `threshold.py:17` has a *different* helper `extract_field(doc, path) -> str | None` (stringifies, different return contract) — **leave it alone**, it is not a duplicate of this function.

Repo conventions: small focused modules under `app/utils/`; `from typing import Any`. Match `crud.py`'s style.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Touched-service tests | `docker compose -f docker-compose.dev.yml run --rm backend pytest tests/services/test_alerts.py tests/services/test_correlation.py tests/services/test_enrichment_offload.py -q` | all pass |
| Full suite (no regressions) | `docker compose -f docker-compose.dev.yml run --rm backend pytest -q` | all pass |
| Confirm no stray defs remain | `grep -rn "def get_nested_value\|def set_nested_value" backend/app/services/` | no matches |
| Lint | `docker compose -f docker-compose.dev.yml run --rm backend ruff check app/` | exit 0 |

## Scope

**In scope**:
- `backend/app/utils/nested.py` (create)
- `backend/app/services/alerts.py`, `backend/app/services/enrichment.py`, `backend/app/services/correlation.py` (remove local defs, import shared)
- `backend/tests/utils/test_nested.py` (create) — or add to an existing utils test module

**Out of scope** (do NOT touch):
- `threshold.py:extract_field` — different contract, not a duplicate.
- Any change to the lookup *semantics* — the shared function must behave exactly like the current copies (return `None` for missing/non-dict path segments).
- Call sites' logic — only the import source of `get_nested_value`/`set_nested_value` changes; names stay identical.

## Git workflow

- Branch: `advisor/008-consolidate-nested-dict-helpers`
- Commit message: `refactor: consolidate nested-dict helpers into app/utils/nested.py`
- Do NOT push or open a PR unless instructed.

## Steps

### Step 1: Create the shared module

Create `backend/app/utils/nested.py`:

```python
"""Dotted-path helpers for nested dicts."""

from typing import Any


def get_nested_value(obj: dict, path: str) -> Any:
    """Get a value from a nested dict using dot notation (None if absent)."""
    value = obj
    for key in path.split("."):
        if isinstance(value, dict) and key in value:
            value = value[key]
        else:
            return None
    return value


def set_nested_value(doc: dict, path: str, value: Any) -> None:
    """Set a value in a nested dict using dot notation, creating parents."""
    keys = path.split(".")
    current = doc
    for key in keys[:-1]:
        if key not in current:
            current[key] = {}
        current = current[key]
    current[keys[-1]] = value
```

### Step 2: Replace the three duplicated definitions with imports

In each of `alerts.py`, `enrichment.py`, `correlation.py`:
- Delete the local `def get_nested_value(...)` (and in `enrichment.py`, also delete `def set_nested_value(...)`).
- Add `from app.utils.nested import get_nested_value` (in `enrichment.py`: `from app.utils.nested import get_nested_value, set_nested_value`).
- Leave every *call site* unchanged — the function name is identical.
- Remove any now-unused `Any` import only if `ruff` flags it (don't remove if still used elsewhere in the file).

**Verify**: `grep -rn "def get_nested_value\|def set_nested_value" backend/app/services/` → no matches. `docker compose -f docker-compose.dev.yml run --rm backend ruff check app/` → exit 0 (ruff's `F401`/`F811` will catch unused or redefined imports).

### Step 3: Add unit tests for the shared helper

Create `backend/tests/utils/test_nested.py` covering:
- `get_nested_value({"a": {"b": 1}}, "a.b") == 1`
- `get_nested_value({"a": {"b": 1}}, "a.c") is None`
- `get_nested_value({"a": 1}, "a.b") is None` (non-dict segment)
- `set_nested_value` creates intermediate dicts and sets the leaf.

These are plain sync unit tests (no DB) — `tests/utils/` runs without the DB fixture.

**Verify**: `docker compose -f docker-compose.dev.yml run --rm backend pytest tests/utils/test_nested.py -q` → all pass.

### Step 4: Run the full suite

The three services are on hot paths (alerting, enrichment, correlation); run everything to be sure no caller broke.

**Verify**: `docker compose -f docker-compose.dev.yml run --rm backend pytest -q` → all pass.

## Test plan

- New `tests/utils/test_nested.py` for the shared helper (happy path, missing key, non-dict segment, set-creates-parents).
- The existing service suites (`test_alerts.py`, `test_correlation.py`, `test_enrichment_offload.py`) must stay green — they exercise the call sites.

## Done criteria

ALL must hold:

- [ ] `backend/app/utils/nested.py` exists with both helpers
- [ ] `grep -rn "def get_nested_value\|def set_nested_value" backend/app/services/` → no matches
- [ ] The three services import from `app.utils.nested`
- [ ] `docker compose -f docker-compose.dev.yml run --rm backend pytest -q` → all pass (incl. new tests)
- [ ] `ruff check app/` exits 0 (no unused/redefined-import warnings)
- [ ] Only the four files above + the test modified (`git status`)
- [ ] `plans/README.md` status row updated

## STOP conditions

Stop and report back if:
- Any "Current state" excerpt doesn't match the live file (drift).
- Removing a local def reveals a call site that depended on a *different* behavior than the shared version (it shouldn't — they're equivalent) — report the divergence rather than special-casing.
- An import cycle appears (it shouldn't, `utils` is a leaf) — report the cycle.

## Maintenance notes

- New code needing dot-path access should import from `app.utils.nested`, not re-implement.
- If dot-path support ever needs array indices (`a.0.b`) or custom separators, that change now lives in one place.
- Reviewer should confirm the shared helper's behavior is byte-for-byte equivalent to the removed copies (especially the `None`-on-missing contract).
