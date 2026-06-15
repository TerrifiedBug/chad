# Plan 012: Fix the broken `get_opensearch_client` import in the health check (0.11.1 runtime bug)

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result. If a STOP condition
> occurs, stop and report. When done, update this plan's row in
> `plans/README.md` — unless a reviewer dispatched you and maintains the index.
>
> **Drift check (run first)**: `git diff --stat 821660f..HEAD -- backend/app/main.py backend/app/services/opensearch.py`
> If `main.py` changed since this plan was written, compare the "Current state"
> excerpt to the live code before proceeding; on a mismatch, STOP.

## Status

- **Priority**: P1
- **Effort**: S
- **Risk**: LOW
- **Depends on**: none
- **Category**: bug
- **Planned at**: commit `821660f`, 2026-06-15

## Why this matters

Production 0.11.1 logs show `cannot import name 'get_opensearch_client' from app.services.opensearch`. The health-check endpoint in `main.py` does a lazy `from app.services.opensearch import get_opensearch_client`, but that name does **not** exist in `app.services.opensearch` — it lives in `app.api.deps` (and there it is an async FastAPI dependency with `Depends(...)` params, not a plain callable). So the OpenSearch sub-check of `/health` raises `ImportError` on every call, is swallowed by the surrounding `except`, and the endpoint silently reports OpenSearch as unhealthy. Beyond the wrong import, the same block also `await`s `client.info()` even though the opensearch-py `OpenSearch` client is **synchronous** — a second latent bug masked by the import failing first. This plan fixes both so the health check actually probes OpenSearch connectivity.

## Current state

- `backend/app/services/opensearch.py` imports the **sync** client (`from opensearchpy import OpenSearch`) and exposes `get_client_from_settings(db_session) -> OpenSearch | None` (line 133, `async def`) — the established way to obtain a client from stored settings (used by `worker.py:260` and `api/logs.py:262`, both `await get_client_from_settings(db)`). There is **no** `get_opensearch_client` in this module.
- `backend/app/main.py` health check, the broken block (around lines 354–360):

```python
            # OpenSearch is configured, check connectivity
            from app.services.opensearch import get_opensearch_client
            client = get_opensearch_client()
            if client:
                info = await client.info()
                if info and info.get("status") == 200:
                    checks["opensearch"] = True
```

  This whole block is inside a `try/except Exception` that logs a warning and sets `checks["opensearch"] = False` — it is best-effort and must not fail the overall health check. `db` is in scope in this function (it called `get_setting(db, "opensearch")` just above).
- Note `info.get("status") == 200` is also wrong — `OpenSearch.info()` returns cluster info (name/version/…), not an HTTP status — so even with a working client the success branch never runs. Use a real connectivity probe instead.

Repo convention: obtain the client via `await get_client_from_settings(db)`; the returned `OpenSearch` client is **synchronous** (its methods are not awaited).

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| App imports cleanly | `docker compose -f docker-compose.dev.yml run --rm backend python -c "import app.main"` | exit 0, no ImportError |
| Health-related tests | `docker compose -f docker-compose.dev.yml run --rm backend pytest tests/api -k health -p no:randomly -q` | all pass |
| Lint touched file | `docker compose -f docker-compose.dev.yml run --rm backend ruff check app/main.py` | no NEW errors (pre-existing tree debt aside) |

## Scope

**In scope**:
- `backend/app/main.py` (the OpenSearch block of the health check only)

**Out of scope** (do NOT touch):
- `app/services/opensearch.py` and `app/api/deps.py` — the symbols are correct; only `main.py`'s import is wrong.
- The database health check above it, and the overall status logic below it.

## Git workflow

- Branch: stay on the current working branch (do not create/switch).
- Commit message: `fix: correct OpenSearch client import in health check`
- Do NOT push or open a PR unless instructed.

## Steps

### Step 1: Use the correct getter and a synchronous connectivity probe

Replace the broken block in `backend/app/main.py` with:

```python
            # OpenSearch is configured, check connectivity
            from app.services.opensearch import get_client_from_settings
            client = await get_client_from_settings(db)
            if client is not None and client.ping():
                checks["opensearch"] = True
```

- `get_client_from_settings` is async → `await` it. The returned `OpenSearch` client is sync → `client.ping()` is **not** awaited; it returns a bool. This replaces both the bad import and the incorrect `await client.info()` / `info.get("status")` logic.
- Leave the surrounding `try/except` and the `checks["opensearch"] = False` default untouched.

**Verify**: `docker compose -f docker-compose.dev.yml run --rm backend python -c "import app.main"` → exit 0; `grep -n "get_opensearch_client" backend/app/main.py` → no matches.

### Step 2: Confirm health tests still pass

**Verify**: `docker compose -f docker-compose.dev.yml run --rm backend pytest tests/api -k health -p no:randomly -q` → all pass.

## Test plan

- This is a small runtime-bug fix in a best-effort branch; the primary proof is that `import app.main` no longer raises and the health endpoint no longer logs the ImportError.
- If a health-endpoint test exists, it must stay green. Optionally add an assertion that `/health` returns 200 and includes an `opensearch` key (don't assert its boolean value — it depends on whether OpenSearch is reachable in the test env).

## Done criteria

- [ ] `grep -n "get_opensearch_client" backend/app/main.py` → no matches
- [ ] `docker compose -f docker-compose.dev.yml run --rm backend python -c "import app.main"` exits 0
- [ ] `docker compose -f docker-compose.dev.yml run --rm backend pytest tests/api -k health -p no:randomly -q` → all pass
- [ ] Only `backend/app/main.py` modified (`git status`)
- [ ] `plans/README.md` status row updated (unless reviewer maintains it)

## STOP conditions

Stop and report if:
- `main.py`'s health block doesn't match the "Current state" excerpt (drift).
- `OpenSearch` turns out to be the async client in this codebase (it should be sync — `from opensearchpy import OpenSearch`); if `client.ping()` must be awaited, report rather than guessing.

## Maintenance notes

- Any future code needing an OpenSearch client should `await get_client_from_settings(db)` (settings-driven) or use the `get_cached_client`/`get_opensearch_client` DI dependency from `app.api.deps` in route handlers — never import `get_opensearch_client` from `app.services.opensearch`.
- Reviewer: confirm the client is used synchronously and the best-effort `except` still guards the block.
