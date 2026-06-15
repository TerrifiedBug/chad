# Plan 001: Make CI actually gate backend correctness (tests, lint, typecheck)

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**: `git diff --stat ccf9970..HEAD -- .github/workflows/ci.yml backend/requirements.txt`
> If `.github/workflows/ci.yml` changed since this plan was written, compare the
> "Current state" excerpt against the live file before proceeding; on a
> mismatch, treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Depends on**: none (this is the prerequisite for every other plan's verification story)
- **Category**: tests / dx
- **Planned at**: commit `ccf9970`, 2026-06-15

## Why this matters

The backend CI job runs `pytest --cov=app --cov-report=xml || echo "Tests completed (some may have been skipped)"`. The trailing `|| echo` swallows pytest's non-zero exit code, so **backend test failures never fail the build**. Neither `ruff` (lint) nor `mypy` (typecheck) run in CI at all, even though both are pinned in `backend/requirements.txt`. The frontend job, by contrast, gates on lint + test + build. The result: broken, lint-failing, or type-failing backend code merges green. Until this is fixed there is no trustworthy "is the backend OK?" signal, which makes every other plan riskier to verify. After this lands, a red backend = a red build.

## Current state

- `.github/workflows/ci.yml` — the only CI workflow that runs tests. Relevant excerpt (lines 38–59):

```yaml
      - name: Install dependencies
        run: |
          cd backend
          pip install -r requirements.txt
          pip install pytest pytest-asyncio pytest-cov

      - name: Run tests
        env:
          DATABASE_URL: postgresql+asyncpg://test:test@localhost:5432/chad_test
          SECRET_KEY: test-secret-key-for-ci
          OPENSEARCH_URL: http://localhost:9200
        run: |
          cd backend
          pytest --cov=app --cov-report=xml || echo "Tests completed (some may have been skipped)"
```

- The `test-backend` job declares only a `postgres` service (lines 13–26). `OPENSEARCH_URL` is set but **no OpenSearch container exists**, so any test that hits a live OpenSearch fails/skips.
- `backend/requirements.txt` already pins the tooling: `ruff==0.15.8` (line 57), `mypy>=1.9.0` (line 71). No install step needed beyond `pip install -r requirements.txt`.
- `backend/pyproject.toml` configures both: `[tool.ruff.lint] select = ["E","F","I","UP"]`, line-length 120; `[tool.mypy]` is strict-ish but pragmatic (`disallow_untyped_defs = false`). Because mypy is only partially adopted, it will likely report many errors today — it must be added **non-gating** initially.
- Test infra: `backend/tests/conftest.py` spins up a real Postgres test DB (`chad_test`) and has `_should_skip_db_setup()` to let pure unit tests run without a DB. Most OpenSearch interaction in tests is mocked, but some integration tests may expect a reachable cluster.

Repo convention: CI jobs `cd backend` then run the tool directly (see the frontend job's `cd frontend && npm run lint`). Match that style.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Validate workflow YAML | `python -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml'))"` | exit 0, no output |
| Backend full suite (local, via compose) | `docker compose -f docker-compose.dev.yml run --rm backend pytest -q` | report pass/fail counts |
| Backend lint (local) | `docker compose -f docker-compose.dev.yml run --rm backend ruff check .` | exit 0 = clean |
| Backend typecheck (local) | `docker compose -f docker-compose.dev.yml run --rm backend mypy app` | prints error count (likely >0 today) |

(If Docker is unavailable, run inside the backend container the repo already uses; do NOT install Python deps onto the host.)

## Scope

**In scope** (the only files you should modify):
- `.github/workflows/ci.yml`

**Out of scope** (do NOT touch):
- Any application source under `backend/app/` — this plan does NOT fix test/lint/type failures it surfaces; it only wires the gates. If turning on a gate reveals failures, that is a STOP condition (see below), not a license to mass-edit source.
- `backend/pyproject.toml` — tool config is already correct.
- The `release.yml` / `docker-build.yml` workflows.

## Git workflow

- Branch: `advisor/001-ci-verification-baseline`
- Commit message style (match `git log`, conventional commits): `ci: gate backend tests, add ruff + mypy + opensearch service`
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Establish the current test baseline (READ-ONLY)

Run the full backend suite locally exactly as it stands:

`docker compose -f docker-compose.dev.yml run --rm backend pytest -q`

Record the result. Three outcomes:
- **All green** → proceed to Step 2.
- **Failures that are clearly infra-only** (e.g. connection refused to OpenSearch) → note them; Step 2 adds the OpenSearch service which should resolve them. Proceed.
- **Real test failures unrelated to infra** → **STOP and report** the failing test names. The pytest gate cannot be turned on over a red suite; the human must triage first.

### Step 2: Add an OpenSearch service container to the `test-backend` job

In `.github/workflows/ci.yml`, under `test-backend:` → `services:`, add an `opensearch` service alongside the existing `postgres` service. Use a single-node, security-disabled config on the port the env var already expects (9200):

```yaml
      opensearch:
        image: opensearchproject/opensearch:2.5.0
        env:
          discovery.type: single-node
          plugins.security.disabled: "true"
          OPENSEARCH_INITIAL_ADMIN_PASSWORD: ChadCi!Passw0rd
          OPENSEARCH_JAVA_OPTS: "-Xms512m -Xmx512m"
        ports:
          - 9200:9200
        options: >-
          --health-cmd "curl -sf http://localhost:9200/_cluster/health || exit 1"
          --health-interval 15s
          --health-timeout 10s
          --health-retries 10
```

Match the `opensearch-py==2.5.0` major line already in `requirements.txt`. The image tag `2.5.0` is intentional — keep client and server majors aligned.

**Verify**: `python -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"` → exit 0.

### Step 3: Make pytest gate, and add ruff (gating) + mypy (non-gating)

Replace the "Run tests" step body so the exit code propagates (remove `|| echo …`), and add two steps after it:

```yaml
      - name: Run tests
        env:
          DATABASE_URL: postgresql+asyncpg://test:test@localhost:5432/chad_test
          SECRET_KEY: test-secret-key-for-ci
          OPENSEARCH_URL: http://localhost:9200
        run: |
          cd backend
          pytest --cov=app --cov-report=xml

      - name: Lint (ruff)
        run: |
          cd backend
          ruff check .

      - name: Typecheck (mypy, non-blocking)
        continue-on-error: true
        run: |
          cd backend
          mypy app
```

Rationale baked in: `ruff` is gating because it is fast and the config is already adopted (Step 1's lint run tells you if the tree is clean). `mypy` uses `continue-on-error: true` because the codebase is only partially typed (`disallow_untyped_defs = false`) and a hard mypy gate would block all PRs on day one. A follow-up plan can ratchet mypy to gating once the error count is driven down.

Before committing, confirm ruff is actually clean locally:
`docker compose -f docker-compose.dev.yml run --rm backend ruff check .`
- Clean (exit 0) → keep ruff gating as written.
- **Not clean** → **STOP and report** the violation count and the top offending files. Do NOT mass-fix lint here; either the human approves a separate cleanup or the ruff step ships as `ruff check . || true` with a TODO — ask, don't decide.

**Verify**: `python -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"` → exit 0; and `grep -c "|| echo" .github/workflows/ci.yml` → `0`.

## Test plan

There are no application tests to add — the deliverable is CI configuration. Verification is:
- The full backend suite passes locally (Step 1 / after Step 2's OpenSearch service).
- `ruff check .` is clean locally (Step 3).
- The workflow YAML parses.

If you have access to push a branch and the operator approved it, the real proof is a CI run on the branch going green with the gates active — but only push if instructed.

## Done criteria

ALL must hold:

- [ ] `grep -c "|| echo" .github/workflows/ci.yml` returns `0`
- [ ] `.github/workflows/ci.yml` contains an `opensearch` service under `test-backend`
- [ ] `.github/workflows/ci.yml` contains a `ruff check .` step and an `mypy app` step (mypy with `continue-on-error: true`)
- [ ] `python -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"` exits 0
- [ ] Backend suite is green locally and `ruff check .` is clean locally
- [ ] No files outside `.github/workflows/ci.yml` modified (`git status`)
- [ ] `plans/README.md` status row updated

## STOP conditions

Stop and report back (do not improvise) if:
- The current backend suite (Step 1) has real, non-infra test failures — the gate cannot go on over red.
- `ruff check .` reports violations — do not mass-fix; ask how to proceed.
- The OpenSearch service makes CI exceed a reasonable time budget or the image fails health checks repeatedly.
- Turning on the pytest gate would require touching `backend/app/` source.

## Maintenance notes

- Follow-up (deferred): ratchet mypy from `continue-on-error: true` to gating once `mypy app` error count is near zero — track that as its own plan.
- A GitHub branch-protection ruleset enforces a fixed set of required status checks. Renaming or adding jobs may require updating the required-checks list in repo settings; flag this for the human reviewer.
- When reviewing the PR: confirm the OpenSearch image major matches `opensearch-py` in `requirements.txt`, and that no source file sneaked into the diff.
