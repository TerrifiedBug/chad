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

**In scope** (the files you may modify):
- `.github/workflows/ci.yml` — wire the gates (Steps 2, 3).
- `backend/pyproject.toml` — ruff `ignore = ["UP042","E402"]` with rationale + pytest determinism `addopts` (Steps 3b, 3c).
- `backend/app/**` — ONLY line-wrapping for `E501` and targeted `# noqa` comments (Step 3b). No behavior changes, no logic edits.

**Out of scope** (do NOT touch):
- Any *behavioral* change to application source — E501 fixes are line-wrapping only; if a fix would alter behavior, STOP.
- The `(str, Enum)` → `StrEnum` migration (UP042) — waived, not performed (changes serialization).
- The deep async test-isolation rework — deferred to a separate plan; this plan only pins determinism.
- The `release.yml` / `docker-build.yml` workflows.

## Git workflow

- Branch: `advisor/001-ci-verification-baseline`
- Commit message style (match `git log`, conventional commits): `ci: gate backend tests, add ruff + mypy + opensearch service`
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Establish the current test baseline (READ-ONLY)

Run the full backend suite locally (deterministic ordering, skipping the GitPython-collection dir that the dev container can't import):

`docker compose -f docker-compose.dev.yml run --rm backend pytest -p no:randomly --ignore=tests/services/git -q`

Record the result. Outcomes:
- **All green** → proceed; Step 3c makes the gate ordering-deterministic.
- **Failures clearly infra-only** (e.g. OpenSearch connection refused) → Step 2 adds the OpenSearch service; proceed.
- **Intermittent errors only under random ordering** → expected pre-existing flakiness; Step 3c pins determinism. Confirm the suite is green under the chosen deterministic setting.
- **Real, deterministic test failures unrelated to infra** → **STOP and report** the failing test names. The gate cannot go on over a deterministically-red suite.

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

Rationale baked in: `ruff` gates (fast, config already adopted); `mypy` uses `continue-on-error: true` because the codebase is only partially typed (`disallow_untyped_defs = false`) and a hard mypy gate would block all PRs day one. Follow-up: ratchet mypy to gating later.

### Step 3b: Resolve the pre-existing ruff debt so the gate is viable (MEASURED)

`ruff check app/` currently reports **109 errors** (measured at `ccf9970`, breakdown via `ruff check app/ --statistics`):

| Count | Rule | Decision |
|---|---|---|
| 56 | `E501` line-too-long | **FIX** — wrap genuinely long lines. Re-measure AFTER plan 010 (it restructures `rules.py`, which holds ~12 of these); fix the post-010 set. |
| 30 | `UP042` replace-str-enum (`(str, Enum)`→`StrEnum`) | **WAIVE** with rationale — migrating changes enum `str()`/serialization output; these enums back DB columns + Pydantic schemas + API responses. The `(str, Enum)` pattern is intentional and stable. Not a correctness bug. |
| 21 | `E402` module-import-not-at-top | **WAIVE** with rationale — deliberate late/in-function imports to break circular dependencies (e.g. lazy GitPython). Hoisting them reintroduces cycles. |
| 2 | `I001` unsorted-imports | **FIX** — `ruff check --fix` (safe, auto). |

Concretely:
1. Add to `backend/pyproject.toml` `[tool.ruff.lint]` an `ignore = ["UP042", "E402"]` with a comment explaining each (intentional str-enum serialization stability; intentional late imports for cycle avoidance). If a *few* specific E402/UP042 sites are genuinely fixable without risk, prefer a targeted `# noqa: <code>  # <reason>` there over the global ignore — but the global ignore is acceptable given the volume and intent.
2. `ruff check --fix app/` to clear the 2 `I001`.
3. Wrap the remaining `E501` long lines (these are real). This is mechanical; do it AFTER plan 010 lands so you fix the final file set, not lines that are about to move.
4. Re-run `ruff check app/` → must reach exit 0 before flipping the gate on.

**Do NOT** auto-`--fix` with `--unsafe-fixes` (that would attempt the risky UP042 StrEnum migration).

### Step 3c: Make the gated suite deterministic (MEASURED)

The suite depends on `pytest-randomly` (random test order each run) and has **pre-existing order-dependent flakiness** — certain random orderings produce intermittent ERRORS in unrelated tests (observed: async event-loop/connection interaction surfacing in correlation tests when other suites run first; `test_engine` is function-scoped so it is NOT row leakage). A gate over a non-deterministic suite is a flaky gate.

Bounded fix for THIS plan: make CI deterministic by pinning the random seed. Add to `backend/pyproject.toml` `[tool.pytest.ini_options]` `addopts = "-p randomly --randomly-seed=<pick a fixed int>"` (or `addopts = "-p no:randomly"` to disable reordering entirely). Verify the full suite passes deterministically under the chosen setting before flipping the gate. **Deferred (separate plan):** the underlying async test-isolation fix (so the suite is robust under ANY ordering) — document it, don't attempt the 140-file rework here.

Also note: `tests/services/git/` fails collection when GitPython is absent. CI installs `requirements.txt` (which pins `GitPython>=3.1.43`), so CI is fine; locally in a container missing it, use `--ignore=tests/services/git`. Confirm the CI image actually installs `requirements.txt` (it does, per the Install step).

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
- [ ] `ruff check app/` exits 0 locally (after Step 3b: I001 auto-fixed, E501 wrapped, UP042+E402 waived with documented rationale in `pyproject.toml`)
- [ ] Full backend suite green locally under the deterministic setting chosen in Step 3c
- [ ] In-scope files only: `.github/workflows/ci.yml`, `backend/pyproject.toml` (ruff ignore + pytest determinism), plus any `backend/app/**` lines wrapped for E501 and any `# noqa` added (`git status`)
- [ ] `plans/README.md` status row updated

## STOP conditions

Stop and report back (do not improvise) if:
- The backend suite has real, deterministic, non-infra test failures — the gate cannot go on over red.
- Clearing E501 would require changing code behavior (not just line-wrapping) — report those sites.
- The OpenSearch service makes CI exceed a reasonable time budget or the image fails health checks repeatedly.
- A `UP042`/`E402` site you intended to *fix* (not waive) turns out to change behavior — waive it instead and note it.

## Maintenance notes

- Follow-up (deferred): ratchet mypy from `continue-on-error: true` to gating once `mypy app` error count is near zero — track that as its own plan.
- A GitHub branch-protection ruleset enforces a fixed set of required status checks. Renaming or adding jobs may require updating the required-checks list in repo settings; flag this for the human reviewer.
- When reviewing the PR: confirm the OpenSearch image major matches `opensearch-py` in `requirements.txt`, and that no source file sneaked into the diff.
