# Plan 013: Run backend CI inside the container to restore env-coupled + integration tests

> **Status: IN PROGRESS.** Created 2026-06-15 during the v0.12.0 release when the
> newly-real CI gate exposed tests coupled to the docker environment. Being
> implemented via **approach 1** (container-based CI): the `test-backend` job now
> runs `docker compose -f docker-compose.dev.yml run --rm backend pytest`, which
> restores the 5 previously-`--deselect`ed tests (the container provides `/app`,
> `DEBUG=true`, the `chad` DB). **Still deferred:** `tests/integration` — the dev
> compose defines no OpenSearch service, so those remain `--ignore`d until an
> OpenSearch service (with index/data provisioning) is added to a CI compose.

## Status

- **Priority**: P2
- **Effort**: M
- **Risk**: MED (CI-only; no app code)
- **Depends on**: none (001 landed the gate)
- **Category**: dx / tests
- **Planned at**: commit `64833ff`, 2026-06-15

## Why this matters

`001` made the backend CI gate real (it had been masked by `|| echo` — backend tests never actually gated). The gate runs `pytest` directly on the bare GitHub runner. Five tests are coupled to the docker dev container and **cannot pass on a bare runner**, so they are currently `--deselect`ed in `.github/workflows/ci.yml` (and `tests/integration` is `--ignore`d). They DO pass under the project's canonical command `docker compose -f docker-compose.dev.yml run --rm backend pytest` (which is how the full suite — 1109+ — was validated locally). This plan moves the CI backend-test job to run inside the container so the deselected/ignored tests are gated again, restoring full coverage.

## Currently deselected / ignored (the coverage gap to close)

- `tests/api/test_audit_export.py::test_chain_envelope_verifies_via_cli`
- `tests/api/test_audit_export.py::test_cli_detects_mutated_row`
- `tests/api/test_audit_export.py::test_cli_refuses_without_key`
  — these `subprocess` the audit-chain-verify CLI expecting the container path `/app`.
- `tests/middleware/test_csrf.py::test_safe_origin_allows_localhost_in_debug`
  — `is_safe_origin` reads `DEBUG` captured at import; the bare runner has `DEBUG` unset, and the test's runtime `settings.DEBUG = True` doesn't affect the import-time value.
- `tests/services/test_scheduler_misp.py::test_run_misp_sync_job`
  — the scheduler job connects to the app DB `chad`; the bare runner only has `chad_test`.
- `tests/integration/**` — needs a provisioned OpenSearch (indices/data), not a bare service container.

## Two viable approaches

1. **Container-based CI job (recommended).** Replace the bare-runner `pip install` + `pytest` steps in the `test-backend` job with: bring up `docker compose -f docker-compose.dev.yml` services, then `docker compose ... run --rm backend pytest` (the canonical command). All five env-coupled tests pass because the container provides `/app`, `DEBUG=true`, and the `chad` DB. Watch for: the dev compose's reliance on a `.env` (provide CI-only test values), CI image build time, and adding an OpenSearch service to the dev compose (or a separate integration job) to also restore `tests/integration`.

2. **De-couple the tests (smaller, incremental).** Fix each test to not depend on the container: make the audit CLI tests resolve the CLI path relative to the repo (not `/app`); make `is_safe_origin` read `settings.DEBUG` live (or have the test set the import-time source); make the MISP scheduler test use the test DB/session. Then drop the `--deselect`s. This also improves test quality but touches app/test code and must be validated in CI (can't fully reproduce the bare-runner env locally).

## Done criteria

- [ ] The five `--deselect` flags and the `--ignore=tests/integration` are removed from `.github/workflows/ci.yml` (or integration moved to its own job with a real OpenSearch).
- [ ] CI `test-backend` is green with the full suite (≈1127+ tests) gating.
- [ ] No app behavior change (CI/test-only), or — if approach 2 — the `is_safe_origin` DEBUG-source change is reviewed for prod impact.

## Notes

- This is a real coverage gap (incl. the audit-chain-verify CLI security tests). Track it; don't let the deselects become permanent.
- The prior state was *zero* backend gating (`|| echo` swallowed everything), so the current 1122-test gate is already a large net improvement — this plan closes the remaining gap.
