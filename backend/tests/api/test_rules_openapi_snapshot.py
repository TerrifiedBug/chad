"""OpenAPI path snapshot for the rules router.

Safety net for the `api/rules` decomposition (plan 010): this test pins the
exact set of `/api/rules*` routes and their HTTP methods. It must stay green
through every step of splitting `rules.py` into a `rules/` package. If it
changes, a route was dropped, renamed, or shadowed by `/{rule_id}` ordering.

It only needs the FastAPI `app` object (no DB).
"""

from app.main import app

# The 36 rule routes as "METHOD /api/rules..." strings, sorted.
EXPECTED_RULE_ROUTES = sorted(
    [
        "DELETE /api/rules/{rule_id}",
        "DELETE /api/rules/{rule_id}/exceptions/{exception_id}",
        "GET /api/rules",
        "GET /api/rules/index-fields/{index_pattern_id}",
        "GET /api/rules/settings",
        "GET /api/rules/{rule_id}",
        "GET /api/rules/{rule_id}/activity",
        "GET /api/rules/{rule_id}/comments",
        "GET /api/rules/{rule_id}/deploy-preview",
        "GET /api/rules/{rule_id}/exceptions",
        "GET /api/rules/{rule_id}/fields",
        "GET /api/rules/{rule_id}/linked-correlations",
        "GET /api/rules/{rule_id}/versions/{version_number}",
        "PATCH /api/rules/{rule_id}",
        "PATCH /api/rules/{rule_id}/exceptions/{exception_id}",
        "PATCH /api/rules/{rule_id}/threshold",
        "PUT /api/rules/settings",
        "POST /api/rules",
        "POST /api/rules/bulk/delete",
        "POST /api/rules/bulk/deploy",
        "POST /api/rules/bulk/snooze",
        "POST /api/rules/bulk/undeploy",
        "POST /api/rules/bulk/unsnooze",
        "POST /api/rules/check-deployment-eligibility",
        "POST /api/rules/check-title",
        "POST /api/rules/test",
        "POST /api/rules/validate",
        "POST /api/rules/{rule_id}/comments",
        "POST /api/rules/{rule_id}/deploy",
        "POST /api/rules/{rule_id}/exceptions",
        "POST /api/rules/{rule_id}/rollback-redeploy/{version_number}",
        "POST /api/rules/{rule_id}/rollback/{version_number}",
        "POST /api/rules/{rule_id}/snooze",
        "POST /api/rules/{rule_id}/test-historical",
        "POST /api/rules/{rule_id}/undeploy",
        "POST /api/rules/{rule_id}/unsnooze",
    ]
)


def _actual_rule_routes() -> list[str]:
    paths = app.openapi()["paths"]
    rows: list[str] = []
    for path, methods in paths.items():
        if not path.startswith("/api/rules"):
            continue
        for method in methods:
            rows.append(f"{method.upper()} {path}")
    return sorted(rows)


def test_rules_openapi_path_snapshot():
    """The full set of /api/rules* paths+methods must be stable."""
    assert _actual_rule_routes() == EXPECTED_RULE_ROUTES


def test_rules_route_count():
    """Exactly 36 rule routes (guards against silent additions/removals)."""
    assert len(_actual_rule_routes()) == 36
