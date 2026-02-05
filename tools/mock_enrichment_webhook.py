#!/usr/bin/env python3
"""
Mock Enrichment Webhook Server

A simple FastAPI server that simulates external enrichment endpoints for testing
CHAD's custom enrichment webhook feature.

Usage:
    # Run directly (requires uvicorn)
    python tools/mock_enrichment_webhook.py

    # Or via docker compose
    docker compose -f docker-compose.dev.yml run --rm -p 8888:8888 backend \
        python /app/tools/mock_enrichment_webhook.py

The server provides several mock endpoints:
- /enrich/user - Returns mock user data from Entra ID
- /enrich/asset - Returns mock asset data from CMDB
- /enrich/hr - Returns mock HR data
- /enrich/slow - Simulates a slow endpoint (for timeout testing)
- /enrich/error - Always returns an error (for circuit breaker testing)
- /enrich/echo - Echoes back the request (for debugging)

All endpoints accept the standard CHAD enrichment webhook format.
"""

import logging
import time
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Mock Enrichment Webhook",
    description="Test server for CHAD custom enrichment webhooks",
    version="1.0.0",
)

# Expected auth token for testing
AUTH_TOKEN = "test-webhook-token"


class EnrichmentRequest(BaseModel):
    """Standard CHAD enrichment webhook request."""

    alert_id: str
    rule_id: str
    rule_title: str
    severity: str
    lookup_field: str
    lookup_value: str
    log_document: dict[str, Any]


# Mock data stores
MOCK_USERS = {
    "jsmith": {
        "display_name": "John Smith",
        "email": "john.smith@example.com",
        "department": "Engineering",
        "title": "Senior Software Engineer",
        "manager": "Jane Doe",
        "office_location": "Building A, Floor 3",
        "is_privileged": False,
        "account_enabled": True,
        "last_sign_in": "2026-02-04T09:15:00Z",
    },
    "admin": {
        "display_name": "Admin User",
        "email": "admin@example.com",
        "department": "IT",
        "title": "System Administrator",
        "manager": "CTO",
        "office_location": "Building B, Floor 1",
        "is_privileged": True,
        "account_enabled": True,
        "last_sign_in": "2026-02-04T10:00:00Z",
    },
    "test_user": {
        "display_name": "Test User",
        "email": "test@example.com",
        "department": "QA",
        "title": "Test Engineer",
        "manager": "QA Lead",
        "office_location": "Remote",
        "is_privileged": False,
        "account_enabled": True,
        "last_sign_in": "2026-02-04T08:30:00Z",
    },
}

MOCK_ASSETS = {
    "WORKSTATION-001": {
        "hostname": "WORKSTATION-001",
        "asset_type": "Workstation",
        "owner": "jsmith",
        "department": "Engineering",
        "os": "Windows 11 Enterprise",
        "criticality": "medium",
        "last_patched": "2026-01-28",
        "location": "Building A",
        "tags": ["developer", "internet-access"],
    },
    "SERVER-DB-01": {
        "hostname": "SERVER-DB-01",
        "asset_type": "Server",
        "owner": "dba-team",
        "department": "IT",
        "os": "RHEL 9",
        "criticality": "critical",
        "last_patched": "2026-02-01",
        "location": "Datacenter 1",
        "tags": ["database", "production", "pci"],
    },
}

MOCK_HR = {
    "jsmith": {
        "employee_id": "EMP-12345",
        "full_name": "John Smith",
        "hire_date": "2020-03-15",
        "employment_status": "Active",
        "cost_center": "CC-ENG-001",
        "badge_access": ["Building A", "Building B", "Datacenter 1"],
        "security_clearance": "Standard",
        "training_completed": ["Security Awareness 2026", "Phishing Training"],
    },
    "admin": {
        "employee_id": "EMP-00001",
        "full_name": "Admin User",
        "hire_date": "2015-01-01",
        "employment_status": "Active",
        "cost_center": "CC-IT-001",
        "badge_access": ["All Buildings", "All Datacenters"],
        "security_clearance": "Elevated",
        "training_completed": ["Security Awareness 2026", "Admin Training", "Incident Response"],
    },
}


def validate_auth(authorization: str | None) -> None:
    """Validate authorization header."""
    if authorization != f"Bearer {AUTH_TOKEN}":
        raise HTTPException(
            status_code=401,
            detail={"error": "Invalid or missing authorization token"},
        )


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "mock-enrichment-webhook"}


@app.post("/enrich/user")
async def enrich_user(
    request: EnrichmentRequest,
    authorization: str = Header(None),
):
    """
    Mock Entra ID / Active Directory user enrichment.

    Returns user details based on username lookup.
    """
    validate_auth(authorization)

    logger.info(
        "User enrichment request: lookup_value=%s, alert_id=%s",
        request.lookup_value,
        request.alert_id,
    )

    user = MOCK_USERS.get(request.lookup_value.lower())
    if not user:
        logger.info("User not found: %s", request.lookup_value)
        return {}

    return user


@app.post("/enrich/asset")
async def enrich_asset(
    request: EnrichmentRequest,
    authorization: str = Header(None),
):
    """
    Mock CMDB asset enrichment.

    Returns asset details based on hostname lookup.
    """
    validate_auth(authorization)

    logger.info(
        "Asset enrichment request: lookup_value=%s, alert_id=%s",
        request.lookup_value,
        request.alert_id,
    )

    asset = MOCK_ASSETS.get(request.lookup_value.upper())
    if not asset:
        logger.info("Asset not found: %s", request.lookup_value)
        return {}

    return asset


@app.post("/enrich/hr")
async def enrich_hr(
    request: EnrichmentRequest,
    authorization: str = Header(None),
):
    """
    Mock HR system enrichment.

    Returns employee details based on username lookup.
    """
    validate_auth(authorization)

    logger.info(
        "HR enrichment request: lookup_value=%s, alert_id=%s",
        request.lookup_value,
        request.alert_id,
    )

    employee = MOCK_HR.get(request.lookup_value.lower())
    if not employee:
        logger.info("Employee not found: %s", request.lookup_value)
        return {}

    return employee


@app.post("/enrich/slow")
async def enrich_slow(
    request: EnrichmentRequest,
    authorization: str = Header(None),
):
    """
    Slow endpoint for testing timeout behavior.

    Sleeps for 15 seconds before responding.
    """
    validate_auth(authorization)

    logger.info("Slow enrichment request - sleeping for 15 seconds")
    time.sleep(15)

    return {"message": "Finally responded after 15 seconds"}


@app.post("/enrich/error")
async def enrich_error(
    request: EnrichmentRequest,
    authorization: str = Header(None),
):
    """
    Error endpoint for testing circuit breaker behavior.

    Always returns a 500 error.
    """
    validate_auth(authorization)

    logger.info("Error endpoint called - returning 500")
    raise HTTPException(
        status_code=500,
        detail={"error": "Simulated internal server error"},
    )


@app.post("/enrich/echo")
async def enrich_echo(
    request: EnrichmentRequest,
    authorization: str = Header(None),
):
    """
    Echo endpoint for debugging.

    Returns the request data back as the enrichment response.
    """
    validate_auth(authorization)

    logger.info("Echo enrichment request: %s", request.model_dump())

    return {
        "echo_alert_id": request.alert_id,
        "echo_rule_id": request.rule_id,
        "echo_rule_title": request.rule_title,
        "echo_severity": request.severity,
        "echo_lookup_field": request.lookup_field,
        "echo_lookup_value": request.lookup_value,
        "echo_log_keys": list(request.log_document.keys()),
    }


@app.post("/enrich/conditional")
async def enrich_conditional(
    request: EnrichmentRequest,
    authorization: str = Header(None),
):
    """
    Conditional enrichment based on severity.

    Returns more detailed data for high/critical alerts.
    """
    validate_auth(authorization)

    logger.info(
        "Conditional enrichment: severity=%s, lookup_value=%s",
        request.severity,
        request.lookup_value,
    )

    base_response = {
        "enriched_at": "2026-02-04T10:30:00Z",
        "lookup_value": request.lookup_value,
    }

    if request.severity in ("high", "critical"):
        base_response.update(
            {
                "priority": "URGENT",
                "escalation_required": True,
                "incident_team": "SOC-Tier2",
                "sla_hours": 4 if request.severity == "high" else 1,
                "additional_context": "High severity alert requires immediate attention",
            }
        )
    else:
        base_response.update(
            {
                "priority": "NORMAL",
                "escalation_required": False,
                "incident_team": "SOC-Tier1",
                "sla_hours": 24,
            }
        )

    return base_response


if __name__ == "__main__":
    import uvicorn

    print("=" * 60)
    print("Mock Enrichment Webhook Server")
    print("=" * 60)
    print()
    print("Available endpoints:")
    print("  POST /enrich/user   - Mock Entra ID user lookup")
    print("  POST /enrich/asset  - Mock CMDB asset lookup")
    print("  POST /enrich/hr     - Mock HR system lookup")
    print("  POST /enrich/slow   - Slow response (15s) for timeout testing")
    print("  POST /enrich/error  - Always returns 500 for circuit breaker testing")
    print("  POST /enrich/echo   - Echoes request back for debugging")
    print("  POST /enrich/conditional - Different response based on severity")
    print()
    print(f"Auth token: Bearer {AUTH_TOKEN}")
    print()
    print("Mock users: jsmith, admin, test_user")
    print("Mock assets: WORKSTATION-001, SERVER-DB-01")
    print()
    print("=" * 60)

    uvicorn.run(app, host="0.0.0.0", port=8888)
