import logging
import os
import uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api.ai_copilot import router as ai_copilot_router
from app.api.alerts import router as alerts_router
from app.api.api_keys import router as api_keys_router
from app.api.attack import router as attack_router
from app.api.audit import router as audit_router
from app.api.audit_settings import router as audit_settings_router
from app.api.auth import router as auth_router
from app.api.cases import router as cases_router
from app.api.circuit_breakers import router as circuit_breakers_router
from app.api.correlation_rules import router as correlation_rules_router
from app.api.deployment_requests import router as deployment_requests_router
from app.api.deps import get_db
from app.api.enrichment_webhooks import router as enrichment_webhooks_router
from app.api.environments import router as environments_router
from app.api.export import router as export_router
from app.api.external import router as external_router
from app.api.field_mappings import router as field_mappings_router
from app.api.git_import import router as git_import_router
from app.api.health import router as health_router
from app.api.index_patterns import router as index_patterns_router
from app.api.jira import router as jira_router
from app.api.logs import router as logs_router
from app.api.metrics import router as metrics_router
from app.api.misp import router as misp_router
from app.api.misp_feedback import router as misp_feedback_router
from app.api.misp_sync import router as misp_sync_router
from app.api.mode import router as mode_router
from app.api.notifications import router as notifications_router
from app.api.organizations import router as organizations_router
from app.api.permissions import router as permissions_router
from app.api.queue import router as queue_router
from app.api.report_schedules import router as report_schedules_router
from app.api.reports import router as reports_router
from app.api.rule_ci import router as rule_ci_router
from app.api.rules import router as rules_router
from app.api.saved_views import router as saved_views_router
from app.api.scim import router as scim_router
from app.api.settings import router as settings_router
from app.api.sigmahq import router as sigmahq_router
from app.api.sla import router as sla_router
from app.api.sso import router as sso_router
from app.api.stats import router as stats_router
from app.api.system_logs import router as system_logs_router
from app.api.teams import router as teams_router
from app.api.ti import router as ti_router
from app.api.users import router as users_router
from app.api.webhooks import router as webhooks_router
from app.api.websocket import router as websocket_router
from app.core.config import settings
from app.core.csrf import CSRFMiddleware
from app.core.errors import HTTPError, http_error_handler
from app.core.logging import setup_logging
from app.core.middleware import ErrorResponseMiddleware, RequestValidationMiddleware
from app.core.org_middleware import OrgScopeMiddleware
from app.core.redis import close_redis
from app.services.scheduler import scheduler_service
from app.services.websocket import manager as websocket_manager

logger = logging.getLogger(__name__)


def validate_delegated_auth_config() -> None:
    """Fail fast when delegated suite auth is misconfigured.

    In the suite 'full' profile, compose sets CHAD_DELEGATED_AUTH=true and
    VF_SESSION_SECRET=${NEXTAUTH_SECRET}. Enabling the flag without the secret
    would silently make every VF session undecodable, so refuse to start.
    """
    if settings.CHAD_DELEGATED_AUTH and not settings.VF_SESSION_SECRET:
        raise RuntimeError(
            "CHAD_DELEGATED_AUTH=true requires VF_SESSION_SECRET to be set "
            "(share NEXTAUTH_SECRET from the VectorFlow service)."
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application startup and shutdown."""
    # Setup structured logging first
    setup_logging()

    # Startup
    # CRITICAL SECURITY CHECK: Reject insecure secret defaults in production
    if not settings.DEBUG:
        insecure_defaults = [
            "dev-secret-key-change-in-prod",
            "dev-session-key-change-in-prod",
            "default-dev-key-change-in-prod",
            "secret",
            "changeme",
        ]

        critical_failures = []

        if settings.JWT_SECRET_KEY.lower() in insecure_defaults:
            critical_failures.append(
                "JWT_SECRET_KEY is using insecure default in production. "
                "Set a secure secret via environment variable: "
                "JWT_SECRET_KEY=$(openssl rand -base64 32)"
            )

        if settings.SESSION_SECRET_KEY.lower() in insecure_defaults:
            critical_failures.append(
                "SESSION_SECRET_KEY is using insecure default in production. "
                "Set a secure secret via environment variable: "
                "SESSION_SECRET_KEY=$(openssl rand -base64 32)"
            )

        encryption_key = os.environ.get("CHAD_ENCRYPTION_KEY", "")
        if encryption_key.lower() in insecure_defaults:
            critical_failures.append(
                "CHAD_ENCRYPTION_KEY is using insecure default in production. "
                "Set a secure key via environment variable: "
                "CHAD_ENCRYPTION_KEY=$(openssl rand -base64 32)"
            )

        if critical_failures:
            raise RuntimeError(
                "CRITICAL SECURITY CONFIGURATION ERROR:\n" + "\n".join(f"  - {msg}" for msg in critical_failures)
            )

    # Delegated suite auth guard: refuse to boot half-configured.
    validate_delegated_auth_config()

    # Begin scheduler leader election. The scheduler runs in exactly one process
    # (whichever wins the Redis leader lock) and that leader syncs jobs from
    # settings itself, so every uvicorn worker no longer runs a duplicate
    # scheduler firing the interval jobs.
    logger.info("Starting scheduler leader election")
    scheduler_service.start()

    # Start WebSocket pub/sub subscriber for cross-worker broadcasts
    # Only start in full deployment mode (not pull-only)
    if not settings.is_pull_only:
        logger.info("Starting WebSocket pub/sub subscriber")
        try:
            await websocket_manager.start_subscriber()
        except Exception as e:
            logger.warning("Failed to start WebSocket subscriber: %s", e)
    else:
        logger.info("Pull-only mode: skipping WebSocket pub/sub subscriber (no Redis)")

    yield

    # Shutdown
    if not settings.is_pull_only:
        logger.info("Stopping WebSocket pub/sub subscriber")
        await websocket_manager.stop_subscriber()

        # Close Redis connection
        logger.info("Closing Redis connection")
        await close_redis()
    else:
        logger.info("Pull-only mode: no Redis connections to close")

    logger.info("Stopping scheduler service")
    scheduler_service.stop()


app = FastAPI(
    title=settings.APP_NAME,
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
    # Disable automatic trailing slash redirects to avoid hostname issues in proxied environments
    redirect_slashes=False,
)

# Register custom exception handler for standardized error responses
app.add_exception_handler(HTTPError, http_error_handler)


# SCIM auth failures carry a pre-built SCIM-shaped JSONResponse out of the
# dependency; surface it verbatim (preserves application/scim+json + status).
from app.api.scim import _ScimAuthError  # noqa: E402


@app.exception_handler(_ScimAuthError)
async def _scim_auth_error_handler(request: Request, exc: _ScimAuthError):
    return exc.response

# Request ID middleware (add first for request tracking)
@app.middleware("http")
async def add_request_id(request: Request, call_next):
    """Add unique request ID for tracking and debugging."""
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    request.state.request_id = request_id

    # Bind request_id to structlog context if available
    try:
        import structlog
        # Bind request_id to all log entries during this request
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)
    except ImportError:
        pass  # structlog not available, skip

    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id

    # Clear contextvars after request
    try:
        structlog.contextvars.clear_contextvars()
    except Exception:
        pass

    return response

# Session middleware (required for OAuth state)
# SameSite=lax is required for OAuth to work (callback from identity provider)
# CSRF protection is still provided by the CSRF middleware
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SESSION_SECRET_KEY,  # Separate from JWT secret for key separation
    same_site="lax",  # Required for OAuth redirects (cross-origin callbacks)
    https_only=not settings.DEBUG,  # Enforce HTTPS in production
    max_age=3600,  # 1 hour session
)

# CSRF Protection Middleware (defense-in-depth)
# Provides CSRF protection on top of JWT authentication
app.add_middleware(CSRFMiddleware)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://frontend:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-CSRF-Token"],  # Expose CSRF token to JavaScript
)


# Production security middleware
if not settings.DEBUG:
    # Prevent host header attacks (configure allowed hosts via env var)
    allowed_hosts = os.environ.get("ALLOWED_HOSTS", "")
    if allowed_hosts:
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=[h.strip() for h in allowed_hosts.split(",")]
        )

    # NOTE: HTTPSRedirectMiddleware is disabled when behind reverse proxy
    # The reverse proxy (nginx) handles HTTPS termination
    # Only enable if FastAPI is directly exposed to the internet
    # app.add_middleware(HTTPSRedirectMiddleware)


# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add OWASP-recommended security headers to all responses."""
    response = await call_next(request)

    # Prevent MIME type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"

    # Prevent clickjacking
    response.headers["X-Frame-Options"] = "DENY"

    # Enable browser XSS filter (not needed in modern browsers but defense-in-depth)
    response.headers["X-XSS-Protection"] = "1; mode=block"

    # Referrer policy for privacy
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Permissions-Policy (formerly Feature-Policy)
    # Control which browser features can be used
    response.headers["Permissions-Policy"] = (
        "geolocation=(), "
        "microphone=(), "
        "camera=(), "
        "payment=(), "
        "usb=(), "
        "magnetometer=(), "
        "gyroscope=(), "
        "accelerometer=()"
    )

    # Cross-Origin-Opener-Policy
    # Isolate browsing contexts and prevent window.opener access
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"

    # Cross-Origin-Resource-Policy
    # Prevent other origins from reading resources
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

    # Cross-Origin-Embedder-Policy
    # Require CORP headers for cross-origin resources
    # Note: Set to 'credentialless' instead of 'require-corp' to allow third-party scripts
    # This is more compatible while still providing security benefits
    response.headers["Cross-Origin-Embedder-Policy"] = "credentialless"

    # Only enable HSTS in production with HTTPS
    if not settings.DEBUG:
        # Enforce HTTPS for 1 year including subdomains
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    # Content Security Policy (tightened)
    # Removed 'unsafe-inline' from script-src - Vite bundles all scripts externally
    # Keep 'unsafe-eval' for now - some libraries use Function() constructor
    # Keep 'unsafe-inline' in style-src - Radix UI uses inline styles for dynamic values
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )

    return response


# Request validation middleware
app.add_middleware(
    RequestValidationMiddleware,
    max_request_size=50 * 1024 * 1024,  # 50 MB - for high-volume, tune shipper batch settings instead
    enforce_content_type=True,
)


# Error response middleware (add last to catch all errors)
app.add_middleware(ErrorResponseMiddleware)


# Org tenancy scope middleware (outermost): resolve Host -> org into the
# request-scoped contextvar so query sites can enforce tenant isolation.
app.add_middleware(OrgScopeMiddleware)


@app.get("/health")
async def health_check(db: AsyncSession = Depends(get_db)):
    """Health check endpoint for container orchestration.

    Returns 200 if all critical services are healthy, 503 otherwise.
    Checks database connectivity and returns appropriate status codes.
    """
    from sqlalchemy import text

    checks = {
        "status": "healthy",
        "database": False,
        "opensearch": False,
    }

    # Check database connectivity
    try:
        await db.execute(text("SELECT 1"))
        checks["database"] = True
    except Exception as e:
        logger.error("Database health check failed: %s", e)
        checks["status"] = "unhealthy"

    # Check OpenSearch if configured (optional - don't fail health if not configured)
    try:
        from app.services.settings import get_setting
        opensearch_setting = await get_setting(db, "opensearch")
        if opensearch_setting:
            # OpenSearch is configured, check connectivity
            from app.services.opensearch import get_client_from_settings
            client = await get_client_from_settings(db)
            if client is not None and client.ping():
                checks["opensearch"] = True
    except Exception as e:
        logger.warning("OpenSearch health check failed: %s", e)
        # Don't fail the health check for OpenSearch issues (it's optional)
        checks["opensearch"] = False

    # Determine overall status
    # Database is critical - must be healthy
    status_code = 200 if checks["database"] else 503

    return JSONResponse(content=checks, status_code=status_code)


# Include routers with /api prefix
app.include_router(auth_router, prefix="/api")
app.include_router(rules_router, prefix="/api")
app.include_router(index_patterns_router, prefix="/api")
app.include_router(settings_router, prefix="/api")
app.include_router(circuit_breakers_router, prefix="/api")
app.include_router(alerts_router, prefix="/api")
app.include_router(logs_router, prefix="/api")
app.include_router(mode_router, prefix="/api")
app.include_router(stats_router, prefix="/api")
app.include_router(system_logs_router, prefix="/api")
app.include_router(users_router, prefix="/api")
app.include_router(api_keys_router, prefix="/api")
app.include_router(audit_router, prefix="/api")
app.include_router(external_router, prefix="/api")
app.include_router(permissions_router, prefix="/api")
app.include_router(sigmahq_router, prefix="/api")
app.include_router(export_router, prefix="/api")
app.include_router(field_mappings_router, prefix="/api")
app.include_router(health_router, prefix="/api")
app.include_router(attack_router, prefix="/api")
app.include_router(webhooks_router, prefix="/api")
app.include_router(enrichment_webhooks_router, prefix="/api")
app.include_router(queue_router, prefix="/api")
app.include_router(metrics_router, prefix="/api")
app.include_router(notifications_router, prefix="/api")
app.include_router(jira_router, prefix="/api")
app.include_router(ti_router, prefix="/api")
app.include_router(misp_router, prefix="/api")
app.include_router(misp_feedback_router, prefix="/api")
app.include_router(misp_sync_router, prefix="/api")
app.include_router(correlation_rules_router, prefix="/api")
app.include_router(reports_router, prefix="/api")
app.include_router(teams_router, prefix="/api")
app.include_router(saved_views_router, prefix="/api")
app.include_router(sla_router, prefix="/api")
app.include_router(cases_router, prefix="/api")
app.include_router(audit_settings_router, prefix="/api")
app.include_router(ai_copilot_router, prefix="/api")
app.include_router(rule_ci_router, prefix="/api")
app.include_router(organizations_router, prefix="/api")
app.include_router(report_schedules_router, prefix="/api")
app.include_router(git_import_router, prefix="/api")
app.include_router(environments_router, prefix="/api")
app.include_router(deployment_requests_router, prefix="/api")
app.include_router(sso_router, prefix="/api")
app.include_router(scim_router, prefix="/api")

# WebSocket router (no /api prefix - WebSocket has its own protocol)
app.include_router(websocket_router)
