import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from app.api.alerts import router as alerts_router
from app.api.api_keys import router as api_keys_router
from app.api.attack import router as attack_router
from app.api.audit import router as audit_router
from app.api.auth import router as auth_router
from app.api.correlation_rules import router as correlation_rules_router
from app.api.export import router as export_router
from app.api.external import router as external_router
from app.api.field_mappings import router as field_mappings_router
from app.api.health import router as health_router
from app.api.index_patterns import router as index_patterns_router
from app.api.jira import router as jira_router
from app.api.logs import router as logs_router
from app.api.ti import router as ti_router
from app.api.notifications import router as notifications_router
from app.api.permissions import router as permissions_router
from app.api.rules import router as rules_router
from app.api.settings import router as settings_router
from app.api.sigmahq import router as sigmahq_router
from app.api.stats import router as stats_router
from app.api.users import router as users_router
from app.api.webhooks import router as webhooks_router
from app.api.websocket import router as websocket_router
from app.core.config import settings
from app.services.scheduler import scheduler_service

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application startup and shutdown."""
    # Startup
    logger.info("Starting scheduler service")
    scheduler_service.start()
    try:
        await scheduler_service.sync_jobs_from_settings()
    except Exception as e:
        logger.warning(f"Failed to sync scheduler jobs on startup: {e}")

    yield

    # Shutdown
    logger.info("Stopping scheduler service")
    scheduler_service.stop()


app = FastAPI(
    title=settings.APP_NAME,
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
    redirect_slashes=False,  # Disable automatic trailing slash redirects to avoid hostname issues in proxied environments
)

# Session middleware (required for OAuth state)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.JWT_SECRET_KEY,
    same_site="lax",  # Required for OAuth redirects
    https_only=False,  # Security handled via same_site; APP_URL is now db-configurable
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://frontend:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health_check():
    return {"status": "healthy"}


# Include routers with /api prefix
app.include_router(auth_router, prefix="/api")
app.include_router(rules_router, prefix="/api")
app.include_router(index_patterns_router, prefix="/api")
app.include_router(settings_router, prefix="/api")
app.include_router(alerts_router, prefix="/api")
app.include_router(logs_router, prefix="/api")
app.include_router(stats_router, prefix="/api")
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
app.include_router(notifications_router, prefix="/api")
app.include_router(jira_router, prefix="/api")
app.include_router(ti_router, prefix="/api")
app.include_router(correlation_rules_router, prefix="/api")

# WebSocket router (no /api prefix - WebSocket has its own protocol)
app.include_router(websocket_router)
