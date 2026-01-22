from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from app.api.alerts import router as alerts_router
from app.api.api_keys import router as api_keys_router
from app.api.audit import router as audit_router
from app.api.auth import router as auth_router
from app.api.external import router as external_router
from app.api.index_patterns import router as index_patterns_router
from app.api.logs import router as logs_router
from app.api.permissions import router as permissions_router
from app.api.rules import router as rules_router
from app.api.settings import router as settings_router
from app.api.sigmahq import router as sigmahq_router
from app.api.stats import router as stats_router
from app.api.users import router as users_router
from app.core.config import settings

app = FastAPI(
    title=settings.APP_NAME,
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
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
