from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.auth import router as auth_router
from app.api.index_patterns import router as index_patterns_router
from app.api.rules import router as rules_router
from app.api.settings import router as settings_router
from app.core.config import settings

app = FastAPI(
    title=settings.APP_NAME,
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
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
