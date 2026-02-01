"""Mode API endpoint - exposes deployment mode to frontend."""

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/mode", tags=["mode"])


def get_settings():
    """Get application settings (for easier mocking in tests)."""
    from app.core.config import settings
    return settings


class ModeResponse(BaseModel):
    mode: str  # 'push' or 'pull'
    is_pull_only: bool  # True if CHAD_MODE=pull
    supports_push: bool  # True in full deployment
    supports_pull: bool  # Always True


@router.get("", response_model=ModeResponse)
async def get_mode() -> ModeResponse:
    """Get the current deployment mode and capabilities."""
    settings = get_settings()
    return ModeResponse(
        mode=settings.CHAD_MODE,
        is_pull_only=settings.is_pull_only,
        supports_push=not settings.is_pull_only,
        supports_pull=True,
    )
