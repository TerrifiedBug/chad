from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.health_check import HealthCheckLog
from app.models.jira_config import JiraConfig
from app.models.ti_config import TISourceConfig


class HealthCheckService:
    """Service for performing and logging health checks."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def log_health_check(
        self,
        service_type: str,
        service_name: str,
        status: str,
        error_message: str | None = None,
        response_time_ms: int | None = None
    ) -> HealthCheckLog:
        """Log a health check result."""
        log = HealthCheckLog(
            service_type=service_type,
            service_name=service_name,
            status=status,
            error_message=error_message,
            response_time_ms=response_time_ms,
            checked_at=datetime.now(UTC)
        )
        self.db.add(log)
        await self.db.commit()
        return log

    async def update_jira_health(self, status: str, error: str | None = None):
        """Update Jira config health status."""
        result = await self.db.execute(select(JiraConfig).limit(1))
        config = result.scalar_one_or_none()
        if config:
            config.last_health_check = datetime.now(UTC)
            config.last_health_status = status
            config.health_check_error = error
            await self.db.commit()

    async def update_ti_source_health(
        self,
        source_type: str,
        status: str,
        error: str | None = None
    ):
        """Update TI source health status."""
        result = await self.db.execute(
            select(TISourceConfig).where(TISourceConfig.source_type == source_type).limit(1)
        )
        config = result.scalar_one_or_none()
        if config:
            config.last_health_check = datetime.now(UTC)
            config.last_health_status = status
            config.health_check_error = error
            await self.db.commit()
