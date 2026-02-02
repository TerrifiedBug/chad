"""
System log service for operational error/warning tracking.

Usage:
    from app.services.system_log import system_log_service, LogCategory

    await system_log_service.log_error(
        db,
        category=LogCategory.PULL_MODE,
        service="pull_detector",
        message="Pull query failed for index pattern: windows-security",
        details={"index_pattern_id": "...", "error": "..."}
    )
"""

import logging
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.system_log import SystemLog
from app.services.websocket import manager as websocket_manager

logger = logging.getLogger(__name__)


class LogCategory(str, Enum):
    OPENSEARCH = "opensearch"
    ALERTS = "alerts"
    PULL_MODE = "pull_mode"
    INTEGRATIONS = "integrations"
    BACKGROUND = "background"


class LogLevel(str, Enum):
    ERROR = "ERROR"
    WARNING = "WARNING"


class SystemLogService:
    """Service for logging operational errors and warnings."""

    async def log_error(
        self,
        db: AsyncSession,
        category: LogCategory,
        service: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> SystemLog:
        """Log an error and broadcast via WebSocket."""
        return await self._create_log(
            db=db,
            level=LogLevel.ERROR,
            category=category,
            service=service,
            message=message,
            details=details or {},
        )

    async def log_warning(
        self,
        db: AsyncSession,
        category: LogCategory,
        service: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> SystemLog:
        """Log a warning and broadcast via WebSocket."""
        return await self._create_log(
            db=db,
            level=LogLevel.WARNING,
            category=category,
            service=service,
            message=message,
            details=details or {},
        )

    async def _create_log(
        self,
        db: AsyncSession,
        level: LogLevel,
        category: LogCategory,
        service: str,
        message: str,
        details: dict,
    ) -> SystemLog:
        """Create log entry and broadcast to WebSocket clients."""
        log = SystemLog(
            level=level.value,
            category=category.value,
            service=service,
            message=message,
            details=details if details else None,
        )
        db.add(log)
        await db.flush()

        # Broadcast to connected clients for Live Tail
        try:
            await websocket_manager.broadcast_to_all_local({
                "type": "system_log",
                "data": {
                    "id": str(log.id),
                    "timestamp": log.timestamp.isoformat(),
                    "level": log.level,
                    "category": log.category,
                    "service": log.service,
                    "message": log.message,
                    "details": log.details,
                },
            })
        except Exception as e:
            logger.warning(f"Failed to broadcast system log: {e}")

        return log

    async def query_logs(
        self,
        db: AsyncSession,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        levels: list[str] | None = None,
        categories: list[str] | None = None,
        search: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[SystemLog], int]:
        """Query system logs with filters."""
        query = select(SystemLog)

        # Apply filters
        if start_time:
            query = query.where(SystemLog.timestamp >= start_time)
        if end_time:
            query = query.where(SystemLog.timestamp <= end_time)
        if levels:
            query = query.where(SystemLog.level.in_(levels))
        if categories:
            query = query.where(SystemLog.category.in_(categories))
        if search:
            query = query.where(SystemLog.message.ilike(f"%{search}%"))

        # Get total count
        count_query = select(func.count()).select_from(query.subquery())
        total_result = await db.execute(count_query)
        total = total_result.scalar() or 0

        # Get paginated results
        query = query.order_by(SystemLog.timestamp.desc()).offset(offset).limit(limit)
        result = await db.execute(query)
        logs = list(result.scalars().all())

        return logs, total

    async def get_stats(self, db: AsyncSession) -> dict:
        """Get statistics for last 24 hours."""
        cutoff = datetime.now(UTC) - timedelta(hours=24)

        # Single grouped query for all stats
        result = await db.execute(
            select(
                SystemLog.level,
                SystemLog.category,
                func.count().label("count")
            )
            .where(SystemLog.timestamp >= cutoff)
            .group_by(SystemLog.level, SystemLog.category)
        )
        rows = result.all()

        # Initialize counters
        errors_24h = 0
        warnings_24h = 0
        by_category = {cat.value: {"errors": 0, "warnings": 0} for cat in LogCategory}

        # Process results
        for level, category, count in rows:
            if level == "ERROR":
                errors_24h += count
                if category in by_category:
                    by_category[category]["errors"] = count
            elif level == "WARNING":
                warnings_24h += count
                if category in by_category:
                    by_category[category]["warnings"] = count

        return {
            "errors_24h": errors_24h,
            "warnings_24h": warnings_24h,
            "by_category": by_category,
        }

    async def purge_old_logs(self, db: AsyncSession, retention_days: int = 14) -> int:
        """Purge logs older than retention period."""
        cutoff = datetime.now(UTC) - timedelta(days=retention_days)
        result = await db.execute(
            delete(SystemLog).where(SystemLog.timestamp < cutoff)
        )
        await db.commit()
        return result.rowcount


# Global service instance
system_log_service = SystemLogService()
