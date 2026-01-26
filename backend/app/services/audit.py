"""
Audit logging service for tracking user actions.

Usage:
    from app.services.audit import audit_log
    await audit_log(db, user_id, "rule.create", "rule", rule.id, {"title": rule.title})
"""
import logging
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.models.setting import Setting
from app.models.user import User

logger = logging.getLogger(__name__)


async def _get_opensearch_client_for_audit(db: AsyncSession):
    """Get OpenSearch client for audit logging if configured and enabled."""
    from app.core.encryption import decrypt
    from app.services.opensearch import create_client

    # Check if audit to OpenSearch is enabled
    audit_setting = await db.execute(
        select(Setting).where(Setting.key == "audit_opensearch_enabled")
    )
    audit_enabled = audit_setting.scalar_one_or_none()
    if not audit_enabled or not audit_enabled.value.get("enabled", False):
        return None

    # Get OpenSearch config
    os_setting = await db.execute(select(Setting).where(Setting.key == "opensearch"))
    setting = os_setting.scalar_one_or_none()
    if not setting:
        return None

    config = setting.value
    password = config.get("password")
    if password:
        try:
            password = decrypt(password)
        except Exception:
            pass

    try:
        return create_client(
            host=config["host"],
            port=config["port"],
            username=config.get("username"),
            password=password,
            use_ssl=config.get("use_ssl", True),
            verify_certs=config.get("verify_certs", True),  # Default to True for security
        )
    except Exception as e:
        logger.warning(f"Failed to create OpenSearch client for audit: {e}")
        return None


async def audit_log(
    db: AsyncSession,
    user_id: UUID | None,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    details: dict[str, Any] | None = None,
    ip_address: str | None = None,
) -> AuditLog:
    """
    Create an audit log entry.

    Args:
        db: Database session
        user_id: User performing the action (None for system actions)
        action: Action type (e.g., "rule.create", "user.login")
        resource_type: Type of resource (e.g., "rule", "user", "settings")
        resource_id: ID of the affected resource
        details: Additional context

    Returns:
        Created AuditLog entry
    """
    # Get user email for denormalization
    user_email = None
    if user_id:
        user_result = await db.execute(select(User).where(User.id == user_id))
        user = user_result.scalar_one_or_none()
        if user:
            user_email = user.email

    # Build details dict with user_email (ip_address now has dedicated column)
    log_details = details.copy() if details else {}
    if user_email:
        log_details["user_email"] = user_email

    # Create PostgreSQL record
    log = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=log_details if log_details else None,
        ip_address=ip_address,
    )
    db.add(log)
    # Don't commit here - let the caller manage the transaction

    # Optionally write to OpenSearch (non-blocking)
    try:
        os_client = await _get_opensearch_client_for_audit(db)
        if os_client:
            os_client.index(
                index="chad-audit-logs",
                body={
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "user_id": str(user_id) if user_id else None,
                    "user_email": user_email,
                    "action": action,
                    "resource_type": resource_type,
                    "resource_id": resource_id,
                    "ip_address": ip_address,
                    "details": details,
                },
            )
    except Exception as e:
        # Log warning but don't fail the operation
        logger.warning(f"Failed to write audit to OpenSearch: {e}")

    return log
