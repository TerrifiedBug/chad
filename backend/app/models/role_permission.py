"""
Role permissions configuration.

Stores customizable permissions for each role (admin, analyst, viewer).
"""

from sqlalchemy import String, Boolean, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class RolePermission(Base):
    """Configurable permission for a role."""

    __tablename__ = "role_permissions"
    __table_args__ = (
        UniqueConstraint("role", "permission", name="uq_role_permission"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    role: Mapped[str] = mapped_column(String(50), index=True)  # admin, analyst, viewer
    permission: Mapped[str] = mapped_column(String(100))  # permission name
    granted: Mapped[bool] = mapped_column(Boolean, default=False)


# Default permissions by role
DEFAULT_ROLE_PERMISSIONS = {
    "admin": {
        "manage_users": True,
        "manage_rules": True,
        "manage_alerts": True,
        "deploy_rules": True,
        "manage_settings": True,
        "manage_api_keys": True,
        "view_audit": True,
        "manage_sigmahq": True,
        "manage_correlation": True,
    },
    "analyst": {
        "manage_users": False,
        "manage_rules": True,
        "manage_alerts": True,
        "deploy_rules": True,
        "manage_settings": False,
        "manage_api_keys": True,
        "view_audit": True,
        "manage_sigmahq": True,
        "manage_correlation": True,
    },
    "viewer": {
        "manage_users": False,
        "manage_rules": False,
        "manage_alerts": False,
        "deploy_rules": False,
        "manage_settings": False,
        "manage_api_keys": False,
        "view_audit": False,
        "manage_sigmahq": False,
        "manage_correlation": False,
    },
}

PERMISSION_DESCRIPTIONS = {
    "manage_users": "Create, edit, and delete users",
    "manage_rules": "Create, edit, and delete detection rules",
    "manage_alerts": "Delete alerts and update alert status",
    "deploy_rules": "Deploy and undeploy rules to OpenSearch",
    "manage_settings": "Modify system settings and webhooks",
    "manage_api_keys": "Create and revoke API keys",
    "view_audit": "Access the audit log viewer",
    "manage_sigmahq": "Sync and import SigmaHQ rules",
    "manage_correlation": "Create, edit, and delete correlation rules",
}
