"""
Role permissions configuration.

Stores customizable permissions for each role (admin, analyst, viewer).
"""

from sqlalchemy import String, Boolean
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class RolePermission(Base):
    """Configurable permission for a role."""

    __tablename__ = "role_permissions"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    role: Mapped[str] = mapped_column(String(50), index=True)  # admin, analyst, viewer
    permission: Mapped[str] = mapped_column(String(100))  # permission name
    granted: Mapped[bool] = mapped_column(Boolean, default=False)


# Default permissions by role
DEFAULT_ROLE_PERMISSIONS = {
    "admin": {
        "manage_users": True,
        "manage_rules": True,
        "deploy_rules": True,
        "manage_settings": True,
        "manage_api_keys": True,
        "view_audit": True,
        "manage_sigmahq": True,
    },
    "analyst": {
        "manage_users": False,
        "manage_rules": True,
        "deploy_rules": True,
        "manage_settings": False,
        "manage_api_keys": True,
        "view_audit": True,
        "manage_sigmahq": True,
    },
    "viewer": {
        "manage_users": False,
        "manage_rules": False,
        "deploy_rules": False,
        "manage_settings": False,
        "manage_api_keys": False,
        "view_audit": False,
        "manage_sigmahq": False,
    },
}

PERMISSION_DESCRIPTIONS = {
    "manage_users": "Create, edit, and delete users",
    "manage_rules": "Create, edit, and delete detection rules",
    "deploy_rules": "Deploy and undeploy rules to OpenSearch",
    "manage_settings": "Modify system settings and webhooks",
    "manage_api_keys": "Create and revoke API keys",
    "view_audit": "Access the audit log viewer",
    "manage_sigmahq": "Sync and import SigmaHQ rules",
}
