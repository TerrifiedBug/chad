from enum import Enum

import uuid

from sqlalchemy import Boolean, ForeignKey, String
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.dialects.postgresql import ENUM as SAEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.encryption import decrypt_with_fallback, encrypt
from app.db.base import Base, TimestampMixin, UUIDMixin


class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class AuthMethod(str, Enum):
    LOCAL = "local"
    SSO = "sso"


class User(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    role: Mapped[UserRole] = mapped_column(SAEnum(UserRole, name="userrole", create_type=False), default=UserRole.VIEWER)
    is_active: Mapped[bool] = mapped_column(default=True)
    auth_method: Mapped[AuthMethod] = mapped_column(SAEnum(AuthMethod, name="authmethodenum", create_type=False), default=AuthMethod.LOCAL, nullable=False)
    must_change_password: Mapped[bool] = mapped_column(default=False)

    # 2FA fields. The TOTP secret is stored encrypted at rest (Fernet); the DB
    # column stays named "totp_secret" and plaintext is read/written via the
    # ``totp_secret`` property so verification code needs no changes. Backup
    # codes are already one-way hashed, so they are left as-is.
    totp_secret_encrypted: Mapped[str | None] = mapped_column(
        "totp_secret", String(255), nullable=True
    )
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    totp_backup_codes: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)

    @property
    def totp_secret(self) -> str | None:
        """Plaintext TOTP secret (decrypted from the encrypted column)."""
        return decrypt_with_fallback(self.totp_secret_encrypted)

    @totp_secret.setter
    def totp_secret(self, value: str | None) -> None:
        self.totp_secret_encrypted = encrypt(value) if value else None

    # Token version for invalidating all tokens on password change
    token_version: Mapped[int] = mapped_column(default=0, nullable=False)

    # Team membership for resource-scoped RBAC (nullable = no team / global user)
    team_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("teams.id", ondelete="SET NULL"), nullable=True
    )

    # Browser notification preferences
    notification_preferences: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        default=None
    )
