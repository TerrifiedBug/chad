from enum import Enum

from sqlalchemy import Boolean, Integer, String
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import ENUM as SAEnum

from app.db.base import Base, TimestampMixin, UUIDMixin


class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class AuthMethod(str, Enum):
    LOCAL = "local"
    SSO = "sso"
    BOTH = "both"


class User(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    role: Mapped[UserRole] = mapped_column(SAEnum(UserRole, name="userrole", create_type=False), default=UserRole.VIEWER)
    is_active: Mapped[bool] = mapped_column(default=True)
    auth_method: Mapped[AuthMethod] = mapped_column(SAEnum(AuthMethod, name="authmethodenum", create_type=False), default=AuthMethod.LOCAL, nullable=False)
    must_change_password: Mapped[bool] = mapped_column(default=False)

    # 2FA fields
    totp_secret: Mapped[str | None] = mapped_column(String(32), nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    totp_backup_codes: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)

    # Token version for invalidating all tokens on password change
    token_version: Mapped[int] = mapped_column(default=0, nullable=False)
