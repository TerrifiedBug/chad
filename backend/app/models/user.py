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


class ProvisionedVia(str, Enum):
    """Provenance of a user account.

    Distinct from ``auth_method`` (how the user authenticates): this records who
    created/owns the account so SCIM can never deprovision a LOCAL/SSO account it
    did not provision, and the LOCAL->SSO silent-fusion vector stays closed.
    """

    LOCAL = "local"
    SSO = "sso"
    SCIM = "scim"


class TeamSource(str, Enum):
    """How a user's ``team_id`` was assigned.

    ``MANUAL`` (admin set it via the UI) is never overridden by group
    reconciliation when no IdP group matches. ``GROUP_MAPPING`` is owned by the
    SSO group-reconciliation writer and may be re-derived on every login.
    """

    MANUAL = "manual"
    GROUP_MAPPING = "group_mapping"


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

    # Tenant the user belongs to (multi-tenant / MSSP). Backfilled to the default
    # org for existing/OSS installs.
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True, index=True,
    )

    # How team_id was assigned: "manual" (admin-set, never clobbered by group
    # reconciliation) or "group_mapping" (owned by the SSO reconciliation writer).
    # Stored as a plain string (not a PG enum) to keep the migration additive and
    # avoid enum-type churn. NULL is treated as "manual" by reconciliation.
    team_source: Mapped[str | None] = mapped_column(String(16), nullable=True)

    # Account provenance: "local" | "sso" | "scim". Defaults to "local" so every
    # pre-existing row (and any account created the classic way) is LOCAL — this
    # backs the C1 fusion refusal and the SCIM coexistence guards. Stored as a
    # plain string for the same additive-migration reasons as team_source.
    provisioned_via: Mapped[str] = mapped_column(
        String(16), nullable=False, default="local", server_default="local"
    )

    # SCIM externalId (IdP-assigned stable identifier). Unique when present so a
    # SCIM client can look a user up by externalId; NULL for non-SCIM accounts.
    scim_external_id: Mapped[str | None] = mapped_column(
        String(255), unique=True, nullable=True
    )

    # Browser notification preferences
    notification_preferences: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        default=None
    )
