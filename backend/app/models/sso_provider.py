"""Multi-provider OIDC/SSO models.

``SSOProvider`` replaces the single legacy ``sso`` Setting key with a per-IdP
row, so CHAD can register more than one identity provider. The legacy key is
migrated into one provider row by the additive migration, so existing
single-IdP prod deployments keep working with zero admin action.

``SSOGroupMapping`` maps an IdP-asserted group value to a CHAD team + role.
Reconciliation (see ``app.services.sso_reconcile``) is the single writer of
group-sourced team membership. CHAD keeps the single ``User.team_id`` FK, so
the highest-priority matched team wins (documented single-team limitation).
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin


class SSOProvider(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "sso_providers"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # OIDC connection
    issuer_url: Mapped[str] = mapped_column(String(512), nullable=False)
    client_id: Mapped[str] = mapped_column(String(512), nullable=False)
    # Client secret is stored encrypted at rest (Fernet). The DB column holds
    # ciphertext; never return the plaintext to clients.
    client_secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    # "client_secret_post" | "client_secret_basic" | "none"
    token_auth_method: Mapped[str] = mapped_column(
        String(32), nullable=False, default="client_secret_post"
    )
    scopes: Mapped[str] = mapped_column(
        String(512), nullable=False, default="openid email profile"
    )

    # Defaults applied when no group/role claim matches
    default_role: Mapped[str] = mapped_column(String(16), nullable=False, default="viewer")
    default_team_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("teams.id", ondelete="SET NULL"), nullable=True
    )

    # Group sync (B): when enabled, the groups_claim drives team+role via
    # SSOGroupMapping rows. groups_scope is requested at the IdP.
    group_sync_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    groups_claim: Mapped[str | None] = mapped_column(String(128), nullable=True)
    groups_scope: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Legacy role-claim mapping (kept for back-compat with the single-provider flow)
    role_claim: Mapped[str | None] = mapped_column(String(128), nullable=True)
    admin_values: Mapped[str | None] = mapped_column(Text, nullable=True)
    analyst_values: Mapped[str | None] = mapped_column(Text, nullable=True)
    viewer_values: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Security: require the IdP to assert email_verified before trusting the email.
    require_email_verified: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )

    # Test-connection probe results
    last_tested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_test_success: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    group_mappings: Mapped[list["SSOGroupMapping"]] = relationship(
        "SSOGroupMapping",
        back_populates="provider",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class SSOGroupMapping(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "sso_group_mappings"

    provider_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sso_providers.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # The IdP-asserted group value to match (case-insensitive at reconcile time).
    group_value: Mapped[str] = mapped_column(String(512), nullable=False)
    team_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("teams.id", ondelete="SET NULL"), nullable=True
    )
    # Role granted when this group matches: "admin" | "analyst" | "viewer".
    role: Mapped[str] = mapped_column(String(16), nullable=False, default="viewer")

    provider: Mapped["SSOProvider"] = relationship(
        "SSOProvider", back_populates="group_mappings"
    )
