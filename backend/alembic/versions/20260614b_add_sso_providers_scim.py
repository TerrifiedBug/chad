"""add multi-provider OIDC (sso_providers, sso_group_mappings) + SCIM/provenance user columns

Revision ID: 20260614b
Revises: 20260614a
Create Date: 2026-06-14 11:00:00.000000

Additive + reversible. Adds:
  - sso_providers       : per-IdP OIDC config (replaces the single ``sso`` Setting key)
  - sso_group_mappings  : group_value -> team + role
  - users.provisioned_via / users.scim_external_id / users.team_source

Back-compat data migration (idempotent): if sso_providers is empty and a legacy
``sso`` Setting key exists, one provider row is inserted from it so existing
single-IdP prod deployments keep logging in with zero admin action. Existing
users default to provisioned_via='local', closing the LOCAL->SSO fusion vector.
"""
import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '20260614b'
down_revision: str | None = '20260614a'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # --- sso_providers ------------------------------------------------------
    op.create_table(
        'sso_providers',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('issuer_url', sa.String(length=512), nullable=False),
        sa.Column('client_id', sa.String(length=512), nullable=False),
        sa.Column('client_secret_encrypted', sa.Text(), nullable=True),
        sa.Column(
            'token_auth_method', sa.String(length=32), nullable=False,
            server_default='client_secret_post',
        ),
        sa.Column(
            'scopes', sa.String(length=512), nullable=False,
            server_default='openid email profile',
        ),
        sa.Column('default_role', sa.String(length=16), nullable=False, server_default='viewer'),
        sa.Column('default_team_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('group_sync_enabled', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('groups_claim', sa.String(length=128), nullable=True),
        sa.Column('groups_scope', sa.String(length=128), nullable=True),
        sa.Column('role_claim', sa.String(length=128), nullable=True),
        sa.Column('admin_values', sa.Text(), nullable=True),
        sa.Column('analyst_values', sa.Text(), nullable=True),
        sa.Column('viewer_values', sa.Text(), nullable=True),
        sa.Column('require_email_verified', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('last_tested_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_test_success', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
        sa.ForeignKeyConstraint(['default_team_id'], ['teams.id'], ondelete='SET NULL'),
    )

    # --- sso_group_mappings -------------------------------------------------
    op.create_table(
        'sso_group_mappings',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('provider_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('group_value', sa.String(length=512), nullable=False),
        sa.Column('team_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('role', sa.String(length=16), nullable=False, server_default='viewer'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['provider_id'], ['sso_providers.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ondelete='SET NULL'),
    )
    op.create_index(
        'ix_sso_group_mappings_provider_id', 'sso_group_mappings', ['provider_id']
    )

    # --- users provenance / SCIM columns ------------------------------------
    op.add_column('users', sa.Column('team_source', sa.String(length=16), nullable=True))
    op.add_column(
        'users',
        sa.Column(
            'provisioned_via', sa.String(length=16), nullable=False, server_default='local'
        ),
    )
    op.add_column('users', sa.Column('scim_external_id', sa.String(length=255), nullable=True))
    op.create_unique_constraint(
        'uq_users_scim_external_id', 'users', ['scim_external_id']
    )

    # --- back-compat data migration (idempotent) ----------------------------
    _migrate_legacy_sso_key()


def _migrate_legacy_sso_key() -> None:
    """Copy the legacy ``sso`` Setting key into one sso_providers row.

    Idempotent: only runs when sso_providers is empty AND the legacy key has a
    configured issuer/client. Secret stays encrypted (copied verbatim — it is
    already Fernet ciphertext in the legacy key). Safe to re-run.
    """
    bind = op.get_bind()

    existing = bind.execute(sa.text("SELECT COUNT(*) FROM sso_providers")).scalar()
    if existing and existing > 0:
        return

    row = bind.execute(
        sa.text("SELECT value FROM settings WHERE key = 'sso'")
    ).first()
    if not row:
        return

    cfg = row[0] or {}
    if not isinstance(cfg, dict):
        return

    issuer_url = (cfg.get("issuer_url") or "").strip()
    client_id = (cfg.get("client_id") or "").strip()
    # Nothing usable to migrate -> leave the table empty (no provider).
    if not issuer_url or not client_id:
        return

    role_mapping_enabled = bool(cfg.get("role_mapping_enabled"))

    bind.execute(
        sa.text(
            """
            INSERT INTO sso_providers (
                id, name, enabled, issuer_url, client_id, client_secret_encrypted,
                token_auth_method, scopes, default_role, group_sync_enabled,
                role_claim, admin_values, analyst_values, viewer_values,
                require_email_verified, created_at, updated_at
            ) VALUES (
                :id, :name, :enabled, :issuer_url, :client_id, :client_secret_encrypted,
                :token_auth_method, :scopes, :default_role, false,
                :role_claim, :admin_values, :analyst_values, :viewer_values,
                :require_email_verified, now(), now()
            )
            """
        ),
        {
            "id": str(uuid.uuid4()),
            "name": (cfg.get("provider_name") or "SSO")[:255],
            "enabled": bool(cfg.get("enabled", False)),
            "issuer_url": issuer_url[:512],
            "client_id": client_id[:512],
            "client_secret_encrypted": cfg.get("client_secret"),
            "token_auth_method": (cfg.get("token_auth_method") or "client_secret_post")[:32],
            "scopes": (cfg.get("scopes") or "openid email profile")[:512],
            "default_role": (cfg.get("default_role") or "viewer")[:16],
            "role_claim": (cfg.get("role_claim") if role_mapping_enabled else None),
            "admin_values": (cfg.get("admin_values") if role_mapping_enabled else None),
            "analyst_values": (cfg.get("analyst_values") if role_mapping_enabled else None),
            "viewer_values": (cfg.get("viewer_values") if role_mapping_enabled else None),
            "require_email_verified": bool(cfg.get("require_email_verified", True)),
        },
    )


def downgrade() -> None:
    # NOTE: downgrade is LOSSY for SSO configuration. Dropping sso_providers /
    # sso_group_mappings discards every configured IdP and group mapping
    # (including the back-compat row migrated from the legacy ``sso`` key) and
    # the users.provisioned_via / scim_external_id / team_source provenance. The
    # legacy ``sso`` Setting key is NOT restored on downgrade. Re-running
    # upgrade() will re-seed only the single legacy provider, if that key still
    # exists.
    op.drop_constraint('uq_users_scim_external_id', 'users', type_='unique')
    op.drop_column('users', 'scim_external_id')
    op.drop_column('users', 'provisioned_via')
    op.drop_column('users', 'team_source')
    op.drop_index('ix_sso_group_mappings_provider_id', table_name='sso_group_mappings')
    op.drop_table('sso_group_mappings')
    op.drop_table('sso_providers')
