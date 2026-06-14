"""add environments + per-env deployment bindings (Model B)

Revision ID: 20260614c
Revises: 20260614b
Create Date: 2026-06-14 12:30:00.000000

Additive + reversible. Adds:
  - environments                  : user-created, team-owned deployment scopes
  - rule_environment_deployments  : per-(rule, environment) deployment binding
  - manage_environments RBAC      : seeded analyst=False / viewer=False overrides
                                    (admin is implicit-allow; defaults live in code)

Back-compat data migration (idempotent):
  1. Create ONE global default environment (is_default=true, name "Production",
     team_id NULL) when none exists.
  2. For every rule currently deployed (deployed_at NOT NULL), INSERT a
     rule_environment_deployments row bound to the default env, copying the
     scalar deployed_version / deployed_at / status / snooze_* across.

The scalar Rule.deployed_*/status columns are KEPT (the default-env mirror) so
existing reads/UX/live detection keep working unchanged. The default env reuses
the legacy ``chad-percolator-{pattern}`` namespace (no re-index).
"""
import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '20260614c'
down_revision: str | None = '20260614b'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

DEFAULT_ENV_NAME = "Production"


def upgrade() -> None:
    # --- environments -------------------------------------------------------
    op.create_table(
        'environments',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('is_default', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            'require_deploy_approval', sa.Boolean(), nullable=False,
            server_default=sa.false(),
        ),
        sa.Column('opensearch_index_prefix', sa.String(length=255), nullable=True),
        sa.Column('color', sa.String(length=32), nullable=True),
        sa.Column('team_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('team_id', 'name', name='uq_environments_team_name'),
        sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ondelete='SET NULL'),
    )

    # --- rule_environment_deployments --------------------------------------
    op.create_table(
        'rule_environment_deployments',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('rule_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('environment_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('deployed_version', sa.Integer(), nullable=True),
        sa.Column('deployed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='undeployed'),
        sa.Column('snooze_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('snooze_indefinite', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('rule_id', 'environment_id', name='uq_rule_environment_deployment'),
        sa.ForeignKeyConstraint(['rule_id'], ['rules.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['environment_id'], ['environments.id'], ondelete='CASCADE'),
    )
    op.create_index(
        'ix_rule_environment_deployments_environment_id',
        'rule_environment_deployments', ['environment_id'],
    )
    op.create_index(
        'ix_rule_environment_deployments_rule_id',
        'rule_environment_deployments', ['rule_id'],
    )

    # --- RBAC: seed manage_environments for non-admin roles -----------------
    # Admin is implicit-allow in code; only the analyst/viewer denials need a
    # row so a customised install still resolves the new permission. Idempotent.
    _seed_manage_environments_permission()

    # --- back-compat data migration (idempotent) ----------------------------
    _backfill_default_environment()


def _seed_manage_environments_permission() -> None:
    """Insert analyst/viewer manage_environments=false rows if missing.

    Mirrors the in-code DEFAULT_ROLE_PERMISSIONS so an existing role_permissions
    table that has customised rows still surfaces the new permission. Admin is
    always-allow in code, so no admin row is needed.
    """
    bind = op.get_bind()
    for role in ('analyst', 'viewer'):
        exists = bind.execute(
            sa.text(
                "SELECT 1 FROM role_permissions "
                "WHERE role = :role AND permission = 'manage_environments'"
            ),
            {"role": role},
        ).first()
        if exists:
            continue
        bind.execute(
            sa.text(
                "INSERT INTO role_permissions (role, permission, granted) "
                "VALUES (:role, 'manage_environments', false)"
            ),
            {"role": role},
        )


def _backfill_default_environment() -> None:
    """Create the global default env and backfill deployed rules' bindings.

    Idempotent: re-running is a no-op once the default env exists (the binding
    INSERT skips rules that already have a row for that env via NOT EXISTS).
    """
    bind = op.get_bind()

    default_id = bind.execute(
        sa.text("SELECT id FROM environments WHERE is_default = true LIMIT 1")
    ).scalar()

    if default_id is None:
        default_id = uuid.uuid4()
        bind.execute(
            sa.text(
                """
                INSERT INTO environments (
                    id, name, description, is_default, require_deploy_approval,
                    team_id, created_at, updated_at
                ) VALUES (
                    :id, :name, :description, true, false,
                    NULL, now(), now()
                )
                """
            ),
            {
                "id": str(default_id),
                "name": DEFAULT_ENV_NAME,
                "description": "Default environment (live detection).",
            },
        )

    # Backfill a binding for every currently-deployed rule (scalar columns kept).
    bind.execute(
        sa.text(
            """
            INSERT INTO rule_environment_deployments (
                id, rule_id, environment_id, deployed_version, deployed_at,
                status, snooze_until, snooze_indefinite, created_at, updated_at
            )
            SELECT
                gen_random_uuid(), r.id, :env_id, r.deployed_version, r.deployed_at,
                r.status::text, r.snooze_until, r.snooze_indefinite, now(), now()
            FROM rules r
            WHERE r.deployed_at IS NOT NULL
              AND NOT EXISTS (
                  SELECT 1 FROM rule_environment_deployments red
                  WHERE red.rule_id = r.id AND red.environment_id = :env_id
              )
            """
        ),
        {"env_id": str(default_id)},
    )


def downgrade() -> None:
    # NOTE: downgrade is LOSSY for per-env deployment bindings and any
    # non-default environments. Dropping these tables discards every
    # environment and its rule bindings. The scalar Rule.deployed_*/status
    # columns are untouched (they were never moved), so live detection state is
    # preserved. The seeded manage_environments role_permission rows are also
    # removed.
    op.get_bind().execute(
        sa.text(
            "DELETE FROM role_permissions WHERE permission = 'manage_environments'"
        )
    )
    op.drop_index(
        'ix_rule_environment_deployments_rule_id',
        table_name='rule_environment_deployments',
    )
    op.drop_index(
        'ix_rule_environment_deployments_environment_id',
        table_name='rule_environment_deployments',
    )
    op.drop_table('rule_environment_deployments')
    op.drop_table('environments')
