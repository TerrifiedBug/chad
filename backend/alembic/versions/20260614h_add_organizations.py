"""add organizations (multi-tenant foundation) + backfill default org

Revision ID: 20260614h
Revises: 20260614g
Create Date: 2026-06-15 09:20:00.000000

Additive + back-compatible. Creates the organizations table, seeds the single
default org, and adds a nullable ``organization_id`` to the core tenant tables
(users, teams, rules, index_patterns), backfilling every existing row to the
default org. OSS / single-tenant installs keep working unchanged; multi-tenant
deployments create additional Organization rows on signup.
"""
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = '20260614h'
down_revision: str | None = '20260614g'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

DEFAULT_ORG_ID = '00000000-0000-0000-0000-000000000001'
_TENANT_TABLES = ('users', 'teams', 'rules', 'index_patterns')


def upgrade() -> None:
    op.create_table(
        'organizations',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('slug', sa.String(length=63), nullable=False),
        sa.Column('plan', sa.String(length=50), nullable=False, server_default='standard'),
        sa.Column('suspended_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('slug', name='uq_organizations_slug'),
    )
    op.create_index('ix_organizations_slug', 'organizations', ['slug'])

    # Seed the single default org. Cast the bound id to uuid (asyncpg infers
    # VARCHAR for a Python str bind, which the uuid column rejects).
    op.execute(
        sa.text(
            "INSERT INTO organizations (id, name, slug, plan, created_at, updated_at) "
            "VALUES (CAST(:id AS uuid), 'Default', 'default', 'standard', now(), now())"
        ).bindparams(id=DEFAULT_ORG_ID)
    )

    # Add nullable organization_id to each tenant table + FK + index, backfill.
    for table in _TENANT_TABLES:
        op.add_column(table, sa.Column('organization_id', postgresql.UUID(as_uuid=True), nullable=True))
        op.create_foreign_key(
            f'fk_{table}_organization_id', table, 'organizations',
            ['organization_id'], ['id'], ondelete='CASCADE',
        )
        op.create_index(f'ix_{table}_organization_id', table, ['organization_id'])
        op.execute(
            sa.text(f"UPDATE {table} SET organization_id = CAST(:org AS uuid)").bindparams(
                org=DEFAULT_ORG_ID
            )
        )


def downgrade() -> None:
    for table in reversed(_TENANT_TABLES):
        op.drop_index(f'ix_{table}_organization_id', table_name=table)
        op.drop_constraint(f'fk_{table}_organization_id', table, type_='foreignkey')
        op.drop_column(table, 'organization_id')
    op.drop_index('ix_organizations_slug', table_name='organizations')
    op.drop_table('organizations')
