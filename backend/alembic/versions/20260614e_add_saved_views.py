"""add saved views (filter presets)

Revision ID: 20260614e
Revises: 20260614d
Create Date: 2026-06-14 22:00:00.000000

Additive. Adds the saved_views table backing named, reusable list filter
presets (alerts/rules/etc). Owner-scoped with optional team sharing. No data
migration — saved views are opt-in and created by users.
"""
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '20260614e'
down_revision: str | None = '20260614d'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'saved_views',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=120), nullable=False),
        sa.Column('resource', sa.String(length=32), nullable=False),
        sa.Column('owner_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('team_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('is_shared', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('is_default', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('filters', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ondelete='SET NULL'),
        sa.UniqueConstraint('owner_id', 'resource', 'name', name='uq_saved_view_owner_resource_name'),
    )
    op.create_index('ix_saved_views_owner_id', 'saved_views', ['owner_id'])
    op.create_index('ix_saved_views_resource', 'saved_views', ['resource'])


def downgrade() -> None:
    op.drop_index('ix_saved_views_resource', table_name='saved_views')
    op.drop_index('ix_saved_views_owner_id', table_name='saved_views')
    op.drop_table('saved_views')
