"""add report schedules (scheduled reporting + compliance)

Revision ID: 20260614i
Revises: 20260614h
Create Date: 2026-06-15 09:40:00.000000

Additive. Adds report_schedules backing recurring detection/compliance reports.
No data migration — schedules are opt-in.
"""
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = '20260614i'
down_revision: str | None = '20260614h'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'report_schedules',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=200), nullable=False),
        sa.Column('report_type', sa.String(length=32), nullable=False, server_default='coverage'),
        sa.Column('cadence', sa.String(length=16), nullable=False, server_default='weekly'),
        sa.Column('framework', sa.String(length=32), nullable=True),
        sa.Column('delivery_type', sa.String(length=16), nullable=False, server_default='webhook'),
        sa.Column('delivery_target', sa.Text(), nullable=True),
        sa.Column('delivery_header_name', sa.String(length=128), nullable=True),
        sa.Column('delivery_header_value', sa.Text(), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('last_run_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('next_run_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('team_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    )
    op.create_index('ix_report_schedules_next_run_at', 'report_schedules', ['next_run_at'])
    op.create_index('ix_report_schedules_organization_id', 'report_schedules', ['organization_id'])


def downgrade() -> None:
    op.drop_index('ix_report_schedules_organization_id', table_name='report_schedules')
    op.drop_index('ix_report_schedules_next_run_at', table_name='report_schedules')
    op.drop_table('report_schedules')
