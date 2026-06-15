"""add case management (investigation workspace)

Revision ID: 20260614f
Revises: 20260614e
Create Date: 2026-06-15 08:30:00.000000

Additive. Adds cases + case_alerts + case_events + case_comments backing the
investigation workspace (link alerts → case, timeline, owner, SLA, comments).
"""
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '20260614f'
down_revision: str | None = '20260614e'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'cases',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('number', sa.BigInteger(), nullable=False),
        sa.Column('title', sa.String(length=300), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='open'),
        sa.Column('severity', sa.String(length=32), nullable=False, server_default='medium'),
        sa.Column('owner_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('team_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('sla_due_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('sla_breached', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('closed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('tags', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('number', name='uq_cases_number'),
        sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='SET NULL'),
    )
    op.create_index('ix_cases_number', 'cases', ['number'])
    op.create_index('ix_cases_status', 'cases', ['status'])
    op.create_index('ix_cases_owner_id', 'cases', ['owner_id'])
    op.create_index('ix_cases_team_id', 'cases', ['team_id'])

    op.create_table(
        'case_alerts',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('case_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('alert_id', sa.String(length=64), nullable=False),
        sa.Column('alert_title', sa.String(length=500), nullable=True),
        sa.Column('alert_severity', sa.String(length=32), nullable=True),
        sa.Column('added_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('added_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('case_id', 'alert_id', name='uq_case_alert'),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['added_by'], ['users.id'], ondelete='SET NULL'),
    )
    op.create_index('ix_case_alerts_case_id', 'case_alerts', ['case_id'])
    op.create_index('ix_case_alerts_alert_id', 'case_alerts', ['alert_id'])

    op.create_table(
        'case_events',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('case_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('event_type', sa.String(length=32), nullable=False),
        sa.Column('actor_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('event_metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['actor_id'], ['users.id'], ondelete='SET NULL'),
    )
    op.create_index('ix_case_events_case_id', 'case_events', ['case_id'])
    op.create_index('ix_case_events_created_at', 'case_events', ['created_at'])

    op.create_table(
        'case_comments',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('case_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    )
    op.create_index('ix_case_comments_case_id', 'case_comments', ['case_id'])


def downgrade() -> None:
    op.drop_table('case_comments')
    op.drop_index('ix_case_events_created_at', table_name='case_events')
    op.drop_index('ix_case_events_case_id', table_name='case_events')
    op.drop_table('case_events')
    op.drop_index('ix_case_alerts_alert_id', table_name='case_alerts')
    op.drop_index('ix_case_alerts_case_id', table_name='case_alerts')
    op.drop_table('case_alerts')
    op.drop_index('ix_cases_team_id', table_name='cases')
    op.drop_index('ix_cases_owner_id', table_name='cases')
    op.drop_index('ix_cases_status', table_name='cases')
    op.drop_index('ix_cases_number', table_name='cases')
    op.drop_table('cases')
