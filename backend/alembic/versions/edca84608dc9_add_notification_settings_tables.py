"""add notification settings tables

Revision ID: edca84608dc9
Revises: b89994fc42cc
Create Date: 2026-01-23 21:44:49.137663

"""
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'edca84608dc9'
down_revision: str | None = 'b89994fc42cc'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('webhooks',
    sa.Column('name', sa.String(length=100), nullable=False),
    sa.Column('url', sa.String(length=2048), nullable=False),
    sa.Column('auth_header', sa.String(length=500), nullable=True),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('alert_notification_settings',
    sa.Column('webhook_id', sa.UUID(), nullable=False),
    sa.Column('severities', postgresql.ARRAY(sa.String()), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.ForeignKeyConstraint(['webhook_id'], ['webhooks.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('webhook_id')
    )
    op.create_table('system_notification_settings',
    sa.Column('event_type', sa.String(length=50), nullable=False),
    sa.Column('webhook_id', sa.UUID(), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.ForeignKeyConstraint(['webhook_id'], ['webhooks.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('event_type', 'webhook_id', name='uq_system_notification_event_webhook')
    )


def downgrade() -> None:
    op.drop_table('system_notification_settings')
    op.drop_table('alert_notification_settings')
    op.drop_table('webhooks')
