"""add_alert_comments

Revision ID: f42b74859833
Revises: 08jq_add_rule_title_unique
Create Date: 2026-01-30 00:54:32.705231

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'f42b74859833'
down_revision: str | None = '08jq_add_rule_title_unique'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create alert_comments table."""
    op.create_table('alert_comments',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('alert_id', sa.String(length=64), nullable=False),
        sa.Column('user_id', sa.UUID(), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('deleted_by_id', sa.UUID(), nullable=True),
        sa.ForeignKeyConstraint(['deleted_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_alert_comments_alert_id'), 'alert_comments', ['alert_id'], unique=False)


def downgrade() -> None:
    """Drop alert_comments table."""
    op.drop_index(op.f('ix_alert_comments_alert_id'), table_name='alert_comments')
    op.drop_table('alert_comments')
