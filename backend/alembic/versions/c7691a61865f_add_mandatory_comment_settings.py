"""add_mandatory_comment_settings

Revision ID: c7691a61865f
Revises: 267127dc6c59
Create Date: 2026-01-25 16:24:23.783102

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'c7691a61865f'
down_revision: str | None = '267127dc6c59'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Create notification_settings table
    op.create_table(
        'notification_settings',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('mandatory_rule_comments', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('mandatory_comments_deployed_only', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    # Insert default row (singleton pattern)
    op.execute(
        "INSERT INTO notification_settings (mandatory_rule_comments, mandatory_comments_deployed_only) "
        "VALUES (true, false)"
    )


def downgrade() -> None:
    op.drop_table('notification_settings')
