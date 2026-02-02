"""add correlation rule comments

Revision ID: 03ae51f937b5
Revises: 02fd40e826a4
Create Date: 2026-01-28 16:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '03ae51f937b5'
down_revision: str | None = '02fd40e826a4'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('correlation_rule_comments',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('correlation_rule_id', sa.UUID(), nullable=False),
        sa.Column('user_id', sa.UUID(), nullable=True),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['correlation_rule_id'], ['correlation_rules.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    op.drop_table('correlation_rule_comments')
