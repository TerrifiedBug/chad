"""add_threshold_matches

Revision ID: cb0624d33784
Revises: f3f04095adff
Create Date: 2026-01-23 14:06:19.495328

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'cb0624d33784'
down_revision: Union[str, None] = 'f3f04095adff'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('threshold_matches',
    sa.Column('rule_id', sa.UUID(), nullable=False),
    sa.Column('group_value', sa.String(length=500), nullable=True),
    sa.Column('log_id', sa.String(length=100), nullable=False),
    sa.Column('matched_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.ForeignKeyConstraint(['rule_id'], ['rules.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_threshold_matches_rule_group_time', 'threshold_matches', ['rule_id', 'group_value', 'matched_at'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_threshold_matches_rule_group_time', table_name='threshold_matches')
    op.drop_table('threshold_matches')
