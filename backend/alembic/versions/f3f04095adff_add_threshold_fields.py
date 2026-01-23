"""add_threshold_fields

Revision ID: f3f04095adff
Revises: 64e87de2efe2
Create Date: 2026-01-23 14:03:12.045247

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f3f04095adff'
down_revision: Union[str, None] = '64e87de2efe2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add threshold alerting fields to rules table
    op.add_column('rules', sa.Column('threshold_enabled', sa.Boolean(), server_default='false', nullable=False))
    op.add_column('rules', sa.Column('threshold_count', sa.Integer(), nullable=True))
    op.add_column('rules', sa.Column('threshold_window_minutes', sa.Integer(), nullable=True))
    op.add_column('rules', sa.Column('threshold_group_by', sa.String(length=255), nullable=True))


def downgrade() -> None:
    op.drop_column('rules', 'threshold_group_by')
    op.drop_column('rules', 'threshold_window_minutes')
    op.drop_column('rules', 'threshold_count')
    op.drop_column('rules', 'threshold_enabled')
