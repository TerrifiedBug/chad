"""add_correlation_rule_snooze

Revision ID: 04bf62g048c6
Revises: b1c2d3e4f5a6
Create Date: 2026-01-29 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '04bf62g048c6'
down_revision: Union[str, None] = '03ae51f937b5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add snooze fields to correlation_rules table
    op.add_column('correlation_rules', sa.Column('snooze_until', sa.DateTime(timezone=True), nullable=True))
    op.add_column('correlation_rules', sa.Column('snooze_indefinite', sa.Boolean(), nullable=False, server_default='false'))


def downgrade() -> None:
    op.drop_column('correlation_rules', 'snooze_indefinite')
    op.drop_column('correlation_rules', 'snooze_until')
