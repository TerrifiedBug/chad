"""add_health_alert_suppressions

Revision ID: b1c2d3e4f5a6
Revises: a3b4c5d6e7f8
Create Date: 2026-01-28 14:15:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID


# revision identifiers, used by Alembic.
revision: str = 'b1c2d3e4f5a6'
down_revision: Union[str, None] = 'a3b4c5d6e7f8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'health_alert_suppressions',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('index_pattern_id', UUID(as_uuid=True), sa.ForeignKey('index_patterns.id', ondelete='CASCADE'), nullable=False),
        sa.Column('alert_type', sa.String(50), nullable=False),
        sa.Column('last_alert_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('suppression_level', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )

    # Unique constraint on (index_pattern_id, alert_type)
    op.create_unique_constraint(
        'uq_health_suppression',
        'health_alert_suppressions',
        ['index_pattern_id', 'alert_type']
    )

    # Index for faster lookups by index_pattern_id
    op.create_index(
        'ix_health_alert_suppressions_index_pattern_id',
        'health_alert_suppressions',
        ['index_pattern_id']
    )


def downgrade() -> None:
    op.drop_index('ix_health_alert_suppressions_index_pattern_id', table_name='health_alert_suppressions')
    op.drop_constraint('uq_health_suppression', 'health_alert_suppressions', type_='unique')
    op.drop_table('health_alert_suppressions')
