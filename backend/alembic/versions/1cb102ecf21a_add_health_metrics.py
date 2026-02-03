"""add_health_metrics

Revision ID: 1cb102ecf21a
Revises: cb0624d33784
Create Date: 2026-01-23 14:30:50.737690

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '1cb102ecf21a'
down_revision: str | None = 'cb0624d33784'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('index_health_metrics',
    sa.Column('index_pattern_id', sa.UUID(), nullable=False),
    sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('logs_received', sa.Integer(), nullable=False),
    sa.Column('logs_processed', sa.Integer(), nullable=False),
    sa.Column('logs_errored', sa.Integer(), nullable=False),
    sa.Column('queue_depth', sa.Integer(), nullable=False),
    sa.Column('avg_latency_ms', sa.Integer(), nullable=False),
    sa.Column('alerts_generated', sa.Integer(), nullable=False),
    sa.Column('rules_triggered', sa.Integer(), nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.ForeignKeyConstraint(['index_pattern_id'], ['index_patterns.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_health_metrics_pattern_time', 'index_health_metrics', ['index_pattern_id', 'timestamp'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_health_metrics_pattern_time', table_name='index_health_metrics')
    op.drop_table('index_health_metrics')
