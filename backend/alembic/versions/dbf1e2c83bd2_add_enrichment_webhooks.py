"""add_enrichment_webhooks

Revision ID: dbf1e2c83bd2
Revises: e25711f6eb54
Create Date: 2026-02-04 21:45:55.594227

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'dbf1e2c83bd2'
down_revision: Union[str, None] = 'e25711f6eb54'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create enrichment_webhooks table
    op.create_table('enrichment_webhooks',
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('url', sa.String(length=2048), nullable=False),
        sa.Column('namespace', sa.String(length=64), nullable=False),
        sa.Column('method', sa.String(length=10), nullable=False),
        sa.Column('header_name', sa.String(length=255), nullable=True),
        sa.Column('header_value_encrypted', sa.Text(), nullable=True),
        sa.Column('timeout_seconds', sa.Integer(), nullable=False),
        sa.Column('max_concurrent_calls', sa.Integer(), nullable=False),
        sa.Column('cache_ttl_seconds', sa.Integer(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_enrichment_webhooks_namespace'), 'enrichment_webhooks', ['namespace'], unique=True)

    # Create junction table for index pattern to webhook configs
    op.create_table('index_pattern_enrichment_webhooks',
        sa.Column('index_pattern_id', sa.UUID(), nullable=False),
        sa.Column('enrichment_webhook_id', sa.UUID(), nullable=False),
        sa.Column('field_to_send', sa.String(length=255), nullable=False),
        sa.Column('is_enabled', sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(['enrichment_webhook_id'], ['enrichment_webhooks.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['index_pattern_id'], ['index_patterns.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('index_pattern_id', 'enrichment_webhook_id')
    )


def downgrade() -> None:
    op.drop_table('index_pattern_enrichment_webhooks')
    op.drop_index(op.f('ix_enrichment_webhooks_namespace'), table_name='enrichment_webhooks')
    op.drop_table('enrichment_webhooks')
