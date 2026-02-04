"""add misp_imported_rules table

Revision ID: 030207644969
Revises: 03272c7aea4c
Create Date: 2026-02-03 17:40:59.656356

"""
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '030207644969'
down_revision: str | None = '03272c7aea4c'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('misp_imported_rules',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('rule_id', sa.UUID(), nullable=False),
    sa.Column('misp_url', sa.String(length=2048), nullable=False),
    sa.Column('misp_event_id', sa.String(length=64), nullable=False),
    sa.Column('misp_event_uuid', sa.String(length=64), nullable=True),
    sa.Column('misp_event_info', sa.Text(), nullable=True),
    sa.Column('misp_event_date', sa.DateTime(timezone=True), nullable=True),
    sa.Column('misp_event_threat_level', sa.String(length=32), nullable=True),
    sa.Column('ioc_type', sa.String(length=64), nullable=False),
    sa.Column('ioc_count', sa.Integer(), nullable=False),
    sa.Column('ioc_values', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('imported_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('last_checked_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('misp_event_updated_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['rule_id'], ['rules.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_misp_imported_rules_misp_event_id'), 'misp_imported_rules', ['misp_event_id'], unique=False)
    op.create_index(op.f('ix_misp_imported_rules_rule_id'), 'misp_imported_rules', ['rule_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_misp_imported_rules_rule_id'), table_name='misp_imported_rules')
    op.drop_index(op.f('ix_misp_imported_rules_misp_event_id'), table_name='misp_imported_rules')
    op.drop_table('misp_imported_rules')
