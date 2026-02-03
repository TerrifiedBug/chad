"""add_attack_tables

Revision ID: f90c3db7c92b
Revises: 4d4c9cbc520f
Create Date: 2026-01-23 17:09:59.051461

"""
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'f90c3db7c92b'
down_revision: str | None = '4d4c9cbc520f'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Create attack_techniques table
    op.create_table(
        'attack_techniques',
        sa.Column('id', sa.String(20), primary_key=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('tactic_id', sa.String(20), nullable=False),
        sa.Column('tactic_name', sa.String(100), nullable=False),
        sa.Column('parent_id', sa.String(20), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('url', sa.String(500), nullable=True),
        sa.Column('platforms', postgresql.JSONB(), nullable=True),
        sa.Column('data_sources', postgresql.JSONB(), nullable=True),
        sa.Column('is_subtechnique', sa.Boolean(), server_default='false'),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_attack_techniques_tactic_id', 'attack_techniques', ['tactic_id'])
    op.create_index('ix_attack_techniques_parent_id', 'attack_techniques', ['parent_id'])

    # Create rule_attack_mappings table
    op.create_table(
        'rule_attack_mappings',
        sa.Column('id', postgresql.UUID(), server_default=sa.text('gen_random_uuid()'), primary_key=True),
        sa.Column('rule_id', postgresql.UUID(), sa.ForeignKey('rules.id', ondelete='CASCADE'), nullable=False),
        sa.Column('technique_id', sa.String(20), sa.ForeignKey('attack_techniques.id', ondelete='CASCADE'), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_rule_attack_mappings_rule_id', 'rule_attack_mappings', ['rule_id'])
    op.create_index('ix_rule_attack_mappings_technique_id', 'rule_attack_mappings', ['technique_id'])
    op.create_unique_constraint('uq_rule_attack_mapping', 'rule_attack_mappings', ['rule_id', 'technique_id'])


def downgrade() -> None:
    op.drop_table('rule_attack_mappings')
    op.drop_table('attack_techniques')
