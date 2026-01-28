"""add correlation rule version history

Revision ID: 01ec39d715f3
Revises: b1c2d3e4f5a6
Create Date: 2026-01-28 15:12:38.934272

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '01ec39d715f3'
down_revision: Union[str, None] = 'b1c2d3e4f5a6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create correlation_rule_versions table
    op.create_table('correlation_rule_versions',
        sa.Column('correlation_rule_id', sa.UUID(), nullable=False),
        sa.Column('version_number', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('rule_a_id', sa.UUID(), nullable=False),
        sa.Column('rule_b_id', sa.UUID(), nullable=False),
        sa.Column('entity_field', sa.String(length=100), nullable=False),
        sa.Column('time_window_minutes', sa.Integer(), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('changed_by', sa.UUID(), nullable=False),
        sa.Column('change_reason', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('id', sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(['changed_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['correlation_rule_id'], ['correlation_rules.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    # Add deployment tracking columns to correlation_rules
    op.add_column('correlation_rules', sa.Column('deployed_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('correlation_rules', sa.Column('deployed_version', sa.Integer(), nullable=True))
    op.add_column('correlation_rules', sa.Column('current_version', sa.Integer(), server_default='1', nullable=False))


def downgrade() -> None:
    op.drop_column('correlation_rules', 'current_version')
    op.drop_column('correlation_rules', 'deployed_version')
    op.drop_column('correlation_rules', 'deployed_at')
    op.drop_table('correlation_rule_versions')
