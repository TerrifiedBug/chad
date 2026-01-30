"""add_entity_field_type_to_correlation_rules

Revision ID: 09kr_add_entity_field_type
Revises: f42b74859833
Create Date: 2026-01-30 11:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '09kr_add_entity_field_type'
down_revision: Union[str, None] = 'f42b74859833'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add entity_field_type to correlation_rules table
    # Default to "sigma" for backward compatibility with existing rules
    op.add_column(
        'correlation_rules',
        sa.Column('entity_field_type', sa.String(10), nullable=False, server_default='sigma')
    )

    # Add entity_field_type to correlation_rule_versions table for versioning
    op.add_column(
        'correlation_rule_versions',
        sa.Column('entity_field_type', sa.String(10), nullable=False, server_default='sigma')
    )


def downgrade() -> None:
    op.drop_column('correlation_rule_versions', 'entity_field_type')
    op.drop_column('correlation_rules', 'entity_field_type')
