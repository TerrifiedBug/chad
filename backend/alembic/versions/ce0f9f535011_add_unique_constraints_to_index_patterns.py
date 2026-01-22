"""add_unique_constraints_to_index_patterns

Revision ID: ce0f9f535011
Revises: d7e9f1a2b3c4
Create Date: 2026-01-22 18:24:41.830718

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'ce0f9f535011'
down_revision: Union[str, None] = 'd7e9f1a2b3c4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add unique constraint to pattern column
    op.create_unique_constraint(
        'uq_index_patterns_pattern',
        'index_patterns',
        ['pattern']
    )
    # Add unique constraint to percolator_index column
    op.create_unique_constraint(
        'uq_index_patterns_percolator_index',
        'index_patterns',
        ['percolator_index']
    )


def downgrade() -> None:
    op.drop_constraint('uq_index_patterns_percolator_index', 'index_patterns', type_='unique')
    op.drop_constraint('uq_index_patterns_pattern', 'index_patterns', type_='unique')
