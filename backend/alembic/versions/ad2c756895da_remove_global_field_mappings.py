"""remove_global_field_mappings

Revision ID: ad2c756895da
Revises: fe29c647c878
Create Date: 2026-01-27 20:53:10.039705

"""
from typing import Sequence, Union

from alembic import op



# revision identifiers, used by Alembic.
revision: str = 'ad2c756895da'
down_revision: Union[str, None] = 'fe29c647c878'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Delete any existing global mappings (safe - no production usage)
    op.execute("DELETE FROM field_mappings WHERE index_pattern_id IS NULL")

    # 2. Make index_pattern_id required (NOT NULL)
    op.alter_column(
        'field_mappings',
        'index_pattern_id',
        existing_type='UUID()',
        nullable=False
    )


def downgrade() -> None:
    # Revert to allow NULL (for rollback)
    op.alter_column(
        'field_mappings',
        'index_pattern_id',
        existing_type='UUID()',
        nullable=True
    )
