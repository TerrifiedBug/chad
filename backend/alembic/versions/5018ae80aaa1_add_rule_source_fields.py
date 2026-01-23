"""add_rule_source_fields

Revision ID: 5018ae80aaa1
Revises: 3e354bc22f9f
Create Date: 2026-01-23 10:15:06.538677

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '5018ae80aaa1'
down_revision: Union[str, None] = '3e354bc22f9f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add columns - use String type for enum compatibility
    op.add_column('rules', sa.Column('source', sa.String(50), nullable=False, server_default='user'))
    op.add_column('rules', sa.Column('sigmahq_path', sa.String(500), nullable=True))

    # Backfill: detect SigmaHQ imports from description
    op.execute("""
        UPDATE rules
        SET source = 'sigmahq',
            sigmahq_path = substring(description from 'Imported from SigmaHQ: (.+)')
        WHERE description LIKE 'Imported from SigmaHQ:%'
    """)


def downgrade() -> None:
    op.drop_column('rules', 'sigmahq_path')
    op.drop_column('rules', 'source')
