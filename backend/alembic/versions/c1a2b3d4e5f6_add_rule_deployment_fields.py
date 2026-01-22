"""Add rule deployment fields

Revision ID: c1a2b3d4e5f6
Revises: b4fc14b9ef95
Create Date: 2026-01-21 15:54:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c1a2b3d4e5f6'
down_revision: Union[str, None] = 'b4fc14b9ef95'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('rules', sa.Column('deployed_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('rules', sa.Column('deployed_version', sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column('rules', 'deployed_version')
    op.drop_column('rules', 'deployed_at')
