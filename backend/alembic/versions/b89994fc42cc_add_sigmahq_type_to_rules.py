"""add sigmahq_type to rules

Revision ID: b89994fc42cc
Revises: f90c3db7c92b
Create Date: 2026-01-23 20:59:22.639626

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b89994fc42cc'
down_revision: Union[str, None] = 'f90c3db7c92b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('rules', sa.Column('sigmahq_type', sa.String(length=50), nullable=True))


def downgrade() -> None:
    op.drop_column('rules', 'sigmahq_type')
