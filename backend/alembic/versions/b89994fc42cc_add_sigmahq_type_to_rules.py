"""add sigmahq_type to rules

Revision ID: b89994fc42cc
Revises: f90c3db7c92b
Create Date: 2026-01-23 20:59:22.639626

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'b89994fc42cc'
down_revision: str | None = 'f90c3db7c92b'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('rules', sa.Column('sigmahq_type', sa.String(length=50), nullable=True))


def downgrade() -> None:
    op.drop_column('rules', 'sigmahq_type')
