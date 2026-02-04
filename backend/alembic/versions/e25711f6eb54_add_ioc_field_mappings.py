"""add_ioc_field_mappings

Revision ID: e25711f6eb54
Revises: 030207644969
Create Date: 2026-02-03 20:49:07.338623

"""
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'e25711f6eb54'
down_revision: str | None = '030207644969'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        'index_patterns',
        sa.Column('ioc_detection_enabled', sa.Boolean(), nullable=False, server_default='false')
    )
    op.add_column(
        'index_patterns',
        sa.Column('ioc_field_mappings', JSONB(), nullable=True)
    )


def downgrade() -> None:
    op.drop_column('index_patterns', 'ioc_field_mappings')
    op.drop_column('index_patterns', 'ioc_detection_enabled')
