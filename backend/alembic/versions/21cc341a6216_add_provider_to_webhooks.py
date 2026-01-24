"""add provider to webhooks

Revision ID: 21cc341a6216
Revises: 0974cdf67845
Create Date: 2026-01-24 09:43:44.851379

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '21cc341a6216'
down_revision: str | None = '0974cdf67845'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        'webhooks',
        sa.Column('provider', sa.String(length=20), nullable=False, server_default='generic')
    )


def downgrade() -> None:
    op.drop_column('webhooks', 'provider')
