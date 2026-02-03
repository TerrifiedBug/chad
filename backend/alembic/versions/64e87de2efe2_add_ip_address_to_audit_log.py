"""add_ip_address_to_audit_log

Revision ID: 64e87de2efe2
Revises: b77120b027c4
Create Date: 2026-01-23 12:16:26.581338

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '64e87de2efe2'
down_revision: str | None = 'b77120b027c4'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('audit_log', sa.Column('ip_address', sa.String(length=45), nullable=True))


def downgrade() -> None:
    op.drop_column('audit_log', 'ip_address')
