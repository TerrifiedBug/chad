"""add_ip_address_to_audit_log

Revision ID: 64e87de2efe2
Revises: b77120b027c4
Create Date: 2026-01-23 12:16:26.581338

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '64e87de2efe2'
down_revision: Union[str, None] = 'b77120b027c4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('audit_log', sa.Column('ip_address', sa.String(length=45), nullable=True))


def downgrade() -> None:
    op.drop_column('audit_log', 'ip_address')
