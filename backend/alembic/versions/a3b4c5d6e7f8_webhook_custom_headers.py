"""webhook custom headers

Revision ID: a3b4c5d6e7f8
Revises: 37119e6d9c74
Create Date: 2026-01-28

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a3b4c5d6e7f8'
down_revision: Union[str, None] = '37119e6d9c74'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add header_name column
    op.add_column('webhooks', sa.Column('header_name', sa.String(100), nullable=True))
    # Rename auth_header to header_value
    op.alter_column('webhooks', 'auth_header', new_column_name='header_value')


def downgrade() -> None:
    # Rename header_value back to auth_header
    op.alter_column('webhooks', 'header_value', new_column_name='auth_header')
    # Drop header_name column
    op.drop_column('webhooks', 'header_name')
