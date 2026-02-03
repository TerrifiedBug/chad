"""webhook custom headers

Revision ID: a3b4c5d6e7f8
Revises: 37119e6d9c74
Create Date: 2026-01-28

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'a3b4c5d6e7f8'
down_revision: str | None = '37119e6d9c74'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Use batch operations for SQLite compatibility
    with op.batch_alter_table('webhooks') as batch_op:
        # Add header_name column
        batch_op.add_column(sa.Column('header_name', sa.String(100), nullable=True))
        # Rename auth_header to header_value
        batch_op.alter_column('auth_header', new_column_name='header_value')


def downgrade() -> None:
    # Use batch operations for SQLite compatibility
    with op.batch_alter_table('webhooks') as batch_op:
        # Rename header_value back to auth_header
        batch_op.alter_column('header_value', new_column_name='auth_header')
        # Drop header_name column
        batch_op.drop_column('header_name')
