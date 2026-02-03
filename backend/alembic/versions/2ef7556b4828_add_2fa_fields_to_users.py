"""add 2fa fields to users

Revision ID: 2ef7556b4828
Revises: aeb4b0c54fbc
Create Date: 2026-01-24 16:18:40.926088

"""
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '2ef7556b4828'
down_revision: str | None = 'aeb4b0c54fbc'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Add 2FA fields to users table
    op.add_column('users', sa.Column('totp_secret', sa.String(length=32), nullable=True))
    op.add_column('users', sa.Column('totp_enabled', sa.Boolean(), server_default=sa.text('false'), nullable=False))
    op.add_column('users', sa.Column('totp_backup_codes', postgresql.ARRAY(sa.String()), nullable=True))


def downgrade() -> None:
    op.drop_column('users', 'totp_backup_codes')
    op.drop_column('users', 'totp_enabled')
    op.drop_column('users', 'totp_secret')
