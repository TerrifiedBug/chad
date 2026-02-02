"""add_two_factor_tokens_table

Revision ID: f0a1b2c3d4e5
Revises: 7be870e36bd1
Create Date: 2026-01-26 13:40:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'f0a1b2c3d4e5'
down_revision: str | None = '7be870e36bd1'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'two_factor_tokens',
        sa.Column('user_id', sa.String(length=255), nullable=False),
        sa.Column('token_type', sa.String(length=20), nullable=False),
        sa.Column('token_data', sa.String(length=500), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('user_id', 'token_type', name='pk_two_factor_tokens')
    )
    op.create_index(
        op.f('ix_two_factor_tokens_expires_at'),
        'two_factor_tokens',
        ['expires_at'],
        unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f('ix_two_factor_tokens_expires_at'), table_name='two_factor_tokens')
    op.drop_table('two_factor_tokens')
