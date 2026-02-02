"""add_login_attempts_table

Revision ID: a88ac2a4a236
Revises: ce0f9f535011
Create Date: 2026-01-22 19:45:08.451349

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'a88ac2a4a236'
down_revision: str | None = 'ce0f9f535011'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('login_attempts',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('email', sa.String(length=255), nullable=False),
    sa.Column('ip_address', sa.String(length=45), nullable=False),
    sa.Column('attempted_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_login_attempts_email'), 'login_attempts', ['email'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_login_attempts_email'), table_name='login_attempts')
    op.drop_table('login_attempts')
