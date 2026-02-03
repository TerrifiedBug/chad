"""add_role_permissions_table

Revision ID: f8d3a9b2c7e1
Revises: a88ac2a4a236
Create Date: 2026-01-22 20:30:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'f8d3a9b2c7e1'
down_revision: str | None = 'a88ac2a4a236'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('role_permissions',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('role', sa.String(length=50), nullable=False),
    sa.Column('permission', sa.String(length=100), nullable=False),
    sa.Column('granted', sa.Boolean(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('role', 'permission', name='uq_role_permission')
    )
    op.create_index(op.f('ix_role_permissions_role'), 'role_permissions', ['role'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_role_permissions_role'), table_name='role_permissions')
    op.drop_table('role_permissions')
