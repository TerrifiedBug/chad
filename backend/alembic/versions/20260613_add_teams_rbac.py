"""Add teams + resource-scoped RBAC ownership.

Creates the teams table and adds nullable team_id ownership FKs to users, rules
and index_patterns (ON DELETE SET NULL so deleting a team un-teams its members
and resources rather than cascading).

Revision ID: 20260613b
Revises: 20260613a
Create Date: 2026-06-13
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '20260613b'
down_revision: str | None = '20260613a'
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        'teams',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
    )

    for table in ('users', 'rules', 'index_patterns'):
        op.add_column(table, sa.Column('team_id', postgresql.UUID(as_uuid=True), nullable=True))
        op.create_foreign_key(
            f'fk_{table}_team_id', table, 'teams', ['team_id'], ['id'], ondelete='SET NULL'
        )


def downgrade() -> None:
    for table in ('index_patterns', 'rules', 'users'):
        op.drop_constraint(f'fk_{table}_team_id', table, type_='foreignkey')
        op.drop_column(table, 'team_id')
    op.drop_table('teams')
