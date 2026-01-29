"""Add group_id to rule_exceptions for AND logic grouping.

Revision ID: 06dh84i260e8
Revises: 05cg73h159d7
Create Date: 2026-01-29

"""
from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

# revision identifiers, used by Alembic.
revision: str = '06dh84i260e8'
down_revision: Union[str, None] = '05cg73h159d7'
branch_labels: Union[str, None] = None
depends_on: Union[str, None] = None


def upgrade() -> None:
    # Add group_id column - each exception gets its own group by default
    # Exceptions with the same group_id are ANDed together
    op.add_column(
        'rule_exceptions',
        sa.Column('group_id', UUID(as_uuid=True), nullable=True)
    )

    # Set existing exceptions to have their own unique group_id (using their id)
    op.execute("UPDATE rule_exceptions SET group_id = id WHERE group_id IS NULL")

    # Now make the column non-nullable
    op.alter_column('rule_exceptions', 'group_id', nullable=False)

    # Add index for faster grouping queries
    op.create_index('ix_rule_exceptions_group_id', 'rule_exceptions', ['group_id'])


def downgrade() -> None:
    op.drop_index('ix_rule_exceptions_group_id', table_name='rule_exceptions')
    op.drop_column('rule_exceptions', 'group_id')
