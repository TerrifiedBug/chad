"""add_change_reason_to_rule_versions

Revision ID: 267127dc6c59
Revises: 07057fb3790e
Create Date: 2026-01-25 15:48:16.508395

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '267127dc6c59'
down_revision: Union[str, None] = '07057fb3790e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Step 1: Add column as nullable
    op.add_column('rule_versions', sa.Column('change_reason', sa.Text(), nullable=True))

    # Step 2: Backfill existing rows with default value
    op.execute("UPDATE rule_versions SET change_reason = 'Migration: Initial version'")

    # Step 3: Make column NOT NULL
    op.alter_column('rule_versions', 'change_reason', nullable=False)


def downgrade() -> None:
    op.drop_column('rule_versions', 'change_reason')
