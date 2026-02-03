"""Add updated_by_id to index_patterns for tracking who last edited.

Revision ID: 20260202_updated_by
Revises: 20260201_detection_latency
Create Date: 2026-02-02 14:45:00.000000
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

# revision identifiers, used by Alembic.
revision = "20260202_updated_by"
down_revision = "20260201_detection_latency"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add updated_by_id column to track who last edited each index pattern
    op.add_column(
        "index_patterns",
        sa.Column("updated_by_id", UUID(as_uuid=True), nullable=True),
    )
    # Add foreign key constraint to users table
    op.create_foreign_key(
        "fk_index_patterns_updated_by_id",
        "index_patterns",
        "users",
        ["updated_by_id"],
        ["id"],
    )


def downgrade() -> None:
    op.drop_constraint("fk_index_patterns_updated_by_id", "index_patterns", type_="foreignkey")
    op.drop_column("index_patterns", "updated_by_id")
