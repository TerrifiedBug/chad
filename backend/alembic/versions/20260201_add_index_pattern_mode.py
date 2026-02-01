"""Add mode field to index patterns and poll state table

Revision ID: add_index_pattern_mode
Revises: 3726deb5f1be
Create Date: 2026-02-01

"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "add_index_pattern_mode"
down_revision: str = "3726deb5f1be"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Add mode and poll_interval_minutes to index_patterns
    op.add_column(
        "index_patterns",
        sa.Column("mode", sa.String(10), nullable=False, server_default="push"),
    )
    op.add_column(
        "index_patterns",
        sa.Column("poll_interval_minutes", sa.Integer(), nullable=False, server_default="5"),
    )

    # Create index_pattern_poll_state table
    op.create_table(
        "index_pattern_poll_state",
        sa.Column("index_pattern_id", sa.UUID(), nullable=False),
        sa.Column("last_poll_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_poll_status", sa.String(20), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["index_pattern_id"],
            ["index_patterns.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("index_pattern_id"),
    )


def downgrade() -> None:
    op.drop_table("index_pattern_poll_state")
    op.drop_column("index_patterns", "poll_interval_minutes")
    op.drop_column("index_patterns", "mode")
