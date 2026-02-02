"""Add metrics columns to poll state table

Revision ID: add_poll_state_metrics
Revises: add_index_pattern_mode
Create Date: 2026-02-01

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "add_poll_state_metrics"
down_revision: str = "add_index_pattern_mode"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Add metrics columns to index_pattern_poll_state
    op.add_column(
        "index_pattern_poll_state",
        sa.Column("total_polls", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "index_pattern_poll_state",
        sa.Column("successful_polls", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "index_pattern_poll_state",
        sa.Column("failed_polls", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "index_pattern_poll_state",
        sa.Column("total_matches", sa.BigInteger(), nullable=False, server_default="0"),
    )
    op.add_column(
        "index_pattern_poll_state",
        sa.Column("total_events_scanned", sa.BigInteger(), nullable=False, server_default="0"),
    )
    op.add_column(
        "index_pattern_poll_state",
        sa.Column("last_poll_duration_ms", sa.Integer(), nullable=True),
    )
    op.add_column(
        "index_pattern_poll_state",
        sa.Column("avg_poll_duration_ms", sa.Float(), nullable=True),
    )
    op.add_column(
        "index_pattern_poll_state",
        sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("index_pattern_poll_state", "consecutive_failures")
    op.drop_column("index_pattern_poll_state", "avg_poll_duration_ms")
    op.drop_column("index_pattern_poll_state", "last_poll_duration_ms")
    op.drop_column("index_pattern_poll_state", "total_events_scanned")
    op.drop_column("index_pattern_poll_state", "total_matches")
    op.drop_column("index_pattern_poll_state", "failed_polls")
    op.drop_column("index_pattern_poll_state", "successful_polls")
    op.drop_column("index_pattern_poll_state", "total_polls")
