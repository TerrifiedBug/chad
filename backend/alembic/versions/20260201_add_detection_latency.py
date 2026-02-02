"""Add avg_detection_latency_ms to poll state for real timestamp-based latency tracking.

Revision ID: 20260201_detection_latency
Revises: 20260201_timestamp
Create Date: 2026-02-01 23:30:00.000000
"""

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "20260201_detection_latency"
down_revision = "20260201_timestamp"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add avg_detection_latency_ms column to track real detection latency
    # This is calculated from actual event timestamps vs alert creation time
    op.add_column(
        "index_pattern_poll_state",
        sa.Column("avg_detection_latency_ms", sa.Float(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("index_pattern_poll_state", "avg_detection_latency_ms")
