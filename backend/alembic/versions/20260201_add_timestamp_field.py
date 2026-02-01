"""Add timestamp_field to index_patterns for configurable pull mode time filtering.

Revision ID: 20260201_timestamp
Revises: 20260201_add_poll_state_metrics
Create Date: 2026-02-01 18:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "20260201_timestamp"
down_revision = "add_poll_state_metrics"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add timestamp_field column with default of @timestamp (standard Elasticsearch/OpenSearch field)
    op.add_column(
        "index_patterns",
        sa.Column(
            "timestamp_field",
            sa.String(255),
            nullable=False,
            server_default="@timestamp",
        ),
    )


def downgrade() -> None:
    op.drop_column("index_patterns", "timestamp_field")
