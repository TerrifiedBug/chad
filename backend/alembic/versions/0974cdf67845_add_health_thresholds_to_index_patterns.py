"""add health thresholds to index patterns

Revision ID: 0974cdf67845
Revises: edca84608dc9
Create Date: 2026-01-23 21:51:22.057587

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0974cdf67845"
down_revision: str | None = "edca84608dc9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "index_patterns",
        sa.Column("health_no_data_minutes", sa.Integer(), nullable=True),
    )
    op.add_column(
        "index_patterns",
        sa.Column("health_error_rate_percent", sa.Float(), nullable=True),
    )
    op.add_column(
        "index_patterns",
        sa.Column("health_latency_ms", sa.Integer(), nullable=True),
    )
    op.add_column(
        "index_patterns",
        sa.Column(
            "health_alerting_enabled", sa.Boolean(), nullable=False, server_default="true"
        ),
    )


def downgrade() -> None:
    op.drop_column("index_patterns", "health_alerting_enabled")
    op.drop_column("index_patterns", "health_latency_ms")
    op.drop_column("index_patterns", "health_error_rate_percent")
    op.drop_column("index_patterns", "health_no_data_minutes")
