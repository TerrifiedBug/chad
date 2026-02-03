"""Add IP allowlist and rate limiting to index patterns

Revision ID: 07ip_allowlist_ratelimit
Revises: 06dh84i260e8
Create Date: 2026-01-29

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "07ip_allowlist_ratelimit"
down_revision: str = "06dh84i260e8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Add IP allowlist column
    op.add_column(
        "index_patterns",
        sa.Column("allowed_ips", postgresql.ARRAY(sa.String()), nullable=True),
    )

    # Add rate limiting columns
    op.add_column(
        "index_patterns",
        sa.Column("rate_limit_enabled", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.add_column(
        "index_patterns",
        sa.Column("rate_limit_requests_per_minute", sa.Integer(), nullable=True),
    )
    op.add_column(
        "index_patterns",
        sa.Column("rate_limit_events_per_minute", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("index_patterns", "rate_limit_events_per_minute")
    op.drop_column("index_patterns", "rate_limit_requests_per_minute")
    op.drop_column("index_patterns", "rate_limit_enabled")
    op.drop_column("index_patterns", "allowed_ips")
