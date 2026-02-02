"""Add system_logs table for structured application logging.

Revision ID: 03272c7aea4c
Revises: 20260202_updated_by
Create Date: 2026-02-02 22:19:59.578875
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

# revision identifiers, used by Alembic.
revision = "03272c7aea4c"
down_revision = "20260202_updated_by"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "system_logs",
        sa.Column(
            "timestamp",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("level", sa.String(length=10), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("service", sa.String(length=64), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("details", JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "idx_system_logs_timestamp_desc",
        "system_logs",
        [sa.literal_column("timestamp DESC")],
        unique=False,
    )
    op.create_index(
        op.f("ix_system_logs_category"), "system_logs", ["category"], unique=False
    )
    op.create_index(
        op.f("ix_system_logs_level"), "system_logs", ["level"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_system_logs_level"), table_name="system_logs")
    op.drop_index(op.f("ix_system_logs_category"), table_name="system_logs")
    op.drop_index("idx_system_logs_timestamp_desc", table_name="system_logs")
    op.drop_table("system_logs")
