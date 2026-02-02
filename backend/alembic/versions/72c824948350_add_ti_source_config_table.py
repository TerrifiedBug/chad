"""add ti source config table

Revision ID: 72c824948350
Revises: 968276b71c85
Create Date: 2026-01-24 18:10:09.567755

"""
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '72c824948350'
down_revision: str | None = '968276b71c85'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Create ti_source_config table
    # Using String for source_type instead of Postgres ENUM for simplicity
    # The Python model uses a Python Enum for validation
    op.create_table(
        'ti_source_config',
        sa.Column('source_type', sa.String(50), nullable=False),
        sa.Column('is_enabled', sa.Boolean(), nullable=False),
        sa.Column('api_key_encrypted', sa.String(length=500), nullable=True),
        sa.Column('instance_url', sa.String(length=255), nullable=True),
        sa.Column('config', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column(
            'created_at',
            sa.DateTime(timezone=True),
            server_default=sa.text('now()'),
            nullable=False,
        ),
        sa.Column(
            'updated_at',
            sa.DateTime(timezone=True),
            server_default=sa.text('now()'),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('source_type'),
    )


def downgrade() -> None:
    op.drop_table('ti_source_config')
