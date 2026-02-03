"""add_ti_config_to_index_patterns

Revision ID: 6b1eb55100a0
Revises: 72c824948350
Create Date: 2026-01-24 18:33:39.936630

"""
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '6b1eb55100a0'
down_revision: str | None = '72c824948350'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Add ti_config JSONB column for per-source TI enrichment configuration
    # Format: {"virustotal": {"enabled": true, "fields": ["source.ip"]}, ...}
    op.add_column(
        'index_patterns',
        sa.Column('ti_config', postgresql.JSONB(astext_type=sa.Text()), nullable=True)
    )


def downgrade() -> None:
    op.drop_column('index_patterns', 'ti_config')
