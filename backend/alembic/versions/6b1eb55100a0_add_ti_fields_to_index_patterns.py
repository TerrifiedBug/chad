"""add_ti_config_to_index_patterns

Revision ID: 6b1eb55100a0
Revises: 72c824948350
Create Date: 2026-01-24 18:33:39.936630

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '6b1eb55100a0'
down_revision: Union[str, None] = '72c824948350'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add ti_config JSONB column for per-source TI enrichment configuration
    # Format: {"virustotal": {"enabled": true, "fields": ["source.ip"]}, ...}
    op.add_column(
        'index_patterns',
        sa.Column('ti_config', postgresql.JSONB(astext_type=sa.Text()), nullable=True)
    )


def downgrade() -> None:
    op.drop_column('index_patterns', 'ti_config')
