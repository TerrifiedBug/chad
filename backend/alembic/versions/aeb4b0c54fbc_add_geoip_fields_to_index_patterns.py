"""add geoip_fields to index patterns

Revision ID: aeb4b0c54fbc
Revises: 21cc341a6216
Create Date: 2026-01-24 10:35:32.620323

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'aeb4b0c54fbc'
down_revision: Union[str, None] = '21cc341a6216'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'index_patterns',
        sa.Column('geoip_fields', postgresql.ARRAY(sa.String()), server_default='{}', nullable=False)
    )


def downgrade() -> None:
    op.drop_column('index_patterns', 'geoip_fields')
