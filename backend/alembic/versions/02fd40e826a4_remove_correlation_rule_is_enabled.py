"""remove correlation rule is_enabled

Revision ID: 02fd40e826a4
Revises: 01ec39d715f3
Create Date: 2026-01-28 15:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '02fd40e826a4'
down_revision: Union[str, None] = '01ec39d715f3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Remove is_enabled column - deploy/undeploy now controls active state
    op.drop_column('correlation_rules', 'is_enabled')


def downgrade() -> None:
    # Add is_enabled back with default True
    op.add_column('correlation_rules', sa.Column('is_enabled', sa.Boolean(), nullable=False, server_default='true'))
