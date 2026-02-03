"""add_field_mapping_version

Revision ID: fe29c647c878
Revises: 20260127_fix_sso_users
Create Date: 2026-01-27 20:36:53.108069

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'fe29c647c878'
down_revision: str | None = '20260127_fix_sso_users'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Add version column to field_mappings
    op.add_column('field_mappings',
        sa.Column('version', sa.Integer(), nullable=False, server_default='1'))

    # Initialize existing mappings to version 1
    op.execute("UPDATE field_mappings SET version = 1")


def downgrade() -> None:
    op.drop_column('field_mappings', 'version')
