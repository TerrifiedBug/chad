"""add_updated_at_to_alert_comments

Revision ID: 3726deb5f1be
Revises: 09kr_add_entity_field_type
Create Date: 2026-01-30 13:02:17.713096

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '3726deb5f1be'
down_revision: Union[str, None] = '09kr_add_entity_field_type'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('alert_comments', sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column('alert_comments', 'updated_at')
