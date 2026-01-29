"""add_user_notification_preferences

Revision ID: 05cg73h159d7
Revises: 04bf62g048c6
Create Date: 2026-01-29 21:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


# revision identifiers, used by Alembic.
revision: str = '05cg73h159d7'
down_revision: Union[str, None] = '04bf62g048c6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add notification_preferences JSON column to users table
    op.add_column('users', sa.Column('notification_preferences', JSONB, nullable=True))


def downgrade() -> None:
    op.drop_column('users', 'notification_preferences')
