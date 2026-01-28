"""add manage_alerts permission

Revision ID: 20260128_add_manage_alerts
Revises: 97df79eef275
Create Date: 2026-01-28

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9e6eee46578a'
down_revision: Union[str, None] = '97df79eef275'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add manage_alerts permission to admin and analyst roles
    op.execute("""
        INSERT INTO role_permissions (role, permission, granted)
        VALUES
            ('admin', 'manage_alerts', true),
            ('analyst', 'manage_alerts', true)
        ON CONFLICT (role, permission)
        DO NOTHING
    """)


def downgrade() -> None:
    # Remove manage_alerts permission
    op.execute("""
        DELETE FROM role_permissions
        WHERE permission = 'manage_alerts'
    """)
