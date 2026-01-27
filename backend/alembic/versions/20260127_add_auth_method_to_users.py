"""add auth_method to users

Revision ID: 20260127_auth_method
Revises: 7d8cb2f0c87b
Create Date: 2026-01-27

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = '20260127_auth_method'
down_revision = '7d8cb2f0c87b'
branch_labels = None
depends_on = None

def upgrade():
    # Create enum type with UPPERCASE values to match Python enum
    op.execute("CREATE TYPE authmethodenum AS ENUM ('LOCAL', 'SSO', 'BOTH')")

    # Add column with default value
    op.add_column(
        'users',
        sa.Column(
            'auth_method',
            sa.Enum('LOCAL', 'SSO', 'BOTH', name='authmethodenum'),
            nullable=False,
            server_default='LOCAL'
        )
    )

def downgrade():
    op.drop_column('users', 'auth_method')
    op.execute("DROP TYPE authmethodenum")
