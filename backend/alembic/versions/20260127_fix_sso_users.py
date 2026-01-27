"""fix auth_method for existing SSO users

Revision ID: 20260127_fix_sso_users
Revises: 20260127_remove_both
Create Date: 2026-01-27

"""
from alembic import op

# revision identifiers
revision = '20260127_fix_sso_users'
down_revision = '20260127_remove_both'
branch_labels = None
depends_on = None

def upgrade():
    # Fix users who were incorrectly marked as LOCAL
    # Users without a password_hash are SSO users
    op.execute("""
        UPDATE users
        SET auth_method = 'SSO'
        WHERE password_hash IS NULL
        AND auth_method = 'LOCAL'
    """)

def downgrade():
    # Revert the fix (mark them back as LOCAL)
    op.execute("""
        UPDATE users
        SET auth_method = 'LOCAL'
        WHERE password_hash IS NULL
        AND auth_method = 'SSO'
    """)
