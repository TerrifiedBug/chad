"""remove BOTH from auth_method enum

Revision ID: 20260127_remove_both
Revises: 20260127_auth_method
Create Date: 2026-01-27

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = '20260127_remove_both'
down_revision = '20260127_auth_method'
branch_labels = None
depends_on = None

def upgrade():
    # Convert any BOTH values to SSO (shouldn't be any, but just in case)
    op.execute("UPDATE users SET auth_method = 'SSO' WHERE auth_method = 'BOTH'")

    # Drop default constraint (depends on enum)
    op.execute("ALTER TABLE users ALTER COLUMN auth_method DROP DEFAULT")

    # Alter column to VARCHAR to drop enum dependency
    op.execute("ALTER TABLE users ALTER COLUMN auth_method TYPE VARCHAR(10)")

    # Drop the old enum type
    op.execute("DROP TYPE authmethodenum")

    # Recreate enum without BOTH
    op.execute("CREATE TYPE authmethodenum AS ENUM ('LOCAL', 'SSO')")

    # Alter column back to enum
    op.execute("ALTER TABLE users ALTER COLUMN auth_method TYPE authmethodenum USING auth_method::authmethodenum")

    # Restore default constraint
    op.execute("ALTER TABLE users ALTER COLUMN auth_method SET DEFAULT 'LOCAL'")

def downgrade():
    # Drop default constraint
    op.execute("ALTER TABLE users ALTER COLUMN auth_method DROP DEFAULT")

    # Alter column to VARCHAR
    op.execute("ALTER TABLE users ALTER COLUMN auth_method TYPE VARCHAR(10)")

    # Drop the enum without BOTH
    op.execute("DROP TYPE authmethodenum")

    # Recreate enum with BOTH
    op.execute("CREATE TYPE authmethodenum AS ENUM ('LOCAL', 'SSO', 'BOTH')")

    # Alter column back to enum
    op.execute("ALTER TABLE users ALTER COLUMN auth_method TYPE authmethodenum USING auth_method::authmethodenum")

    # Restore default constraint
    op.execute("ALTER TABLE users ALTER COLUMN auth_method SET DEFAULT 'LOCAL'")
