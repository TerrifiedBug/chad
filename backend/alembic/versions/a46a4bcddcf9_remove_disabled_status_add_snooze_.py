"""remove_disabled_status_add_snooze_indefinite

Revision ID: a46a4bcddcf9
Revises: 5018ae80aaa1
Create Date: 2026-01-23 10:20:13.939844

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'a46a4bcddcf9'
down_revision: str | None = '5018ae80aaa1'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Add snooze_indefinite column
    op.add_column('rules', sa.Column('snooze_indefinite', sa.Boolean(), nullable=False, server_default='false'))

    # Convert disabled rules before removing the enum value
    # First convert status column to VARCHAR to allow data migration
    op.execute("ALTER TABLE rules ALTER COLUMN status TYPE VARCHAR(50) USING status::VARCHAR")

    # Convert disabled rules:
    # - If deployed (deployed_at is not null): undeploy them (clear deployed_at)
    # - Set status to 'ENABLED'
    op.execute("""
        UPDATE rules
        SET deployed_at = NULL,
            deployed_version = NULL,
            status = 'ENABLED'
        WHERE status = 'DISABLED' AND deployed_at IS NOT NULL
    """)
    op.execute("""
        UPDATE rules
        SET status = 'ENABLED'
        WHERE status = 'DISABLED'
    """)

    # Now recreate the enum without DISABLED
    op.execute("DROP TYPE IF EXISTS rulestatus_new")
    op.execute("CREATE TYPE rulestatus_new AS ENUM ('ENABLED', 'SNOOZED')")
    op.execute("ALTER TABLE rules ALTER COLUMN status TYPE rulestatus_new USING status::rulestatus_new")
    op.execute("DROP TYPE rulestatus")
    op.execute("ALTER TYPE rulestatus_new RENAME TO rulestatus")


def downgrade() -> None:
    # Convert back: add DISABLED to enum
    op.execute("ALTER TABLE rules ALTER COLUMN status TYPE VARCHAR(50) USING status::VARCHAR")
    op.execute("DROP TYPE IF EXISTS rulestatus_new")
    op.execute("CREATE TYPE rulestatus_new AS ENUM ('ENABLED', 'DISABLED', 'SNOOZED')")
    op.execute("ALTER TABLE rules ALTER COLUMN status TYPE rulestatus_new USING status::rulestatus_new")
    op.execute("DROP TYPE rulestatus")
    op.execute("ALTER TYPE rulestatus_new RENAME TO rulestatus")

    op.drop_column('rules', 'snooze_indefinite')
