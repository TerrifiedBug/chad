"""status_model_simplification

Revision ID: b77120b027c4
Revises: a46a4bcddcf9
Create Date: 2026-01-23 12:10:31.062055

"""
from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'b77120b027c4'
down_revision: str | None = 'a46a4bcddcf9'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Convert RuleStatus enum from enabled/snoozed to deployed/undeployed/snoozed
    # Step 1: Rename old enum
    op.execute("ALTER TYPE rulestatus RENAME TO rulestatus_old")

    # Step 2: Create new enum
    op.execute("CREATE TYPE rulestatus AS ENUM ('deployed', 'undeployed', 'snoozed')")

    # Step 3: Convert existing data:
    # - ENABLED with deployed_at -> DEPLOYED
    # - ENABLED without deployed_at -> UNDEPLOYED
    # - SNOOZED -> SNOOZED (keep as is)
    op.execute("""
        ALTER TABLE rules
        ALTER COLUMN status TYPE rulestatus
        USING CASE
            WHEN status::text = 'enabled' AND deployed_at IS NOT NULL THEN 'deployed'::rulestatus
            WHEN status::text = 'enabled' AND deployed_at IS NULL THEN 'undeployed'::rulestatus
            WHEN status::text = 'snoozed' THEN 'snoozed'::rulestatus
            ELSE 'undeployed'::rulestatus
        END
    """)

    # Step 4: Drop old enum
    op.execute("DROP TYPE rulestatus_old")


def downgrade() -> None:
    # Reverse migration: deployed/undeployed/snoozed -> enabled/snoozed
    op.execute("ALTER TYPE rulestatus RENAME TO rulestatus_new")
    op.execute("CREATE TYPE rulestatus AS ENUM ('enabled', 'snoozed')")

    op.execute("""
        ALTER TABLE rules
        ALTER COLUMN status TYPE rulestatus
        USING CASE
            WHEN status::text IN ('deployed', 'undeployed') THEN 'enabled'::rulestatus
            WHEN status::text = 'snoozed' THEN 'snoozed'::rulestatus
            ELSE 'enabled'::rulestatus
        END
    """)

    op.execute("DROP TYPE rulestatus_new")
