"""Drop alerts table - alerts are stored in OpenSearch only.

Revision ID: 20260206b
Revises: 20260206a
Create Date: 2026-02-06
"""

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '20260206b'
down_revision: str | None = '20260206a'
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.drop_table('alerts')


def downgrade() -> None:
    # Recreating the table is not needed - it was never populated.
    # If needed, restore from the original migration 97df79eef275.
    pass
