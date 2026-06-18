"""add PRESET value to mappingorigin enum

Revision ID: 20260618j
Revises: 20260614i
Create Date: 2026-06-18 20:00:00.000000

Additive enum change. Adds 'PRESET' to the existing mappingorigin Postgres enum
so deterministic preset-resolved field mappings carry distinct provenance from
MANUAL and AI_SUGGESTED. No data migration. Postgres cannot drop an enum value,
so downgrade is a documented no-op.
"""
from collections.abc import Sequence

from alembic import op

revision: str = '20260618j'
down_revision: str | None = '20260614i'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ADD VALUE IF NOT EXISTS is idempotent; safe on re-run.
    op.execute("ALTER TYPE mappingorigin ADD VALUE IF NOT EXISTS 'PRESET'")


def downgrade() -> None:
    # Postgres does not support removing a value from an enum type.
    # Leaving 'PRESET' in place is harmless; no rows reference it after a
    # downgrade of the application code.
    pass
