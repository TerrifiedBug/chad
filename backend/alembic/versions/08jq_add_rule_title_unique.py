"""Add unique constraint to rule title

Revision ID: 08jq_add_rule_title_unique
Revises: 07ip_allowlist_ratelimit_add
Create Date: 2026-01-29

"""
from sqlalchemy import text

from alembic import op

# revision identifiers, used by Alembic.
revision = "08jq_add_rule_title_unique"
down_revision = "07ip_allowlist_ratelimit"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # First, deduplicate any existing rules with the same title
    # by appending a number to duplicates
    conn = op.get_bind()

    # Find duplicate titles
    result = conn.execute(text("""
        SELECT title, COUNT(*) as cnt
        FROM rules
        GROUP BY title
        HAVING COUNT(*) > 1
    """))
    duplicates = result.fetchall()

    for title, count in duplicates:
        # Get all rules with this title, ordered by created_at
        rules = conn.execute(text("""
            SELECT id, title FROM rules
            WHERE title = :title
            ORDER BY created_at ASC
        """), {"title": title}).fetchall()

        # Keep the first one as-is, rename the rest
        for i, (rule_id, rule_title) in enumerate(rules[1:], start=2):
            new_title = f"{rule_title} ({i})"
            # Make sure the new title doesn't conflict
            while conn.execute(text(
                "SELECT 1 FROM rules WHERE title = :title"
            ), {"title": new_title}).fetchone():
                i += 1
                new_title = f"{rule_title} ({i})"

            conn.execute(text("""
                UPDATE rules SET title = :new_title WHERE id = :id
            """), {"new_title": new_title, "id": rule_id})

    # Now add the unique constraint
    op.create_unique_constraint("uq_rules_title", "rules", ["title"])


def downgrade() -> None:
    op.drop_constraint("uq_rules_title", "rules", type_="unique")
