"""enhanced latency metrics

Revision ID: 37119e6d9c74
Revises: 9e6eee46578a
Create Date: 2026-01-28

"""
from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '37119e6d9c74'
down_revision: str | None = '9e6eee46578a'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Rename avg_latency_ms to avg_detection_latency_ms
    op.execute("""
        ALTER TABLE index_health_metrics
        RENAME COLUMN avg_latency_ms TO avg_detection_latency_ms
    """)

    # 2. Add OpenSearch query latency columns
    op.execute("""
        ALTER TABLE index_health_metrics
        ADD COLUMN IF NOT EXISTS avg_opensearch_query_latency_ms FLOAT,
        ADD COLUMN IF NOT EXISTS max_opensearch_query_latency_ms FLOAT
    """)

    # 3. Add detection latency thresholds to index_patterns
    op.execute("""
        ALTER TABLE index_patterns
        ADD COLUMN IF NOT EXISTS health_detection_latency_warning INTEGER DEFAULT 2000,
        ADD COLUMN IF NOT EXISTS health_detection_latency_critical INTEGER DEFAULT 10000
    """)

    # 4. Add OpenSearch query latency thresholds to index_patterns
    op.execute("""
        ALTER TABLE index_patterns
        ADD COLUMN IF NOT EXISTS health_opensearch_latency_warning INTEGER DEFAULT 1000,
        ADD COLUMN IF NOT EXISTS health_opensearch_latency_critical INTEGER DEFAULT 5000
    """)

    # 5. Migrate existing latency_ms to new split thresholds
    op.execute("""
        UPDATE settings
        SET value = jsonb_set(
            value,
            '{detection_latency_warning_ms}',
            to_jsonb(COALESCE((value->>'latency_ms')::int, 1000) * 2)
        )
        WHERE key = 'health_thresholds'
    """)

    op.execute("""
        UPDATE settings
        SET value = jsonb_set(
            value,
            '{detection_latency_critical_ms}',
            to_jsonb(COALESCE((value->>'latency_ms')::int, 1000) * 10)
        )
        WHERE key = 'health_thresholds'
    """)

    # 6. Remove old latency_ms field from settings
    op.execute("""
        UPDATE settings
        SET value = value - 'latency_ms'
        WHERE key = 'health_thresholds'
    """)


def downgrade() -> None:
    # Revert changes
    op.execute("""
        ALTER TABLE index_health_metrics
        RENAME COLUMN avg_detection_latency_ms TO avg_latency_ms
    """)

    op.execute("""
        ALTER TABLE index_health_metrics
        DROP COLUMN IF EXISTS avg_opensearch_query_latency_ms,
        DROP COLUMN IF EXISTS max_opensearch_query_latency_ms
    """)

    op.execute("""
        ALTER TABLE index_patterns
        DROP COLUMN IF EXISTS health_detection_latency_warning,
        DROP COLUMN IF EXISTS health_detection_latency_critical,
        DROP COLUMN IF EXISTS health_opensearch_latency_warning,
        DROP COLUMN IF EXISTS health_opensearch_latency_critical
    """)
