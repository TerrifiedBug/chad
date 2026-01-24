#!/usr/bin/env python3
"""
Load Test Fixture Setup/Teardown

Creates a test index pattern with a known auth token for load testing.
Run inside the backend container:

    docker compose -f docker-compose.dev.yml exec backend python /app/load-tests/scripts/setup-test-fixtures.py setup
    docker compose -f docker-compose.dev.yml exec backend python /app/load-tests/scripts/setup-test-fixtures.py teardown
"""

import asyncio
import sys

# Add backend to path when running from container
sys.path.insert(0, "/app")

TEST_INDEX_PATTERN = {
    "name": "Load Test Pattern",
    "pattern": "loadtest-*",
    "percolator_index": "chad-percolator-windows-sysmon",  # Matches k6 default
    "description": "Temporary index pattern for load testing",
    "auth_token": "test-secret",  # Matches k6 default LOG_SHIPPING_SECRET
}

PERCOLATOR_INDEX = TEST_INDEX_PATTERN["percolator_index"]
ALERTS_INDEX = "chad-alerts-windows-sysmon"


async def get_opensearch_client():
    """Get OpenSearch client from database settings."""
    from sqlalchemy import select
    from app.db.session import async_session_maker
    from app.models.setting import Setting
    from app.core.encryption import decrypt
    from app.services.opensearch import create_client

    async with async_session_maker() as db:
        result = await db.execute(select(Setting).where(Setting.key == "opensearch"))
        setting = result.scalar_one_or_none()

        if setting is None:
            print("ERROR: OpenSearch not configured in settings")
            print("Please configure OpenSearch in the CHAD settings UI first")
            return None

        config = setting.value
        password = config.get("password")
        if password:
            try:
                password = decrypt(password)
            except Exception:
                pass

        return create_client(
            host=config["host"],
            port=config["port"],
            username=config.get("username"),
            password=password,
            use_ssl=config.get("use_ssl", True),
        )


async def setup_opensearch_indices():
    """Create percolator and alerts indices if they don't exist."""
    client = await get_opensearch_client()
    if client is None:
        return False

    # Percolator index mapping
    percolator_mapping = {
        "mappings": {
            "properties": {
                "query": {"type": "percolator"},
                "rule_id": {"type": "keyword"},
                "rule_title": {"type": "text"},
                "severity": {"type": "keyword"},
                "tags": {"type": "keyword"},
                "enabled": {"type": "boolean"},
            }
        }
    }

    # Alerts index mapping
    alerts_mapping = {
        "mappings": {
            "properties": {
                "alert_id": {"type": "keyword"},
                "rule_id": {"type": "keyword"},
                "rule_title": {"type": "text"},
                "severity": {"type": "keyword"},
                "tags": {"type": "keyword"},
                "timestamp": {"type": "date"},
                "log_document": {"type": "object", "enabled": False},
            }
        }
    }

    # Create percolator index
    if not client.indices.exists(index=PERCOLATOR_INDEX):
        client.indices.create(index=PERCOLATOR_INDEX, body=percolator_mapping)
        print(f"Created percolator index: {PERCOLATOR_INDEX}")
    else:
        print(f"Percolator index already exists: {PERCOLATOR_INDEX}")

    # Create alerts index
    if not client.indices.exists(index=ALERTS_INDEX):
        client.indices.create(index=ALERTS_INDEX, body=alerts_mapping)
        print(f"Created alerts index: {ALERTS_INDEX}")
    else:
        print(f"Alerts index already exists: {ALERTS_INDEX}")

    return True


async def teardown_opensearch_indices():
    """Delete test indices."""
    client = await get_opensearch_client()
    if client is None:
        return

    for index in [PERCOLATOR_INDEX, ALERTS_INDEX]:
        if client.indices.exists(index=index):
            client.indices.delete(index=index)
            print(f"Deleted index: {index}")
        else:
            print(f"Index not found: {index}")


async def setup():
    """Create test index pattern and OpenSearch indices."""
    from sqlalchemy import select
    from app.db.session import async_session_maker
    from app.models.index_pattern import IndexPattern

    # Setup OpenSearch indices first
    print("Setting up OpenSearch indices...")
    if not await setup_opensearch_indices():
        print("WARNING: Could not setup OpenSearch indices - tests may fail")
        print("Configure OpenSearch in the CHAD settings UI first")

    async with async_session_maker() as db:
        # Check if already exists
        result = await db.execute(
            select(IndexPattern).where(
                IndexPattern.percolator_index == TEST_INDEX_PATTERN["percolator_index"]
            )
        )
        existing = result.scalar_one_or_none()

        if existing:
            print(f"Test index pattern already exists: {existing.id}")
            print(f"Auth token: {existing.auth_token}")
            return

        # Create new pattern
        pattern = IndexPattern(**TEST_INDEX_PATTERN)
        db.add(pattern)
        await db.commit()
        await db.refresh(pattern)

        print(f"Created test index pattern: {pattern.id}")
        print(f"Auth token: {pattern.auth_token}")
        print(f"Percolator index: {pattern.percolator_index}")


async def teardown():
    """Remove test index pattern and OpenSearch indices."""
    from sqlalchemy import select
    from app.db.session import async_session_maker
    from app.models.index_pattern import IndexPattern

    async with async_session_maker() as db:
        result = await db.execute(
            select(IndexPattern).where(
                IndexPattern.percolator_index == TEST_INDEX_PATTERN["percolator_index"]
            )
        )
        pattern = result.scalar_one_or_none()

        if pattern is None:
            print("Test index pattern not found in database")
        else:
            await db.delete(pattern)
            await db.commit()
            print(f"Deleted test index pattern: {pattern.id}")

    # Cleanup OpenSearch indices
    print("Cleaning up OpenSearch indices...")
    await teardown_opensearch_indices()


async def status():
    """Check if test index pattern exists."""
    from sqlalchemy import select
    from app.db.session import async_session_maker
    from app.models.index_pattern import IndexPattern

    async with async_session_maker() as db:
        result = await db.execute(
            select(IndexPattern).where(
                IndexPattern.percolator_index == TEST_INDEX_PATTERN["percolator_index"]
            )
        )
        pattern = result.scalar_one_or_none()

        if pattern:
            print(f"EXISTS: {pattern.name}")
            print(f"ID: {pattern.id}")
            print(f"Auth token: {pattern.auth_token}")
        else:
            print("NOT FOUND")


def main():
    if len(sys.argv) < 2:
        print("Usage: setup-test-fixtures.py [setup|teardown|status]")
        sys.exit(1)

    command = sys.argv[1]

    if command == "setup":
        asyncio.run(setup())
    elif command == "teardown":
        asyncio.run(teardown())
    elif command == "status":
        asyncio.run(status())
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
