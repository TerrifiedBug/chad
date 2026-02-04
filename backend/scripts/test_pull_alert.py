#!/usr/bin/env python3
"""
Test script for pull mode alert generation.

This script sets up everything needed to test pull mode alerts:
1. Creates a test index pattern with pull mode
2. Creates OpenSearch index with field mappings (via test document)
3. Creates a test Sigma rule and marks it as DEPLOYED
4. Optionally injects test IOC into Redis
5. Indexes a test log document that matches the rule
6. Manually triggers the pull detection poll
7. Reports results

Run from backend container:
    docker compose -f docker-compose.dev.yml exec backend python scripts/test_pull_alert.py

Options:
    --with-ioc      Also test IOC detection (injects test IOC into Redis)
    --cleanup       Remove test data after test
"""

import argparse
import asyncio
import secrets
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Add parent directory to path for app imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Test constants
TEST_INDEX_PATTERN_NAME = "chad-test-pull"
TEST_INDEX_NAME = f"{TEST_INDEX_PATTERN_NAME}-test"
TEST_IOC_IP = "192.0.2.2"  # TEST-NET-1 (different from push test)
TEST_IOC_EVENT_ID = "test-event-002"

# Test Sigma rule - uses ECS field names that match our test log
# Note: The ID must be a valid UUID per Sigma specification
TEST_SIGMA_RULE = """
title: CHAD Test Rule - Pull Mode
id: 00000000-0000-0000-0000-000000000002
status: test
description: Test rule for validating pull mode alert generation
author: CHAD Testing
date: 2026/02/04
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        process.command_line|contains: 'CHAD_TEST_PULL'
    condition: selection
falsepositives:
    - Test executions
level: medium
tags:
    - test.chad
"""


def create_test_log(with_ioc: bool = False) -> dict:
    """Create a test log document that matches the test Sigma rule."""
    log = {
        "@timestamp": datetime.now(UTC).isoformat(),
        "event": {
            "type": "process_creation",
            "category": "process",
        },
        "process": {
            "name": "cmd.exe",
            "executable": "C:\\Windows\\System32\\cmd.exe",
            "command_line": "cmd.exe /c echo CHAD_TEST_PULL",
            "pid": 5678,
        },
        "user": {
            "name": "test_user",
            "domain": "WORKGROUP",
        },
        "host": {
            "name": "test-workstation",
            "ip": ["10.0.0.100"],
        },
    }

    if with_ioc:
        log["source"] = {"ip": TEST_IOC_IP}
        log["client_real_ip"] = TEST_IOC_IP

    return log


async def setup_opensearch_index(os_client, with_ioc: bool = False) -> str:
    """Create test index in OpenSearch with a sample document for field mappings.

    Returns the document ID.
    """
    # Index a sample document to create the index with proper mappings
    sample_doc = create_test_log(with_ioc=with_ioc)

    result = os_client.index(
        index=TEST_INDEX_NAME,
        body=sample_doc,
        refresh=True,
    )
    doc_id = result.get("_id")

    if os_client.indices.exists(index=TEST_INDEX_NAME):
        print(f"   Indexed test document: {TEST_INDEX_NAME}/{doc_id}")

    return doc_id


async def setup_test_index_pattern(db_session) -> tuple[str, str]:
    """Create or update test index pattern with pull mode.

    Returns:
        Tuple of (index_pattern_id, auth_token)
    """
    from sqlalchemy import select

    from app.models.index_pattern import IndexPattern

    # Check if test pattern already exists
    result = await db_session.execute(
        select(IndexPattern).where(IndexPattern.name == TEST_INDEX_PATTERN_NAME)
    )
    pattern = result.scalar_one_or_none()

    if pattern:
        print(f"   Using existing index pattern: {pattern.name}")
        # Ensure pull mode and IOC detection are enabled
        pattern.mode = "pull"
        pattern.poll_interval_minutes = 1  # 1 minute for testing
        pattern.ioc_detection_enabled = True
        pattern.ti_config = {
            "ioc_fields": {
                "ip": ["source.ip", "client_real_ip", "destination.ip"],
                "domain": ["dns.question.name", "url.domain"],
            }
        }
        await db_session.commit()
        return str(pattern.id), pattern.auth_token

    # Create new test pattern
    auth_token = secrets.token_urlsafe(32)
    percolator_index = f"chad-percolator-{TEST_INDEX_PATTERN_NAME}"
    pattern = IndexPattern(
        name=TEST_INDEX_PATTERN_NAME,
        pattern=f"{TEST_INDEX_PATTERN_NAME}-*",
        percolator_index=percolator_index,  # Required even for pull mode
        description="Test index pattern for pull mode alert testing",
        auth_token=auth_token,
        mode="pull",
        poll_interval_minutes=1,
        timestamp_field="@timestamp",
        ioc_detection_enabled=True,
        ti_config={
            "ioc_fields": {
                "ip": ["source.ip", "client_real_ip", "destination.ip"],
                "domain": ["dns.question.name", "url.domain"],
            }
        },
    )
    db_session.add(pattern)
    await db_session.commit()
    await db_session.refresh(pattern)

    print(f"   Created index pattern: {pattern.name} (mode: pull)")
    return str(pattern.id), pattern.auth_token


async def deploy_test_sigma_rule(db_session, index_pattern_id: str, user_id: str):
    """Create the test Sigma rule and mark it as deployed."""
    from sqlalchemy import select

    from app.models.rule import Rule, RuleStatus

    # Check if rule already exists
    result = await db_session.execute(
        select(Rule).where(Rule.title == "CHAD Test Rule - Pull Mode")
    )
    existing_rule = result.scalar_one_or_none()

    if existing_rule:
        print(f"   Using existing rule: {existing_rule.title}")
        rule = existing_rule
        # Always update rule content and index pattern
        rule.yaml_content = TEST_SIGMA_RULE.strip()
        rule.index_pattern_id = uuid.UUID(index_pattern_id)
        rule.status = RuleStatus.DEPLOYED
        rule.deployed_at = datetime.now(UTC)
        await db_session.commit()
    else:
        # Create new rule
        rule = Rule(
            title="CHAD Test Rule - Pull Mode",
            description="Test rule for pull mode alert generation",
            yaml_content=TEST_SIGMA_RULE.strip(),
            severity="medium",
            status=RuleStatus.DEPLOYED,
            deployed_at=datetime.now(UTC),
            index_pattern_id=uuid.UUID(index_pattern_id),
            created_by=uuid.UUID(user_id),
            source="user",
        )
        db_session.add(rule)
        await db_session.commit()
        await db_session.refresh(rule)
        print(f"   Created rule: {rule.title}")

    print(f"   Rule status: {rule.status.value}")
    return str(rule.id)


async def inject_test_ioc() -> None:
    """Inject test IOC into Redis cache."""
    from app.services.ti.ioc_cache import IOCCache
    from app.services.ti.ioc_types import IOCRecord, IOCType

    record = IOCRecord(
        ioc_type=IOCType.IP_SRC,
        value=TEST_IOC_IP,
        misp_event_id=TEST_IOC_EVENT_ID,
        misp_event_uuid=str(uuid.uuid4()),
        misp_attribute_uuid=str(uuid.uuid4()),
        misp_event_info="Test Event - Pull Mode IOC Detection",
        threat_level="high",
        tags=["test", "chad-test"],
        first_seen=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )

    cache = IOCCache()
    await cache.store_ioc(record)
    print(f"   Injected IOC: {TEST_IOC_IP} (type: ip-src)")


async def cleanup_test_ioc() -> None:
    """Remove test IOC from Redis cache."""
    from app.services.ti.ioc_cache import IOCCache
    from app.services.ti.ioc_types import IOCType

    cache = IOCCache()
    deleted = await cache.evict_ioc(IOCType.IP_SRC, TEST_IOC_IP)
    if deleted:
        print(f"   Cleaned up IOC: {TEST_IOC_IP}")
    else:
        print(f"   IOC not found: {TEST_IOC_IP}")


async def run_pull_detection(db_session, index_pattern_id: str) -> dict:
    """Manually trigger pull detection for the test index pattern."""
    from app.services.pull_detector import run_poll_job

    print("   Running pull detection poll...")
    await run_poll_job(index_pattern_id)

    # Get poll state to check results
    from sqlalchemy import select
    from app.models.poll_state import IndexPatternPollState

    result = await db_session.execute(
        select(IndexPatternPollState).where(
            IndexPatternPollState.index_pattern_id == index_pattern_id
        )
    )
    poll_state = result.scalar_one_or_none()

    return {
        "status": poll_state.last_poll_status if poll_state else "unknown",
        "events_scanned": poll_state.total_events_scanned if poll_state else 0,
        "matches_found": poll_state.total_matches if poll_state else 0,
        "error": poll_state.last_error if poll_state else None,
    }


async def get_admin_user_id(db_session) -> str:
    """Get an admin user ID for rule creation."""
    from sqlalchemy import select

    from app.models.user import User

    result = await db_session.execute(select(User).limit(1))
    user = result.scalar_one_or_none()
    if not user:
        print("ERROR: No users found in database")
        sys.exit(1)
    return str(user.id)


async def main():
    parser = argparse.ArgumentParser(
        description="Test pull mode alert generation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--with-ioc",
        action="store_true",
        help="Also test IOC detection (injects test IOC into Redis)",
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Remove test data after test",
    )

    args = parser.parse_args()

    # Import dependencies
    from app.db.session import async_session_maker
    from app.services.opensearch import get_client_from_settings

    print("=" * 60)
    print("CHAD Pull Mode Test Script")
    print("=" * 60)

    # Get OpenSearch client from database settings
    async with async_session_maker() as db:
        os_client = await get_client_from_settings(db)
        if not os_client:
            print("ERROR: OpenSearch not configured. Please configure OpenSearch in Settings.")
            sys.exit(1)

    # Step 1: Create test index pattern
    async with async_session_maker() as db:
        print("\n1. Setting up index pattern...")
        index_pattern_id, auth_token = await setup_test_index_pattern(db)

    # Step 2: Index test document in OpenSearch
    print("\n2. Indexing test document...")
    doc_id = await setup_opensearch_index(os_client, with_ioc=args.with_ioc)

    # Step 3: Deploy test Sigma rule
    async with async_session_maker() as db:
        print("\n3. Setting up test Sigma rule...")
        user_id = await get_admin_user_id(db)
        rule_id = await deploy_test_sigma_rule(db, index_pattern_id, user_id)

    # Step 4: Inject IOC if requested
    if args.with_ioc:
        print("\n4. Injecting test IOC...")
        await inject_test_ioc()

    # Step 5: Run pull detection
    step_num = 5 if args.with_ioc else 4
    print(f"\n{step_num}. Running pull detection...")
    async with async_session_maker() as db:
        result = await run_pull_detection(db, index_pattern_id)

    # Step 6: Report results
    step_num += 1
    print(f"\n{step_num}. Results:")
    print(f"   Poll status: {result.get('status', 'unknown')}")
    print(f"   Events scanned: {result.get('events_scanned', 0)}")
    print(f"   Matches found: {result.get('matches_found', 0)}")
    if result.get("error"):
        print(f"   Error: {result.get('error')}")

    if result.get("matches_found", 0) > 0:
        print("\n   ✓ SUCCESS: Alert(s) generated!")
    else:
        print("\n   ✗ No alerts created")
        print("   Note: Check if the rule query matches the indexed document")

    # Cleanup if requested
    if args.cleanup:
        step_num += 1
        print(f"\n{step_num}. Cleaning up...")
        if args.with_ioc:
            await cleanup_test_ioc()
        # Optionally delete test document
        try:
            os_client.delete(index=TEST_INDEX_NAME, id=doc_id, refresh=True)
            print(f"   Deleted test document: {doc_id}")
        except Exception:
            pass

    print("\n" + "=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
