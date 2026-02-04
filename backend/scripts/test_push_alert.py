#!/usr/bin/env python3
"""
Test script for push mode alert generation.

This script sets up everything needed to test push mode alerts:
1. Creates a test index pattern with push mode
2. Creates OpenSearch index with field mappings (via test document)
3. Creates and deploys a test Sigma rule
4. Optionally injects test IOC into Redis
5. Sends a test log that triggers the rule and/or IOC detection
6. Reports results

Run from backend container:
    docker compose -f docker-compose.dev.yml exec backend python scripts/test_push_alert.py

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

import httpx

# Test constants
TEST_INDEX_PATTERN_NAME = "chad-test-push"
TEST_INDEX_NAME = f"{TEST_INDEX_PATTERN_NAME}-test"
TEST_PERCOLATOR_INDEX = f"chad-percolator-{TEST_INDEX_PATTERN_NAME}"
TEST_IOC_IP = "192.0.2.1"  # TEST-NET-1 (reserved for documentation)
TEST_IOC_EVENT_ID = "test-event-001"

# Test Sigma rule - uses ECS field names that match our test log
# Note: The ID must be a valid UUID per Sigma specification
TEST_SIGMA_RULE = """
title: CHAD Test Rule - Push Mode
id: 00000000-0000-0000-0000-000000000001
status: test
description: Test rule for validating push mode alert generation
author: CHAD Testing
date: 2026/02/04
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        process.command_line|contains: 'CHAD_TEST_PUSH'
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
            "command_line": "cmd.exe /c echo CHAD_TEST_PUSH",
            "pid": 1234,
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


async def setup_opensearch_index(os_client) -> None:
    """Create test index in OpenSearch with a sample document for field mappings."""
    # Check if index exists
    if os_client.indices.exists(index=TEST_INDEX_NAME):
        print(f"   Test index exists: {TEST_INDEX_NAME}")
        return

    # Index a sample document to create the index with proper mappings
    sample_doc = create_test_log(with_ioc=True)
    sample_doc["@timestamp"] = datetime.now(UTC).isoformat()

    os_client.index(
        index=TEST_INDEX_NAME,
        body=sample_doc,
        refresh=True,
    )
    print(f"   Created test index: {TEST_INDEX_NAME}")


async def setup_percolator_index(os_client) -> None:
    """Create or update percolator index for Sigma rules, syncing field mappings from source."""
    from app.services.percolator import PercolatorService

    percolator = PercolatorService(os_client)

    # Use PercolatorService to create/update the percolator index
    # This copies field mappings from the source index so queries validate correctly
    percolator.ensure_percolator_index(TEST_PERCOLATOR_INDEX, TEST_INDEX_NAME)

    if os_client.indices.exists(index=TEST_PERCOLATOR_INDEX):
        print(f"   Percolator index ready: {TEST_PERCOLATOR_INDEX}")
    else:
        print(f"   Created percolator index: {TEST_PERCOLATOR_INDEX}")


async def setup_test_index_pattern(db_session) -> tuple[str, str]:
    """Create or update test index pattern with push mode.

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
        # Ensure IOC detection is enabled with proper field mappings
        # ioc_field_mappings uses IOCType enum values: ip-src, ip-dst, domain, etc.
        pattern.ioc_detection_enabled = True
        pattern.ioc_field_mappings = {
            "ip-src": ["source.ip", "client_real_ip"],
            "ip-dst": ["destination.ip"],
            "domain": ["dns.question.name", "url.domain"],
        }
        await db_session.commit()
        return str(pattern.id), pattern.auth_token

    # Create new test pattern
    auth_token = secrets.token_urlsafe(32)
    pattern = IndexPattern(
        name=TEST_INDEX_PATTERN_NAME,
        pattern=f"{TEST_INDEX_PATTERN_NAME}-*",
        percolator_index=TEST_PERCOLATOR_INDEX,
        description="Test index pattern for push mode alert testing",
        auth_token=auth_token,
        mode="push",
        ioc_detection_enabled=True,
        # ioc_field_mappings uses IOCType enum values: ip-src, ip-dst, domain, etc.
        ioc_field_mappings={
            "ip-src": ["source.ip", "client_real_ip"],
            "ip-dst": ["destination.ip"],
            "domain": ["dns.question.name", "url.domain"],
        },
    )
    db_session.add(pattern)
    await db_session.commit()
    await db_session.refresh(pattern)

    print(f"   Created index pattern: {pattern.name}")
    return str(pattern.id), pattern.auth_token


async def deploy_test_sigma_rule(db_session, os_client, index_pattern_id: str, user_id: str):
    """Create and deploy the test Sigma rule."""
    from sqlalchemy import select

    from app.models.rule import Rule
    from app.services.sigma import sigma_service

    # Check if rule already exists
    result = await db_session.execute(
        select(Rule).where(Rule.title == "CHAD Test Rule - Push Mode")
    )
    existing_rule = result.scalar_one_or_none()

    if existing_rule:
        print(f"   Using existing rule: {existing_rule.title}")
        rule = existing_rule
        # Always update rule content and index pattern to ensure latest test config
        rule.yaml_content = TEST_SIGMA_RULE.strip()
        rule.index_pattern_id = uuid.UUID(index_pattern_id)
        rule.status = "undeployed"  # Force re-deployment
        await db_session.commit()
    else:
        # Create new rule
        rule = Rule(
            title="CHAD Test Rule - Push Mode",
            description="Test rule for push mode alert generation",
            yaml_content=TEST_SIGMA_RULE.strip(),
            severity="medium",
            status="undeployed",
            index_pattern_id=uuid.UUID(index_pattern_id),
            created_by=uuid.UUID(user_id),
            source="user",
        )
        db_session.add(rule)
        await db_session.commit()
        await db_session.refresh(rule)
        print(f"   Created rule: {rule.title}")

    # Deploy to OpenSearch percolator
    if rule.status != "deployed":
        # Translate Sigma to OpenSearch query
        validation = sigma_service.translate_and_validate(rule.yaml_content)
        if not validation.success:
            errors = ", ".join(e.message for e in (validation.errors or []))
            print(f"   ERROR: Failed to translate rule: {errors}")
            return

        # Index to percolator
        # Sigma returns {"query": {"query_string": ...}}, percolator needs {"query_string": ...}
        percolator_query = validation.query.get("query", validation.query) if validation.query else {}
        perc_doc = {
            "query": percolator_query,
            "rule_id": str(rule.id),
            "rule_title": rule.title,
            "severity": rule.severity,
            "tags": ["test.chad"],
        }

        os_client.index(
            index=TEST_PERCOLATOR_INDEX,
            id=str(rule.id),
            body=perc_doc,
            refresh=True,
        )

        rule.status = "deployed"
        rule.deployed_at = datetime.now(UTC)
        await db_session.commit()
        print(f"   Deployed rule to percolator: {TEST_PERCOLATOR_INDEX}")
    else:
        print(f"   Rule already deployed")


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
        misp_event_info="Test Event - Push Mode IOC Detection",
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


async def send_push_log(api_url: str, auth_token: str, log: dict) -> dict:
    """Send a log to the push webhook endpoint."""
    url = f"{api_url}/api/logs/{TEST_INDEX_PATTERN_NAME}"
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(url, json=[log], headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            print(f"ERROR: Push failed with status {response.status_code}")
            print(f"Response: {response.text}")
            sys.exit(1)


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
        description="Test push mode alert generation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--api-url",
        default="http://backend:8000",
        help="CHAD API base URL (default: http://backend:8000)",
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
    print("CHAD Push Mode Test Script")
    print("=" * 60)

    # Get OpenSearch client from database settings
    async with async_session_maker() as db:
        os_client = await get_client_from_settings(db)
        if not os_client:
            print("ERROR: OpenSearch not configured. Please configure OpenSearch in Settings.")
            sys.exit(1)

    # Step 1: Create OpenSearch indexes
    print("\n1. Setting up OpenSearch indexes...")
    await setup_opensearch_index(os_client)
    await setup_percolator_index(os_client)

    async with async_session_maker() as db:
        # Step 2: Setup index pattern
        print("\n2. Setting up index pattern...")
        index_pattern_id, auth_token = await setup_test_index_pattern(db)

        # Step 3: Deploy test Sigma rule
        print("\n3. Deploying test Sigma rule...")
        user_id = await get_admin_user_id(db)
        await deploy_test_sigma_rule(db, os_client, index_pattern_id, user_id)

    # Step 4: Inject IOC if requested
    if args.with_ioc:
        print("\n4. Injecting test IOC...")
        await inject_test_ioc()

    # Step 5: Create and send test log
    step_num = 5 if args.with_ioc else 4
    print(f"\n{step_num}. Sending test log...")
    log = create_test_log(with_ioc=args.with_ioc)
    print(f"   Timestamp: {log['@timestamp']}")
    print(f"   CommandLine: {log['process']['command_line']}")
    if args.with_ioc:
        print(f"   Source IP (IOC): {log['source']['ip']}")

    result = await send_push_log(args.api_url, auth_token, log)

    # Step 6: Report results
    step_num += 1
    print(f"\n{step_num}. Results:")
    print(f"   Logs received: {result.get('logs_received', 0)}")
    print(f"   Matches found: {result.get('matches_found', 0)}")
    print(f"   Alerts created: {result.get('alerts_created', 0)}")

    if result.get("alerts_created", 0) > 0:
        print("\n   ✓ SUCCESS: Alert(s) generated!")
    else:
        print("\n   ✗ No alerts created")

    # Cleanup if requested
    if args.cleanup and args.with_ioc:
        step_num += 1
        print(f"\n{step_num}. Cleaning up...")
        await cleanup_test_ioc()

    print("\n" + "=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
