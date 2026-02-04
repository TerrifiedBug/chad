#!/usr/bin/env python3
"""
Test script for pull mode alert generation.

Injects test logs directly into OpenSearch to trigger Sigma rule matches
during pull mode detection cycles.

Usage:
    # Basic pull test (requires index pattern with pull mode)
    python scripts/test_pull_alert.py --index logs-windows-*

    # With IOC injection (requires Redis)
    python scripts/test_pull_alert.py --index logs-windows-* --with-ioc

    # With cleanup after test
    python scripts/test_pull_alert.py --index logs-windows-* --with-ioc --cleanup

    # Wait for detection (polls for alert creation)
    python scripts/test_pull_alert.py --index logs-windows-* --wait

Environment variables:
    OPENSEARCH_URL: OpenSearch URL (default: http://localhost:9200)
"""

import argparse
import asyncio
import sys
import time
import uuid
from datetime import UTC, datetime, timedelta

# Test IOC for injection
TEST_IOC_IP = "192.0.2.2"  # TEST-NET-1 (reserved for documentation)
TEST_IOC_EVENT_ID = "test-event-002"
TEST_IOC_ATTRIBUTE_UUID = str(uuid.uuid4())


def create_test_log(with_ioc: bool = False) -> dict:
    """Create a test log document that matches the test Sigma rule.

    The test rule matches: user.name|contains: 'CHAD_TEST_PULL'
    """
    log = {
        "@timestamp": datetime.now(UTC).isoformat(),
        "event": {
            "type": "authentication_success",
            "category": "authentication",
            "outcome": "success",
        },
        "user": {
            "name": "CHAD_TEST_PULL_USER",
            "domain": "WORKGROUP",
        },
        "source": {
            "ip": "10.0.0.50",
        },
        "host": {
            "name": "test-server",
            "ip": ["10.0.0.10"],
        },
        "message": "User CHAD_TEST_PULL_USER logged in successfully",
    }

    # Add IOC field if testing IOC detection
    if with_ioc:
        log["source"]["ip"] = TEST_IOC_IP
        log["client_real_ip"] = TEST_IOC_IP

    return log


async def inject_test_ioc() -> None:
    """Inject test IOC into Redis cache."""
    try:
        from app.services.ti.ioc_cache import IOCCache
        from app.services.ti.ioc_types import IOCRecord, IOCType
    except ImportError:
        print("ERROR: Cannot import CHAD modules. Run this script inside the backend container:")
        print("  docker compose -f docker-compose.dev.yml exec backend python scripts/test_pull_alert.py ...")
        sys.exit(1)

    record = IOCRecord(
        ioc_type=IOCType.IP_SRC,
        value=TEST_IOC_IP,
        misp_event_id=TEST_IOC_EVENT_ID,
        misp_event_uuid=str(uuid.uuid4()),
        misp_attribute_uuid=TEST_IOC_ATTRIBUTE_UUID,
        misp_event_info="Test Event - Pull Mode IOC Detection",
        threat_level="medium",
        tags=["test", "chad-test"],
        first_seen=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )

    cache = IOCCache()
    await cache.store_ioc(record)
    print(f"Injected test IOC: {TEST_IOC_IP} (type: ip-src)")


async def cleanup_test_ioc() -> None:
    """Remove test IOC from Redis cache."""
    try:
        from app.services.ti.ioc_cache import IOCCache
        from app.services.ti.ioc_types import IOCType
    except ImportError:
        print("WARNING: Cannot import CHAD modules for cleanup")
        return

    cache = IOCCache()
    deleted = await cache.evict_ioc(IOCType.IP_SRC, TEST_IOC_IP)
    if deleted:
        print(f"Cleaned up test IOC: {TEST_IOC_IP}")
    else:
        print(f"Test IOC not found in cache: {TEST_IOC_IP}")


def inject_log_to_opensearch(index: str, log: dict, os_url: str) -> str:
    """Inject a log document directly into OpenSearch.

    Returns:
        Document ID of the indexed log.
    """
    try:
        from opensearchpy import OpenSearch
    except ImportError:
        print("ERROR: opensearch-py not installed")
        sys.exit(1)

    # Parse URL for auth if present
    client = OpenSearch(
        hosts=[os_url],
        http_compress=True,
        use_ssl=os_url.startswith("https"),
        verify_certs=False,
        ssl_show_warn=False,
    )

    # Generate a unique doc ID for easy cleanup
    doc_id = f"chad-test-{uuid.uuid4().hex[:8]}"

    result = client.index(
        index=index,
        id=doc_id,
        body=log,
        refresh=True,  # Make immediately searchable
    )

    return result["_id"]


def cleanup_test_log(index: str, doc_id: str, os_url: str) -> bool:
    """Remove test log from OpenSearch."""
    try:
        from opensearchpy import OpenSearch
    except ImportError:
        return False

    client = OpenSearch(
        hosts=[os_url],
        http_compress=True,
        use_ssl=os_url.startswith("https"),
        verify_certs=False,
        ssl_show_warn=False,
    )

    try:
        client.delete(index=index, id=doc_id, refresh=True)
        return True
    except Exception:
        return False


async def main():
    parser = argparse.ArgumentParser(
        description="Test pull mode alert generation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--index",
        required=True,
        help="OpenSearch index to inject test log (e.g., 'logs-windows-2026.02.04')",
    )
    parser.add_argument(
        "--os-url",
        default="http://localhost:9200",
        help="OpenSearch URL (default: http://localhost:9200)",
    )
    parser.add_argument(
        "--with-ioc",
        action="store_true",
        help="Inject test IOC into Redis before injecting log",
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Remove test log and IOC after test",
    )
    parser.add_argument(
        "--wait",
        type=int,
        default=0,
        metavar="SECONDS",
        help="Wait for detection cycle (0 = don't wait)",
    )

    args = parser.parse_args()

    print("=" * 60)
    print("CHAD Pull Mode Test Script")
    print("=" * 60)

    # Inject IOC if requested
    if args.with_ioc:
        print("\n1. Injecting test IOC into Redis...")
        await inject_test_ioc()

    # Create test log
    print("\n2. Creating test log document...")
    log = create_test_log(with_ioc=args.with_ioc)
    print(f"   Log timestamp: {log['@timestamp']}")
    print(f"   User: {log['user']['name']}")
    if args.with_ioc:
        print(f"   Source IP (IOC): {log['source']['ip']}")

    # Inject into OpenSearch
    print(f"\n3. Injecting log into OpenSearch index: {args.index}...")
    doc_id = inject_log_to_opensearch(args.index, log, args.os_url)
    print(f"   Document ID: {doc_id}")

    print("\n4. Log injected successfully!")
    print("   The pull detector will pick up this log on the next detection cycle.")
    print("   Check the Alerts page in CHAD UI for new alerts.")

    # Wait if requested
    if args.wait > 0:
        print(f"\n5. Waiting {args.wait} seconds for detection cycle...")
        for i in range(args.wait):
            time.sleep(1)
            remaining = args.wait - i - 1
            if remaining > 0 and remaining % 10 == 0:
                print(f"   {remaining} seconds remaining...")
        print("   Wait complete. Check CHAD UI for alerts.")

    # Cleanup if requested
    if args.cleanup:
        print("\n6. Cleaning up...")
        if cleanup_test_log(args.index, doc_id, args.os_url):
            print(f"   Removed test log: {doc_id}")
        else:
            print(f"   Could not remove test log: {doc_id}")

        if args.with_ioc:
            await cleanup_test_ioc()

    print("\n" + "=" * 60)
    print(f"Test log document ID: {doc_id}")
    print("Use this ID to manually clean up if needed:")
    print(f"  DELETE /{args.index}/_doc/{doc_id}")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
