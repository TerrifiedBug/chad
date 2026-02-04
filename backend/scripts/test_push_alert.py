#!/usr/bin/env python3
"""
Test script for push mode alert generation.

Sends test logs to the push webhook endpoint to trigger Sigma rule matches
and optionally IOC detections.

Usage:
    # Basic push test (requires index pattern with push mode)
    python scripts/test_push_alert.py --index-suffix my-logs --token <auth-token>

    # With IOC injection (requires Redis and MISP-style IOC)
    python scripts/test_push_alert.py --index-suffix my-logs --token <token> --with-ioc

    # With cleanup after test
    python scripts/test_push_alert.py --index-suffix my-logs --token <token> --with-ioc --cleanup

Environment variables:
    CHAD_API_URL: Base URL for CHAD API (default: http://localhost:8000)
"""

import argparse
import asyncio
import sys
import uuid
from datetime import UTC, datetime, timedelta

import httpx

# Test IOC for injection
TEST_IOC_IP = "192.0.2.1"  # TEST-NET-1 (reserved for documentation)
TEST_IOC_EVENT_ID = "test-event-001"
TEST_IOC_ATTRIBUTE_UUID = str(uuid.uuid4())


def create_test_log(with_ioc: bool = False) -> dict:
    """Create a test log document that matches the test Sigma rule.

    The test rule matches: CommandLine|contains: 'CHAD_TEST_PUSH'
    """
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

    # Add IOC field if testing IOC detection
    if with_ioc:
        log["source"] = {"ip": TEST_IOC_IP}
        log["client_real_ip"] = TEST_IOC_IP

    return log


async def inject_test_ioc() -> None:
    """Inject test IOC into Redis cache."""
    # Import here to avoid issues when running outside container
    try:
        from app.services.ti.ioc_cache import IOCCache
        from app.services.ti.ioc_types import IOCRecord, IOCType
    except ImportError:
        print("ERROR: Cannot import CHAD modules. Run this script inside the backend container:")
        print("  docker compose -f docker-compose.dev.yml exec backend python scripts/test_push_alert.py ...")
        sys.exit(1)

    record = IOCRecord(
        ioc_type=IOCType.IP_SRC,
        value=TEST_IOC_IP,
        misp_event_id=TEST_IOC_EVENT_ID,
        misp_event_uuid=str(uuid.uuid4()),
        misp_attribute_uuid=TEST_IOC_ATTRIBUTE_UUID,
        misp_event_info="Test Event - Push Mode IOC Detection",
        threat_level="high",
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


async def send_push_log(
    api_url: str,
    index_suffix: str,
    token: str,
    log: dict,
) -> dict:
    """Send a log to the push webhook endpoint."""
    url = f"{api_url}/api/logs/{index_suffix}"
    headers = {
        "Authorization": f"Bearer {token}",
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


async def main():
    parser = argparse.ArgumentParser(
        description="Test push mode alert generation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--index-suffix",
        required=True,
        help="Index suffix (e.g., 'my-logs' for chad-percolator-my-logs)",
    )
    parser.add_argument(
        "--token",
        required=True,
        help="Auth token for the index pattern",
    )
    parser.add_argument(
        "--api-url",
        default="http://localhost:8000",
        help="CHAD API base URL (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--with-ioc",
        action="store_true",
        help="Inject test IOC into Redis before sending log",
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Remove test IOC from Redis after test",
    )

    args = parser.parse_args()

    print("=" * 60)
    print("CHAD Push Mode Test Script")
    print("=" * 60)

    # Inject IOC if requested
    if args.with_ioc:
        print("\n1. Injecting test IOC into Redis...")
        await inject_test_ioc()

    # Create and send test log
    print("\n2. Creating test log document...")
    log = create_test_log(with_ioc=args.with_ioc)
    print(f"   Log timestamp: {log['@timestamp']}")
    print(f"   CommandLine: {log['process']['command_line']}")
    if args.with_ioc:
        print(f"   Source IP (IOC): {log['source']['ip']}")

    print(f"\n3. Sending log to {args.api_url}/api/logs/{args.index_suffix}...")
    result = await send_push_log(args.api_url, args.index_suffix, args.token, log)

    print("\n4. Results:")
    print(f"   Logs received: {result.get('logs_received', 0)}")
    print(f"   Matches found: {result.get('matches_found', 0)}")
    print(f"   Alerts created: {result.get('alerts_created', 0)}")

    if result.get('alerts_created', 0) > 0:
        print("\n   SUCCESS: Alert(s) generated!")
    else:
        print("\n   NOTE: No alerts created. Check:")
        print("   - Is the test Sigma rule deployed?")
        print("   - Is IOC detection enabled on the index pattern?")

    # Cleanup if requested
    if args.cleanup and args.with_ioc:
        print("\n5. Cleaning up test IOC...")
        await cleanup_test_ioc()

    print("\n" + "=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
