"""Background health check tasks for monitoring external services."""

import ssl
from datetime import UTC, datetime

from opensearchpy import OpenSearch
from opensearchpy.exceptions import ConnectionError, TransportError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.encryption import decrypt
from app.models.jira_config import JiraConfig
from app.models.setting import Setting
from app.models.ti_config import TISourceConfig
from app.services.health_check import HealthCheckService
from app.services.jira import JiraAPIError, JiraService


async def check_opensearch_health(db: AsyncSession):
    """Check OpenSearch cluster health."""
    service = HealthCheckService(db)

    try:
        # Get OpenSearch configuration from settings
        result = await db.execute(select(Setting).where(Setting.key == "opensearch"))
        setting = result.scalar_one_or_none()

        if not setting:
            await service.log_health_check(
                service_type="opensearch",
                service_name="OpenSearch",
                status="unhealthy",
                error_message="OpenSearch not configured"
            )
            return

        config = setting.value

        # Decrypt password if stored encrypted
        password = config.get("password")
        if password:
            try:
                password = decrypt(password)
            except Exception:
                # Password may be stored in plaintext (legacy) - use as-is
                pass

        use_ssl = config.get("use_ssl", True)
        verify_certs = config.get("verify_certs", True)

        # When verify_certs is False, we need to provide an ssl_context that explicitly
        # disables certificate verification, same as in app.services.opensearch.create_client
        ssl_context = None
        if use_ssl and not verify_certs:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        opensearch_client = OpenSearch(
            hosts=[{"host": config.get("host", "localhost"), "port": config.get("port", 9200)}],
            http_auth=(config.get("username", ""), password) if config.get("username") else None,
            use_ssl=use_ssl,
            ssl_context=ssl_context,
            verify_certs=verify_certs,
            ssl_show_warn=False,
        )

        start_time = datetime.now(UTC)

        # Ping cluster
        health = opensearch_client.cluster.health()

        response_time = int((datetime.now(UTC) - start_time).total_seconds() * 1000)

        # Determine status
        status_str = health.get("status", "unknown")
        if status_str == "red":
            await service.log_health_check(
                service_type="opensearch",
                service_name="OpenSearch",
                status="unhealthy",
                error_message=f"Cluster status: {status_str}",
                response_time_ms=response_time
            )
        elif status_str == "yellow":
            await service.log_health_check(
                service_type="opensearch",
                service_name="OpenSearch",
                status="warning",
                error_message=f"Cluster status: {status_str}",
                response_time_ms=response_time
            )
        else:
            await service.log_health_check(
                service_type="opensearch",
                service_name="OpenSearch",
                status="healthy",
                response_time_ms=response_time
            )

    except (ConnectionError, TransportError) as e:
        # Safely extract error message - opensearchpy exceptions can have complex __str__
        try:
            error_msg = getattr(e, 'info', str(e))
        except (AttributeError, IndexError):
            error_msg = "Connection error"

        if isinstance(error_msg, dict):
            error_msg = error_msg.get('error', str(error_msg))
        elif not isinstance(error_msg, str):
            error_msg = str(error_msg)

        await service.log_health_check(
            service_type="opensearch",
            service_name="OpenSearch",
            status="unhealthy",
            error_message=error_msg
        )
    except Exception as e:
        await service.log_health_check(
            service_type="opensearch",
            service_name="OpenSearch",
            status="unhealthy",
            error_message=f"Unexpected error: {str(e)}"
        )


async def check_jira_health(db: AsyncSession):
    """Check Jira Cloud API connectivity."""
    service = HealthCheckService(db)

    # Get Jira config
    result = await db.execute(select(JiraConfig).limit(1))
    config = result.scalar_one_or_none()

    if not config or not config.is_enabled:
        await service.log_health_check(
            service_type="jira",
            service_name="Jira Cloud",
            status="unhealthy",
            error_message="Jira not configured or disabled"
        )
        return

    try:
        start_time = datetime.now(UTC)

        # Create Jira service and test connectivity
        jira = JiraService(config)

        await jira.test_connection()

        response_time = int((datetime.now(UTC) - start_time).total_seconds() * 1000)

        await service.log_health_check(
            service_type="jira",
            service_name="Jira Cloud",
            status="healthy",
            response_time_ms=response_time
        )
        await service.update_jira_health(status="healthy", error=None)

    except JiraAPIError as e:
        error_msg = str(e) if e.message else "Jira API error"
        await service.log_health_check(
            service_type="jira",
            service_name="Jira Cloud",
            status="unhealthy",
            error_message=error_msg
        )
        await service.update_jira_health(status="unhealthy", error=error_msg)

    except Exception as e:
        await service.log_health_check(
            service_type="jira",
            service_name="Jira Cloud",
            status="unhealthy",
            error_message=f"Unexpected error: {str(e)}"
        )
        await service.update_jira_health(status="unhealthy", error=str(e))


async def check_ti_source_health(db: AsyncSession):
    """
    Check health of all enabled TI sources.

    Uses Redis caching to avoid hitting rate limits. TI source health checks
    are cached for 5 minutes (300 seconds) to prevent excessive API calls.
    """
    import json

    from app.core.encryption import decrypt
    from app.core.redis import get_redis
    from app.services.ti import (
        AbuseIPDBClient,
        GreyNoiseClient,
        ThreatFoxClient,
        VirusTotalClient,
    )

    service = HealthCheckService(db)

    # TI health check cache TTL (5 minutes)
    TI_HEALTH_CACHE_TTL = 300
    TI_HEALTH_CACHE_PREFIX = "health:ti:"

    # Get Redis for caching
    try:
        redis = await get_redis()
    except Exception:
        redis = None

    # Get all enabled TI sources
    result = await db.execute(
        select(TISourceConfig).where(TISourceConfig.is_enabled == True)
    )
    configs = result.scalars().all()

    for config in configs:
        # Check cache first to avoid rate limits
        cache_key = f"{TI_HEALTH_CACHE_PREFIX}{config.source_type}"
        if redis:
            try:
                cached = await redis.get(cache_key)
                if cached:
                    # Use cached result, skip API call
                    cached_data = json.loads(cached)
                    config.last_health_check = datetime.now(UTC)
                    config.last_health_status = cached_data.get("status", "unknown")
                    config.health_check_error = cached_data.get("error")
                    continue  # Skip to next source
            except Exception:
                pass  # Cache miss or error, proceed with check
        client = None
        try:
            start_time = datetime.now(UTC)

            # Get API key
            api_key = None
            if config.api_key_encrypted:
                api_key = decrypt(config.api_key_encrypted)

            # Create client and test connectivity
            if config.source_type == "virustotal":
                if not api_key:
                    raise Exception("API key not configured")
                client = VirusTotalClient(api_key)
                success = await client.test_connection()
            elif config.source_type == "abuseipdb":
                if not api_key:
                    raise Exception("API key not configured")
                client = AbuseIPDBClient(api_key)
                success = await client.test_connection()
            elif config.source_type == "greynoise":
                if not api_key:
                    raise Exception("API key not configured")
                client = GreyNoiseClient(api_key)
                success = await client.test_connection()
            elif config.source_type == "threatfox":
                client = ThreatFoxClient(api_key)
                success = await client.test_connection()
            else:
                raise Exception(f"Unknown source type: {config.source_type}")

            if not success:
                raise Exception("Connection test failed")

            response_time = int((datetime.now(UTC) - start_time).total_seconds() * 1000)

            # Update health status
            config.last_health_check = datetime.now(UTC)
            config.last_health_status = "healthy"
            config.health_check_error = None

            # Cache the successful result
            if redis:
                try:
                    cache_data = json.dumps({"status": "healthy", "error": None})
                    await redis.set(cache_key, cache_data, ex=TI_HEALTH_CACHE_TTL)
                except Exception:
                    pass  # Cache write failure is non-critical

            # Log health check
            service_name = config.source_type.replace("_", " ").title()
            await service.log_health_check(
                service_type=config.source_type,
                service_name=service_name,
                status="healthy",
                response_time_ms=response_time
            )

        except Exception as e:
            error_msg = str(e)
            config.last_health_check = datetime.now(UTC)
            config.last_health_status = "unhealthy"
            config.health_check_error = error_msg

            # Cache the failed result (still cache to avoid rate limits)
            if redis:
                try:
                    cache_data = json.dumps({"status": "unhealthy", "error": error_msg})
                    await redis.set(cache_key, cache_data, ex=TI_HEALTH_CACHE_TTL)
                except Exception:
                    pass  # Cache write failure is non-critical

            service_name = config.source_type.replace("_", " ").title()
            await service.log_health_check(
                service_type=config.source_type,
                service_name=service_name,
                status="unhealthy",
                error_message=error_msg
            )
        finally:
            if client:
                try:
                    await client.close()
                except Exception:
                    pass

    await db.commit()
