"""Background health check tasks for monitoring external services."""

from datetime import UTC, datetime

from opensearchpy.exceptions import ConnectionError, TransportError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.health_check import HealthCheckLog
from app.models.jira_config import JiraConfig
from app.models.ti_config import TISourceConfig
from app.models.setting import Setting
from app.services.health_check import HealthCheckService
from app.services.jira import JiraService, JiraAPIError
from opensearchpy import OpenSearch
import httpx


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
        opensearch_client = OpenSearch(
            hosts=[config.get("host", "localhost")],
            port=config.get("port", 9200),
            http_auth=(config.get("username", ""), config.get("password", "")),
            use_ssl=config.get("use_ssl", True),
            verify_certs=config.get("verify_certs", True),
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
        jira = JiraService(
            base_url=config.jira_url,
            email=config.email,
            api_token=config.api_token_encrypted
        )

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
    """Check health of all enabled TI sources."""
    service = HealthCheckService(db)

    # Get all enabled TI sources
    result = await db.execute(
        select(TISourceConfig).where(TISourceConfig.is_enabled == True)
    )
    configs = result.scalars().all()

    for config in configs:
        try:
            start_time = datetime.now(UTC)

            # Test connectivity based on source type
            if config.source_type == "virustotal":
                await _check_virustotal(config)
            elif config.source_type == "abuseipdb":
                await _check_abuseipdb(config)
            elif config.source_type == "greynoise":
                await _check_greynoise(config)
            elif config.source_type == "threatfox":
                await _check_threatfox(config)

            response_time = int((datetime.now(UTC) - start_time).total_seconds() * 1000)

            # Update health status
            config.last_health_check = datetime.now(UTC)
            config.last_health_status = "healthy"
            config.health_check_error = None

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

            service_name = config.source_type.replace("_", " ").title()
            await service.log_health_check(
                service_type=config.source_type,
                service_name=service_name,
                status="unhealthy",
                error_message=error_msg
            )

    await db.commit()


async def _check_virustotal(config: TISourceConfig):
    """Check VirusTotal API connectivity."""
    from app.core.encryption import decrypt

    api_key = decrypt(config.api_key_encrypted)

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            "https://www.virustotal.com/vtapi/v2/ip-address/report",
            params={"ip": "8.8.8.8"},  # Use Google DNS for testing
            headers={"x-apikey": api_key}
        )
        response.raise_for_status()


async def _check_abuseipdb(config: TISourceConfig):
    """Check AbuseIPDB API connectivity."""
    from app.core.encryption import decrypt

    api_key = decrypt(config.api_key_encrypted)

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": "8.8.8.8", "maxAgeInDays": "90"},
            headers={"Key": api_key, "Accept": "application/json"}
        )
        response.raise_for_status()


async def _check_greynoise(config: TISourceConfig):
    """Check GreyNoise API connectivity."""
    from app.core.encryption import decrypt

    api_key = decrypt(config.api_key_encrypted)

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            "https://api.greynoise.io/v3/noise/quick/8.8.8.8",
            headers={"key": api_key, "Accept": "application/json"}
        )
        response.raise_for_status()


async def _check_threatfox(config: TISourceConfig):
    """Check ThreatFox API connectivity."""
    from app.core.encryption import decrypt

    api_key = decrypt(config.api_key_encrypted)
    base_url = config.instance_url or "https://threatfox.abuse.ch"

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{base_url.rstrip('/')}/api/v1/",
            params={"query": "get_iocs", "days_limit": "1"},
            headers={"API-KEY": api_key}
        )
        response.raise_for_status()
