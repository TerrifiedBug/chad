"""Background health check tasks for monitoring external services."""

from datetime import UTC, datetime

from opensearchpy.exceptions import ConnectionError, TransportError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.health_check import HealthCheckLog
from app.models.setting import Setting
from app.services.health_check import HealthCheckService
from opensearchpy import OpenSearch


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
