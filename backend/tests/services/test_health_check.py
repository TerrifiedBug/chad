import pytest

from app.models.jira_config import JiraConfig
from app.models.ti_config import TISourceConfig
from app.services.health_check import HealthCheckService


@pytest.mark.asyncio
async def test_log_health_check(db_session):
    """Test logging a health check result."""
    service = HealthCheckService(db_session)

    log = await service.log_health_check(
        service_type="jira",
        service_name="Jira Cloud",
        status="healthy",
        response_time_ms=150
    )

    assert log.service_type == "jira"
    assert log.service_name == "Jira Cloud"
    assert log.status == "healthy"
    assert log.response_time_ms == 150
    assert log.error_message is None


@pytest.mark.asyncio
async def test_log_health_check_with_error(db_session):
    """Test logging a failed health check with error message."""
    service = HealthCheckService(db_session)

    log = await service.log_health_check(
        service_type="opensearch",
        service_name="OpenSearch",
        status="unhealthy",
        error_message="Connection timeout",
        response_time_ms=5000
    )

    assert log.status == "unhealthy"
    assert log.error_message == "Connection timeout"
    assert log.response_time_ms == 5000


@pytest.mark.asyncio
async def test_update_jira_health(db_session):
    """Test updating Jira health status."""
    # Create a Jira config
    config = JiraConfig(
        jira_url="https://test.atlassian.net",
        email="test@example.com",
        api_token_encrypted="encrypted_token",
        default_project="TEST",
        default_issue_type="Bug"
    )
    db_session.add(config)
    await db_session.commit()

    service = HealthCheckService(db_session)
    await service.update_jira_health(status="unhealthy", error="Connection refused")

    await db_session.refresh(config)
    assert config.last_health_status == "unhealthy"
    assert config.health_check_error == "Connection refused"
    assert config.last_health_check is not None


@pytest.mark.asyncio
async def test_update_jira_health_no_config(db_session):
    """Test updating Jira health when no config exists."""
    service = HealthCheckService(db_session)

    # Should not raise an error
    await service.update_jira_health(status="healthy")


@pytest.mark.asyncio
async def test_update_ti_source_health(db_session):
    """Test updating TI source health status."""
    # Create a TI source config
    config = TISourceConfig(
        source_type="virustotal",
        is_enabled=True,
        api_key_encrypted="encrypted_key"
    )
    db_session.add(config)
    await db_session.commit()

    service = HealthCheckService(db_session)
    await service.update_ti_source_health(
        source_type="virustotal",
        status="warning",
        error="Rate limit exceeded"
    )

    await db_session.refresh(config)
    assert config.last_health_status == "warning"
    assert config.health_check_error == "Rate limit exceeded"
    assert config.last_health_check is not None


@pytest.mark.asyncio
async def test_update_ti_source_health_no_config(db_session):
    """Test updating TI source health when config doesn't exist."""
    service = HealthCheckService(db_session)

    # Should not raise an error
    await service.update_ti_source_health(
        source_type="virustotal",
        status="healthy"
    )
