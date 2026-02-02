"""Tests for background health check tasks."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from opensearchpy.exceptions import ConnectionError
from sqlalchemy import select

from app.background.tasks.health_checks import check_jira_health, check_opensearch_health
from app.models.health_check import HealthCheckLog
from app.models.jira_config import JiraConfig
from app.models.setting import Setting


@pytest.mark.asyncio
async def test_opensearch_healthy(db_session):
    """Test OpenSearch health check when cluster is healthy."""
    # Mock OpenSetting configuration
    mock_setting = MagicMock()
    mock_setting.value = {
        "host": "localhost",
        "port": 9200,
        "username": "admin",
        "password": "admin",
        "use_ssl": False,
        "verify_certs": False,
    }

    # Create the setting in DB
    setting = Setting(key="opensearch", value=mock_setting.value)
    db_session.add(setting)
    await db_session.commit()

    with patch("app.background.tasks.health_checks.OpenSearch") as mock_os_class:
        mock_os = MagicMock()
        mock_os.cluster.health.return_value = {"status": "green"}
        mock_os_class.return_value = mock_os

        await check_opensearch_health(db_session)

    # Verify health log was created
    result = await db_session.execute(
        select(HealthCheckLog).filter_by(service_type="opensearch")
    )
    log = result.scalar_one_or_none()

    assert log is not None
    assert log.status == "healthy"
    assert log.service_name == "OpenSearch"
    assert log.response_time_ms is not None


@pytest.mark.asyncio
async def test_opensearch_yellow_warning(db_session):
    """Test OpenSearch health check when cluster status is yellow."""
    mock_setting_value = {
        "host": "localhost",
        "port": 9200,
        "username": "admin",
        "password": "admin",
        "use_ssl": False,
        "verify_certs": False,
    }

    setting = Setting(key="opensearch", value=mock_setting_value)
    db_session.add(setting)
    await db_session.commit()

    with patch("app.background.tasks.health_checks.OpenSearch") as mock_os_class:
        mock_os = MagicMock()
        mock_os.cluster.health.return_value = {"status": "yellow"}
        mock_os_class.return_value = mock_os

        await check_opensearch_health(db_session)

    result = await db_session.execute(
        select(HealthCheckLog).filter_by(service_type="opensearch")
    )
    log = result.scalar_one_or_none()

    assert log is not None
    assert log.status == "warning"
    assert "yellow" in log.error_message


@pytest.mark.asyncio
async def test_opensearch_red_unhealthy(db_session):
    """Test OpenSearch health check when cluster status is red."""
    mock_setting_value = {
        "host": "localhost",
        "port": 9200,
        "username": "admin",
        "password": "admin",
        "use_ssl": False,
        "verify_certs": False,
    }

    setting = Setting(key="opensearch", value=mock_setting_value)
    db_session.add(setting)
    await db_session.commit()

    with patch("app.background.tasks.health_checks.OpenSearch") as mock_os_class:
        mock_os = MagicMock()
        mock_os.cluster.health.return_value = {"status": "red"}
        mock_os_class.return_value = mock_os

        await check_opensearch_health(db_session)

    result = await db_session.execute(
        select(HealthCheckLog).filter_by(service_type="opensearch")
    )
    log = result.scalar_one_or_none()

    assert log is not None
    assert log.status == "unhealthy"
    assert "red" in log.error_message


@pytest.mark.asyncio
async def test_opensearch_connection_error(db_session):
    """Test OpenSearch health check when connection fails."""
    mock_setting_value = {
        "host": "localhost",
        "port": 9200,
        "username": "admin",
        "password": "admin",
        "use_ssl": False,
        "verify_certs": False,
    }

    setting = Setting(key="opensearch", value=mock_setting_value)
    db_session.add(setting)
    await db_session.commit()

    with patch("app.background.tasks.health_checks.OpenSearch") as mock_os_class:
        # Use proper opensearchpy ConnectionError (400, "Connection refused")
        mock_os_class.side_effect = ConnectionError(400, "Connection refused")

        await check_opensearch_health(db_session)

    result = await db_session.execute(
        select(HealthCheckLog).filter_by(service_type="opensearch")
    )
    log = result.scalar_one_or_none()

    assert log is not None
    assert log.status == "unhealthy"
    # The exception's info property fails, so we return a generic message
    assert "Connection" in log.error_message or "error" in log.error_message.lower()


@pytest.mark.asyncio
async def test_opensearch_not_configured(db_session):
    """Test OpenSearch health check when OpenSearch is not configured."""
    # Don't create any setting - should handle gracefully
    await check_opensearch_health(db_session)

    result = await db_session.execute(
        select(HealthCheckLog).filter_by(service_type="opensearch")
    )
    log = result.scalar_one_or_none()

    assert log is not None
    assert log.status == "unhealthy"
    assert "not configured" in log.error_message


@pytest.mark.asyncio
async def test_jira_healthy(db_session):
    """Test Jira health check when connection succeeds."""
    config = JiraConfig(
        jira_url="https://test.atlassian.net",
        email="test@example.com",
        api_token_encrypted="encrypted_token",
        default_project="TEST",
        default_issue_type="Bug",
        is_enabled=True
    )
    db_session.add(config)
    await db_session.commit()

    with patch("app.background.tasks.health_checks.JiraService") as mock_jira_class:
        mock_jira = MagicMock()
        mock_jira.test_connection = AsyncMock(return_value=True)
        mock_jira_class.return_value = mock_jira

        await check_jira_health(db_session)

    # Verify health log was created
    result = await db_session.execute(
        select(HealthCheckLog).filter_by(service_type="jira")
    )
    log = result.scalar_one_or_none()

    assert log is not None
    assert log.status == "healthy"
    assert log.service_name == "Jira Cloud"

    # Verify config was updated
    await db_session.refresh(config)
    assert config.last_health_status == "healthy"
    assert config.health_check_error is None


@pytest.mark.asyncio
async def test_jira_disabled(db_session):
    """Test Jira health check when Jira is disabled."""
    config = JiraConfig(
        jira_url="https://test.atlassian.net",
        email="test@example.com",
        api_token_encrypted="encrypted_token",
        default_project="TEST",
        default_issue_type="Bug",
        is_enabled=False
    )
    db_session.add(config)
    await db_session.commit()

    await check_jira_health(db_session)

    result = await db_session.execute(
        select(HealthCheckLog).filter_by(service_type="jira")
    )
    log = result.scalar_one_or_none()

    assert log is not None
    assert log.status == "unhealthy"
    assert "disabled" in log.error_message


@pytest.mark.asyncio
async def test_jira_connection_error(db_session):
    """Test Jira health check when connection fails."""
    from app.services.jira import JiraAPIError

    config = JiraConfig(
        jira_url="https://test.atlassian.net",
        email="test@example.com",
        api_token_encrypted="encrypted_token",
        default_project="TEST",
        default_issue_type="Bug",
        is_enabled=True
    )
    db_session.add(config)
    await db_session.commit()

    with patch("app.background.tasks.health_checks.JiraService") as mock_jira_class:
        mock_jira = MagicMock()
        mock_jira.test_connection = AsyncMock(
            side_effect=JiraAPIError(message="Authentication failed")
        )
        mock_jira_class.return_value = mock_jira

        await check_jira_health(db_session)

    result = await db_session.execute(
        select(HealthCheckLog).filter_by(service_type="jira")
    )
    log = result.scalar_one_or_none()

    assert log is not None
    assert log.status == "unhealthy"
    assert "Authentication failed" in log.error_message

    # Verify config was updated
    await db_session.refresh(config)
    assert config.last_health_status == "unhealthy"
    assert "Authentication failed" in config.health_check_error
