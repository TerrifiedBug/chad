"""
Jira Cloud integration service.

Handles Jira Cloud REST API v3 interactions for creating tickets
when alerts fire.
"""

import base64
import logging
from typing import Any

import httpx

from app.core.encryption import decrypt
from app.models.jira_config import JiraConfig

logger = logging.getLogger(__name__)


class JiraAPIError(Exception):
    """Exception raised for Jira API errors."""

    def __init__(self, message: str, status_code: int | None = None, details: dict | None = None):
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        super().__init__(self.message)


class JiraService:
    """Service for interacting with Jira Cloud REST API v3."""

    def __init__(self, config: JiraConfig):
        """
        Initialize the Jira service with configuration.

        Args:
            config: JiraConfig model with connection details
        """
        self.config = config
        self._base_url = config.jira_url.rstrip("/")
        self._email = config.email
        self._default_project = config.default_project
        self._default_issue_type = config.default_issue_type

    def _get_auth_header(self) -> str:
        """
        Generate Basic Auth header value.

        Jira Cloud uses Basic Auth with email:api_token base64 encoded.

        Returns:
            Base64 encoded auth string for Authorization header
        """
        # Decrypt the API token from encrypted storage
        api_token = decrypt(self.config.api_token_encrypted)
        credentials = f"{self._email}:{api_token}"
        encoded = base64.b64encode(credentials.encode()).decode()
        return f"Basic {encoded}"

    def _get_headers(self) -> dict[str, str]:
        """Get common headers for Jira API requests."""
        return {
            "Authorization": self._get_auth_header(),
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        json_data: dict | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """
        Make an HTTP request to the Jira API.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint (will be appended to base URL)
            json_data: Optional JSON payload for POST/PUT requests
            timeout: Request timeout in seconds

        Returns:
            JSON response as dictionary

        Raises:
            JiraAPIError: If the API returns an error
        """
        url = f"{self._base_url}{endpoint}"

        try:
            async with httpx.AsyncClient() as client:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=self._get_headers(),
                    json=json_data,
                    timeout=timeout,
                )

                # Handle successful responses
                if response.status_code in (200, 201, 204):
                    if response.status_code == 204 or not response.content:
                        return {}
                    return response.json()

                # Handle error responses
                error_message = f"Jira API error: {response.status_code}"
                error_details = {}

                try:
                    error_body = response.json()
                    if "errorMessages" in error_body:
                        error_message = "; ".join(error_body["errorMessages"])
                    elif "errors" in error_body:
                        error_message = str(error_body["errors"])
                    error_details = error_body
                except Exception:
                    error_message = response.text[:500] if response.text else error_message

                logger.error(f"Jira API error: {response.status_code} - {error_message}")
                raise JiraAPIError(
                    message=error_message,
                    status_code=response.status_code,
                    details=error_details,
                )

        except httpx.TimeoutException as e:
            logger.error(f"Jira API timeout: {url}")
            raise JiraAPIError(
                message="Request timed out while connecting to Jira",
                details={"timeout": timeout},
            ) from e
        except httpx.RequestError as e:
            logger.error(f"Jira API network error: {e}")
            raise JiraAPIError(
                message=f"Network error while connecting to Jira: {str(e)}",
            ) from e

    async def test_connection(self) -> bool:
        """
        Test API connectivity to Jira.

        Makes a request to the serverInfo endpoint to verify credentials
        and connectivity.

        Returns:
            True if connection is successful

        Raises:
            JiraAPIError: If connection fails
        """
        try:
            result = await self._make_request("GET", "/rest/api/3/serverInfo")
            # Verify we got a valid response with expected fields
            if "baseUrl" in result or "serverTitle" in result:
                logger.info(f"Successfully connected to Jira: {result.get('serverTitle', 'Unknown')}")
                return True
            raise JiraAPIError(message="Invalid response from Jira serverInfo endpoint")
        except JiraAPIError:
            raise
        except Exception as e:
            logger.error(f"Unexpected error testing Jira connection: {e}")
            raise JiraAPIError(message=f"Unexpected error: {str(e)}") from e

    async def create_issue(
        self,
        summary: str,
        description: str,
        project: str | None = None,
        issue_type: str | None = None,
    ) -> dict[str, Any]:
        """
        Create a new Jira issue.

        Args:
            summary: Issue summary/title
            description: Issue description (plain text, will be converted to ADF)
            project: Project key (uses default if not provided)
            issue_type: Issue type name (uses default if not provided)

        Returns:
            Dict containing created issue details including:
                - id: Issue ID
                - key: Issue key (e.g., "PROJ-123")
                - self: API URL for the issue

        Raises:
            JiraAPIError: If issue creation fails
        """
        project_key = project or self._default_project
        type_name = issue_type or self._default_issue_type

        if not project_key:
            raise JiraAPIError(message="Project key is required to create an issue")
        if not type_name:
            raise JiraAPIError(message="Issue type is required to create an issue")

        # Build the issue payload using Atlassian Document Format (ADF)
        # for the description field as required by Jira Cloud API v3
        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": summary,
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [{"type": "text", "text": description}],
                        }
                    ],
                },
                "issuetype": {"name": type_name},
            }
        }

        result = await self._make_request("POST", "/rest/api/3/issue", json_data=payload)
        logger.info(f"Created Jira issue: {result.get('key')}")
        return result

    async def get_projects(self) -> list[dict[str, Any]]:
        """
        Get list of available Jira projects.

        Returns:
            List of project dictionaries containing:
                - id: Project ID
                - key: Project key
                - name: Project name

        Raises:
            JiraAPIError: If request fails
        """
        result = await self._make_request("GET", "/rest/api/3/project")

        # Result should be a list of projects
        if isinstance(result, list):
            return [
                {
                    "id": p.get("id"),
                    "key": p.get("key"),
                    "name": p.get("name"),
                }
                for p in result
            ]

        # Handle paginated response format
        if isinstance(result, dict) and "values" in result:
            return [
                {
                    "id": p.get("id"),
                    "key": p.get("key"),
                    "name": p.get("name"),
                }
                for p in result["values"]
            ]

        return []

    async def get_issue_types(self, project_key: str) -> list[dict[str, Any]]:
        """
        Get available issue types for a project.

        Args:
            project_key: The project key to get issue types for

        Returns:
            List of issue type dictionaries containing:
                - id: Issue type ID
                - name: Issue type name
                - description: Issue type description

        Raises:
            JiraAPIError: If request fails
        """
        result = await self._make_request("GET", f"/rest/api/3/project/{project_key}")

        issue_types = result.get("issueTypes", [])

        return [
            {
                "id": it.get("id"),
                "name": it.get("name"),
                "description": it.get("description", ""),
            }
            for it in issue_types
            # Filter out subtask types as they cannot be created directly
            if not it.get("subtask", False)
        ]


async def create_jira_ticket_for_alert(
    config: JiraConfig,
    alert_id: str,
    rule_title: str,
    severity: str,
    matched_log: dict[str, Any],
    alert_url: str | None = None,
) -> dict[str, Any]:
    """
    Convenience function to create a Jira ticket for an alert.

    Args:
        config: JiraConfig with Jira connection details
        alert_id: The alert ID
        rule_title: Title of the triggered rule
        severity: Alert severity level
        matched_log: The log document that triggered the alert
        alert_url: Optional URL to the alert detail page

    Returns:
        Dict with created issue details (id, key, self)

    Raises:
        JiraAPIError: If ticket creation fails
    """
    service = JiraService(config)

    # Build summary
    summary = f"[{severity.upper()}] Alert: {rule_title}"

    # Build description
    description_parts = [
        f"Alert ID: {alert_id}",
        f"Rule: {rule_title}",
        f"Severity: {severity.upper()}",
        "",
        "Matched Log Document:",
        str(matched_log),
    ]

    if alert_url:
        description_parts.insert(0, f"View in CHAD: {alert_url}")
        description_parts.insert(1, "")

    description = "\n".join(description_parts)

    return await service.create_issue(summary=summary, description=description)
