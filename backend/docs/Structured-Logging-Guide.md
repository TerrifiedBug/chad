# Structured Logging Guide

## Overview

CHAD uses structured logging for production-ready log management. All logs include:
- Timestamps (ISO 8601 format)
- Request IDs (for tracing requests across logs)
- Sensitive data redaction (tokens, passwords, emails)
- JSON format in production (text format in development)

## Usage

### Basic Logging

```python
import logging

logger = logging.getLogger(__name__)

logger.info("User logged in", extra={"user_id": user.id})
logger.error("Failed to create rule", extra={"error": str(e), "rule_id": rule.id})
```

### Using LogHelper (Recommended)

```python
from app.core.logging import LogHelper

logger = LogHelper(__name__)

# Automatic context management
logger.info("User logged in", user_id=123)
logger.error("Failed to create rule", error=str(e), rule_id=456)

# With exception handling
try:
    create_rule(data)
except Exception as e:
    logger.exception("Failed to create rule", rule_id=data["id"])
```

### Request IDs

Every request automatically gets a unique `request_id` that's:
- Added to response headers (`X-Request-ID`)
- Included in all log entries for that request
- Traceable across all services

```python
# In your endpoint
logger.info("Processing request", user_id=user.id, request_id=request.state.request_id)
```

## Log Levels

- `DEBUG`: Detailed diagnostic information
- `INFO`: General informational messages (default)
- `WARNING`: Something unexpected but recoverable
- `ERROR`: Error occurred, operation failed
- `CRITICAL`: Critical error, service may be unavailable

## Sensitive Data Redaction

The following are automatically redacted from logs:
- Passwords
- API keys and tokens
- Session IDs
- CSRF tokens
- Email addresses (partially masked)
- Long alphanumeric strings (potential API keys)

Example:
```python
# This will be logged as: {"email": "u***@example.com", "token": "abc1...2345"}
logger.info("User action", email="user@example.com", token="abc123def456")
```

## Environments

### Development (DEBUG=True)
Human-readable text format:
```
2025-01-26 14:30:45 - app.api.auth - INFO - User logged in
```

### Production (DEBUG=False)
JSON format:
```json
{
  "timestamp": "2025-01-26T14:30:45.123Z",
  "logger": "app.api.auth",
  "level": "info",
  "service": "chad-backend",
  "request_id": "abc-123-def",
  "event": "User logged in",
  "user_id": 123
}
```

## Querying Logs

### With grep (Development)
```bash
grep "request_id=abc-123" /var/log/chad/backend.log
```

### With jq (Production JSON logs)
```bash
jq 'select(.request_id == "abc-123")' /var/log/chad/backend.log
```

### With Elasticsearch/OpenSearch
```json
{
  "query": {
    "term": { "request_id": "abc-123" }
  }
}
```

## Best Practices

1. **Add Context**: Always include relevant context in log entries
   ```python
   # Good
   logger.info("Rule created", rule_id=rule.id, user_id=user.id)

   # Bad
   logger.info("Rule created")
   ```

2. **Use Appropriate Levels**: Choose the right log level
   ```python
   logger.debug("Detailed diagnostic info")  # For debugging
   logger.info("Normal operation")  # Normal events
   logger.warning("Something unexpected")  # Recoverable issues
   logger.error("Operation failed")  # Errors
   logger.critical("Service unavailable")  # Critical issues
   ```

3. **Don't Log Sensitive Data**: Let the redaction handle it, but avoid explicitly logging secrets
   ```python
   # Bad - explicitly logging password
   logger.info("User login", password=password)  # Will be redacted, but don't do this!

   # Good - no sensitive data
   logger.info("User login successful", user_id=user.id)
   ```

4. **Log Exceptions**: Use `logger.exception()` in exception handlers
   ```python
   try:
       create_rule(data)
   except Exception as e:
       logger.exception("Failed to create rule", rule_id=data.get("id"))
       raise
   ```

## Monitoring and Alerting

Recommended alerts:
- High rate of ERROR level logs
- Critical level logs
- Specific error patterns (e.g., "authentication failed")
- Missing request IDs (indicates middleware issue)

## Log Rotation

Configure in production:
```bash
# /etc/logrotate.d/chad
/var/log/chad/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 chad chad
}
```
