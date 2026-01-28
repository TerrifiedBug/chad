"""
Structured logging configuration.

Provides JSON-structured logging with correlation IDs for production.
"""
import logging
import sys
from typing import Any

from app.core.config import settings


def setup_logging() -> None:
    """
    Configure structured logging for the application.

    In production: JSON format with timestamps and request IDs
    In development: Readable text format with colors
    """
    log_level = getattr(logging, settings.LOG_LEVEL)

    if settings.DEBUG:
        # Development: Human-readable logging
        configure_development_logging(log_level)
    else:
        # Production: JSON logging
        configure_production_logging(log_level)


def configure_development_logging(level: int) -> None:
    """Configure logging for development (readable format)."""
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        stream=sys.stdout,
    )

    # Silence noisy SQLAlchemy engine logs
    logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)
    logging.getLogger('sqlalchemy.pool').setLevel(logging.WARNING)
    logging.getLogger('sqlalchemy.dialects').setLevel(logging.WARNING)
    logging.getLogger('sqlalchemy.orm').setLevel(logging.WARNING)


def configure_production_logging(level: int) -> None:
    """Configure logging for production (JSON format)."""
    try:
        import structlog

        # Configure structlog
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                # Sensitive data redaction
                redact_sensitive_data,
                # JSON output
                structlog.processors.JSONRenderer(),
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )

        # Configure standard logging to use structlog
        logging.basicConfig(
            format="%(message)s",
            stream=sys.stdout,
            level=level,
        )

    except ImportError:
        # Fallback to python-json-logger if structlog not available
        from pythonjsonlogger import jsonlogger

        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            jsonlogger.JsonFormatter(
                '%(asctime)s %(name)s %(levelname)s %(message)s',
                timestamp=True
            )
        )

        root_logger = logging.getLogger()
        root_logger.handlers = [handler]
        root_logger.setLevel(level)


def redact_sensitive_data(
    logger: logging.Logger,
    method_name: str,
    event_dict: dict[str, Any],
) -> dict[str, Any]:
    """
    Redact sensitive data from logs.

    Removes or masks:
    - API keys and tokens
    - Passwords
    - Session IDs
    - PII (email addresses, IP addresses in production)
    """
    # Fields to redact completely
    sensitive_fields = [
        'password',
        'token',
        'api_key',
        'secret',
        'session_id',
        'csrf_token',
        'authorization',
        'cookie',
        'x-api-key',
    ]

    # Create a copy to avoid mutating original
    redacted = event_dict.copy()

    for key, value in redacted.items():
        if isinstance(key, str):
            # Check if this is a sensitive field
            key_lower = key.lower()
            if any(sensitive in key_lower for sensitive in sensitive_fields):
                redacted[key] = "***REDACTED***"
            elif isinstance(value, str):
                # Check for common patterns in string values
                redacted[key] = redact_string(value)

    return redacted


def redact_string(value: str) -> str:
    """
    Redact sensitive patterns from strings.

    Patterns:
    - Email addresses
    - API keys (long alphanumeric strings)
    - Tokens (JWT, etc.)
    """
    import re

    # Redact email addresses
    if '@' in value and '.' in value.split('@')[-1]:
        # Looks like an email
        parts = value.split('@')
        if len(parts) == 2:
            return f"{parts[0][0]}***@{parts[1]}"

    # Redact potential API keys/tokens (long alphanumeric strings)
    if len(value) > 20 and value.replace('_', '').replace('-', '').isalnum():
        return f"{value[:8]}...{value[-4:]}"

    return value


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance.

    Args:
        name: Logger name (usually __name__)

    Returns:
        Logger instance
    """
    return logging.getLogger(name)


class LogHelper:
    """
    Helper for consistent structured logging.

    Usage:
        logger = LogHelper(__name__)
        logger.info("User logged in", user_id=123, email="user@example.com")
        logger.error("Failed to create rule", error=str(e), rule_id=456)
    """

    def __init__(self, name: str):
        self.logger = get_logger(name)
        self.name = name

    def _add_context(self, **kwargs: Any) -> dict[str, Any]:
        """Add standard context to all log entries."""
        context = {
            "service": "chad-backend",
            "logger": self.name,
        }
        context.update(kwargs)
        return context

    def debug(self, message: str, **kwargs: Any) -> None:
        """Log debug message."""
        self.logger.debug(message, extra=self._add_context(**kwargs))

    def info(self, message: str, **kwargs: Any) -> None:
        """Log info message."""
        self.logger.info(message, extra=self._add_context(**kwargs))

    def warning(self, message: str, **kwargs: Any) -> None:
        """Log warning message."""
        self.logger.warning(message, extra=self._add_context(**kwargs))

    def error(self, message: str, **kwargs: Any) -> None:
        """Log error message."""
        self.logger.error(message, extra=self._add_context(**kwargs))

    def critical(self, message: str, **kwargs: Any) -> None:
        """Log critical message."""
        self.logger.critical(message, extra=self._add_context(**kwargs))

    def exception(self, message: str, **kwargs: Any) -> None:
        """Log exception with traceback."""
        self.logger.exception(message, extra=self._add_context(**kwargs))
