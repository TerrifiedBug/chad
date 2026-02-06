"""Custom exceptions for CHAD backend."""


class OpenSearchUnavailableError(Exception):
    """Raised when OpenSearch is unreachable and no cached data is available."""

    def __init__(self, reason: str = "unknown"):
        self.reason = reason
        super().__init__(f"OpenSearch unavailable: {reason}")
