"""Queue configuration schemas."""

from pydantic import BaseModel, Field


class QueueSettings(BaseModel):
    """Queue and worker configuration settings."""

    # Queue limits
    max_queue_size: int = Field(default=100000, ge=1000, description="Maximum messages in queue")
    warning_threshold: int = Field(default=10000, ge=100, description="Queue depth warning threshold")
    critical_threshold: int = Field(default=50000, ge=1000, description="Queue depth critical threshold")

    # Backpressure behavior
    backpressure_mode: str = Field(default="drop", description="'reject' (503) or 'drop' (evict oldest)")

    # Worker settings
    batch_size: int = Field(default=500, ge=10, le=5000, description="Logs per batch")
    batch_timeout_seconds: int = Field(default=5, ge=1, le=60, description="Max wait for batch to fill")

    # Message TTL
    message_ttl_seconds: int = Field(default=1800, ge=60, description="Message TTL before dead-letter (30 min default)")


class QueueSettingsUpdate(BaseModel):
    """Update schema for queue settings."""

    max_queue_size: int | None = None
    warning_threshold: int | None = None
    critical_threshold: int | None = None
    backpressure_mode: str | None = None
    batch_size: int | None = None
    batch_timeout_seconds: int | None = None
    message_ttl_seconds: int | None = None
