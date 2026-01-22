import secrets
from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin


def generate_api_key() -> str:
    """Generate a secure API key with a chad_ prefix."""
    return f"chad_{secrets.token_urlsafe(32)}"


class APIKey(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "api_keys"

    # The full key is only returned once at creation time
    # We store a hash of the key for verification
    key_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    key_prefix: Mapped[str] = mapped_column(String(20), nullable=False)  # First few chars for identification

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Link to owner user
    user_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    user = relationship("User", backref="api_keys")

    # Optional expiration
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Track last usage
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Status
    is_active: Mapped[bool] = mapped_column(default=True)
