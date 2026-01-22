import secrets

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDMixin


def generate_auth_token() -> str:
    """Generate a secure auth token for log shipping."""
    return secrets.token_urlsafe(32)


class IndexPattern(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "index_patterns"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    pattern: Mapped[str] = mapped_column(String(255), nullable=False)
    percolator_index: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    auth_token: Mapped[str] = mapped_column(
        String(64), nullable=False, default=generate_auth_token
    )
