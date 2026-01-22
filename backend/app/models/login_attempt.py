"""
Login attempt tracking for rate limiting.

Stores failed login attempts per account (email) for lockout logic.
"""

from datetime import datetime
from sqlalchemy import String, DateTime, Integer, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class LoginAttempt(Base):
    """Track failed login attempts for rate limiting."""

    __tablename__ = "login_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)  # IPv6 max length
    attempted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self) -> str:
        return f"<LoginAttempt {self.email} at {self.attempted_at}>"
