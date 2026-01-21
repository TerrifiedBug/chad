from datetime import datetime

from sqlalchemy import DateTime, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(255), primary_key=True)
    value: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
