from datetime import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AuditChainTail(Base):
    """Singleton-per-scope pointer to the head of the audit hash chain.

    CHAD is single-tenant, so there is one row with ``scope_key='global'``. It
    holds the most recent row's hash so a new audit write can link to it under an
    advisory lock without scanning the whole table.
    """

    __tablename__ = "audit_chain_tail"

    scope_key: Mapped[str] = mapped_column(String(32), primary_key=True)
    last_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_write_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
