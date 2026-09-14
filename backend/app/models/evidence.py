from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.constants import EvidenceStatus
from app.database.connection import Base
from app.utils.helpers import generate_uuid, utc_now
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models.threat import Threat

class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)

    threat_id: Mapped[str] = mapped_column(ForeignKey("threats.id"), index=True)
    title: Mapped[str] = mapped_column(String(256))
    description: Mapped[str | None] = mapped_column(String(2000), nullable=True)

    payload: Mapped[dict] = mapped_column(JSON)
    content_hash: Mapped[str] = mapped_column(String(64), index=True)

    status: Mapped[str] = mapped_column(String(16), default=EvidenceStatus.DRAFT.value, index=True)

    blockchain_tx_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    blockchain_block_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    anchored_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )

    threat: Mapped["Threat"] = relationship(back_populates="evidence_records")