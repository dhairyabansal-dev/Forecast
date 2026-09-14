from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, JSON, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.constants import MitreTactic, ThreatSeverity
from app.database.connection import Base
from app.utils.helpers import generate_uuid, utc_now
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from backend.app.models.anomaly import ThreatAnomalyLink
    from app.models.evidence import Evidence

class Threat(Base):
    __tablename__ = "threats"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)

    title: Mapped[str] = mapped_column(String(256))
    description: Mapped[str] = mapped_column(String(4000))
    severity: Mapped[str] = mapped_column(String(16), index=True)

    src_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    dst_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)

    mitre_technique_id: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    mitre_tactic: Mapped[str | None] = mapped_column(String(32), nullable=True)

    confidence_score: Mapped[float] = mapped_column(Float)
    iocs: Mapped[list] = mapped_column(JSON, default=list)

    is_resolved: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )

    anomaly_links: Mapped[list["ThreatAnomalyLink"]] = relationship(
        back_populates="threat", cascade="all, delete-orphan"
    )
    evidence_records: Mapped[list["Evidence"]] = relationship(
        back_populates="threat", cascade="all, delete-orphan"
    )

    @property
    def related_anomaly_ids(self) -> list[str]:
        return [link.anomaly_id for link in self.anomaly_links]