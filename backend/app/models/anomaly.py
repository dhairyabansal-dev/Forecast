from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, String, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.constants import AnomalyStatus
from app.database.connection import Base
from app.utils.helpers import generate_uuid, utc_now
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models.threat import Threat

class Anomaly(Base):
    __tablename__ = "anomalies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)

    flow_id: Mapped[str] = mapped_column(String(128), index=True)
    src_ip: Mapped[str] = mapped_column(String(45), index=True)
    dst_ip: Mapped[str] = mapped_column(String(45), index=True)
    src_port: Mapped[int | None] = mapped_column(nullable=True)
    dst_port: Mapped[int | None] = mapped_column(nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)

    anomaly_score: Mapped[float] = mapped_column(Float)
    is_anomalous: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    status: Mapped[str] = mapped_column(
        String(32), default=AnomalyStatus.PENDING.value, index=True
    )

    raw_features: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    analyst_notes: Mapped[str | None] = mapped_column(String(2000), nullable=True)

    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )

    threats: Mapped[list["ThreatAnomalyLink"]] = relationship(
        back_populates="anomaly", cascade="all, delete-orphan"
    )


class ThreatAnomalyLink(Base):
    """Join table linking threats to the anomalies that contributed to them."""
    __tablename__ = "threat_anomaly_links"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    threat_id: Mapped[str] = mapped_column(ForeignKey("threats.id"), index=True)
    anomaly_id: Mapped[str] = mapped_column(ForeignKey("anomalies.id"), index=True)

    anomaly: Mapped["Anomaly"] = relationship(back_populates="threats")
    threat: Mapped["Threat"] = relationship(back_populates="anomaly_links")