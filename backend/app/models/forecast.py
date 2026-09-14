from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.constants import ForecastConfidence
from app.database.connection import Base
from app.utils.helpers import generate_uuid, utc_now


class Forecast(Base):
    __tablename__ = "forecasts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)

    network_segment: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    horizon_hours: Mapped[int] = mapped_column(Integer)
    sequence_length: Mapped[int] = mapped_column(Integer)
    confidence: Mapped[str] = mapped_column(String(16), default=ForecastConfidence.MEDIUM.value)
    model_version: Mapped[str] = mapped_column(String(64), default="v1")

    # Points stored as JSON list of {timestamp, predicted_threat_level, lower_bound, upper_bound}
    points: Mapped[list] = mapped_column(JSON)

    peak_threat_level: Mapped[float] = mapped_column(Float, default=0.0)
    peak_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)