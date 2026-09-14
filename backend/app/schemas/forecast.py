from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from app.core.constants import ForecastConfidence


class ForecastRequest(BaseModel):
    network_segment: Optional[str] = Field(
        None, description="Optional network segment/subnet identifier to scope the forecast"
    )
    horizon_hours: int = Field(24, ge=1, le=168, description="How many hours ahead to forecast")
    sequence_length: int = Field(48, ge=8, le=336, description="Historical window length used as model input")


class ForecastPoint(BaseModel):
    timestamp: datetime
    predicted_threat_level: float = Field(..., ge=0.0, le=1.0)
    lower_bound: float = Field(..., ge=0.0, le=1.0)
    upper_bound: float = Field(..., ge=0.0, le=1.0)
    predicted_stage: Optional[str] = None
    stage_confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    explainability: Optional[dict[str, float]] = None


class LiveForecastRequest(BaseModel):
    network_segment: Optional[str] = None
    capture_duration_seconds: int = Field(12, ge=1, le=300)
    forecast_steps: int = Field(10, ge=1, le=168)
    window_size: int = Field(10, ge=2, le=336)
    packet_limit: int = Field(2000, ge=100, le=100000)


class LiveForecastStartResponse(BaseModel):
    job_id: str
    status: str


class LiveForecastStatusResponse(BaseModel):
    job_id: str
    status: str
    forecast_id: Optional[str] = None
    error: Optional[str] = None


class ForecastResponse(BaseModel):
    id: str
    network_segment: Optional[str] = None
    generated_at: datetime
    horizon_hours: int
    confidence: ForecastConfidence
    points: list[ForecastPoint]
    model_version: str

    model_config = {"from_attributes": True}


class ForecastSummary(BaseModel):
    id: str
    network_segment: Optional[str] = None
    generated_at: datetime
    horizon_hours: int
    confidence: ForecastConfidence
    peak_threat_level: float
    peak_timestamp: datetime

    model_config = {"from_attributes": True}


class ForecastListResponse(BaseModel):
    items: list[ForecastSummary]
    total: int
    page: int
    page_size: int
    total_pages: int