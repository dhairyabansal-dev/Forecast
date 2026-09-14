from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from app.core.constants import AnomalyStatus


class AnomalyBase(BaseModel):
    flow_id: str = Field(..., description="Identifier of the network flow this anomaly relates to")
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = Field(None, ge=0, le=65535)
    dst_port: Optional[int] = Field(None, ge=0, le=65535)
    protocol: Optional[str] = None
    anomaly_score: float = Field(
        ..., ge=-1.0, le=1.0, description="Isolation Forest anomaly score"
    )
    is_anomalous: bool


class AnomalyCreate(BaseModel):
    """Input for server-side anomaly scoring."""

    flow_id: str
    src_ip: str
    dst_ip: str
    feature_vector: list[float] = Field(..., min_length=1)
    src_port: Optional[int] = Field(None, ge=0, le=65535)
    dst_port: Optional[int] = Field(None, ge=0, le=65535)
    protocol: Optional[str] = None
    detected_at: Optional[datetime] = None
    raw_features: Optional[dict] = None


class AnomalyUpdate(BaseModel):
    status: Optional[AnomalyStatus] = None
    analyst_notes: Optional[str] = Field(None, max_length=2000)


class AnomalyResponse(AnomalyBase):
    id: str
    status: AnomalyStatus
    detected_at: datetime
    created_at: datetime
    updated_at: datetime
    analyst_notes: Optional[str] = None

    model_config = {"from_attributes": True}


class AnomalyExplanation(BaseModel):
    anomaly_id: str
    feature_importances: dict[str, float] = Field(
        ..., description="SHAP values keyed by feature name"
    )
    top_contributing_features: list[str]
    explanation_summary: str


class AnomalyListResponse(BaseModel):
    items: list[AnomalyResponse]
    total: int
    page: int
    page_size: int
    total_pages: int
