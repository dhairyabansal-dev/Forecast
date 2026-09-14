from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from app.core.constants import MitreTactic, ThreatSeverity


class ThreatBase(BaseModel):
    title: str
    description: str
    severity: ThreatSeverity
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    mitre_technique_id: Optional[str] = Field(None, description="e.g. T1059")
    mitre_tactic: Optional[MitreTactic] = None
    confidence_score: float = Field(..., ge=0.0, le=1.0)


class ThreatCreate(ThreatBase):
    related_anomaly_ids: list[str] = Field(default_factory=list)
    iocs: list[str] = Field(default_factory=list, description="Associated indicators of compromise")


class ThreatUpdate(BaseModel):
    severity: Optional[ThreatSeverity] = None
    description: Optional[str] = None
    is_resolved: Optional[bool] = None


class ThreatResponse(ThreatBase):
    id: str
    related_anomaly_ids: list[str]
    iocs: list[str]
    is_resolved: bool
    detected_at: datetime
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class MitreMappingResult(BaseModel):
    technique_id: str
    technique_name: str
    tactic: MitreTactic
    confidence: float = Field(..., ge=0.0, le=1.0)
    matched_indicators: list[str]


class ThreatListResponse(BaseModel):
    items: list[ThreatResponse]
    total: int
    page: int
    page_size: int
    total_pages: int