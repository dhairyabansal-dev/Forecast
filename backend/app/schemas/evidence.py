from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from app.core.constants import EvidenceStatus


class EvidenceBase(BaseModel):
    threat_id: str
    title: str
    description: Optional[str] = None
    payload: dict = Field(..., description="Raw evidence payload (flows, packets metadata, etc.)")


class EvidenceCreate(EvidenceBase):
    pass


class EvidenceResponse(EvidenceBase):
    id: str
    content_hash: str
    status: EvidenceStatus
    blockchain_tx_hash: Optional[str] = None
    blockchain_block_number: Optional[int] = None
    anchored_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class EvidenceAnchorRequest(BaseModel):
    evidence_id: str


class EvidenceAnchorResponse(BaseModel):
    evidence_id: str
    content_hash: str
    tx_hash: str
    block_number: int
    anchored_at: datetime
    status: EvidenceStatus


class EvidenceVerifyResponse(BaseModel):
    evidence_id: str
    is_valid: bool
    on_chain_hash: Optional[str] = None
    local_hash: str
    checked_at: datetime
    message: str


class EvidenceListResponse(BaseModel):
    items: list[EvidenceResponse]
    total: int
    page: int
    page_size: int
    total_pages: int