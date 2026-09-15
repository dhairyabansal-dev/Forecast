from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_user, get_db_session, get_threat_service, require_roles
from app.core.constants import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from app.models.user import User
from app.schemas.threat import ThreatCreate, ThreatListResponse, ThreatResponse, ThreatUpdate
from app.services.audit_service import record_audit
from app.services.threat_service import ThreatService

router = APIRouter(prefix="/threats", tags=["Threats"])


@router.post("", response_model=ThreatResponse, status_code=201)
async def create_threat(payload: ThreatCreate, user: User = Depends(require_roles("ADMIN", "DATA_SCIENTIST")), service: ThreatService = Depends(get_threat_service), session: AsyncSession = Depends(get_db_session)):
    threat = await service.create_threat(title=payload.title, description=payload.description, severity=payload.severity.value, confidence_score=payload.confidence_score, src_ip=payload.src_ip, dst_ip=payload.dst_ip, mitre_technique_id=payload.mitre_technique_id, mitre_tactic=payload.mitre_tactic.value if payload.mitre_tactic else None, related_anomaly_ids=payload.related_anomaly_ids, iocs=payload.iocs)
    await record_audit(session, action="THREAT_CREATION", status="SUCCESS", user_id=user.id, resource=getattr(threat, "id", None))
    return threat


@router.get("", response_model=ThreatListResponse)
async def list_threats(page: int = Query(1, ge=1), page_size: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE), severity: Optional[str] = None, is_resolved: Optional[bool] = None, mitre_tactic: Optional[str] = None, user: User = Depends(get_current_user), service: ThreatService = Depends(get_threat_service)):
    items, total = await service.list_threats(page=page, page_size=page_size, severity=severity, is_resolved=is_resolved, mitre_tactic=mitre_tactic)
    return ThreatListResponse(items=items, total=total, page=page, page_size=page_size, total_pages=(total + page_size - 1) // page_size if total else 0)


@router.get("/{threat_id}", response_model=ThreatResponse)
async def get_threat(threat_id: str, user: User = Depends(get_current_user), service: ThreatService = Depends(get_threat_service)):
    threat = await service.get_threat(threat_id)
    if threat is None: raise HTTPException(status_code=404, detail="Threat not found")
    return threat


@router.patch("/{threat_id}", response_model=ThreatResponse)
async def update_threat(threat_id: str, payload: ThreatUpdate, user: User = Depends(require_roles("ADMIN", "DATA_SCIENTIST")), service: ThreatService = Depends(get_threat_service), session: AsyncSession = Depends(get_db_session)):
    fields = {"severity": payload.severity.value if payload.severity else None, "description": payload.description, "is_resolved": payload.is_resolved}
    threat = await service.update_threat(threat_id, **fields)
    if threat is None: raise HTTPException(status_code=404, detail="Threat not found")
    await record_audit(session, action="THREAT_UPDATE", status="SUCCESS", user_id=user.id, resource=threat_id)
    return threat


@router.post("/{threat_id}/resolve", response_model=ThreatResponse)
async def resolve_threat(threat_id: str, user: User = Depends(require_roles("ADMIN", "DATA_SCIENTIST", "ANALYST")), service: ThreatService = Depends(get_threat_service), session: AsyncSession = Depends(get_db_session)):
    threat = await service.resolve_threat(threat_id)
    if threat is None: raise HTTPException(status_code=404, detail="Threat not found")
    await record_audit(session, action="THREAT_RESOLUTION", status="SUCCESS", user_id=user.id, resource=threat_id)
    return threat


@router.delete("/{threat_id}", status_code=204)
async def delete_threat(threat_id: str, user: User = Depends(require_roles("ADMIN")), service: ThreatService = Depends(get_threat_service), session: AsyncSession = Depends(get_db_session)):
    deleted = await service.delete_threat(threat_id)
    if not deleted: raise HTTPException(status_code=404, detail="Threat not found")
    await record_audit(session, action="THREAT_DELETION", status="SUCCESS", user_id=user.id, resource=threat_id)
