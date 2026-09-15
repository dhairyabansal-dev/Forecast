from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.dependencies import get_current_user, get_detection_service, require_roles
from app.models.user import User
from app.core.constants import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from app.schemas.anomaly import AnomalyCreate, AnomalyListResponse, AnomalyResponse, AnomalyUpdate
from app.services.detection_service import DetectionService

router = APIRouter(prefix="/detection", tags=["Detection"])


@router.post("/analyze", response_model=AnomalyResponse, status_code=201)
async def analyze_flow(payload: AnomalyCreate, user: User = Depends(require_roles("ADMIN", "DATA_SCIENTIST")), service: DetectionService = Depends(get_detection_service)):
    return await service.detect_and_store(flow_id=payload.flow_id, src_ip=payload.src_ip, dst_ip=payload.dst_ip, feature_vector=payload.feature_vector, raw_features=payload.raw_features, src_port=payload.src_port, dst_port=payload.dst_port, protocol=payload.protocol)


@router.get("/anomalies", response_model=AnomalyListResponse)
async def list_anomalies(page: int = Query(1, ge=1), page_size: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE), is_anomalous: Optional[bool] = None, status: Optional[str] = None, src_ip: Optional[str] = None, user: User = Depends(get_current_user), service: DetectionService = Depends(get_detection_service)):
    items, total = await service.list_anomalies(page=page, page_size=page_size, is_anomalous=is_anomalous, status=status, src_ip=src_ip)
    return AnomalyListResponse(items=items, total=total, page=page, page_size=page_size, total_pages=(total + page_size - 1) // page_size if total else 0)


@router.get("/anomalies/{anomaly_id}", response_model=AnomalyResponse)
async def get_anomaly(anomaly_id: str, user: User = Depends(get_current_user), service: DetectionService = Depends(get_detection_service)):
    anomaly = await service.get_anomaly(anomaly_id)
    if anomaly is None:
        raise HTTPException(status_code=404, detail="Anomaly not found")
    return anomaly


@router.patch("/anomalies/{anomaly_id}", response_model=AnomalyResponse)
async def update_anomaly(anomaly_id: str, payload: AnomalyUpdate, user: User = Depends(require_roles("ADMIN", "DATA_SCIENTIST")), service: DetectionService = Depends(get_detection_service)):
    updated = await service.update_status(anomaly_id, status=payload.status.value if payload.status else None, notes=payload.analyst_notes)
    if updated is None:
        raise HTTPException(status_code=404, detail="Anomaly not found")
    return updated
