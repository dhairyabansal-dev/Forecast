from typing import Optional

import numpy as np
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_user, get_db_session, get_forecast_service, require_roles
from app.core.constants import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from app.models.user import User
from app.schemas.forecast import ForecastListResponse, ForecastRequest, ForecastResponse, LiveForecastRequest, LiveForecastStartResponse, LiveForecastStatusResponse
from app.services.audit_service import record_audit
from app.services.forecast_service import ForecastService

router = APIRouter(prefix="/forecast", tags=["Forecast"])


@router.post("/live", response_model=LiveForecastStartResponse, status_code=501)
async def start_live_forecast(payload: LiveForecastRequest, user: User = Depends(require_roles("ADMIN", "DATA_SCIENTIST", "ANALYST"))):
    raise HTTPException(status_code=501, detail="Live packet capture is unavailable on Vercel. Use POST /forecast/generate for the serverless forecast.")


@router.get("/live/{job_id}", response_model=LiveForecastStatusResponse, status_code=501)
async def get_live_forecast_status(job_id: str, user: User = Depends(get_current_user)):
    raise HTTPException(status_code=501, detail="Live packet capture jobs are unavailable on Vercel.")


@router.post("/generate", response_model=ForecastResponse, status_code=201)
async def generate_forecast(payload: ForecastRequest, user: User = Depends(require_roles("ADMIN", "DATA_SCIENTIST", "ANALYST")), service: ForecastService = Depends(get_forecast_service), session: AsyncSession = Depends(get_db_session)):
    sequence = np.zeros((payload.sequence_length, 1), dtype=np.float32)
    result = await service.generate_forecast(historical_sequence=sequence, network_segment=payload.network_segment, horizon_hours=payload.horizon_hours, sequence_length=payload.sequence_length)
    await record_audit(session, action="FORECAST_EXECUTION", status="SUCCESS", user_id=user.id, resource=getattr(result, "id", None), metadata={"horizon_hours": payload.horizon_hours, "sequence_length": payload.sequence_length})
    return result


@router.get("/latest", response_model=ForecastResponse)
async def get_latest_forecast(network_segment: Optional[str] = None, user: User = Depends(get_current_user), service: ForecastService = Depends(get_forecast_service)):
    forecast = await service.get_latest_forecast(network_segment)
    if forecast is None:
        raise HTTPException(status_code=404, detail="No forecasts available yet")
    return forecast


@router.get("/{forecast_id}", response_model=ForecastResponse)
async def get_forecast(forecast_id: str, user: User = Depends(get_current_user), service: ForecastService = Depends(get_forecast_service)):
    forecast = await service.get_forecast(forecast_id)
    if forecast is None:
        raise HTTPException(status_code=404, detail="Forecast not found")
    return forecast


@router.get("", response_model=ForecastListResponse)
async def list_forecasts(page: int = Query(1, ge=1), page_size: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE), network_segment: Optional[str] = None, user: User = Depends(get_current_user), service: ForecastService = Depends(get_forecast_service)):
    items, total = await service.list_forecasts(page=page, page_size=page_size, network_segment=network_segment)
    return ForecastListResponse(items=items, total=total, page=page, page_size=page_size, total_pages=(total + page_size - 1) // page_size if total else 0)
