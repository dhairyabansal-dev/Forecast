import asyncio
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.dependencies import get_forecast_service
from app.core.constants import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from app.schemas.forecast import (
    ForecastListResponse,
    ForecastRequest,
    ForecastResponse,
    LiveForecastRequest,
    LiveForecastStartResponse,
    LiveForecastStatusResponse,
)
from app.services.live_forecast_service import live_forecast_service
from app.services.forecast_service import ForecastService

router = APIRouter(prefix="/forecast", tags=["Forecast"])


@router.post("/live", response_model=LiveForecastStartResponse, status_code=202)
async def start_live_forecast(payload: LiveForecastRequest):
    try:
        job_id = live_forecast_service.start(
            duration_seconds=payload.capture_duration_seconds,
            forecast_steps=payload.forecast_steps,
            window_size=payload.window_size,
            network_segment=payload.network_segment,
            packet_limit=payload.packet_limit,
            loop=asyncio.get_running_loop(),
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return LiveForecastStartResponse(job_id=job_id, status="queued")


@router.get("/live/{job_id}", response_model=LiveForecastStatusResponse)
async def get_live_forecast_status(job_id: str):
    status = live_forecast_service.get_status(job_id)
    if status is None:
        raise HTTPException(status_code=404, detail="Live forecast job not found")
    return LiveForecastStatusResponse(job_id=job_id, **status)


@router.post("/generate", response_model=ForecastResponse, status_code=201)
async def generate_forecast(
    payload: ForecastRequest,
    service: ForecastService = Depends(get_forecast_service),
):
    raise HTTPException(
        status_code=410,
        detail="Synthetic forecast generation is disabled. Use POST /forecast/live.",
    )


@router.get("/latest", response_model=ForecastResponse)
async def get_latest_forecast(
    network_segment: Optional[str] = None,
    service: ForecastService = Depends(get_forecast_service),
):
    forecast = await service.get_latest_forecast(network_segment)
    if forecast is None:
        raise HTTPException(status_code=404, detail="No forecasts available yet")
    return forecast


@router.get("/{forecast_id}", response_model=ForecastResponse)
async def get_forecast(forecast_id: str, service: ForecastService = Depends(get_forecast_service)):
    forecast = await service.get_forecast(forecast_id)
    if forecast is None:
        raise HTTPException(status_code=404, detail="Forecast not found")
    return forecast


@router.get("", response_model=ForecastListResponse)
async def list_forecasts(
    page: int = Query(1, ge=1),
    page_size: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    network_segment: Optional[str] = None,
    service: ForecastService = Depends(get_forecast_service),
):
    items, total = await service.list_forecasts(
        page=page, page_size=page_size, network_segment=network_segment
    )
    return ForecastListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size if total else 0,
    )