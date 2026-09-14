from typing import AsyncGenerator

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.connection import get_db
from app.services.blockchain_service import BlockchainService
from app.services.detection_service import DetectionService
from app.services.forecast_service import ForecastService
from app.services.threat_service import ThreatService

# Reuse a single BlockchainService instance (holds a Web3 connection pool)
_blockchain_service = BlockchainService()


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    async for session in get_db():
        yield session


def get_detection_service(session: AsyncSession = Depends(get_db_session)) -> DetectionService:
    return DetectionService(session)


def get_forecast_service(session: AsyncSession = Depends(get_db_session)) -> ForecastService:
    return ForecastService(session)


def get_threat_service(session: AsyncSession = Depends(get_db_session)) -> ThreatService:
    return ThreatService(session)


def get_blockchain_service() -> BlockchainService:
    return _blockchain_service