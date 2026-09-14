from datetime import datetime

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_blockchain_service, get_db_session
from app.core.config import settings
from app.services.blockchain_service import BlockchainService

router = APIRouter(prefix="/health", tags=["Health"])


@router.get("")
async def health_check():
    return {
        "status": "ok",
        "app_name": settings.APP_NAME,
        "env": settings.APP_ENV,
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/db")
async def db_health(session: AsyncSession = Depends(get_db_session)):
    try:
        await session.execute(text("SELECT 1"))
        return {"database": "connected"}
    except Exception as e:
        return {"database": "unavailable", "error": str(e)}


@router.get("/blockchain")
async def blockchain_health(blockchain: BlockchainService = Depends(get_blockchain_service)):
    connected = blockchain.is_connected()
    return {
        "blockchain": "connected" if connected else "unavailable",
        "provider_url": settings.BLOCKCHAIN_PROVIDER_URL,
    }