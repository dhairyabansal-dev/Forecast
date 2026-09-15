from datetime import datetime, timezone
from typing import AsyncGenerator, Iterable

from fastapi import Cookie, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.connection import get_db
from app.models.user import User, UserSession
from app.core.auth import COOKIE_NAME, decode_session_token, token_digest
from app.services.blockchain_service import BlockchainService
from app.services.detection_service import DetectionService
from app.services.forecast_service import ForecastService
from app.services.threat_service import ThreatService

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


async def get_current_user(
    session: AsyncSession = Depends(get_db_session),
    session_cookie: str | None = Cookie(default=None, alias=COOKIE_NAME),
) -> User:
    if not session_cookie:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")

    claims = decode_session_token(session_cookie)
    if not claims or not claims.get("sub") or not claims.get("jti"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired or invalid")

    result = await session.execute(select(UserSession).where(UserSession.jti == claims["jti"]))
    db_session = result.scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if (
        db_session is None
        or db_session.revoked_at is not None
        or db_session.expires_at <= now
        or db_session.token_hash != token_digest(session_cookie)
    ):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired or invalid")

    result = await session.execute(select(User).where(User.id == claims["sub"]))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account inactive or unavailable")
    return user


def require_roles(*roles: str):
    async def dependency(user: User = Depends(get_current_user)) -> User:
        if user.role.upper() not in {role.upper() for role in roles}:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return user

    return dependency


require_authenticated = get_current_user
