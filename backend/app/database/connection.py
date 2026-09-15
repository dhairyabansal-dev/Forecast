import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings


class Base(DeclarativeBase):
    """Base class for all ORM models."""


def _async_database_url(url: str) -> str:
    normalized = url.strip()
    if normalized.startswith("postgres://"):
        return "postgresql+asyncpg://" + normalized[len("postgres://") :]
    if normalized.startswith("postgresql://"):
        return "postgresql+asyncpg://" + normalized[len("postgresql://") :]
    return normalized


def _resolve_database_url() -> str:
    """Resolve the database URL from the app setting or common Vercel Postgres names."""
    candidates = (
        settings.DATABASE_URL,
        os.getenv("POSTGRES_URL", ""),
        os.getenv("POSTGRES_URL_NON_POOLING", ""),
        os.getenv("POSTGRES_PRISMA_URL", ""),
    )
    for value in candidates:
        if value and value.strip():
            return _async_database_url(value)
    return ""


DATABASE_URL = _resolve_database_url()

# Do not construct SQLAlchemy's engine with an empty URL. That raises during
# module import and makes Vercel report the misleading "could not import
# api/index.py" error. The engine is created only when a database is configured.
engine = (
    create_async_engine(
        DATABASE_URL,
        echo=settings.DEBUG,
        pool_pre_ping=True,
        pool_size=1,
        max_overflow=0,
        pool_recycle=300,
    )
    if DATABASE_URL
    else None
)

AsyncSessionLocal = (
    async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )
    if engine is not None
    else None
)


def _require_database() -> async_sessionmaker[AsyncSession]:
    if AsyncSessionLocal is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database is not configured. Set DATABASE_URL in the deployment environment.",
        )
    return AsyncSessionLocal


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    session_factory = _require_database()
    async with session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


@asynccontextmanager
async def get_db_context() -> AsyncGenerator[AsyncSession, None]:
    session_factory = _require_database()
    async with session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    """Create missing tables for local development and serverless deployments."""
    if engine is None:
        return

    from app.models.anomaly import Anomaly, ThreatAnomalyLink  # noqa: F401
    from app.models.evidence import Evidence  # noqa: F401
    from app.models.forecast import Forecast  # noqa: F401
    from app.models.threat import Threat  # noqa: F401
    from app.models.user import AuditLog, User, UserSession  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    if engine is not None:
        await engine.dispose()
