from contextlib import asynccontextmanager
from typing import AsyncGenerator

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


DATABASE_URL = _async_database_url(settings.DATABASE_URL)
engine = create_async_engine(
    DATABASE_URL,
    echo=settings.DEBUG,
    pool_pre_ping=True,
    pool_size=1,
    max_overflow=0,
    pool_recycle=300,
)
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


@asynccontextmanager
async def get_db_context() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    """Create missing tables for local development and serverless deployments.

    create_all() is idempotent and only creates missing tables; schema migrations
    remain the source of truth for controlled production schema changes.
    """
    from app.models.anomaly import Anomaly, ThreatAnomalyLink  # noqa: F401
    from app.models.evidence import Evidence  # noqa: F401
    from app.models.forecast import Forecast  # noqa: F401
    from app.models.threat import Threat  # noqa: F401
    from app.models.user import AuditLog, User, UserSession  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    await engine.dispose()
