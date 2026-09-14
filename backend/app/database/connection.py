from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings


class Base(DeclarativeBase):
    """Base class for all ORM models."""


def _async_database_url(url: str) -> str:
    """Normalize common PostgreSQL URLs for SQLAlchemy asyncpg."""
    normalized = url.strip()
    if normalized.startswith("postgres://"):
        return "postgresql+asyncpg://" + normalized[len("postgres://") :]
    if normalized.startswith("postgresql://"):
        return "postgresql+asyncpg://" + normalized[len("postgresql://") :]
    return normalized


DATABASE_URL = _async_database_url(settings.DATABASE_URL)
IS_SQLITE = DATABASE_URL.startswith("sqlite+")

if IS_SQLITE:
    engine = create_async_engine(
        DATABASE_URL,
        echo=settings.DEBUG,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
else:
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
    """FastAPI dependency that yields a DB session per request."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


@asynccontextmanager
async def get_db_context() -> AsyncGenerator[AsyncSession, None]:
    """Use a DB session outside FastAPI dependency injection."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def _seed_demo_data(session: AsyncSession) -> None:
    """Seed realistic demo telemetry for a standalone hosted deployment."""
    from app.models.anomaly import Anomaly, ThreatAnomalyLink
    from app.models.evidence import Evidence
    from app.models.threat import Threat
    from app.utils.hashing import hash_json
    from app.utils.helpers import utc_now

    anomaly_count = await session.scalar(select(func.count(Anomaly.id)))
    if anomaly_count:
        return

    now = utc_now()
    anomalies = [
        Anomaly(
            flow_id="flow-demo-001",
            src_ip="10.10.4.21",
            dst_ip="185.199.108.153",
            src_port=51824,
            dst_port=443,
            protocol="TCP",
            anomaly_score=0.94,
            is_anomalous=True,
            status="confirmed",
            raw_features={"bytes": 184200, "packets": 912, "duration_ms": 1840},
            detected_at=now,
            created_at=now,
            updated_at=now,
        ),
        Anomaly(
            flow_id="flow-demo-002",
            src_ip="10.10.8.14",
            dst_ip="10.10.1.5",
            src_port=49152,
            dst_port=445,
            protocol="TCP",
            anomaly_score=0.81,
            is_anomalous=True,
            status="pending",
            raw_features={"bytes": 88200, "packets": 421, "duration_ms": 920},
            detected_at=now,
            created_at=now,
            updated_at=now,
        ),
        Anomaly(
            flow_id="flow-demo-003",
            src_ip="10.10.3.77",
            dst_ip="8.8.8.8",
            src_port=53412,
            dst_port=53,
            protocol="UDP",
            anomaly_score=0.37,
            is_anomalous=False,
            status="false_positive",
            raw_features={"bytes": 3200, "packets": 18, "duration_ms": 210},
            detected_at=now,
            created_at=now,
            updated_at=now,
        ),
    ]
    session.add_all(anomalies)
    await session.flush()

    threats = [
        Threat(
            title="Credential Access Pattern Detected",
            description="Unusual outbound authentication traffic followed by a burst of encrypted sessions.",
            severity="critical",
            src_ip="10.10.4.21",
            dst_ip="185.199.108.153",
            mitre_technique_id="T1078",
            mitre_tactic="credential-access",
            confidence_score=0.96,
            iocs=["185.199.108.153", "flow-demo-001"],
            is_resolved=False,
            detected_at=now,
            created_at=now,
            updated_at=now,
        ),
        Threat(
            title="Internal SMB Lateral Movement",
            description="A workstation initiated an abnormal sequence of SMB connections across protected segments.",
            severity="high",
            src_ip="10.10.8.14",
            dst_ip="10.10.1.5",
            mitre_technique_id="T1021.002",
            mitre_tactic="lateral-movement",
            confidence_score=0.89,
            iocs=["10.10.8.14", "10.10.1.5"],
            is_resolved=False,
            detected_at=now,
            created_at=now,
            updated_at=now,
        ),
        Threat(
            title="Suspicious DNS Beaconing",
            description="Low-volume periodic DNS traffic matched a known beaconing cadence.",
            severity="medium",
            src_ip="10.10.3.77",
            dst_ip="8.8.8.8",
            mitre_technique_id="T1071.004",
            mitre_tactic="command-and-control",
            confidence_score=0.72,
            iocs=["10.10.3.77"],
            is_resolved=True,
            detected_at=now,
            created_at=now,
            updated_at=now,
        ),
    ]
    session.add_all(threats)
    await session.flush()

    session.add_all([
        ThreatAnomalyLink(threat_id=threats[0].id, anomaly_id=anomalies[0].id),
        ThreatAnomalyLink(threat_id=threats[1].id, anomaly_id=anomalies[1].id),
        ThreatAnomalyLink(threat_id=threats[2].id, anomaly_id=anomalies[2].id),
    ])

    evidence_payloads = [
        ("Credential Access Evidence", threats[0], {"flow_id": "flow-demo-001", "src_ip": "10.10.4.21"}),
        ("SMB Movement Evidence", threats[1], {"flow_id": "flow-demo-002", "dst_ip": "10.10.1.5"}),
        ("DNS Beacon Evidence", threats[2], {"flow_id": "flow-demo-003", "domain": "resolver.example"}),
    ]
    for title, threat, payload in evidence_payloads:
        session.add(Evidence(
            threat_id=threat.id,
            title=title,
            description="Demo evidence generated by the hosted CyberPulse environment.",
            payload=payload,
            content_hash=hash_json(payload),
            status="hashed",
            created_at=now,
            updated_at=now,
        ))

    await session.commit()


async def init_db() -> None:
    """Create tables and seed demo data when the app starts."""
    from app.models.anomaly import Anomaly, ThreatAnomalyLink  # noqa: F401
    from app.models.evidence import Evidence  # noqa: F401
    from app.models.forecast import Forecast  # noqa: F401
    from app.models.threat import Threat  # noqa: F401

    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        if IS_SQLITE:
            async with AsyncSessionLocal() as session:
                await _seed_demo_data(session)
    except Exception as exc:
        # External PostgreSQL remains optional for the hosted demo. If a
        # configured database is temporarily unavailable, health endpoints
        # remain available and the UI can still load.
        if IS_SQLITE:
            raise
        from app.utils.logger import app_logger
        app_logger.warning(f"Database initialization skipped: {exc}")


async def close_db() -> None:
    """Dispose of the engine pool when the process shuts down."""
    await engine.dispose()
