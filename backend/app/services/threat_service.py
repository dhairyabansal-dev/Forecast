from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.threat_repository import ThreatRepository
from app.models.threat import Threat
from app.utils.logger import app_logger


class ThreatService:
    """Business logic for creating, correlating, and managing threat records."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.repo = ThreatRepository(session)

    async def create_threat(
        self,
        title: str,
        description: str,
        severity: str,
        confidence_score: float,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        mitre_technique_id: Optional[str] = None,
        mitre_tactic: Optional[str] = None,
        related_anomaly_ids: Optional[list[str]] = None,
        iocs: Optional[list[str]] = None,
    ) -> Threat:
        threat = Threat(
            title=title,
            description=description,
            severity=severity,
            src_ip=src_ip,
            dst_ip=dst_ip,
            mitre_technique_id=mitre_technique_id,
            mitre_tactic=mitre_tactic,
            confidence_score=confidence_score,
            iocs=iocs or [],
        )
        created = await self.repo.create(threat, related_anomaly_ids=related_anomaly_ids)
        app_logger.info(f"Threat created: {created.id} ({severity}) - {title}")
        return created

    async def get_threat(self, threat_id: str) -> Optional[Threat]:
        return await self.repo.get_by_id(threat_id)

    async def list_threats(self, **filters):
        return await self.repo.list(**filters)

    async def update_threat(self, threat_id: str, **fields) -> Optional[Threat]:
        threat = await self.repo.get_by_id(threat_id)
        if threat is None:
            return None
        return await self.repo.update(threat, **fields)

    async def resolve_threat(self, threat_id: str) -> Optional[Threat]:
        return await self.update_threat(threat_id, is_resolved=True)

    async def delete_threat(self, threat_id: str) -> bool:
        threat = await self.repo.get_by_id(threat_id)
        if threat is None:
            return False
        await self.repo.delete(threat)
        return True