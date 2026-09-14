from __future__ import annotations
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.anomaly import ThreatAnomalyLink
from app.models.threat import Threat
from app.utils.helpers import utc_now


class ThreatRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, threat: Threat, related_anomaly_ids: list[str] | None = None) -> Threat:
        self.session.add(threat)
        await self.session.flush()  # get threat.id before linking

        for anomaly_id in related_anomaly_ids or []:
            link = ThreatAnomalyLink(threat_id=threat.id, anomaly_id=anomaly_id)
            self.session.add(link)

        await self.session.commit()
        await self.session.refresh(threat, attribute_names=["anomaly_links"])
        return threat

    async def get_by_id(self, threat_id: str) -> Optional[Threat]:
        result = await self.session.execute(
            select(Threat)
            .where(Threat.id == threat_id)
            .options(selectinload(Threat.anomaly_links))
        )
        return result.scalar_one_or_none()

    async def list(
        self,
        page: int = 1,
        page_size: int = 50,
        severity: Optional[str] = None,
        is_resolved: Optional[bool] = None,
        mitre_tactic: Optional[str] = None,
    ) -> tuple[list[Threat], int]:
        query = select(Threat).options(selectinload(Threat.anomaly_links))
        count_query = select(func.count()).select_from(Threat)

        if severity:
            query = query.where(Threat.severity == severity)
            count_query = count_query.where(Threat.severity == severity)
        if is_resolved is not None:
            query = query.where(Threat.is_resolved == is_resolved)
            count_query = count_query.where(Threat.is_resolved == is_resolved)
        if mitre_tactic:
            query = query.where(Threat.mitre_tactic == mitre_tactic)
            count_query = count_query.where(Threat.mitre_tactic == mitre_tactic)

        query = query.order_by(Threat.detected_at.desc())
        query = query.offset((page - 1) * page_size).limit(page_size)

        result = await self.session.execute(query)
        total_result = await self.session.execute(count_query)

        items = list(result.scalars().all())
        total = total_result.scalar_one()

        return items, total

    async def update(self, threat: Threat, **fields) -> Threat:
        for key, value in fields.items():
            if value is not None:
                setattr(threat, key, value)
        threat.updated_at = utc_now()
        await self.session.commit()
        await self.session.refresh(threat)
        return threat

    async def delete(self, threat: Threat) -> None:
        await self.session.delete(threat)
        await self.session.commit()