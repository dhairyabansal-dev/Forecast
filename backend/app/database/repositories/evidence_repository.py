from __future__ import annotations

from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.evidence import Evidence
from app.utils.helpers import utc_now


class EvidenceRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, evidence: Evidence) -> Evidence:
        self.session.add(evidence)
        await self.session.commit()
        await self.session.refresh(evidence)
        return evidence

    async def get_by_id(self, evidence_id: str) -> Optional[Evidence]:
        result = await self.session.execute(
            select(Evidence).where(Evidence.id == evidence_id)
        )
        return result.scalar_one_or_none()

    async def list(
        self,
        page: int = 1,
        page_size: int = 50,
        threat_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> tuple[list[Evidence], int]:
        query = select(Evidence)
        count_query = select(func.count()).select_from(Evidence)

        if threat_id:
            query = query.where(Evidence.threat_id == threat_id)
            count_query = count_query.where(Evidence.threat_id == threat_id)
        if status:
            query = query.where(Evidence.status == status)
            count_query = count_query.where(Evidence.status == status)

        query = query.order_by(Evidence.created_at.desc())
        query = query.offset((page - 1) * page_size).limit(page_size)

        result = await self.session.execute(query)
        total_result = await self.session.execute(count_query)

        items = list(result.scalars().all())
        total = total_result.scalar_one()
        return items, total

    async def update(self, evidence: Evidence, **fields) -> Evidence:
        for key, value in fields.items():
            if value is not None:
                setattr(evidence, key, value)
        evidence.updated_at = utc_now()
        await self.session.commit()
        await self.session.refresh(evidence)
        return evidence

    async def delete(self, evidence: Evidence) -> None:
        await self.session.delete(evidence)
        await self.session.commit()
