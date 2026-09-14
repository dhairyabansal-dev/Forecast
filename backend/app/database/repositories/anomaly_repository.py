from __future__ import annotations
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.anomaly import Anomaly
from app.utils.helpers import utc_now


class AnomalyRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, anomaly: Anomaly) -> Anomaly:
        self.session.add(anomaly)
        await self.session.commit()
        await self.session.refresh(anomaly)
        return anomaly

    async def get_by_id(self, anomaly_id: str) -> Optional[Anomaly]:
        result = await self.session.execute(
            select(Anomaly).where(Anomaly.id == anomaly_id)
        )
        return result.scalar_one_or_none()

    async def list(
        self,
        page: int = 1,
        page_size: int = 50,
        is_anomalous: Optional[bool] = None,
        status: Optional[str] = None,
        src_ip: Optional[str] = None,
    ) -> tuple[list[Anomaly], int]:
        query = select(Anomaly)
        count_query = select(func.count()).select_from(Anomaly)

        if is_anomalous is not None:
            query = query.where(Anomaly.is_anomalous == is_anomalous)
            count_query = count_query.where(Anomaly.is_anomalous == is_anomalous)
        if status:
            query = query.where(Anomaly.status == status)
            count_query = count_query.where(Anomaly.status == status)
        if src_ip:
            query = query.where(Anomaly.src_ip == src_ip)
            count_query = count_query.where(Anomaly.src_ip == src_ip)

        query = query.order_by(Anomaly.detected_at.desc())
        query = query.offset((page - 1) * page_size).limit(page_size)

        result = await self.session.execute(query)
        total_result = await self.session.execute(count_query)

        items = list(result.scalars().all())
        total = total_result.scalar_one()

        return items, total

    async def update(self, anomaly: Anomaly, **fields) -> Anomaly:
        for key, value in fields.items():
            if value is not None:
                setattr(anomaly, key, value)
        anomaly.updated_at = utc_now()
        await self.session.commit()
        await self.session.refresh(anomaly)
        return anomaly

    async def bulk_create(self, anomalies: list[Anomaly]) -> list[Anomaly]:
        self.session.add_all(anomalies)
        await self.session.commit()
        for a in anomalies:
            await self.session.refresh(a)
        return anomalies

    async def delete(self, anomaly: Anomaly) -> None:
        await self.session.delete(anomaly)
        await self.session.commit()