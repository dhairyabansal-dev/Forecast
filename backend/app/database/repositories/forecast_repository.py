from __future__ import annotations
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.forecast import Forecast


class ForecastRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, forecast: Forecast) -> Forecast:
        self.session.add(forecast)
        await self.session.commit()
        await self.session.refresh(forecast)
        return forecast

    async def get_by_id(self, forecast_id: str) -> Optional[Forecast]:
        result = await self.session.execute(
            select(Forecast).where(Forecast.id == forecast_id)
        )
        return result.scalar_one_or_none()

    async def get_latest(self, network_segment: Optional[str] = None) -> Optional[Forecast]:
        query = select(Forecast).order_by(Forecast.generated_at.desc())
        if network_segment:
            query = query.where(Forecast.network_segment == network_segment)
        query = query.limit(1)
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def list(
        self,
        page: int = 1,
        page_size: int = 50,
        network_segment: Optional[str] = None,
    ) -> tuple[list[Forecast], int]:
        query = select(Forecast)
        count_query = select(func.count()).select_from(Forecast)

        if network_segment:
            query = query.where(Forecast.network_segment == network_segment)
            count_query = count_query.where(Forecast.network_segment == network_segment)

        query = query.order_by(Forecast.generated_at.desc())
        query = query.offset((page - 1) * page_size).limit(page_size)

        result = await self.session.execute(query)
        total_result = await self.session.execute(count_query)

        items = list(result.scalars().all())
        total = total_result.scalar_one()

        return items, total

    async def delete(self, forecast: Forecast) -> None:
        await self.session.delete(forecast)
        await self.session.commit()