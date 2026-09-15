from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import AuditLog
from app.utils.helpers import utc_now


async def record_audit(
    session: AsyncSession,
    *,
    action: str,
    status: str,
    user_id: str | None = None,
    resource: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    # Never pass secrets, passwords, tokens, or credential material in metadata.
    session.add(
        AuditLog(
            user_id=user_id,
            action=action,
            resource=resource,
            status=status,
            metadata_json=metadata,
            timestamp=utc_now(),
        )
    )
    await session.commit()
