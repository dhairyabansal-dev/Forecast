"""Create the first ADMIN from ADMIN_EMAIL and ADMIN_PASSWORD environment variables.
Usage: python -m scripts.create_admin
"""
import asyncio

from sqlalchemy import select

from app.core.auth import hash_password, validate_password, valid_email, normalize_email
from app.core.config import settings
from app.database.connection import AsyncSessionLocal, engine
from app.database.connection import Base
from app.models.user import AuditLog, User, UserSession
from app.utils.helpers import generate_uuid, utc_now


async def main() -> None:
    email = normalize_email(settings.ADMIN_EMAIL)
    password = settings.ADMIN_PASSWORD
    if not email or not password:
        raise SystemExit("ADMIN_EMAIL and ADMIN_PASSWORD must be set in the backend environment")
    if not valid_email(email):
        raise SystemExit("ADMIN_EMAIL must be a valid email")
    errors = validate_password(password)
    if errors:
        raise SystemExit("ADMIN_PASSWORD does not meet requirements: " + "; ".join(errors))

    # Local convenience only. Production schema must be applied with the migration first.
    if settings.APP_ENV.lower() not in {"production", "prod", "vercel"} and not settings.VERCEL:
        from app.models.anomaly import Anomaly, ThreatAnomalyLink
        from app.models.evidence import Evidence
        from app.models.forecast import Forecast
        from app.models.threat import Threat
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as session:
        existing = await session.execute(select(User).where(User.email == email))
        if existing.scalar_one_or_none():
            raise SystemExit("An account with ADMIN_EMAIL already exists")
        user = User(id=generate_uuid(), email=email, password_hash=hash_password(password), full_name="System Administrator", role="ADMIN", is_active=True, created_at=utc_now(), updated_at=utc_now())
        session.add(user)
        session.add(AuditLog(id=generate_uuid(), user_id=user.id, action="USER_CREATION", resource=user.id, status="SUCCESS", metadata_json={"role": "ADMIN"}, timestamp=utc_now()))
        await session.commit()
    print("ADMIN account created successfully.")


if __name__ == "__main__":
    asyncio.run(main())
