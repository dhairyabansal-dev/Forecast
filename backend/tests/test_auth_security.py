from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.auth import hash_password, verify_password
from app.database.connection import AsyncSessionLocal
from app.main import app
from app.models.user import User


def test_argon2id_hashing_never_stores_plaintext():
    password = "Strong!Pass9"
    password_hash = hash_password(password)
    assert password_hash.startswith("$argon2id$")
    assert password_hash != password
    assert verify_password(password, password_hash)
    assert not verify_password("Wrong!Pass9", password_hash)


def test_auth_flow_and_backend_role_enforcement():
    email = f"auth-{uuid4().hex[:12]}@example.com"
    password = "Secure!Pass9"
    with TestClient(app) as client:
        registered = client.post("/api/auth/register", json={"email": email, "password": password, "full_name": "Test User"})
        assert registered.status_code == 201
        body = registered.json()
        assert body["user"]["role"] == "VIEWER"
        assert "password_hash" not in body["user"]

        me = client.get("/api/auth/me")
        assert me.status_code == 200
        assert me.json()["email"] == email

        wrong = client.post("/api/auth/login", json={"username": email, "password": "Wrong!Pass9"})
        assert wrong.status_code == 401
        assert wrong.json()["detail"] == "Invalid email or password."

        # VIEWER may read forecasts but cannot run the forecast operation.
        forbidden = client.post("/api/v1/forecast/generate", json={"horizon_hours": 24, "sequence_length": 48})
        assert forbidden.status_code == 403

        logged_out = client.post("/api/auth/logout")
        assert logged_out.status_code == 204
        assert client.get("/api/auth/me").status_code == 401


def test_sensitive_forecast_endpoint_rejects_unauthenticated_requests():
    with TestClient(app) as client:
        response = client.get("/api/v1/forecast/latest")
        assert response.status_code == 401


def test_password_hash_is_present_only_on_backend():
    email = f"hash-{uuid4().hex[:12]}@example.com"
    password = "Backend!Hash7"
    with TestClient(app) as client:
        assert client.post("/api/auth/register", json={"email": email, "password": password, "full_name": "Hash Test"}).status_code == 201
    import asyncio

    async def read_user():
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(User).where(User.email == email))
            return result.scalar_one()

    user = asyncio.run(read_user())
    assert user.password_hash.startswith("$argon2id$")
    assert password not in user.password_hash
