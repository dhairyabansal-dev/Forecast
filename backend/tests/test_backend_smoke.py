import pytest
from httpx import ASGITransport, AsyncClient

from app.database.connection import close_db, init_db
from app.main import app
from app.schemas.anomaly import AnomalyCreate
from app.utils.hashing import hash_json


@pytest.mark.asyncio
async def test_root_and_health_endpoints_with_database():
    # Keep database setup, requests, and teardown on the same asyncio loop.
    # This avoids asyncpg connections being reused across TestClient loops.
    await init_db()
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            root = await client.get("/")
            assert root.status_code == 200
            assert root.json()["status"] == "running"

            health = await client.get("/api/v1/health")
            assert health.status_code == 200
            assert health.json()["status"] == "ok"

            database = await client.get("/api/v1/health/db")
            assert database.status_code == 200
            assert database.json()["database"] == "connected"
    finally:
        await close_db()


def test_anomaly_create_schema_requires_features():
    payload = AnomalyCreate(
        flow_id="flow-1",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        feature_vector=[0.1, 0.2, 0.3],
    )
    assert payload.feature_vector == [0.1, 0.2, 0.3]


def test_hash_json_is_deterministic():
    payload = {"b": 2, "a": 1}
    assert hash_json(payload) == hash_json({"a": 1, "b": 2})
    assert len(hash_json(payload)) == 64
