import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.schemas.anomaly import AnomalyCreate
from app.services.blockchain_service import BlockchainService
from app.utils.hashing import hash_json


def test_root_and_health_endpoints_with_lifespan():
    with TestClient(app) as client:
        root = client.get("/")
        assert root.status_code == 200
        assert root.json()["status"] == "running"

        health = client.get("/api/v1/health")
        assert health.status_code == 200
        assert health.json()["status"] == "ok"

        database = client.get("/api/v1/health/db")
        assert database.status_code == 200
        assert database.json()["database"] == "connected"


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


def test_blockchain_hash_validation():
    valid_hash = "a" * 64
    assert BlockchainService._hash_bytes(valid_hash) == bytes.fromhex(valid_hash)
    assert BlockchainService._hash_bytes("0x" + valid_hash) == bytes.fromhex(valid_hash)

    with pytest.raises(ValueError):
        BlockchainService._hash_bytes("invalid")
    with pytest.raises(ValueError):
        BlockchainService._hash_bytes("z" * 64)
