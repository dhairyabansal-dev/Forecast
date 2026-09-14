from fastapi.testclient import TestClient

from app.main import app
from app.schemas.anomaly import AnomalyCreate
from app.utils.hashing import hash_json


def test_root_endpoint():
    response = TestClient(app).get("/")
    assert response.status_code == 200
    assert response.json()["status"] == "running"


def test_health_endpoint():
    response = TestClient(app).get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


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
