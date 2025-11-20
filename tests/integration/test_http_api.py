from fastapi.testclient import TestClient

from eeia.api.http import app


client = TestClient(app)


def test_health_ok():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_create_policy_and_route_packet():
    # создаём политику
    policy = {
        "policy_id": "policy-int-1",
        "name": "Int test medical policy",
        "match_environment": "ground",
        "match_domain": "medical",
        "min_priority": "high",
        "target_endpoint": "https://medical-core.example/api/events",
        "store_in_timeseries": True,
        "store_in_object_storage": True,
        "require_auth": True,
        "require_integrity_check": True,
        "require_encryption": True,
    }
    resp = client.post("/v1/policies", json=policy)
    assert resp.status_code == 200
    body = resp.json()
    assert body["policy_id"] == "policy-int-1"

    # отправляем пакет
    packet = {
        "packet_id": "pkt-int-1",
        "device_id": "dev-int-1",
        "created_at": "2025-11-20T07:30:00Z",
        "env": "ground",
        "domain": "medical",
        "packet_type": "alert",
        "priority": "high",
        "size_bytes": 128,
        "data": {"heart_rate": 110},
        "metadata": {"patient_id": "anon-int"},
    }
    resp2 = client.post("/v1/packets/route", json=packet)
    assert resp2.status_code == 200
    body2 = resp2.json()

    assert body2["packet_id"] == "pkt-int-1"
    assert body2["decision"]["policy_id"] == "policy-int-1"
    assert body2["decision"]["should_forward"] is True
