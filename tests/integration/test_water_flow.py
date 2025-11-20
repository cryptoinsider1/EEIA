from fastapi.testclient import TestClient

from eeia.api.http import app

client = TestClient(app)


def test_water_domain_flow_orbit_policy_and_routing():
    # 1) создаём политику для WATER + ORBIT
    policy = {
        "policy_id": "policy-water-int-1",
        "name": "Marine telemetry via orbit",
        "match_environment": "orbit",
        "match_domain": "water",
        "min_priority": "normal",
        "target_endpoint": "https://navy-core.example/api/telemetry",
        "store_in_timeseries": True,
        "store_in_object_storage": True,
        "require_auth": True,
        "require_integrity_check": True,
        "require_encryption": True,
    }

    resp = client.post("/v1/policies", json=policy)
    assert resp.status_code == 200
    body = resp.json()
    assert body["policy_id"] == "policy-water-int-1"

    # 2) отправляем пакет от морского буя, прокидываем через HTTP API
    packet = {
        "packet_id": "pkt-water-int-1",
        "device_id": "dev-buoy-int-1",
        "created_at": "2025-11-20T09:00:00Z",
        "env": "orbit",
        "domain": "water",
        "packet_type": "telemetry",
        "priority": "normal",
        "size_bytes": 256,
        "data": {"wave_height": 2.7, "water_temp": 12.3},
        "metadata": {"buoy_id": "buoy-int-42"},
    }

    resp2 = client.post("/v1/packets/route", json=packet)
    assert resp2.status_code == 200
    body2 = resp2.json()

    # базовые проверки решения
    assert body2["packet_id"] == "pkt-water-int-1"
    assert body2["decision"]["target_endpoint"] == "https://navy-core.example/api/telemetry"
    assert body2["decision"]["store_in_timeseries"] is True
    assert body2["decision"]["store_in_object_storage"] is True
