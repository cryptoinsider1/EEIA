from fastapi.testclient import TestClient

from eeia.api.http import app


client = TestClient(app)


def _base_packet_json() -> dict:
    # минимальный валидный пакет (по аналогии с другими интеграционными тестами)
    return {
        "packet_id": "pkt-trace-1",
        "device_id": "dev-trace-1",
        "created_at": "2025-11-20T07:30:00Z",
        "env": "ground",
        "domain": "medical",
        "packet_type": "alert",
        "priority": "high",
        "size_bytes": 128,
        "data": {"heart_rate": 100},
        "metadata": {"patient_id": "trace-test"},
    }


def test_route_packet_with_explicit_trace_id():
    payload = _base_packet_json()
    trace_id = "trace-12345-explicit"

    resp = client.post(
        "/v1/packets/route",
        json=payload,
        headers={"X-Request-Id": trace_id},
    )

    assert resp.status_code == 200
    body = resp.json()

    # trace_id должен сохраниться как есть
    assert body["trace_id"] == trace_id
    assert resp.headers.get("X-Request-Id") == trace_id


def test_route_packet_generates_trace_id_if_missing():
    payload = _base_packet_json()

    resp = client.post("/v1/packets/route", json=payload)

    assert resp.status_code == 200
    body = resp.json()

    # trace_id должен появиться и в теле, и в заголовке
    trace_body = body.get("trace_id")
    trace_header = resp.headers.get("X-Request-Id")

    assert isinstance(trace_body, str) and len(trace_body) > 0
    assert isinstance(trace_header, str) and len(trace_header) > 0
    # и они должны совпадать между собой
    assert trace_body == trace_header
