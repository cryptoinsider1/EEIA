from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from eeia.api.http import create_app
from eeia.core.models import Packet
from eeia.edge_ml.hooks import PacketScorer, ScoringResult


class DummyScorer(PacketScorer):
    """Простой тестовый ML-скорер, чтобы проверить интеграцию в HTTP API."""

    def score(self, packet: Packet) -> ScoringResult:  # type: ignore[override]
        return ScoringResult(
            score=0.87,
            label="suspicious",
            reasons=["unit-test-dummy"],
        )


def _make_packet() -> dict:
    """Подготовить тестовый Packet в JSON-формате для HTTP-запроса."""
    return {
        "packet_id": "pkt-ml-1",
        "device_id": "dev-ml-1",
        "created_at": "2025-11-20T07:30:00Z",
        "env": "ground",
        "domain": "medical",
        "packet_type": "alert",
        "priority": "high",
        "size_bytes": 256,
        "data": {"heart_rate": 130},
        "metadata": {"patient_id": "ml-test"},
    }


def test_route_packet_includes_ml_block(tmp_path: Path) -> None:
    """Пакет, прошедший через HTTP API, должен содержать блок decision.ml."""

    # создаём приложение с кастомным скорером
    app = create_app(
        cache_path=tmp_path / "test_ml_cache.db",
        packet_scorer=DummyScorer(),
    )
    client = TestClient(app)

    # шлём пакет
    resp = client.post("/v1/packets/route", json=_make_packet())
    assert resp.status_code == 200

    body = resp.json()
    assert "decision" in body

    ml = body["decision"].get("ml")
    assert ml is not None

    # проверяем, что данные от DummyScorer попали в ответ
    assert ml["label"] == "suspicious"
    assert ml["score"] == 0.87
    assert "unit-test-dummy" in ml["reasons"]
