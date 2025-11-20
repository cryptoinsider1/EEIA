from datetime import datetime, timezone

from eeia.core.models import (
    Domain,
    Environment,
    Packet,
    PacketPriority,
    PacketType,
    Policy,
)
from eeia.core.router import HybridRouter, PolicyStore
from eeia.core.cache import OfflineCache


def _make_packet(priority: PacketPriority = PacketPriority.NORMAL) -> Packet:
    return Packet(
        packet_id="pkt-000001",  # было "pkt-1" — стало 9 символов
        device_id="dev-000001",
        created_at=datetime.now(timezone.utc),
        env=Environment.GROUND,
        domain=Domain.MEDICAL,
        packet_type=PacketType.ALERT,
        priority=priority,
        size_bytes=42,
        data={"heart_rate": 90},
        metadata={"patient_id": "anon-123"},
    )


def test_policy_store_and_router_basic():
    router = HybridRouter(PolicyStore())

    # без политик действует дефолтное поведение
    packet = _make_packet()
    decision = router.route(packet)
    assert decision.policy is None
    assert decision.store_in_timeseries is True
    assert decision.store_in_object_storage is True  # ALERT

    # добавляем политику для MEDICAL на земле с высоким приоритетом
    policy = Policy(
        policy_id="p1",
        name="Critical medical ground traffic",
        match_environment=Environment.GROUND,
        match_domain=Domain.MEDICAL,
        min_priority=PacketPriority.HIGH,
        target_endpoint="https://medical-core.example/api/events",
        store_in_timeseries=True,
        store_in_object_storage=True,
        require_auth=True,
        require_integrity_check=True,
        require_encryption=True,
    )
    router.add_policies([policy])

    # пакет с NORMAL приоритетом не подпадает под политику
    normal_packet = _make_packet(priority=PacketPriority.NORMAL)
    decision_normal = router.route(normal_packet)
    assert decision_normal.policy is None

    # пакет с CRITICAL приоритетом должен совпасть
    critical_packet = _make_packet(priority=PacketPriority.CRITICAL)
    decision_critical = router.route(critical_packet)
    assert decision_critical.policy is not None
    assert decision_critical.policy.policy_id == "p1"
    assert decision_critical.target_endpoint == "https://medical-core.example/api/events"


def test_offline_cache_roundtrip(tmp_path):
    cache_db = tmp_path / "cache.db"
    cache = OfflineCache(db_path=cache_db)

    packet = _make_packet()
    cache.enqueue(packet)
    assert cache.count() == 1

    batch = cache.dequeue_batch(limit=10)
    assert len(batch) == 1
    cached = batch[0]
    assert cached.packet.packet_id == packet.packet_id

    # удаляем и проверяем, что очередь пустая
    cache.delete_many([cached.internal_id])
    assert cache.count() == 0
