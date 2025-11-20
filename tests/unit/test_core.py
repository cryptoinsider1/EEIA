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
        packet_id="pkt-000001",  
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
        policy_id="policy-1",
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
    assert decision_critical.policy.policy_id == "policy-1"
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

    from eeia.core.models import Domain, Environment, Packet, PacketPriority, PacketType
    from eeia.core.router import HybridRouter, PolicyStore, Policy

def test_policy_store_water_agriculture_body_domains():
    router = HybridRouter(PolicyStore())

    # политика для морского домена: WATER + ORBIT (морские дроны + спутниковый канал)
    water_policy = Policy(
        policy_id="policy-water-1",
        name="Naval & marine traffic via sat link",
        match_environment=Environment.ORBIT,
        match_domain=Domain.WATER,
        min_priority=PacketPriority.NORMAL,
        target_endpoint="https://navy-core.example/api/events",
        store_in_timeseries=True,
        store_in_object_storage=True,
        require_auth=True,
        require_integrity_check=True,
        require_encryption=True,
    )

    # политика для агросектора: AGRICULTURE + ground
    agriculture_policy = Policy(
        policy_id="policy-agri-1",
        name="Agriculture sensor stream",
        match_environment=Environment.GROUND,
        match_domain=Domain.AGRICULTURE,
        min_priority=PacketPriority.LOW,
        target_endpoint="https://agri-core.example/ingest",
        store_in_timeseries=True,
        store_in_object_storage=False,
        require_auth=True,
        require_integrity_check=True,
        require_encryption=False,  # допустим, внутри доверенного сегмента
    )

    # политика для BODY: всё что касается тела — всегда максимально жёстко
    body_policy = Policy(
        policy_id="policy-body-1",
        name="Body-mounted medical devices",
        match_environment=Environment.GROUND,
        match_domain=Domain.BODY,
        min_priority=PacketPriority.LOW,
        target_endpoint="https://body-secure-core.example/api/measurements",
        store_in_timeseries=True,
        store_in_object_storage=True,
        require_auth=True,
        require_integrity_check=True,
        require_encryption=True,
    )

    router.add_policies([water_policy, agriculture_policy, body_policy])

    # --- WATER + ORBIT --------------------------------------------------------
    water_packet = Packet(
        packet_id="pkt-water-1",
        device_id="dev-buoy-1",
        created_at="2025-11-20T07:30:00Z",
        env=Environment.ORBIT,
        domain=Domain.WATER,
        packet_type=PacketType.TELEMETRY,
        priority=PacketPriority.NORMAL,
        size_bytes=256,
        data={"wave_height": 3.2},
        metadata={"buoy_id": "buoy-001"},
    )

    decision_water = router.route(water_packet)
    assert decision_water.policy is not None
    assert decision_water.policy.policy_id == "policy-water-1"
    assert decision_water.target_endpoint == "https://navy-core.example/api/events"
    assert decision_water.store_in_timeseries is True
    assert decision_water.store_in_object_storage is True

    # --- AGRICULTURE + GROUND -------------------------------------------------
    agri_packet = Packet(
        packet_id="pkt-agri-1",
        device_id="dev-field-1",
        created_at="2025-11-20T08:00:00Z",
        env=Environment.GROUND,
        domain=Domain.AGRICULTURE,
        packet_type=PacketType.TELEMETRY,
        priority=PacketPriority.LOW,
        size_bytes=128,
        data={"soil_moisture": 0.27},
        metadata={"field_id": "field-42"},
    )

    decision_agri = router.route(agri_packet)
    assert decision_agri.policy is not None
    assert decision_agri.policy.policy_id == "policy-agri-1"
    assert decision_agri.target_endpoint == "https://agri-core.example/ingest"
    assert decision_agri.store_in_timeseries is True
    assert decision_agri.store_in_object_storage is False

    # --- BODY + GROUND --------------------------------------------------------
    body_packet = Packet(
        packet_id="pkt-body-1",
        device_id="dev-heart-1",
        created_at="2025-11-20T08:15:00Z",
        env=Environment.GROUND,
        domain=Domain.BODY,
        packet_type=PacketType.ALERT,
        priority=PacketPriority.CRITICAL,
        size_bytes=256,
        data={"heart_rate": 155},
        metadata={"patient_id": "anon-body-1"},
    )

    decision_body = router.route(body_packet)
    assert decision_body.policy is not None
    assert decision_body.policy.policy_id == "policy-body-1"
    assert decision_body.target_endpoint == "https://body-secure-core.example/api/measurements"
    # BODY-домен: всегда сохраняем всё
    assert decision_body.store_in_timeseries is True
    assert decision_body.store_in_object_storage is True

