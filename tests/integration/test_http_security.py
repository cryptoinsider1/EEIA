from fastapi.testclient import TestClient

from eeia.api.http import app
from eeia.core.models import (
    Packet,
    Domain,
    Environment,
    PacketPriority,
    PacketType,
)
from eeia.security.packet_security import (
    DeviceKey,
    device_keystore,
    sign_packet_hmac,
)

client = TestClient(app)


def _make_packet_model() -> Packet:
    return Packet(
        packet_id="pkt-sec-int-1",
        device_id="dev-sec-int-1",
        created_at="2025-11-20T07:30:00Z",
        env=Environment.GROUND,
        domain=Domain.BODY,
        packet_type=PacketType.ALERT,
        priority=PacketPriority.HIGH,
        size_bytes=256,
        data={"heart_rate": 130},
        metadata={"patient_id": "anon-sec-int"},
    )


def test_route_packet_with_valid_hmac_signature():
    # 1. Регистрируем ключ устройства в глобальном keystore
    key = DeviceKey(
        device_id="dev-sec-int-1",
        key_id="default",
        secret="dev-sec-int-1-secret",
    )
    device_keystore.register(key)

    # 2. Собираем Packet-модель и считаем подпись
    pkt = _make_packet_model()
    signature = sign_packet_hmac(pkt, key)

    # 3. Подготавливаем JSON-представление для HTTP-запроса
    payload = {
        "packet_id": pkt.packet_id,
        "device_id": pkt.device_id,
        "created_at": pkt.created_at.isoformat(),
        "env": pkt.env.value,
        "domain": pkt.domain.value,
        "packet_type": pkt.packet_type.value,
        "priority": pkt.priority.value,
        "size_bytes": pkt.size_bytes,
        "data": pkt.data,
        "metadata": pkt.metadata,
    }

    # 4. Отправляем запрос с корректными заголовками безопасности
    resp = client.post(
        "/v1/packets/route",
        json=payload,
        headers={
            "X-EEIA-Key-Id": key.key_id,
            "X-EEIA-Signature": signature,
        },
    )

    assert resp.status_code == 200
    body = resp.json()

    assert body["packet_id"] == pkt.packet_id
    assert body["device_id"] == pkt.device_id

    decision = body["decision"]
    # т.к. явной политики под BODY может не быть, policy_id может быть None,
    # но флаги хранения должны соответствовать дефолтной логике ALERT
    assert decision["store_in_timeseries"] is True
    assert decision["store_in_object_storage"] is True
    assert decision["should_forward"] is True
