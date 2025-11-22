from eeia.core.models import Packet, Domain, Environment, PacketPriority, PacketType
from eeia.security.packet_security import (
    DeviceKey,
    DeviceKeyStore,
    SecurityResult,
    sign_packet_hmac,
    verify_packet_hmac,
)


def _make_packet() -> Packet:
    return Packet(
        packet_id="pkt-sec-1",
        device_id="dev-sec-1",
        created_at="2025-11-20T07:30:00Z",
        env=Environment.GROUND,
        domain=Domain.BODY,
        packet_type=PacketType.ALERT,
        priority=PacketPriority.HIGH,
        size_bytes=128,
        data={"heart_rate": 120},
        metadata={"patient_id": "anon"},
    )


def test_sign_and_verify_ok():
    store = DeviceKeyStore()
    key = DeviceKey(device_id="dev-sec-1", key_id="default", secret="super-secret")
    store.register(key)

    pkt = _make_packet()
    sig = sign_packet_hmac(pkt, key)

    res = verify_packet_hmac(
        packet=pkt,
        signature=sig,
        device_id="dev-sec-1",
        key_id="default",
        keystore=store,
    )

    assert isinstance(res, SecurityResult)
    assert res.ok is True
    assert res.reason is None


def test_verify_fails_on_wrong_signature():
    store = DeviceKeyStore()
    key = DeviceKey(device_id="dev-sec-1", key_id="default", secret="super-secret")
    store.register(key)

    pkt = _make_packet()
    bad_sig = "0" * 64  # заведомо неправильный HMAC

    res = verify_packet_hmac(
        packet=pkt,
        signature=bad_sig,
        device_id="dev-sec-1",
        key_id="default",
        keystore=store,
    )

    assert res.ok is False
    assert res.reason == "signature_mismatch"
