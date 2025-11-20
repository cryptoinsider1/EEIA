from __future__ import annotations

"""
Zero-Trust security core for EEIA.
Здесь:
- модель ключей устройств;
- HMAC-подпись/проверка Packet'ов;
- базовый hook под ML-scoring (внешняя модель риска);
- функция безопасной валидации входа в роутер.
"""

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional

from eeia.core.models import Packet


# ---------------------------------------------------------------------------
# Модель ключей устройств
# ---------------------------------------------------------------------------

@dataclass
class DeviceKey:
    device_id: str
    key_id: str
    secret: bytes  # для HMAC; для асимметрии здесь будет сериализованный приват/публичный ключ
    algorithm: str = "HS256"
    active: bool = True


class DeviceKeyStore:
    """Простое in-memory хранилище ключей устройств.
    В боевой системе будет бэкенд (KMS, HSM, Vault).
    """

    def __init__(self) -> None:
        self._keys_by_device: Dict[str, DeviceKey] = {}

    def register(self, key: DeviceKey) -> None:
        self._keys_by_device[key.device_id] = key

    def revoke(self, device_id: str) -> None:
        if device_id in self._keys_by_device:
            self._keys_by_device[device_id].active = False

    def get_active_key(self, device_id: str) -> Optional[DeviceKey]:
        key = self._keys_by_device.get(device_id)
        if key is None or not key.active:
            return None
        return key


# ---------------------------------------------------------------------------
# Подпись и проверка Packet (HMAC)
# ---------------------------------------------------------------------------

def _serialize_packet_for_signing(packet: Packet) -> bytes:
    """Каноническая сериализация Packet для подписи.
    Важно:
    - никакой нестабильной сериализации dict'ов;
    - фиксированный порядок полей;
    - в проде лучше использовать protobuf/CBOR.
    """
    parts = [
        packet.packet_id,
        packet.device_id,
        packet.created_at.isoformat() if hasattr(packet.created_at, "isoformat") else str(packet.created_at),
        str(packet.env.value),
        str(packet.domain.value),
        str(packet.packet_type.value),
        str(packet.priority.value),
        str(packet.size_bytes),
        repr(packet.data),
        repr(packet.metadata),
    ]
    return "|".join(parts).encode("utf-8")


def sign_packet_hmac(packet: Packet, key: DeviceKey) -> str:
    if key.algorithm != "HS256":
        raise ValueError(f"Unsupported algorithm for HMAC: {key.algorithm}")
    msg = _serialize_packet_for_signing(packet)
    sig = hmac.new(key.secret, msg, hashlib.sha256).hexdigest()
    return sig


def verify_packet_hmac(packet: Packet, signature: str, key: DeviceKey) -> bool:
    if key.algorithm != "HS256":
        raise ValueError(f"Unsupported algorithm for HMAC: {key.algorithm}")
    expected = sign_packet_hmac(packet, key)
    # защищаемся от timing-attack
    return hmac.compare_digest(expected, signature)


# ---------------------------------------------------------------------------
# ML-scoring hook
# ---------------------------------------------------------------------------

RiskScorer = Callable[[Packet], float]


@dataclass
class RiskScoringEngine:
    """Тонкий адаптер к внешней ML-модели.
    В реальности здесь будет клиент gRPC/HTTP, загрузка локальной модели и т.п.
    """

    scorer: Optional[RiskScorer] = None
    threshold_block: float = 0.9  # выше этого значения – блокируем трафик
    threshold_audit: float = 0.7  # выше этого значения – усиливаем аудит

    def set_scorer(self, scorer: RiskScorer) -> None:
        self.scorer = scorer

    def score(self, packet: Packet) -> Optional[float]:
        if self.scorer is None:
            return None
        return float(self.scorer(packet))

    def should_block(self, packet: Packet) -> bool:
        score = self.score(packet)
        return score is not None and score >= self.threshold_block

    def should_strict_audit(self, packet: Packet) -> bool:
        score = self.score(packet)
        return score is not None and score >= self.threshold_audit


global_risk_engine = RiskScoringEngine()


# ---------------------------------------------------------------------------
# Безопасная валидация входа в роутер
# ---------------------------------------------------------------------------

@dataclass
class EntryValidationResult:
    ok: bool
    reason: Optional[str] = None
    risk_score: Optional[float] = None
    strict_audit: bool = False
    blocked: bool = False
    extra: Dict[str, str] = field(default_factory=dict)


def validate_packet_entry(
    packet: Packet,
    signature: Optional[str],
    key_store: DeviceKeyStore,
    risk_engine: RiskScoringEngine = global_risk_engine,
) -> EntryValidationResult:
    """Проверка перед допуском пакета в роутер.
    Шаги:
    1. Проверяем, есть ли активный ключ устройства.
    2. Если заголовок подписи присутствует – верифицируем.
       (в строгом режиме можно будет требовать подпись всегда).
    3. Отдаём пакет в ML-scoring (если настроен).
    """

    key = key_store.get_active_key(packet.device_id)
    if key is None:
        return EntryValidationResult(
            ok=False,
            reason="unknown_or_inactive_device",
            blocked=True,
        )

    if signature is not None:
        if not verify_packet_hmac(packet, signature, key):
            return EntryValidationResult(
                ok=False,
                reason="invalid_signature",
                blocked=True,
            )

    score = risk_engine.score(packet)
    blocked = risk_engine.should_block(packet) if score is not None else False
    strict_audit = risk_engine.should_strict_audit(packet) if score is not None else False

    if blocked:
        return EntryValidationResult(
            ok=False,
            reason="ml_risk_block",
            blocked=True,
            risk_score=score,
            strict_audit=strict_audit,
        )

    return EntryValidationResult(
        ok=True,
        reason=None,
        blocked=False,
        strict_audit=strict_audit,
        risk_score=score,
    )
