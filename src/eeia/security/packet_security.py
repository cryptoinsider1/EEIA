from __future__ import annotations

"""
packet_security.py

Базовый Zero-Trust-слой для EEIA:
- модель ключей устройств (DeviceKey, DeviceKeyStore),
- HMAC-SHA256 подпись пакетов,
- верификация подписи с аккуратным результатом (SecurityResult).

Важно:
- подписание идёт не "сырого" JSON, а стабильного канонического представления Packet;
- используется compare_digest для защиты от тайминговых атак;
- модуль НЕ привязан к FastAPI/HTTP – чистая доменная логика.
"""

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

import hashlib
import hmac
import json

from eeia.core.models import Packet


# --- модели ключей устройств --------------------------------------------------


@dataclass(frozen=True)
class DeviceKey:
    """Симметричный ключ устройства.

    device_id: идентификатор устройства (из Packet.device_id)
    key_id: логический идентификатор ключа (можно ротировать ключи)
    secret: общий секрет (HMAC-ключ), хранится ТОЛЬКО на доверенных сторонах
    """

    device_id: str
    key_id: str
    secret: str


class DeviceKeyStore:
    """Простое in-memory хранилище ключей устройств.

    В боевой системе это может быть:
    - HSM/KMS (AWS KMS, HashiCorp Vault, Luna HSM и т.п.),
    - отдельный микросервис,
    - БД с шифрованием на уровне столбцов.

    Здесь – минимальная реализация для демо и тестов.
    """

    def __init__(self) -> None:
        self._keys: Dict[Tuple[str, str], DeviceKey] = {}

    def register(self, key: DeviceKey) -> None:
        """Зарегистрировать/обновить ключ устройства."""
        self._keys[(key.device_id, key.key_id)] = key

    def get(self, device_id: str, key_id: str) -> Optional[DeviceKey]:
        """Вернуть ключ по (device_id, key_id) или None, если ключа нет."""
        return self._keys.get((device_id, key_id))


# --- результат проверки безопасности ------------------------------------------


@dataclass(frozen=True)
class SecurityResult:
    """Результат проверки подписи/аутентичности пакета."""

    ok: bool
    reason: Optional[str] = None  # например: "unknown_device_or_key", "signature_mismatch"


# --- каноническое представление пакета ----------------------------------------


def _packet_payload_for_signing(packet: Packet) -> bytes:
    """Сформировать стабильное JSON-представление пакета для подписи.

    Мы намеренно берём только семантически важные поля и сортируем ключи.
    Это уменьшает риск несоответствия из-за порядка полей/форматирования.
    """
    base = {
        "packet_id": packet.packet_id,
        "device_id": packet.device_id,
        "created_at": packet.created_at.isoformat(),
        "env": packet.env.value,
        "domain": packet.domain.value,
        "packet_type": packet.packet_type.value,
        "priority": packet.priority.value,
        "size_bytes": packet.size_bytes,
        "data": packet.data,
        "metadata": packet.metadata,
    }
    return json.dumps(base, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _compute_hmac_sha256(payload: bytes, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


# --- публичные функции для подписи / проверки ---------------------------------


def sign_packet_hmac(packet: Packet, key: DeviceKey) -> str:
    """Подписать Packet HMAC-SHA256 с использованием ключа устройства."""
    payload = _packet_payload_for_signing(packet)
    return _compute_hmac_sha256(payload, key.secret)


def verify_packet_hmac(
    packet: Packet,
    signature: str,
    device_id: str,
    key_id: str,
    keystore: DeviceKeyStore,
) -> SecurityResult:
    """Проверить HMAC-подпись пакета.

    Возвращает SecurityResult.ok == True, если:
    - ключ найден;
    - подпись совпадает (сравнение через compare_digest).
    """
    key = keystore.get(device_id, key_id)
    if key is None:
        return SecurityResult(ok=False, reason="unknown_device_or_key")

    expected = sign_packet_hmac(packet, key)

    if not hmac.compare_digest(expected, signature):
        return SecurityResult(ok=False, reason="signature_mismatch")

    return SecurityResult(ok=True)


# --- глобальное in-memory хранилище для демо/тестов ---------------------------

device_keystore = DeviceKeyStore()

# Несколько тестовых ключей, чтобы сразу можно было играться:
device_keystore.register(
    DeviceKey(
        device_id="dev-int-1",
        key_id="default",
        secret="dev-int-1-secret",
    )
)

device_keystore.register(
    DeviceKey(
        device_id="dev-000001",
        key_id="default",
        secret="dev-000001-secret",
    )
)
