"""Core data models for EEIA.

Здесь описываются базовые сущности:
- Environment / Domain: в каких средах и отраслях работает устройство.
- Device: гражданское IoT-устройство (медицина, промышленность, РЖД, флот и т.д.).
- Packet: телеметрия/событие, проходящее через EEIA.
- Policy: высокоуровневая политика маршрутизации/безопасности.

⚠ Важно: это публичная референсная модель.
Никаких военных/клаcсифированных расширений здесь не описываем.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Dict, Optional, Union

from pydantic import BaseModel, Field, HttpUrl, IPvAnyAddress, conint, constr


# --- Базовые перечисления ----------------------------------------------------


class Environment(str, Enum):
    """Физическая среда, в которой работает устройство."""

    GROUND = "ground"  # города, промышленные объекты, железные дороги
    WATER = "water"  # флот, гидротехника, подводные конструкции
    AIR = "air"  # лёгкая авиация, БПЛА гражданского назначения
    BODY = "body"  # медицина: носимые сенсоры, клиника, МЧС-медицина


class Domain(str, Enum):
    """Отрасль/домен применения (гражданский фокус)."""

    MEDICAL = "medical"
    INDUSTRIAL = "industrial"
    TRANSPORT = "transport"
    AGRICULTURE = "agriculture"
    CLIMATE = "climate"
    ENERGY = "energy"
    GENERIC = "generic"


class PacketPriority(str, Enum):
    """Приоритет обработки пакета."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class PacketType(str, Enum):
    """Тип пакета/события."""

    TELEMETRY = "telemetry"
    ALERT = "alert"
    CONTROL = "control"
    HEARTBEAT = "heartbeat"


IPAddress = Union[IPv4Address, IPv6Address, IPvAnyAddress]


# --- Модели устройств и пакетов ----------------------------------------------


class Device(BaseModel):
    """Гражданское IoT-устройство, зарегистрированное в EEIA."""

    device_id: constr(min_length=3, max_length=64) = Field(
        ...,
        description="Стойкий идентификатор устройства в рамках EEIA.",
    )
    environment: Environment = Field(
        ...,
        description="Физическая среда (земля/вода/воздух/тело).",
    )
    domain: Domain = Field(
        Domain.GENERIC,
        description="Отрасль применения (медицина, промышленность и т.п.).",
    )

    vendor: Optional[constr(max_length=128)] = Field(
        None, description="Производитель устройства (опционально)."
    )
    model: Optional[constr(max_length=128)] = Field(
        None, description="Модель устройства (опционально)."
    )
    firmware_version: Optional[constr(max_length=64)] = Field(
        None, description="Версия прошивки."
    )

    ip_address: Optional[IPAddress] = Field(
        None,
        description="Текущий IP-адрес (если применимо). "
        "Для некоторых протоколов может быть отсутствовать.",
    )

    online: bool = Field(
        True,
        description="Флаг: доступно ли устройство по мнению ядра EEIA.",
    )
    last_seen: Optional[datetime] = Field(
        None,
        description="Метка времени последнего события от устройства.",
    )

    labels: Dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Произвольные метки (location=..., hospital_id=..., "
            "train_id=..., vessel_id=...). "
            "Используются для маршрутизации и аналитики."
        ),
    )

    class Config:
        extra = "forbid"
        frozen = False  # устройство может обновляться по ходу жизни


class Packet(BaseModel):
    """Пакет данных/событие, проходящий через EEIA.

    Это минимальный формат, который должен уметь понять HybridRouter и все
    слои безопасности. Реальный полезный payload находится в поле `data`.
    """

    packet_id: constr(min_length=8, max_length=64) = Field(
        ...,
        description="Уникальный идентификатор пакета в рамках системы.",
    )
    device_id: constr(min_length=3, max_length=64) = Field(
        ...,
        description="ID устройства-источника (ссылается на Device.device_id).",
    )

    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Когда пакет был сформирован на источнике.",
    )
    received_at: Optional[datetime] = Field(
        None,
        description="Когда пакет был принят ядром EEIA (может заполняться на шлюзе).",
    )

    env: Environment = Field(
        ...,
        description="Дублируем среду устройства для удобства маршрутизации.",
    )
    domain: Domain = Field(
        Domain.GENERIC,
        description="Дублируем домен применения для политик и аналитики.",
    )

    packet_type: PacketType = Field(
        PacketType.TELEMETRY,
        description="Класс события: телеметрия, алерт, управляющая команда и т.п.",
    )
    priority: PacketPriority = Field(
        PacketPriority.NORMAL,
        description="Приоритет обработки для очередей и роутинга.",
    )

    size_bytes: conint(ge=0, le=10_000_000) = Field(
        0,
        description="Размер полезной нагрузки (байт). "
        "Ограничен для защиты от тривиальных DoS.",
    )

    data: Dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Структурированные данные телеметрии/события. "
            "Содержимое зависит от профиля/домена (generic_iot, aks_rv и т.д.)."
        ),
    )

    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Доп. сведения: качество сигнала, координаты, "
            "идентификаторы смены/бригады/пациента (в псевдонимизированном виде)."
        ),
    )

    class Config:
        extra = "forbid"


class Policy(BaseModel):
    """Высокоуровневая политика маршрутизации и обработки.

    Эти объекты читаются HybridRouter и модулями безопасности для принятия
    решений: куда отправить пакет, с каким уровнем приоритета, где хранить
    и какие проверки применить.
    """

    policy_id: constr(min_length=3, max_length=64) = Field(
        ...,
        description="Идентификатор политики.",
    )
    name: constr(min_length=3, max_length=128) = Field(
        ...,
        description="Человекочитаемое имя политики.",
    )

    # Примеры критериев политики (минимальный набор, можно расширять).
    match_environment: Optional[Environment] = Field(
        None,
        description="Если указано — политика применяется только к этой среде.",
    )
    match_domain: Optional[Domain] = Field(
        None,
        description="Если указано — политика применяется только к этому домену.",
    )
    min_priority: Optional[PacketPriority] = Field(
        None,
        description="Минимальный приоритет пакета, с которого политика активна.",
    )

    # Куда и как маршрутизировать.
    target_endpoint: Optional[HttpUrl] = Field(
        None,
        description="Базовый URL сервиса/шлюза, куда следует отправлять такие пакеты.",
    )
    store_in_timeseries: bool = Field(
        True, description="Сохранять ли данные в TSDB (телеметрия/метрики)."
    )
    store_in_object_storage: bool = Field(
        False, description="Сохранять ли данные в объектное хранилище (сырые данные)."
    )

    # Флаги безопасности (публичные, без кастомных шифров).
    require_auth: bool = Field(
        True,
        description="Обязательно ли требовать аутентификацию устройства.",
    )
    require_integrity_check: bool = Field(
        True,
        description="Проверять ли целостность пакета (подпись/хэш).",
    )
    require_encryption: bool = Field(
        True,
        description="Ожидать ли, что канал/пакет зашифрован (TLS/VPN/PQC и т.п.).",
    )

    class Config:
        extra = "forbid"
