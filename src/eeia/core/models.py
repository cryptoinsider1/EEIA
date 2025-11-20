from __future__ import annotations

"""
Базовые доменные модели EEIA:
- Environment / Domain / PacketType / PacketPriority — строгие перечисления,
- Device — описание граничного устройства,
- Packet — единица трафика,
- Policy — политика маршрутизации/хранения/безопасности.

Модели приведены к стилю Pydantic v2 (ConfigDict),
лишние поля запрещены (extra="forbid"), включена валидация при присвоении.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional
from uuid import UUID

from pydantic import BaseModel, Field, ConfigDict


class Environment(str, Enum):
    GROUND = "ground"
    AIR = "air"
    ORBIT = "orbit"


class Domain(str, Enum):
    MEDICAL = "medical"          # больницы, телемедицина, МЧС-медицина
    SMART_CITY = "smart_city"    # умные города, ЖКХ, городская инфраструктура
    INDUSTRIAL = "industrial"    # промышленные объекты, фабрики, энергетика
    WATER = "water"              # флот, гидротехника, подводные конструкции
    BODY = "body"                # медицина: носимые сенсоры, клиника, МЧС
    TRANSPORT = "transport"      # транспорт, логистика, общественный транспорт
    AGRICULTURE = "agriculture"  # агросектор, фермы, теплицы, датчики полей
    OTHER = "other"              # прочие/резервный домен


class PacketType(str, Enum):
    TELEMETRY = "telemetry"
    HEARTBEAT = "heartbeat"
    ALERT = "alert"
    CONTROL = "control"


class PacketPriority(str, Enum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class Device(BaseModel):
    """Описание устройства на границе EEIA."""

    model_config = ConfigDict(
        extra="forbid",           # запрет лишних полей
        validate_assignment=True, # валидация при изменении атрибутов
    )

    device_id: str = Field(..., description="Идентификатор устройства в EEIA")
    environment: Environment = Field(..., description="Среда (земля/воздух/орбита и т.д.)")
    domain: Domain = Field(..., description="Домен применения устройства (медицина, умный город и т.п.)")

    name: Optional[str] = Field(
        None,
        description="Человекочитаемое имя устройства",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Дополнительные атрибуты устройства (геопозиция, модель железа и т.п.)",
    )


class Packet(BaseModel):
    """Универсальный пакет данных, проходящий через EEIA."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
    )
    trace_id: Optional[str] = None  # или UUID, но строка проще для JSON
    packet_id: str = Field(..., description="Идентификатор пакета")
    device_id: str = Field(..., description="ID устройства-источника")
    created_at: datetime = Field(..., description="Момент формирования пакета (UTC)")

    env: Environment = Field(..., description="Среда, в которой находится устройство")
    domain: Domain = Field(..., description="Домен применения данных")

    packet_type: PacketType = Field(..., description="Тип пакета (telemetry / alert / control / heartbeat)")
    priority: PacketPriority = Field(..., description="Приоритет обработки")

    size_bytes: int = Field(
        ...,
        ge=0,
        description="Размер полезной нагрузки в байтах",
    )
    data: Dict[str, Any] = Field(
        default_factory=dict,
        description="Основная полезная нагрузка (бездоменно-структурированный JSON)",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Технические/контекстные метаданные пакета",
    )


class Policy(BaseModel):
    """Политика маршрутизации и хранения трафика."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
    )

    policy_id: str = Field(..., description="Уникальный идентификатор политики")
    name: str = Field(..., description="Человекочитаемое имя политики")

    match_environment: Optional[Environment] = Field(
        None,
        description="Фильтр по среде; если None — политика подходит для любой среды",
    )
    match_domain: Optional[Domain] = Field(
        None,
        description="Фильтр по домену; если None — подходит для любого домена",
    )
    min_priority: Optional[PacketPriority] = Field(
        None,
        description="Минимальный приоритет пакета, с которого политика начинает совпадать",
    )

    target_endpoint: Optional[str] = Field(
        None,
        description="Целевой endpoint (URL API, брокер и т.п.) для маршрутизации",
    )

    store_in_timeseries: bool = Field(
        default=True,
        description="Сохранять ли данные в TSDB",
    )
    store_in_object_storage: bool = Field(
        default=False,
        description="Сохранять ли данные в объектном хранилище (blob/object)",
    )

    require_auth: bool = Field(
        default=True,
        description="Требовать ли аутентификацию источника",
    )
    require_integrity_check: bool = Field(
        default=True,
        description="Требовать ли проверку целостности (подпись/хеш)",
    )
    require_encryption: bool = Field(
        default=True,
        description="Требовать ли сквозное шифрование данных",
    )
