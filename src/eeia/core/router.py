from __future__ import annotations

"""Hybrid router and routing policies for EEIA.

Этот модуль отвечает за принятие решения, что делать с входящим Packet:
- какую политику применить;
- куда отправить (target_endpoint);
- где хранить (time-series / object storage);
- какие базовые требования безопасности должны быть соблюдены.

Важно:
- здесь нет привязки к конкретным протоколам (MQTT/HTTP и т.д.);
- это чистая «доменная логика», которую затем используют адаптеры.
"""

from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence

from .models import (
    Domain,
    Environment,
    Packet,
    PacketPriority,
    PacketType,
    Policy,
)


@dataclass(frozen=True)
class RoutingDecision:
    """Результат решения роутера для конкретного пакета.

    Это минимальный контракт между ядром и инфраструктурными адаптерами:
    - сам пакет (возможно, уже обогащённый метаданными);
    - выбранная политика (может быть None, если не найдено совпадений);
    - целевой endpoint (например, URL API или адрес брокера);
    - флаги, нужно ли сохранять данные в TSDB/объектное хранилище.
    """

    packet: Packet
    policy: Optional[Policy]
    target_endpoint: Optional[str]
    store_in_timeseries: bool
    store_in_object_storage: bool


class PolicyStore:
    """Простое in-memory хранилище политик.

    В реальной системе это может быть БД/конфиг-сервис/центральный реестр.
    Здесь – минимальная реализация для демонстрации и тестов.
    """

    def __init__(self, policies: Optional[Iterable[Policy]] = None) -> None:
        self._policies: List[Policy] = list(policies or [])

    # --- управление политиками -------------------------------------------------

    def add(self, policy: Policy) -> None:
        """Добавить или заменить политику по её идентификатору."""
        self.remove(policy.policy_id)
        self._policies.append(policy)

    def remove(self, policy_id: str) -> None:
        """Удалить политику по ID (если её нет – ничего не делаем)."""
        self._policies = [p for p in self._policies if p.policy_id != policy_id]

    def all(self) -> List[Policy]:
        """Вернуть копию списка всех политик (защита от внешних мутаций)."""
        return list(self._policies)

    # --- поиск подходящей политики --------------------------------------------

    def match_for_packet(self, packet: Packet) -> Optional[Policy]:
        """Найти первую политику, подходящую под данный пакет.

        Правила сопоставления (упрощённо):
        - если у политики задан `match_environment`, он должен совпадать с packet.env;
        - если задан `match_domain`, он должен совпадать с packet.domain;
        - если задан `min_priority`, приоритет пакета должен быть не ниже.
        Порядок политик имеет значение: первая подходящая выигрывает.
        """
        for policy in self._policies:
            if policy.match_environment is not None:
                if policy.match_environment is not packet.env:
                    continue

            if policy.match_domain is not None:
                if policy.match_domain is not packet.domain:
                    continue

            if policy.min_priority is not None:
                # сравниваем по порядку приоритетов
                if _priority_order(packet.priority) < _priority_order(policy.min_priority):
                    continue

            return policy

        return None


def _priority_order(priority: PacketPriority) -> int:
    """Числовой порядок приоритетов для удобного сравнения."""
    order = {
        PacketPriority.LOW: 0,
        PacketPriority.NORMAL: 1,
        PacketPriority.HIGH: 2,
        PacketPriority.CRITICAL: 3,
    }
    return order[priority]


class HybridRouter:
    """Гибридный роутер EEIA.

    Его задача – на основе Packet и набора Policy выдать RoutingDecision.
    В «боевой» системе он не отправляет данные сам, а лишь решает:
    - куда (endpoint) и как (хранить/не хранить) их передавать;
    - нужна ли дополнительная обработка на следующих слоях.

    Здесь реализуется только чистая логика выбора.
    """

    def __init__(self, policy_store: Optional[PolicyStore] = None) -> None:
        self.policy_store = policy_store or PolicyStore()

    # --- основной метод маршрутизации -----------------------------------------

    def route(self, packet: Packet) -> RoutingDecision:
        """Принять решение по маршрутизации пакета.

        Если ни одна политика не совпала, применяется дефолтное поведение:
        - пакеты TELEMETRY и HEARTBEAT сохраняем в TSDB;
        - ALERT дополнительно считаем критичным с точки зрения хранения;
        - CONTROL можно обрабатывать без хранения (по умолчанию).
        Target endpoint в этом случае остаётся None – это сигнал
        инфраструктурному коду использовать значение по умолчанию.
        """
        policy = self.policy_store.match_for_packet(packet)

        if policy is not None:
            return RoutingDecision(
                packet=packet,
                policy=policy,
                target_endpoint=str(policy.target_endpoint) if policy.target_endpoint else None,
                store_in_timeseries=policy.store_in_timeseries,
                store_in_object_storage=policy.store_in_object_storage,
            )

        # --- дефолтное поведение, если политика не найдена --------------------
        store_ts = packet.packet_type in {PacketType.TELEMETRY, PacketType.HEARTBEAT, PacketType.ALERT}
        store_obj = packet.packet_type is PacketType.ALERT

        return RoutingDecision(
            packet=packet,
            policy=None,
            target_endpoint=None,
            store_in_timeseries=store_ts,
            store_in_object_storage=store_obj,
        )

    # --- вспомогательные методы -----------------------------------------------

    def add_policies(self, policies: Sequence[Policy]) -> None:
        """Массовое добавление/обновление политик."""
        for policy in policies:
            self.policy_store.add(policy)

    def clear_policies(self) -> None:
        """Удалить все политики (для тестов или перезагрузки конфигурации)."""
        for policy in list(self.policy_store.all()):
            self.policy_store.remove(policy.policy_id)
